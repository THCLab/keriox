//! Automatic retry with exponential backoff for network operations.
//!
//! Witnesses and watchers are ordinary HTTP services: they restart, drop
//! connections and answer slowly. Every facade operation that talks to them
//! retries transient failures automatically, governed by a [`RetryPolicy`].
//! The default policy suits most applications; pass a custom one to
//! [`crate::Keri::open_with`] to tune it.

use std::time::Duration;

use crate::error::Result;

/// How network operations are retried before giving up.
///
/// Delays grow exponentially: `initial_delay`, then `initial_delay *
/// multiplier`, and so on, capped at `max_delay`, for at most `max_attempts`
/// total attempts.
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Total number of attempts (the first try counts as one).
    pub max_attempts: u32,
    /// Delay before the second attempt.
    pub initial_delay: Duration,
    /// Upper bound on the delay between attempts.
    pub max_delay: Duration,
    /// Factor the delay grows by after each failed attempt.
    pub multiplier: f64,
}

impl Default for RetryPolicy {
    /// 6 attempts, 250 ms → 8 s, doubling each time.
    fn default() -> Self {
        RetryPolicy {
            max_attempts: 6,
            initial_delay: Duration::from_millis(250),
            max_delay: Duration::from_secs(8),
            multiplier: 2.0,
        }
    }
}

impl RetryPolicy {
    /// A policy that never retries — useful in tests of failure paths.
    pub fn no_retries() -> Self {
        RetryPolicy {
            max_attempts: 1,
            ..Default::default()
        }
    }

    fn delay_for(&self, attempt: u32) -> Duration {
        let factor = self.multiplier.powi(attempt as i32);
        let delay = self.initial_delay.mul_f64(factor);
        delay.min(self.max_delay)
    }
}

/// Run `op` until it succeeds, the error is permanent, or attempts run out.
pub(crate) async fn with_retry<T, F, Fut>(policy: &RetryPolicy, mut op: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let mut attempt = 0;
    loop {
        match op().await {
            Ok(value) => return Ok(value),
            Err(e) if e.is_transient() && attempt + 1 < policy.max_attempts => {
                log::debug!(
                    "transient failure (attempt {}/{}): {e}; retrying",
                    attempt + 1,
                    policy.max_attempts
                );
                tokio::time::sleep(policy.delay_for(attempt)).await;
                attempt += 1;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Like [`with_retry`], but retries while `op` reports "not yet" (`Ok(None)`)
/// — for polling witnesses or watchers until an expected update arrives.
/// Returns `Ok(None)` when attempts run out, letting the caller decide how to
/// report the timeout.
#[allow(dead_code)] // used by later facade stages (credential status, multi-party flows)
pub(crate) async fn poll_until<T, F, Fut>(policy: &RetryPolicy, mut op: F) -> Result<Option<T>>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<Option<T>>>,
{
    let mut attempt = 0;
    loop {
        match op().await {
            Ok(Some(value)) => return Ok(Some(value)),
            Ok(None) if attempt + 1 < policy.max_attempts => {
                tokio::time::sleep(policy.delay_for(attempt)).await;
                attempt += 1;
            }
            Ok(None) => return Ok(None),
            Err(e) if e.is_transient() && attempt + 1 < policy.max_attempts => {
                tokio::time::sleep(policy.delay_for(attempt)).await;
                attempt += 1;
            }
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn transient_error() -> Error {
        Error::WitnessUnreachable {
            url: "http://example.invalid".into(),
            attempts: 1,
            cause: "connection refused".into(),
        }
    }

    #[tokio::test]
    async fn retries_transient_errors_until_success() {
        let policy = RetryPolicy {
            max_attempts: 4,
            initial_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(2),
            multiplier: 2.0,
        };
        let calls = AtomicU32::new(0);
        let result = with_retry(&policy, || {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            async move {
                if n < 2 {
                    Err(transient_error())
                } else {
                    Ok(42)
                }
            }
        })
        .await;
        assert_eq!(result.unwrap(), 42);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn does_not_retry_permanent_errors() {
        let policy = RetryPolicy::default();
        let calls = AtomicU32::new(0);
        let result: Result<()> = with_retry(&policy, || {
            calls.fetch_add(1, Ordering::SeqCst);
            async { Err(Error::IdentityNotFound("alice".into())) }
        })
        .await;
        assert!(matches!(result, Err(Error::IdentityNotFound(_))));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn gives_up_after_max_attempts() {
        let policy = RetryPolicy {
            max_attempts: 3,
            initial_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(1),
            multiplier: 1.0,
        };
        let calls = AtomicU32::new(0);
        let result: Result<()> = with_retry(&policy, || {
            calls.fetch_add(1, Ordering::SeqCst);
            async { Err(transient_error()) }
        })
        .await;
        assert!(result.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn poll_until_polls_through_not_yet() {
        let policy = RetryPolicy {
            max_attempts: 5,
            initial_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(1),
            multiplier: 1.0,
        };
        let calls = AtomicU32::new(0);
        let result = poll_until(&policy, || {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            async move { Ok(if n < 3 { None } else { Some("ready") }) }
        })
        .await;
        assert_eq!(result.unwrap(), Some("ready"));
    }
}
