//! Discovering KERI infrastructure (witnesses, watchers) from plain URLs.
//!
//! Witness and watcher services answer `GET /introduce` with a small JSON
//! document (an "OOBI") stating their identifier and address. The facade does
//! this lookup internally so applications only ever supply base URLs like
//! `"http://witness.example:3232"`.

use keri_controller::LocationScheme;
use url::Url;

use crate::error::{Error, Result};
use crate::retry::{with_retry, RetryPolicy};

/// Fetch a service's self-description (OOBI) from its base URL via
/// `GET /introduce`, retrying transient connection failures.
pub(crate) async fn discover(base_url: &str, policy: &RetryPolicy) -> Result<LocationScheme> {
    let url = Url::parse(base_url).map_err(|e| Error::InvalidInput {
        expected: "witness or watcher base URL",
        cause: format!("{base_url:?}: {e}"),
    })?;
    let introduce_url = url.join("introduce").map_err(|e| Error::InvalidInput {
        expected: "witness or watcher base URL",
        cause: format!("{base_url:?}: {e}"),
    })?;

    with_retry(policy, || {
        let introduce_url = introduce_url.clone();
        async move {
            let response = reqwest::get(introduce_url.clone()).await.map_err(|e| {
                Error::WitnessUnreachable {
                    url: introduce_url.to_string(),
                    attempts: 1,
                    cause: e.to_string(),
                }
            })?;
            response
                .json::<LocationScheme>()
                .await
                .map_err(|e| Error::InvalidInput {
                    expected: "OOBI JSON from GET /introduce",
                    cause: e.to_string(),
                })
        }
    })
    .await
    .map_err(|e| match e {
        // Re-stamp the attempt count with the policy's total for the message.
        Error::WitnessUnreachable { url, cause, .. } => Error::WitnessUnreachable {
            url,
            attempts: policy.max_attempts,
            cause,
        },
        other => other,
    })
}

/// Parse `source` as either a raw OOBI JSON document or fetch it from a base
/// URL. Used by contact import, where callers may hold either form.
#[allow(dead_code)] // used by Keri::import_contact in a later facade stage
pub(crate) async fn resolve_source(source: &str, policy: &RetryPolicy) -> Result<LocationScheme> {
    let trimmed = source.trim();
    if trimmed.starts_with('{') {
        serde_json::from_str(trimmed).map_err(|e| Error::InvalidInput {
            expected: "OOBI JSON document",
            cause: e.to_string(),
        })
    } else {
        discover(trimmed, policy).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn discover_rejects_invalid_url() {
        let err = discover("not a url", &RetryPolicy::no_retries())
            .await
            .unwrap_err();
        assert!(matches!(err, Error::InvalidInput { .. }));
    }

    #[tokio::test]
    async fn discover_reports_unreachable_witness() {
        // Port 9 (discard) is reliably closed for HTTP.
        let err = discover("http://127.0.0.1:9", &RetryPolicy::no_retries())
            .await
            .unwrap_err();
        assert!(matches!(err, Error::WitnessUnreachable { .. }));
    }

    #[tokio::test]
    async fn resolve_source_accepts_raw_oobi_json() {
        let oobi = r#"{"eid":"BErocgXD2RGSyvn3MObcx59jeOsEQhv2TqHirVkzrp0Q","scheme":"http","url":"http://127.0.0.1:3232/"}"#;
        let loc = resolve_source(oobi, &RetryPolicy::no_retries())
            .await
            .unwrap();
        assert_eq!(loc.url.as_str(), "http://127.0.0.1:3232/");
    }
}
