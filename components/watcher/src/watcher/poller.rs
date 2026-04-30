use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use futures::stream::{FuturesUnordered, StreamExt};
use keri_core::{oobi_manager::storage::OobiStorageBackend, prefix::IdentifierPrefix};
use tokio::time::sleep;

use super::watcher_data::WatcherData;

/// Cap on how many AIDs the poller will fetch concurrently in a single
/// cycle. Each poll fans out one query per witness, so the *effective*
/// concurrent HTTP requests are roughly this number times witnesses per
/// AID. Bounded to keep the total within the shared HTTP client's
/// connection pool ceiling and avoid pathological fan-out at large AID
/// counts.
const MAX_CONCURRENT_POLLS: usize = 16;

/// Tracks the polling state for a single AID.
#[derive(Debug, Clone)]
struct TrackedAid {
    /// Last known sequence number from witnesses.
    last_known_sn: u64,
    /// When this AID was last polled.
    last_polled: Option<Instant>,
    /// When the SN last changed (used for adaptive intervals).
    last_changed: Option<Instant>,
    /// Whether this AID has active subscribers (higher priority).
    subscribed: bool,
}

impl TrackedAid {
    fn new() -> Self {
        Self {
            last_known_sn: 0,
            last_polled: None,
            last_changed: None,
            subscribed: false,
        }
    }

    /// Compute the effective poll interval for this AID.
    /// Recently active AIDs are polled more frequently.
    /// Subscribed AIDs get the base interval.
    /// Stable AIDs get progressively longer intervals.
    fn effective_interval(&self, base_interval: Duration) -> Duration {
        if self.subscribed {
            return base_interval;
        }

        let idle_time = self
            .last_changed
            .map(|t| t.elapsed())
            .unwrap_or(Duration::from_secs(3600));

        if idle_time < Duration::from_secs(60) {
            // Changed in the last minute — poll at base rate
            base_interval
        } else if idle_time < Duration::from_secs(300) {
            // Changed in the last 5 minutes — poll at 2x base
            base_interval * 2
        } else if idle_time < Duration::from_secs(3600) {
            // Changed in the last hour — poll at 5x base
            base_interval * 5
        } else {
            // Stable for over an hour — poll at 10x base
            base_interval * 10
        }
    }

    /// Whether this AID should be polled now based on its adaptive interval.
    fn should_poll(&self, base_interval: Duration) -> bool {
        match self.last_polled {
            None => true,
            Some(last) => last.elapsed() >= self.effective_interval(base_interval),
        }
    }
}

/// Background poller that periodically queries witnesses for KSN updates
/// on all tracked AIDs, ensuring the watcher's local KEL stays current
/// without relying on external query triggers.
///
/// Features adaptive polling intervals:
/// - Recently active AIDs are polled at the base rate
/// - Stable (unchanged) AIDs are polled less frequently
/// - Subscribed AIDs always get the base rate regardless of activity
pub struct WitnessPoller<S: OobiStorageBackend> {
    watcher_data: Arc<WatcherData<S>>,
    tracked_aids: Arc<RwLock<HashMap<IdentifierPrefix, TrackedAid>>>,
    poll_interval: Duration,
}

impl<S: OobiStorageBackend> WitnessPoller<S> {
    pub fn new(watcher_data: Arc<WatcherData<S>>, poll_interval: Duration) -> Self {
        Self {
            watcher_data,
            tracked_aids: Arc::new(RwLock::new(HashMap::new())),
            poll_interval,
        }
    }

    /// Register an AID for periodic polling.
    pub fn track_aid(&self, id: IdentifierPrefix) {
        let mut tracked = self.tracked_aids.write().unwrap();
        tracked.entry(id).or_insert_with(TrackedAid::new);
    }

    /// Remove an AID from periodic polling.
    pub fn untrack_aid(&self, id: &IdentifierPrefix) {
        let mut tracked = self.tracked_aids.write().unwrap();
        tracked.remove(id);
    }

    /// Subscribe to an AID — it will always be polled at the base interval
    /// regardless of activity level. Automatically tracks the AID if not already tracked.
    pub fn subscribe(&self, id: IdentifierPrefix) {
        let mut tracked = self.tracked_aids.write().unwrap();
        let entry = tracked.entry(id).or_insert_with(TrackedAid::new);
        entry.subscribed = true;
    }

    /// Unsubscribe from an AID — it will fall back to adaptive polling intervals.
    /// The AID remains tracked; use `untrack_aid` to stop polling entirely.
    pub fn unsubscribe(&self, id: &IdentifierPrefix) {
        let mut tracked = self.tracked_aids.write().unwrap();
        if let Some(entry) = tracked.get_mut(id) {
            entry.subscribed = false;
        }
    }

    /// Get the list of currently tracked AIDs.
    pub fn tracked_aid_ids(&self) -> Vec<IdentifierPrefix> {
        let tracked = self.tracked_aids.read().unwrap();
        tracked.keys().cloned().collect()
    }

    /// Run the polling loop. This should be spawned as a background task.
    pub async fn run(&self) {
        if self.poll_interval.is_zero() {
            tracing::info!("Witness polling disabled (interval = 0)");
            return;
        }

        tracing::info!(
            interval_secs = self.poll_interval.as_secs(),
            "Starting witness poller"
        );

        loop {
            self.poll_due_aids().await;
            // Sleep for a fraction of the base interval to check due AIDs more often
            sleep(self.poll_interval / 2).await;
        }
    }

    /// Poll only AIDs whose adaptive interval has elapsed.
    async fn poll_due_aids(&self) {
        let _cycle_timer = crate::metrics::LatencyTimer::new(
            crate::metrics::names::POLL_CYCLE_SECONDS,
            vec![],
        );
        let due_aids: Vec<(IdentifierPrefix, TrackedAid)> = {
            let tracked = self.tracked_aids.read().unwrap();
            tracked
                .iter()
                .filter(|(_, t)| t.should_poll(self.poll_interval))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        };

        // Always observe the cycle's fan-out size, even when zero —
        // dashboards plot the histogram count and want to see "we ran a
        // cycle and found nothing to do" distinguishable from "we never
        // ran a cycle".
        metrics::histogram!(crate::metrics::names::POLL_AIDS_PER_CYCLE)
            .record(due_aids.len() as f64);

        if due_aids.is_empty() {
            return;
        }

        tracing::debug!(
            due = due_aids.len(),
            total = self.tracked_aids.read().unwrap().len(),
            "Polling due AIDs"
        );

        // Fan out polls with bounded concurrency. Each AID's poll is
        // independent so they're safe to run in parallel; the bound stops
        // a large tracked-AID set from saturating the connection pool.
        // Tracked-state writes happen sequentially as each future
        // completes, which is fine because they're all keyed by AID and
        // touch disjoint map entries.
        let mut in_flight: FuturesUnordered<_> = FuturesUnordered::new();
        let mut iter = due_aids.into_iter();
        for _ in 0..MAX_CONCURRENT_POLLS {
            if let Some((aid, tracked)) = iter.next() {
                in_flight.push(self.poll_one(aid, tracked));
            } else {
                break;
            }
        }
        while let Some((aid, result)) = in_flight.next().await {
            self.apply_poll_result(&aid, result);
            if let Some((next_aid, next_tracked)) = iter.next() {
                in_flight.push(self.poll_one(next_aid, next_tracked));
            }
        }
    }

    async fn poll_one(
        &self,
        aid: IdentifierPrefix,
        tracked: TrackedAid,
    ) -> (
        IdentifierPrefix,
        Result<u64, keri_core::actor::error::ActorError>,
    ) {
        let result = self.poll_aid(&aid, &tracked).await;
        (aid, result)
    }

    fn apply_poll_result(
        &self,
        aid: &IdentifierPrefix,
        result: Result<u64, keri_core::actor::error::ActorError>,
    ) {
        match result {
            Ok(new_sn) => {
                let mut tracked_map = self.tracked_aids.write().unwrap();
                if let Some(entry) = tracked_map.get_mut(aid) {
                    entry.last_polled = Some(Instant::now());
                    if new_sn > entry.last_known_sn {
                        tracing::info!(
                            prefix = %aid,
                            old_sn = entry.last_known_sn,
                            new_sn = new_sn,
                            "AID updated via polling"
                        );
                        entry.last_known_sn = new_sn;
                        entry.last_changed = Some(Instant::now());
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    prefix = %aid,
                    error = %e,
                    "Failed to poll AID"
                );
                // Still update last_polled to avoid hammering on errors.
                let mut tracked_map = self.tracked_aids.write().unwrap();
                if let Some(entry) = tracked_map.get_mut(aid) {
                    entry.last_polled = Some(Instant::now());
                }
            }
        }
    }

    /// Poll witnesses for a single AID. Returns the new SN after update.
    async fn poll_aid(
        &self,
        aid: &IdentifierPrefix,
        tracked: &TrackedAid,
    ) -> Result<u64, keri_core::actor::error::ActorError> {
        // Query witnesses for latest KSN
        let witness_sn = self.watcher_data.query_state(aid).await?;

        if witness_sn > tracked.last_known_sn {
            // Fetch missing KEL events
            let local_sn = self
                .watcher_data
                .event_storage
                .get_state(aid)
                .map(|s| s.sn)
                .unwrap_or(0);

            if local_sn < witness_sn {
                self.watcher_data.forward_query_from(aid, local_sn).await?;
            }
        }

        // Return the current SN (local state after potential update)
        Ok(self
            .watcher_data
            .event_storage
            .get_state(aid)
            .map(|s| s.sn)
            .unwrap_or(0))
    }
}
