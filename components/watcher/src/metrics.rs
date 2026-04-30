//! Prometheus metrics for the watcher.
//!
//! The watcher's job is the AID-verification critical path: client asks to
//! verify an AID -> watcher resolves OOBI -> queries witnesses -> returns the
//! latest KEL/TEL. These metrics decompose that round-trip so we can see
//! which hop is responsible when end-to-end latency spikes.
//!
//! Histograms are registered with explicit bucket boundaries (in seconds)
//! tuned for the observed range — sub-millisecond local calls up through
//! 30s+ failures.
//!
//! Beyond per-handler latency, the module also exposes scaling KPIs via
//! gauges that a [`sampler`] task refreshes on a timer: tracked AIDs,
//! per-witness EMA latency, circuit-breaker state, etc. Sampling is cheap
//! (in-memory state only) and runs off the request path so a slow scrape
//! never costs end-user latency.

use std::sync::OnceLock;
use std::sync::Arc;
use std::time::Instant;

use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};

const LATENCY_BUCKETS: &[f64] = &[
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 20.0, 30.0, 60.0,
];

/// Install the Prometheus recorder. Idempotent — only the first call wins.
/// Returns `None` if some other component already installed a global
/// recorder (e.g. when watcher and witness run in the same process for
/// integration tests); in that case metrics still flow to the existing
/// global recorder, but `/metrics` on this component will render empty.
pub fn install() -> Option<&'static PrometheusHandle> {
    static HANDLE: OnceLock<Option<PrometheusHandle>> = OnceLock::new();
    HANDLE
        .get_or_init(|| {
            PrometheusBuilder::new()
                .set_buckets_for_metric(Matcher::Suffix("_seconds".to_string()), LATENCY_BUCKETS)
                .expect("valid bucket config")
                .install_recorder()
                .ok()
        })
        .as_ref()
}

/// Render the current metrics snapshot in Prometheus exposition format.
/// If no recorder is owned by this component, returns an empty body.
pub fn render() -> String {
    install().map(|h| h.render()).unwrap_or_default()
}

/// Publish a `keri_watcher_build_info{version}` gauge fixed at 1 so
/// dashboards can filter by deploy and confirm a scrape target is alive.
pub fn record_build_info() {
    let version = env!("CARGO_PKG_VERSION");
    let git_suffix = option_env!("GIT_VERSION_SUFFIX").unwrap_or("");
    let full = format!("{version}{git_suffix}");
    metrics::gauge!(names::BUILD_INFO, "version" => full).set(1.0);
}

/// Small RAII timer that records `Instant::now() - start` to a histogram on
/// drop. Use it to time a code region without juggling start variables.
/// When `status` is set, also bumps `keri_watcher_http_requests_total` so
/// dashboards can compute per-endpoint error rates without a separate
/// counter wired in every handler.
pub struct LatencyTimer {
    name: &'static str,
    labels: Vec<(&'static str, String)>,
    start: Instant,
    status: Option<u16>,
}

impl LatencyTimer {
    pub fn new(name: &'static str, labels: Vec<(&'static str, String)>) -> Self {
        Self {
            name,
            labels,
            start: Instant::now(),
            status: None,
        }
    }

    pub fn with_status(mut self, status: u16) -> Self {
        self.status = Some(status);
        self
    }

    pub fn set_status(&mut self, status: u16) {
        self.status = Some(status);
    }
}

impl Drop for LatencyTimer {
    fn drop(&mut self) {
        let elapsed = self.start.elapsed().as_secs_f64();
        let labels: Vec<(&'static str, String)> = std::mem::take(&mut self.labels);
        let metric_labels: Vec<metrics::Label> = labels
            .iter()
            .cloned()
            .map(|(k, v)| metrics::Label::new(k, v))
            .collect();
        metrics::histogram!(self.name, metric_labels).record(elapsed);

        if let Some(status) = self.status.take() {
            let mut counter_labels: Vec<metrics::Label> = labels
                .into_iter()
                .map(|(k, v)| metrics::Label::new(k, v))
                .collect();
            counter_labels.push(metrics::Label::new("status", status.to_string()));
            metrics::counter!(names::HTTP_REQUESTS_TOTAL, counter_labels).increment(1);
        }
    }
}

/// RAII guard that increments [`names::INFLIGHT_QUERIES`] on construction
/// and decrements on drop. Wrap KEL fetch fan-out with this so dashboards
/// can show concurrent witness traffic — the most useful early signal that
/// the watcher is approaching its connection-pool ceiling.
pub struct InflightGuard;

impl InflightGuard {
    pub fn enter() -> Self {
        metrics::gauge!(names::INFLIGHT_QUERIES).increment(1.0);
        Self
    }
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        metrics::gauge!(names::INFLIGHT_QUERIES).decrement(1.0);
    }
}

// Metric names — referenced from instrumented call sites. Centralised so a
// dashboard can grep the source for the canonical names.
pub mod names {
    pub const OOBI_RESOLVE_SECONDS: &str = "keri_watcher_oobi_resolve_seconds";
    pub const WITNESS_QUERY_SECONDS: &str = "keri_watcher_witness_query_seconds";
    pub const KEL_FETCH_SECONDS: &str = "keri_watcher_kel_fetch_seconds";
    pub const KEL_FETCH_TOTAL: &str = "keri_watcher_kel_fetch_total";
    pub const HANDLER_SECONDS: &str = "keri_watcher_handler_seconds";
    pub const INFLIGHT_QUERIES: &str = "keri_watcher_inflight_queries";
    pub const WITNESS_QUERY_FAILURES_TOTAL: &str = "keri_watcher_witness_query_failures_total";

    pub const HTTP_REQUESTS_TOTAL: &str = "keri_watcher_http_requests_total";
    pub const OOBI_RESOLUTIONS_TOTAL: &str = "keri_watcher_oobi_resolutions_total";
    pub const TRACKED_AIDS: &str = "keri_watcher_tracked_aids";
    pub const MONITORED_WITNESSES: &str = "keri_watcher_monitored_witnesses";
    pub const WITNESS_CONSECUTIVE_FAILURES: &str = "keri_watcher_witness_consecutive_failures";
    pub const WITNESS_AVG_RESPONSE_MS: &str = "keri_watcher_witness_avg_response_ms";
    pub const CIRCUIT_BREAKER_OPEN: &str = "keri_watcher_circuit_breaker_open";
    pub const POLL_CYCLE_SECONDS: &str = "keri_watcher_poll_cycle_seconds";
    pub const POLL_AIDS_PER_CYCLE: &str = "keri_watcher_poll_aids_per_cycle";
    pub const BUILD_INFO: &str = "keri_watcher_build_info";
}

/// Background sampler that reads cheap in-memory watcher state on a timer
/// and writes it to gauges. Keeps the scrape path itself O(1) — Prometheus
/// just reads pre-computed values rather than walking the health tracker
/// every time it polls.
///
/// Spawn from `main.rs` after the watcher is constructed; the task lives
/// for the lifetime of the process. A 10s tick is fine for the values we
/// expose: tracked-AID count and per-witness health move on human
/// timescales, not microsecond ones.
pub mod sampler {
    use std::time::Duration;

    use keri_core::oobi_manager::storage::OobiStorageBackend;

    use crate::watcher::Watcher;

    const SAMPLE_INTERVAL: Duration = Duration::from_secs(10);

    pub fn spawn<S: OobiStorageBackend + Send + Sync + 'static>(
        watcher: super::Arc<Watcher<S>>,
    ) {
        actix_web::rt::spawn(async move {
            // Hand-rolled tick loop — `actix_web::rt::time::interval` exists
            // but `MissedTickBehavior` is not re-exported, and we just need
            // a simple "sleep for the interval" loop anyway. Using `sleep`
            // also means a very slow `sample_once` shifts subsequent ticks
            // backwards instead of bursting catch-up samples.
            loop {
                actix_web::rt::time::sleep(SAMPLE_INTERVAL).await;
                sample_once(&watcher);
            }
        });
    }

    fn sample_once<S: OobiStorageBackend>(watcher: &Watcher<S>) {
        use super::names;

        // Tracked AIDs gauge — this is the watcher's "fan-out load" and
        // the headline number for capacity planning.
        let tracked = watcher.poller.tracked_aid_ids().len() as f64;
        metrics::gauge!(names::TRACKED_AIDS).set(tracked);

        // Per-witness state. We snapshot the whole map under the read lock
        // so a long iteration here can't block writers.
        let healths = watcher.watcher_data.health_tracker.get_all_health();
        let mut healthy = 0u64;
        let mut tripped = 0u64;
        for (witness_id, health) in healths.iter() {
            metrics::gauge!(
                names::WITNESS_CONSECUTIVE_FAILURES,
                "witness_id" => witness_id.clone()
            )
            .set(health.consecutive_failures as f64);
            metrics::gauge!(
                names::WITNESS_AVG_RESPONSE_MS,
                "witness_id" => witness_id.clone()
            )
            .set(health.avg_response_ms);

            let is_healthy = health.is_healthy();
            metrics::gauge!(
                names::CIRCUIT_BREAKER_OPEN,
                "witness_id" => witness_id.clone()
            )
            .set(if is_healthy { 0.0 } else { 1.0 });

            if is_healthy {
                healthy += 1;
            } else {
                tripped += 1;
            }
        }
        metrics::gauge!(names::MONITORED_WITNESSES, "state" => "healthy")
            .set(healthy as f64);
        metrics::gauge!(names::MONITORED_WITNESSES, "state" => "tripped")
            .set(tripped as f64);
    }
}
