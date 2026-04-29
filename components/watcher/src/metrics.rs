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

use std::sync::OnceLock;
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

/// Small RAII timer that records `Instant::now() - start` to a histogram on
/// drop. Use it to time a code region without juggling start variables.
pub struct LatencyTimer {
    name: &'static str,
    labels: Vec<(&'static str, String)>,
    start: Instant,
}

impl LatencyTimer {
    pub fn new(name: &'static str, labels: Vec<(&'static str, String)>) -> Self {
        Self {
            name,
            labels,
            start: Instant::now(),
        }
    }
}

impl Drop for LatencyTimer {
    fn drop(&mut self) {
        let elapsed = self.start.elapsed().as_secs_f64();
        // metrics 0.23 expects an array of Label or KeyName; build via &[(&str, String)]
        let labels: Vec<(&'static str, String)> = std::mem::take(&mut self.labels);
        let labels: Vec<metrics::Label> = labels
            .into_iter()
            .map(|(k, v)| metrics::Label::new(k, v))
            .collect();
        metrics::histogram!(self.name, labels).record(elapsed);
    }
}

// Metric names — referenced from instrumented call sites. Centralised so a
// dashboard can grep the source for the canonical names.
pub mod names {
    pub const OOBI_RESOLVE_SECONDS: &str = "keri_watcher_oobi_resolve_seconds";
    pub const WITNESS_QUERY_SECONDS: &str = "keri_watcher_witness_query_seconds";
    pub const KEL_FETCH_SECONDS: &str = "keri_watcher_kel_fetch_seconds";
    pub const HANDLER_SECONDS: &str = "keri_watcher_handler_seconds";
    pub const INFLIGHT_QUERIES: &str = "keri_watcher_inflight_queries";
    pub const WITNESS_QUERY_FAILURES_TOTAL: &str = "keri_watcher_witness_query_failures_total";
}
