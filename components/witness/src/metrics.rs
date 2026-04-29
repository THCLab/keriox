//! Prometheus metrics for the witness.
//!
//! The witness sits on the receiving end of every watcher/controller round
//! trip. These metrics expose how long each handler spends inside the
//! witness so we can tell server-side slowness from network slowness when
//! debugging.

use std::sync::OnceLock;
use std::time::Instant;

use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};

const LATENCY_BUCKETS: &[f64] = &[
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 20.0, 30.0, 60.0,
];

/// See [`watcher::metrics::install`] for rationale on the Option return.
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

pub fn render() -> String {
    install().map(|h| h.render()).unwrap_or_default()
}

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
        let labels: Vec<(&'static str, String)> = std::mem::take(&mut self.labels);
        let labels: Vec<metrics::Label> = labels
            .into_iter()
            .map(|(k, v)| metrics::Label::new(k, v))
            .collect();
        metrics::histogram!(self.name, labels).record(elapsed);
    }
}

pub mod names {
    pub const HANDLER_SECONDS: &str = "keri_witness_handler_seconds";
    pub const QUERY_PROCESSING_SECONDS: &str = "keri_witness_query_processing_seconds";
}
