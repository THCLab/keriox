//! Prometheus metrics for the witness.
//!
//! The witness sits on the receiving end of every watcher/controller round
//! trip. These metrics expose how long each handler spends inside the
//! witness so we can tell server-side slowness from network slowness when
//! debugging.
//!
//! Surface is split between latency histograms (`*_seconds`), throughput
//! counters (`*_total`) and identity gauges (`build_info`). Histograms are
//! registered with explicit bucket boundaries tuned for the observed range —
//! sub-millisecond local calls up through 30s+ stalls.

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

/// Publish a `keri_witness_build_info{version}` gauge fixed at 1 so dashboards
/// can filter by deploy and confirm a scrape target is alive.
pub fn record_build_info() {
    let version = env!("CARGO_PKG_VERSION");
    let git_suffix = option_env!("GIT_VERSION_SUFFIX").unwrap_or("");
    let full = format!("{version}{git_suffix}");
    metrics::gauge!(names::BUILD_INFO, "version" => full).set(1.0);
}

/// RAII timer that records to the handler latency histogram and bumps the
/// http-request counter on drop. The drop path captures `status` so handlers
/// can record outcome before returning.
pub struct LatencyTimer {
    name: &'static str,
    labels: Vec<(&'static str, String)>,
    start: Instant,
    /// Optional HTTP status; if set, also bumps the requests-total counter.
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

    /// Record an HTTP status to be emitted on drop. Only meaningful when the
    /// timer is wrapping an HTTP handler.
    pub fn with_status(mut self, status: u16) -> Self {
        self.status = Some(status);
        self
    }

    /// Mutate status mid-flight (e.g. on early return). Returns &mut so it
    /// chains in `let mut t = ...; t.set_status(500);`.
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

        // If an HTTP status was recorded, also emit the request counter.
        // We piggyback on the same labels (assumed to include `endpoint`).
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

pub mod names {
    pub const HANDLER_SECONDS: &str = "keri_witness_handler_seconds";
    pub const QUERY_PROCESSING_SECONDS: &str = "keri_witness_query_processing_seconds";
    pub const HTTP_REQUESTS_TOTAL: &str = "keri_witness_http_requests_total";
    pub const OOBI_RESOLUTIONS_TOTAL: &str = "keri_witness_oobi_resolutions_total";
    pub const EVENTS_PROCESSED_TOTAL: &str = "keri_witness_events_processed_total";
    pub const QUERIES_TOTAL: &str = "keri_witness_queries_total";
    pub const BUILD_INFO: &str = "keri_witness_build_info";
}
