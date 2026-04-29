use std::{
    collections::HashMap,
    sync::RwLock,
    time::{Duration, Instant},
};

use keri_core::prefix::IdentifierPrefix;
use serde::Serialize;

/// Per-witness health record.
#[derive(Debug, Clone, Serialize)]
pub struct WitnessHealth {
    /// Total number of successful queries.
    pub successes: u64,
    /// Total number of failed queries.
    pub failures: u64,
    /// Consecutive failures (resets on success).
    pub consecutive_failures: u64,
    /// Average response time in milliseconds (rolling).
    pub avg_response_ms: f64,
    /// Last successful contact time (seconds ago, computed at serialization).
    #[serde(skip)]
    pub last_success: Option<Instant>,
    /// Last failure time.
    #[serde(skip)]
    pub last_failure: Option<Instant>,
    /// Last error message.
    pub last_error: Option<String>,
}

impl Default for WitnessHealth {
    fn default() -> Self {
        Self {
            successes: 0,
            failures: 0,
            consecutive_failures: 0,
            avg_response_ms: 0.0,
            last_success: None,
            last_failure: None,
            last_error: None,
        }
    }
}

impl WitnessHealth {
    pub fn record_success(&mut self, response_time: Duration) {
        self.successes += 1;
        self.consecutive_failures = 0;
        self.last_success = Some(Instant::now());

        // Rolling average
        let ms = response_time.as_secs_f64() * 1000.0;
        if self.successes == 1 {
            self.avg_response_ms = ms;
        } else {
            // Exponential moving average with alpha = 0.2
            self.avg_response_ms = self.avg_response_ms * 0.8 + ms * 0.2;
        }
    }

    pub fn record_failure(&mut self, error: String) {
        self.failures += 1;
        self.consecutive_failures += 1;
        self.last_failure = Some(Instant::now());
        self.last_error = Some(error);
    }

    /// Whether this witness is considered healthy (responsive).
    ///
    /// A small circuit breaker: once a witness crosses
    /// [`Self::FAILURE_THRESHOLD`] consecutive failures it's marked
    /// unhealthy for [`Self::COOL_DOWN`]. After the cool-down expires
    /// the next call treats it as healthy again — that call is the
    /// "probe": if it succeeds, `consecutive_failures` resets to zero
    /// in `record_success`; if it fails, the timer restarts. There's no
    /// explicit half-open state, just a read of `last_failure`.
    pub fn is_healthy(&self) -> bool {
        if self.consecutive_failures < Self::FAILURE_THRESHOLD {
            return true;
        }
        match self.last_failure {
            Some(t) => t.elapsed() >= Self::COOL_DOWN,
            None => true,
        }
    }

    pub const FAILURE_THRESHOLD: u64 = 3;
    pub const COOL_DOWN: Duration = Duration::from_secs(30);
}

/// Aggregated health status for the watcher's view of a specific AID.
#[derive(Debug, Clone, Serialize)]
pub struct AidHealthStatus {
    pub prefix: String,
    pub total_witnesses: usize,
    pub healthy_witnesses: usize,
    pub degraded: bool,
}

/// Tracks health statistics for all witnesses the watcher interacts with.
pub struct WitnessHealthTracker {
    /// Per-witness health records keyed by witness identifier string.
    records: RwLock<HashMap<String, WitnessHealth>>,
}

impl WitnessHealthTracker {
    pub fn new() -> Self {
        Self {
            records: RwLock::new(HashMap::new()),
        }
    }

    /// Record a successful response from a witness.
    pub fn record_success(&self, witness_id: &IdentifierPrefix, response_time: Duration) {
        let key = witness_id.to_string();
        let mut records = self.records.write().unwrap();
        records
            .entry(key)
            .or_insert_with(WitnessHealth::default)
            .record_success(response_time);
    }

    /// Record a failed response from a witness.
    pub fn record_failure(&self, witness_id: &IdentifierPrefix, error: String) {
        let key = witness_id.to_string();
        let mut records = self.records.write().unwrap();
        records
            .entry(key)
            .or_insert_with(WitnessHealth::default)
            .record_failure(error);
    }

    /// Check if a specific witness is considered healthy.
    pub fn is_healthy(&self, witness_id: &IdentifierPrefix) -> bool {
        let key = witness_id.to_string();
        let records = self.records.read().unwrap();
        records.get(&key).map(|h| h.is_healthy()).unwrap_or(true) // unknown witnesses are assumed healthy
    }

    /// Get health snapshot for all tracked witnesses.
    pub fn get_all_health(&self) -> HashMap<String, WitnessHealth> {
        let records = self.records.read().unwrap();
        records.clone()
    }

    /// Order a witness list by query priority, splitting into a healthy
    /// front (sorted ascending by EMA response time) and a degraded tail.
    /// Unknown witnesses are treated as healthy with zero average latency
    /// so they get tried before known-slow ones — that gives them a chance
    /// to register a baseline.
    ///
    /// Callers that want to fail fast should iterate the returned list and
    /// stop at `degraded_start` (the second tuple element); the tail is only
    /// useful as a fallback when every healthy witness has failed.
    pub fn priority_order(
        &self,
        witness_ids: &[IdentifierPrefix],
    ) -> (Vec<IdentifierPrefix>, usize) {
        let records = self.records.read().unwrap();
        let mut healthy: Vec<(IdentifierPrefix, f64)> = vec![];
        let mut degraded: Vec<(IdentifierPrefix, f64)> = vec![];
        for w in witness_ids {
            let key = w.to_string();
            match records.get(&key) {
                Some(h) if h.is_healthy() => healthy.push((w.clone(), h.avg_response_ms)),
                Some(h) => degraded.push((w.clone(), h.avg_response_ms)),
                None => healthy.push((w.clone(), 0.0)),
            }
        }
        healthy.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
        degraded.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
        let degraded_start = healthy.len();
        let mut out: Vec<IdentifierPrefix> = healthy.into_iter().map(|(w, _)| w).collect();
        out.extend(degraded.into_iter().map(|(w, _)| w));
        (out, degraded_start)
    }

    /// Get health status for witnesses of a specific AID.
    pub fn get_aid_health(
        &self,
        aid: &IdentifierPrefix,
        witness_ids: &[IdentifierPrefix],
    ) -> AidHealthStatus {
        let records = self.records.read().unwrap();
        let healthy_count = witness_ids
            .iter()
            .filter(|w| {
                records
                    .get(&w.to_string())
                    .map(|h| h.is_healthy())
                    .unwrap_or(true)
            })
            .count();

        AidHealthStatus {
            prefix: aid.to_string(),
            total_witnesses: witness_ids.len(),
            healthy_witnesses: healthy_count,
            degraded: healthy_count == 0 && !witness_ids.is_empty(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_health_is_healthy() {
        let h = WitnessHealth::default();
        assert!(h.is_healthy());
    }

    #[test]
    fn opens_at_failure_threshold() {
        let mut h = WitnessHealth::default();
        for _ in 0..WitnessHealth::FAILURE_THRESHOLD {
            h.record_failure("boom".into());
        }
        assert!(!h.is_healthy(), "should be unhealthy after threshold failures");
    }

    #[test]
    fn cooldown_allows_probe() {
        let mut h = WitnessHealth::default();
        for _ in 0..WitnessHealth::FAILURE_THRESHOLD {
            h.record_failure("boom".into());
        }
        // Simulate cool-down elapsing by rewinding last_failure.
        h.last_failure = Some(Instant::now() - WitnessHealth::COOL_DOWN - Duration::from_secs(1));
        assert!(h.is_healthy(), "should be healthy after cool-down (probe)");
    }

    #[test]
    fn success_after_failures_resets_state() {
        let mut h = WitnessHealth::default();
        for _ in 0..WitnessHealth::FAILURE_THRESHOLD {
            h.record_failure("boom".into());
        }
        assert!(!h.is_healthy());
        h.record_success(Duration::from_millis(20));
        assert!(h.is_healthy());
        assert_eq!(h.consecutive_failures, 0);
    }

    #[test]
    fn probe_failure_keeps_circuit_open() {
        let mut h = WitnessHealth::default();
        for _ in 0..WitnessHealth::FAILURE_THRESHOLD {
            h.record_failure("boom".into());
        }
        // Cool-down elapses, probe is permitted.
        h.last_failure = Some(Instant::now() - WitnessHealth::COOL_DOWN - Duration::from_secs(1));
        assert!(h.is_healthy());
        // Probe fails — last_failure resets to now, circuit closes again.
        h.record_failure("still bad".into());
        assert!(!h.is_healthy());
    }
}
