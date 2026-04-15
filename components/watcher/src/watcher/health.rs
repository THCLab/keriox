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
    pub fn is_healthy(&self) -> bool {
        self.consecutive_failures < 3
    }
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
        records
            .get(&key)
            .map(|h| h.is_healthy())
            .unwrap_or(true) // unknown witnesses are assumed healthy
    }

    /// Get health snapshot for all tracked witnesses.
    pub fn get_all_health(&self) -> HashMap<String, WitnessHealth> {
        let records = self.records.read().unwrap();
        records.clone()
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
