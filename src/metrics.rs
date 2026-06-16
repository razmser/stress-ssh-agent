//! Per-worker latency histogram and outcome counters.
//!
//! Stub for Task 1; real logic arrives in Task 4.

use crate::verify::VerifyOutcome;
use hdrhistogram::Histogram;
use std::time::Duration;

/// Latency histogram and outcome tallies recorded by a single worker.
pub struct WorkerStats {
    /// Sign latency in microseconds (1µs–60s, 3 significant figures).
    pub hist: Histogram<u64>,
    pub verified: u64,
    pub bad_signature: u64,
    pub sign_error: u64,
}

impl Default for WorkerStats {
    fn default() -> Self {
        let hist =
            Histogram::<u64>::new_with_bounds(1, 60_000_000, 3).expect("valid histogram bounds");
        Self {
            hist,
            verified: 0,
            bad_signature: 0,
            sign_error: 0,
        }
    }
}

impl WorkerStats {
    /// Record one operation's outcome and sign latency.
    ///
    /// Stub for Task 1; real logic arrives in Task 4.
    pub fn record(&mut self, outcome: &VerifyOutcome, sign_latency: Duration) {
        let _ = (outcome, sign_latency);
        unimplemented!("WorkerStats::record arrives in Task 4")
    }

    /// Merge another worker's stats into this one.
    ///
    /// Stub for Task 1; real logic arrives in Task 4.
    pub fn merge(&mut self, other: &WorkerStats) {
        let _ = other;
        unimplemented!("WorkerStats::merge arrives in Task 4")
    }

    /// Whether the run should exit with a non-zero code.
    pub fn should_exit_nonzero(&self) -> bool {
        self.bad_signature + self.sign_error > 0
    }
}
