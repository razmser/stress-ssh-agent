//! Per-worker latency histogram and outcome counters.
//!
//! Each worker records sign latency (microseconds) into an HDR histogram and
//! tallies outcomes; `main` merges the per-worker stats and prints the report.

use crate::verify::VerifyOutcome;
use hdrhistogram::Histogram;
use std::fmt::Write as _;
use std::time::Duration;

/// Histogram low bound (1µs) and high bound (60s), with 3 significant figures.
const HIST_LOW: u64 = 1;
const HIST_HIGH: u64 = 60_000_000;
const HIST_SIGFIG: u8 = 3;

/// Latency histogram and outcome tallies recorded by a single worker.
pub struct WorkerStats {
    /// Sign latency in microseconds (1µs–60s, 3 significant figures).
    pub hist: Histogram<u64>,
    pub verified: u64,
    pub bad_signature: u64,
    pub sign_error: u64,
    /// Agent returned a signature whose algorithm we cannot verify. Counted as
    /// a failure (it is an unverified operation), not silently dropped.
    pub unsupported: u64,
}

impl Default for WorkerStats {
    fn default() -> Self {
        Self::new()
    }
}

impl WorkerStats {
    /// Construct empty stats. The histogram bounds are compile-time constants
    /// known to be valid, so the `new_with_bounds` Result is unwrapped here.
    pub fn new() -> Self {
        let hist = Histogram::<u64>::new_with_bounds(HIST_LOW, HIST_HIGH, HIST_SIGFIG)
            .expect("valid histogram bounds");
        Self {
            hist,
            verified: 0,
            bad_signature: 0,
            sign_error: 0,
            unsupported: 0,
        }
    }

    /// Record one operation's outcome and sign latency.
    ///
    /// Latency is recorded for every attempt that produced a signature
    /// (`Verified` / `BadSignature` / `Unsupported`). `SignError` has no
    /// meaningful sign latency (signing failed or never returned), so it is
    /// counted but not recorded into the histogram. `Unsupported` is rare at
    /// runtime (most unhandled key types are filtered before workers start) but
    /// can still arise — e.g. an RSA key whose agent response carries an
    /// unexpected signature algorithm — so it is counted as a failure rather
    /// than dropped, otherwise such unverified ops could let a run exit 0.
    pub fn record(&mut self, outcome: &VerifyOutcome, sign_latency: Duration) {
        match outcome {
            VerifyOutcome::Verified => {
                self.verified += 1;
                self.record_latency(sign_latency);
            }
            VerifyOutcome::BadSignature => {
                self.bad_signature += 1;
                self.record_latency(sign_latency);
            }
            VerifyOutcome::SignError(_) => {
                self.sign_error += 1;
            }
            VerifyOutcome::Unsupported(_) => {
                self.unsupported += 1;
                self.record_latency(sign_latency);
            }
        }
    }

    /// Record a latency into the histogram, saturating-casting micros to `u64`
    /// and clamping to the high bound so `record` never errors.
    fn record_latency(&mut self, latency: Duration) {
        let micros = latency.as_micros().min(u128::from(HIST_HIGH)) as u64;
        let value = micros.clamp(HIST_LOW, self.hist.high());
        // record on a clamped value cannot fail.
        let _ = self.hist.record(value);
    }

    /// Merge another worker's stats into this one.
    pub fn merge(&mut self, other: &WorkerStats) {
        self.verified += other.verified;
        self.bad_signature += other.bad_signature;
        self.sign_error += other.sign_error;
        self.unsupported += other.unsupported;
        self.hist
            .add(&other.hist)
            .expect("histograms share identical bounds");
    }

    /// Whether the run should exit with a non-zero code. Any bad signature,
    /// sign error, or unsupported (unverified) outcome is a failure.
    pub fn should_exit_nonzero(&self) -> bool {
        self.bad_signature + self.sign_error + self.unsupported > 0
    }

    /// Total completed sign attempts (everything we counted).
    fn total_ops(&self) -> u64 {
        self.verified + self.bad_signature + self.sign_error + self.unsupported
    }

    /// Convert a microsecond histogram value to milliseconds.
    fn micros_to_ms(micros: u64) -> f64 {
        micros as f64 / 1000.0
    }

    /// Format the final multi-line run report.
    pub fn report(
        &self,
        algorithm_desc: &str,
        workers: usize,
        reconnect: bool,
        duration: Duration,
    ) -> String {
        let secs = duration.as_secs_f64();
        let total = self.total_ops();
        let ops_per_sec = if secs > 0.0 { total as f64 / secs } else { 0.0 };
        let conn_mode = if reconnect { "reconnect" } else { "persistent" };

        let p50 = Self::micros_to_ms(self.hist.value_at_quantile(0.50));
        let p90 = Self::micros_to_ms(self.hist.value_at_quantile(0.90));
        let p99 = Self::micros_to_ms(self.hist.value_at_quantile(0.99));
        let p999 = Self::micros_to_ms(self.hist.value_at_quantile(0.999));
        let max = Self::micros_to_ms(self.hist.max());

        let mut out = String::new();
        let _ = writeln!(out, "Results:");
        let _ = writeln!(out, "  algorithm:     {algorithm_desc}");
        let _ = writeln!(out, "  workers:       {workers}");
        let _ = writeln!(out, "  connection:    {conn_mode}");
        let _ = writeln!(out, "  duration:      {secs:.2}s");
        let _ = writeln!(out, "  total ops:     {total} ({ops_per_sec:.2} ops/s)");
        let _ = writeln!(out, "  verified:      {}", self.verified);
        let _ = writeln!(out, "  bad signature: {}", self.bad_signature);
        let _ = writeln!(out, "  sign error:    {}", self.sign_error);
        let _ = writeln!(out, "  unsupported:   {}", self.unsupported);
        let _ = writeln!(out, "  latency (ms):");
        let _ = writeln!(out, "    p50:   {p50:.3}");
        let _ = writeln!(out, "    p90:   {p90:.3}");
        let _ = writeln!(out, "    p99:   {p99:.3}");
        let _ = writeln!(out, "    p99.9: {p999:.3}");
        let _ = write!(out, "    max:   {max:.3}");
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn micros(n: u64) -> Duration {
        Duration::from_micros(n)
    }

    #[test]
    fn record_counts_and_histogram() {
        let mut s = WorkerStats::new();
        s.record(&VerifyOutcome::Verified, micros(1000));
        s.record(&VerifyOutcome::Verified, micros(2000));
        s.record(&VerifyOutcome::BadSignature, micros(3000));
        s.record(&VerifyOutcome::SignError("boom".into()), micros(9999));
        s.record(&VerifyOutcome::Unsupported("rsa".into()), micros(9999));

        assert_eq!(s.verified, 2);
        assert_eq!(s.bad_signature, 1);
        assert_eq!(s.sign_error, 1);
        assert_eq!(s.unsupported, 1);
        // Verified (2) + BadSignature (1) + Unsupported (1) recorded latency;
        // SignError did not.
        assert_eq!(s.hist.len(), 4);
    }

    #[test]
    fn record_latency_clamps_extremes() {
        let mut s = WorkerStats::new();
        // Sub-µs latency clamps up to the 1µs low bound; an over-60s latency
        // clamps down to the high bound. Neither errors, both are counted.
        s.record(&VerifyOutcome::Verified, Duration::ZERO);
        s.record(&VerifyOutcome::Verified, Duration::from_secs(120));

        // The key property: recording both extremes was counted and did not
        // error (an unclamped 0µs or 120s record would have).
        assert_eq!(s.verified, 2);
        assert_eq!(s.hist.len(), 2);
        // The 0µs sample was clamped up to the 1µs low bound.
        assert!(s.hist.min() >= HIST_LOW);
        // The 120s sample was clamped down to the 60s high bound, so the max
        // bucket sits at the high bound (within HDR's bucket-width tolerance),
        // not at 120s.
        assert!(s.hist.equivalent(s.hist.max(), HIST_HIGH));
    }

    #[test]
    fn merge_sums_counters_and_histograms() {
        let mut a = WorkerStats::new();
        a.record(&VerifyOutcome::Verified, micros(1000));
        a.record(&VerifyOutcome::BadSignature, micros(2000));
        a.record(&VerifyOutcome::SignError("e".into()), micros(0));

        let mut b = WorkerStats::new();
        b.record(&VerifyOutcome::Verified, micros(3000));
        b.record(&VerifyOutcome::Verified, micros(4000));
        b.record(&VerifyOutcome::SignError("e".into()), micros(0));
        b.record(&VerifyOutcome::Unsupported("u".into()), micros(500));

        let a_hist_count = a.hist.len();
        let b_hist_count = b.hist.len();

        a.merge(&b);

        assert_eq!(a.verified, 3);
        assert_eq!(a.bad_signature, 1);
        assert_eq!(a.sign_error, 2);
        assert_eq!(a.unsupported, 1);
        assert_eq!(a.hist.len(), a_hist_count + b_hist_count);
    }

    #[test]
    fn report_contains_counts_and_percentiles() {
        let mut s = WorkerStats::new();
        // 100 samples at 5000µs (5ms) → all percentiles ~5ms.
        for _ in 0..100 {
            s.record(&VerifyOutcome::Verified, micros(5000));
        }
        s.record(&VerifyOutcome::BadSignature, micros(5000));
        s.record(&VerifyOutcome::SignError("x".into()), Duration::ZERO);

        let report = s.report("ssh-ed25519", 4, false, Duration::from_secs(10));

        assert!(report.contains("workers:       4"));
        assert!(report.contains("connection:    persistent"));
        assert!(report.contains("verified:      100"));
        assert!(report.contains("bad signature: 1"));
        assert!(report.contains("sign error:    1"));
        assert!(report.contains("unsupported:   0"));
        assert!(report.contains("total ops:     102"));
        // 102 ops over 10s ≈ 10.20 ops/s.
        assert!(report.contains("10.20 ops/s"));
        // HDR quantization: p50 should round near 5.0ms; assert the "5." prefix.
        assert!(
            report.contains("p50:   5."),
            "expected p50 near 5ms, got:\n{report}"
        );
        // persistent mode must not advertise reconnect.
        assert!(!report.contains("connection:    reconnect"));
    }

    #[test]
    fn report_reconnect_mode() {
        let s = WorkerStats::new();
        let report = s.report("ecdsa-sha2-nistp256", 1, true, Duration::from_secs(1));
        assert!(report.contains("connection:    reconnect"));
    }

    #[test]
    fn should_exit_nonzero_logic() {
        let mut s = WorkerStats::new();
        assert!(!s.should_exit_nonzero());

        s.record(&VerifyOutcome::Verified, micros(100));
        assert!(!s.should_exit_nonzero());

        let mut bad = WorkerStats::new();
        bad.record(&VerifyOutcome::BadSignature, micros(100));
        assert!(bad.should_exit_nonzero());

        let mut err = WorkerStats::new();
        err.record(&VerifyOutcome::SignError("x".into()), Duration::ZERO);
        assert!(err.should_exit_nonzero());

        // An unsupported (unverified) outcome is also a failure.
        let mut uns = WorkerStats::new();
        uns.record(&VerifyOutcome::Unsupported("rsa-weird".into()), micros(100));
        assert!(uns.should_exit_nonzero());
    }
}
