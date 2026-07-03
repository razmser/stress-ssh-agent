//! Per-worker latency histograms and outcome counters.
//!
//! Each worker records sign latency (microseconds) into a per-key HDR histogram
//! and tallies outcomes per key, indexed by the key's position in the selected
//! key set (shared by all workers). `main` merges the per-worker stats and
//! prints the report: aggregate totals/percentiles, plus a per-key breakdown
//! when more than one key was exercised (`--all`), since mixing algorithms in
//! one histogram makes the aggregate percentiles describe neither.

use crate::verify::VerifyOutcome;
use hdrhistogram::Histogram;
use std::fmt::Write as _;
use std::time::Duration;

/// Histogram low bound (1µs) and high bound (60s), with 3 significant figures.
const HIST_LOW: u64 = 1;
const HIST_HIGH: u64 = 60_000_000;
const HIST_SIGFIG: u8 = 3;

/// Latency histogram and outcome tallies for a single key.
pub struct KeyStats {
    /// Sign latency in microseconds (1µs–60s, 3 significant figures).
    pub hist: Histogram<u64>,
    pub verified: u64,
    pub bad_signature: u64,
    pub sign_error: u64,
    pub unsupported: u64,
}

impl KeyStats {
    /// Construct empty stats. The histogram bounds are compile-time constants
    /// known to be valid, so the `new_with_bounds` Result is unwrapped here.
    fn new() -> Self {
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
    fn record(&mut self, outcome: &VerifyOutcome, sign_latency: Duration) {
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

    /// Merge another key's stats into this one.
    fn merge(&mut self, other: &KeyStats) {
        self.verified += other.verified;
        self.bad_signature += other.bad_signature;
        self.sign_error += other.sign_error;
        self.unsupported += other.unsupported;
        self.hist
            .add(&other.hist)
            .expect("histograms share identical bounds");
    }

    /// Total completed sign attempts (everything we counted).
    fn total_ops(&self) -> u64 {
        self.verified + self.bad_signature + self.sign_error + self.unsupported
    }

    /// Failed (unverified) attempts.
    fn failures(&self) -> u64 {
        self.bad_signature + self.sign_error + self.unsupported
    }

    /// Percentiles + max in milliseconds: (p50, p90, p99, p99.9, max).
    fn percentiles_ms(&self) -> (f64, f64, f64, f64, f64) {
        let ms = |micros: u64| micros as f64 / 1000.0;
        (
            ms(self.hist.value_at_quantile(0.50)),
            ms(self.hist.value_at_quantile(0.90)),
            ms(self.hist.value_at_quantile(0.99)),
            ms(self.hist.value_at_quantile(0.999)),
            ms(self.hist.max()),
        )
    }
}

/// Per-key latency histograms and outcome tallies recorded by a single worker.
///
/// Indexed by key position in the selected key set every worker is handed, so
/// per-worker stats merge key-by-key at the end of the run.
pub struct WorkerStats {
    keys: Vec<KeyStats>,
}

impl WorkerStats {
    /// Construct empty stats for `num_keys` keys (must be >= 1).
    pub fn new(num_keys: usize) -> Self {
        Self {
            keys: (0..num_keys).map(|_| KeyStats::new()).collect(),
        }
    }

    /// Record one operation's outcome and sign latency against the key at
    /// `key_idx` (the key's position in the selected key set).
    pub fn record(&mut self, key_idx: usize, outcome: &VerifyOutcome, sign_latency: Duration) {
        self.keys[key_idx].record(outcome, sign_latency);
    }

    /// Merge another worker's stats into this one, key by key. Both sides must
    /// have been built from the same selected key set.
    pub fn merge(&mut self, other: &WorkerStats) {
        assert_eq!(
            self.keys.len(),
            other.keys.len(),
            "merging WorkerStats with different key counts"
        );
        for (mine, theirs) in self.keys.iter_mut().zip(&other.keys) {
            mine.merge(theirs);
        }
    }

    /// Whether the run should exit with a non-zero code. Any bad signature,
    /// sign error, or unsupported (unverified) outcome is a failure.
    pub fn should_exit_nonzero(&self) -> bool {
        self.keys.iter().map(KeyStats::failures).sum::<u64>() > 0
    }

    /// Collapse all per-key stats into one aggregate for the report totals.
    fn aggregate(&self) -> KeyStats {
        let mut agg = KeyStats::new();
        for key in &self.keys {
            agg.merge(key);
        }
        agg
    }

    /// Format the final multi-line run report.
    ///
    /// `key_labels` describes the selected keys in the same order the workers
    /// indexed them; when more than one key was exercised a per-key breakdown
    /// follows the aggregate section.
    pub fn report(
        &self,
        algorithm_desc: &str,
        key_labels: &[String],
        workers: usize,
        reconnect: bool,
        duration: Duration,
    ) -> String {
        debug_assert_eq!(key_labels.len(), self.keys.len());

        let agg = self.aggregate();
        let secs = duration.as_secs_f64();
        let total = agg.total_ops();
        let ops_per_sec = if secs > 0.0 { total as f64 / secs } else { 0.0 };
        let conn_mode = if reconnect { "reconnect" } else { "persistent" };
        let (p50, p90, p99, p999, max) = agg.percentiles_ms();

        let mut out = String::new();
        let _ = writeln!(out, "Results:");
        let _ = writeln!(out, "  algorithm:     {algorithm_desc}");
        let _ = writeln!(out, "  workers:       {workers}");
        let _ = writeln!(out, "  connection:    {conn_mode}");
        let _ = writeln!(out, "  duration:      {secs:.2}s");
        let _ = writeln!(out, "  total ops:     {total} ({ops_per_sec:.2} ops/s)");
        let _ = writeln!(out, "  verified:      {}", agg.verified);
        let _ = writeln!(out, "  bad signature: {}", agg.bad_signature);
        let _ = writeln!(out, "  sign error:    {}", agg.sign_error);
        let _ = writeln!(out, "  unsupported:   {}", agg.unsupported);
        let _ = writeln!(out, "  latency (ms):");
        let _ = writeln!(out, "    p50:   {p50:.3}");
        let _ = writeln!(out, "    p90:   {p90:.3}");
        let _ = writeln!(out, "    p99:   {p99:.3}");
        let _ = writeln!(out, "    p99.9: {p999:.3}");
        let _ = writeln!(out, "    max:   {max:.3}");

        // Per-key breakdown: only worth printing with several keys, where the
        // aggregate percentiles mix algorithms.
        if self.keys.len() > 1 {
            let _ = writeln!(out, "  per-key:");
            for (key, label) in self.keys.iter().zip(key_labels) {
                let (p50, p90, p99, p999, max) = key.percentiles_ms();
                let _ = writeln!(out, "    {label}");
                let _ = writeln!(
                    out,
                    "      ops: {}  verified: {}  bad signature: {}  sign error: {}  unsupported: {}",
                    key.total_ops(),
                    key.verified,
                    key.bad_signature,
                    key.sign_error,
                    key.unsupported
                );
                let _ = writeln!(
                    out,
                    "      latency (ms): p50 {p50:.3}  p90 {p90:.3}  p99 {p99:.3}  p99.9 {p999:.3}  max {max:.3}"
                );
            }
        }

        out.truncate(out.trim_end().len());
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
        let mut s = WorkerStats::new(1);
        s.record(0, &VerifyOutcome::Verified, micros(1000));
        s.record(0, &VerifyOutcome::Verified, micros(2000));
        s.record(0, &VerifyOutcome::BadSignature, micros(3000));
        s.record(0, &VerifyOutcome::SignError("boom".into()), micros(9999));
        s.record(0, &VerifyOutcome::Unsupported("rsa".into()), micros(9999));

        let agg = s.aggregate();
        assert_eq!(agg.verified, 2);
        assert_eq!(agg.bad_signature, 1);
        assert_eq!(agg.sign_error, 1);
        assert_eq!(agg.unsupported, 1);
        // Verified (2) + BadSignature (1) + Unsupported (1) recorded latency;
        // SignError did not.
        assert_eq!(agg.hist.len(), 4);
    }

    #[test]
    fn record_is_per_key() {
        let mut s = WorkerStats::new(2);
        s.record(0, &VerifyOutcome::Verified, micros(1000));
        s.record(1, &VerifyOutcome::BadSignature, micros(2000));
        s.record(1, &VerifyOutcome::Verified, micros(3000));

        assert_eq!(s.keys[0].verified, 1);
        assert_eq!(s.keys[0].bad_signature, 0);
        assert_eq!(s.keys[0].hist.len(), 1);
        assert_eq!(s.keys[1].verified, 1);
        assert_eq!(s.keys[1].bad_signature, 1);
        assert_eq!(s.keys[1].hist.len(), 2);
    }

    #[test]
    fn record_latency_clamps_extremes() {
        let mut s = WorkerStats::new(1);
        // Sub-µs latency clamps up to the 1µs low bound; an over-60s latency
        // clamps down to the high bound. Neither errors, both are counted.
        s.record(0, &VerifyOutcome::Verified, Duration::ZERO);
        s.record(0, &VerifyOutcome::Verified, Duration::from_secs(120));

        // The key property: recording both extremes was counted and did not
        // error (an unclamped 0µs or 120s record would have).
        let agg = s.aggregate();
        assert_eq!(agg.verified, 2);
        assert_eq!(agg.hist.len(), 2);
        // The 0µs sample was clamped up to the 1µs low bound.
        assert!(agg.hist.min() >= HIST_LOW);
        // The 120s sample was clamped down to the 60s high bound, so the max
        // bucket sits at the high bound (within HDR's bucket-width tolerance),
        // not at 120s.
        assert!(agg.hist.equivalent(agg.hist.max(), HIST_HIGH));
    }

    #[test]
    fn merge_sums_counters_and_histograms_per_key() {
        let mut a = WorkerStats::new(2);
        a.record(0, &VerifyOutcome::Verified, micros(1000));
        a.record(1, &VerifyOutcome::BadSignature, micros(2000));
        a.record(0, &VerifyOutcome::SignError("e".into()), micros(0));

        let mut b = WorkerStats::new(2);
        b.record(0, &VerifyOutcome::Verified, micros(3000));
        b.record(1, &VerifyOutcome::Verified, micros(4000));
        b.record(1, &VerifyOutcome::SignError("e".into()), micros(0));
        b.record(0, &VerifyOutcome::Unsupported("u".into()), micros(500));

        a.merge(&b);

        assert_eq!(a.keys[0].verified, 2);
        assert_eq!(a.keys[0].sign_error, 1);
        assert_eq!(a.keys[0].unsupported, 1);
        assert_eq!(a.keys[0].hist.len(), 3);
        assert_eq!(a.keys[1].verified, 1);
        assert_eq!(a.keys[1].bad_signature, 1);
        assert_eq!(a.keys[1].sign_error, 1);
        // SignError records no latency, so key 1's histogram holds only the
        // Verified + BadSignature samples.
        assert_eq!(a.keys[1].hist.len(), 2);

        let agg = a.aggregate();
        assert_eq!(agg.verified, 3);
        assert_eq!(agg.bad_signature, 1);
        assert_eq!(agg.sign_error, 2);
        assert_eq!(agg.unsupported, 1);
        assert_eq!(agg.hist.len(), 5);
    }

    #[test]
    #[should_panic(expected = "different key counts")]
    fn merge_rejects_mismatched_key_counts() {
        let mut a = WorkerStats::new(1);
        let b = WorkerStats::new(2);
        a.merge(&b);
    }

    #[test]
    fn report_contains_counts_and_percentiles() {
        let mut s = WorkerStats::new(1);
        // 100 samples at 5000µs (5ms) → all percentiles ~5ms.
        for _ in 0..100 {
            s.record(0, &VerifyOutcome::Verified, micros(5000));
        }
        s.record(0, &VerifyOutcome::BadSignature, micros(5000));
        s.record(0, &VerifyOutcome::SignError("x".into()), Duration::ZERO);

        let labels = vec!["ssh-ed25519 SHA256:x".to_string()];
        let report = s.report("ssh-ed25519", &labels, 4, false, Duration::from_secs(10));

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
        // A single key gets no per-key breakdown.
        assert!(!report.contains("per-key:"));
    }

    #[test]
    fn report_per_key_breakdown_with_multiple_keys() {
        let mut s = WorkerStats::new(2);
        // Key 0: fast (1ms) and clean; key 1: slow (20ms) with a bad signature.
        for _ in 0..50 {
            s.record(0, &VerifyOutcome::Verified, micros(1000));
            s.record(1, &VerifyOutcome::Verified, micros(20_000));
        }
        s.record(1, &VerifyOutcome::BadSignature, micros(20_000));

        let labels = vec![
            "ssh-ed25519 SHA256:aaa (alice)".to_string(),
            "ssh-rsa SHA256:bbb (bob)".to_string(),
        ];
        let report = s.report(
            "2 keys, round-robin",
            &labels,
            1,
            false,
            Duration::from_secs(10),
        );

        assert!(report.contains("per-key:"));
        assert!(report.contains("ssh-ed25519 SHA256:aaa (alice)"));
        assert!(report.contains("ssh-rsa SHA256:bbb (bob)"));
        // Key 0 line: 50 clean ops; key 1 line: 51 ops with one bad signature.
        assert!(report
            .contains("ops: 50  verified: 50  bad signature: 0  sign error: 0  unsupported: 0"));
        assert!(report
            .contains("ops: 51  verified: 50  bad signature: 1  sign error: 0  unsupported: 0"));
        // Per-key percentiles reflect each key's own latency, not the mix:
        // key 0 p50 near 1ms, key 1 p50 near 20ms.
        assert!(
            report.contains("latency (ms): p50 1.0"),
            "expected key 0 p50 near 1ms, got:\n{report}"
        );
        assert!(
            report.contains("latency (ms): p50 20."),
            "expected key 1 p50 near 20ms, got:\n{report}"
        );
    }

    #[test]
    fn report_reconnect_mode() {
        let s = WorkerStats::new(1);
        let labels = vec!["ecdsa-sha2-nistp256 SHA256:x".to_string()];
        let report = s.report(
            "ecdsa-sha2-nistp256",
            &labels,
            1,
            true,
            Duration::from_secs(1),
        );
        assert!(report.contains("connection:    reconnect"));
    }

    #[test]
    fn should_exit_nonzero_logic() {
        let mut s = WorkerStats::new(1);
        assert!(!s.should_exit_nonzero());

        s.record(0, &VerifyOutcome::Verified, micros(100));
        assert!(!s.should_exit_nonzero());

        let mut bad = WorkerStats::new(1);
        bad.record(0, &VerifyOutcome::BadSignature, micros(100));
        assert!(bad.should_exit_nonzero());

        let mut err = WorkerStats::new(1);
        err.record(0, &VerifyOutcome::SignError("x".into()), Duration::ZERO);
        assert!(err.should_exit_nonzero());

        // An unsupported (unverified) outcome is also a failure.
        let mut uns = WorkerStats::new(1);
        uns.record(
            0,
            &VerifyOutcome::Unsupported("rsa-weird".into()),
            micros(100),
        );
        assert!(uns.should_exit_nonzero());

        // Failures on any key flip the exit code.
        let mut multi = WorkerStats::new(2);
        multi.record(0, &VerifyOutcome::Verified, micros(100));
        assert!(!multi.should_exit_nonzero());
        multi.record(1, &VerifyOutcome::BadSignature, micros(100));
        assert!(multi.should_exit_nonzero());
    }
}
