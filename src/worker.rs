//! Closed-loop signing worker.
//!
//! A worker is a synchronous function meant to run inside
//! [`tokio::task::spawn_blocking`] (the `ssh-agent-client-rs` client is
//! blocking). In persistent mode it owns one reused [`Client`]. It loops until
//! a shared stop flag flips or the deadline passes, signing 32 random bytes
//! each iteration and timing the sign call. Verification does NOT happen here:
//! each successful sign is handed to the verifier pool as a
//! [`VerifyJob`](crate::verifier::VerifyJob), so client-side verify CPU
//! (nontrivial for P-521/RSA) never throttles the sign loop. The worker's own
//! [`WorkerStats`] therefore only ever holds `SignError`s; verified outcomes
//! are tallied by the pool and merged with these at the end of the run. The
//! only shared state touched in the hot loop is the atomic op counter (drives
//! main's ~1Hz progress line), the atomic stop flag, and the bounded job
//! channel.
//!
//! RSA reality (informational; nothing to configure here):
//! `ssh-agent-client-rs 1.1.2`'s `sign` exposes no algorithm flag; it always
//! sends `SSH_AGENT_RSA_SHA2_512` for RSA keys, so a conforming agent returns
//! `rsa-sha2-512`. If an agent ignores the flag and signs with `ssh-rsa`
//! (SHA-1), we expect — inferred from `ssh-key` 0.6.7's decode constraints, not
//! observed against a live agent — the client's `sign` to error at the decode
//! layer: `ssh-key`'s `Signature::decode` rejects `Algorithm::Rsa { hash: None }`,
//! and the client shares that decode. Such an attempt would be recorded as a
//! [`VerifyOutcome::SignError`] (counted as a failure). The verify-side hash
//! selection lives in `verify.rs`; there is no flag to set here.

use crate::metrics::WorkerStats;
use crate::verifier::VerifyJob;
use crate::verify::VerifyOutcome;
use rand::RngCore;
use ssh_agent_client_rs::{Client, Identity};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::Arc;
use std::time::Instant;

/// Number of random bytes signed per iteration.
pub const SIGN_BYTES: usize = 32;

/// Whether the worker loop should stop, given the stop flag and the deadline.
///
/// Pure helper so the stop condition is unit-testable without a live agent.
fn should_stop(stop: &AtomicBool, deadline: Instant, now: Instant) -> bool {
    stop.load(Ordering::Acquire) || now >= deadline
}

/// Run a closed-loop signing worker until `stop` flips or `deadline` passes.
///
/// Designed to be called inside `tokio::task::spawn_blocking`. Takes owned
/// arguments so the closure is `'static`. Returns the worker's local
/// [`WorkerStats`] (holding only `SignError`s; successful signs are verified
/// and tallied by the verifier pool fed through `jobs`) for the caller to
/// merge.
///
/// `keys` is the full set of keys this worker should exercise; the worker
/// rotates through them round-robin, one per iteration. This guarantees every
/// selected key is actually tested even with a single worker (`-p 1 --all`).
///
/// Connection model:
/// - persistent (`reconnect == false`): connect once and reuse the `Client`.
///   If the persistent client errors mid-loop, we record a `SignError` and try
///   to re-establish the connection on the next iteration; we only give up the
///   whole worker if connecting is permanently failing (handled by the
///   reconnect attempt also failing, which is likewise recorded and retried).
/// - reconnect (`reconnect == true`): open a fresh `Client::connect(&sock)`
///   every iteration (measures connection-churn cost).
///
/// A connect failure is recorded as a `SignError` and counted as a completed op
/// (so ops/s reflects attempted work), then the loop continues.
pub fn run_worker(
    sock: PathBuf,
    keys: Vec<ssh_key::PublicKey>,
    reconnect: bool,
    deadline: Instant,
    stop: Arc<AtomicBool>,
    ops_counter: Arc<AtomicU64>,
    jobs: SyncSender<VerifyJob>,
) -> WorkerStats {
    let mut stats = WorkerStats::new(keys.len());
    let mut rng = rand::thread_rng();

    // Pre-build one Identity per key so the per-iteration hot loop does not
    // clone the key + rebuild the Identity each time.
    let identities: Vec<Identity> = keys.iter().cloned().map(Identity::from).collect();
    let mut key_idx = 0usize;

    // Persistent client, established lazily on the first iteration (and after
    // any mid-loop error) by the `persistent.is_none()` block below.
    let mut persistent: Option<Client> = None;

    loop {
        if should_stop(&stop, deadline, Instant::now()) {
            break;
        }

        // Round-robin to the next key for this iteration. Outcomes are
        // recorded against `idx` so stats stay per-key.
        let idx = key_idx;
        let identity = &identities[idx];
        key_idx = (key_idx + 1) % keys.len();

        let mut data = [0u8; SIGN_BYTES];
        rng.fill_bytes(&mut data);

        // Obtain a client for this iteration.
        let mut fresh: Option<Client> = None;
        let client: &mut Client = if reconnect {
            match Client::connect(&sock) {
                Ok(c) => {
                    fresh = Some(c);
                    fresh.as_mut().expect("just set")
                }
                Err(e) => {
                    stats.record(
                        idx,
                        &VerifyOutcome::SignError(format!("connect: {e}")),
                        std::time::Duration::ZERO,
                    );
                    ops_counter.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            }
        } else {
            // Persistent: reconnect if we don't currently hold a live client.
            if persistent.is_none() {
                match Client::connect(&sock) {
                    Ok(c) => persistent = Some(c),
                    Err(e) => {
                        stats.record(
                            idx,
                            &VerifyOutcome::SignError(format!("reconnect: {e}")),
                            std::time::Duration::ZERO,
                        );
                        ops_counter.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                }
            }
            persistent.as_mut().expect("just ensured Some")
        };

        // Time the sign call only. `sign_with_ref` borrows the pre-built
        // Identity, so the hot loop neither clones the key nor the Identity.
        let t0 = Instant::now();
        let sign_result = client.sign_with_ref(identity, &data);
        let elapsed = t0.elapsed();

        match sign_result {
            Ok(sig) => {
                // Hand off to the verifier pool; a full queue blocks here
                // (bounded memory) but that only happens if signing outpaces
                // every verifier core combined. A send error means the pool is
                // gone, which only happens when the run is being torn down.
                let _ = jobs.send(VerifyJob::Signed {
                    key_idx: idx,
                    data,
                    signature: sig,
                    sign_latency: elapsed,
                });
            }
            Err(e) => {
                stats.record(idx, &VerifyOutcome::SignError(e.to_string()), elapsed);
                // In persistent mode a sign error may mean a dead connection;
                // drop it so the next iteration reconnects.
                if !reconnect {
                    persistent = None;
                }
            }
        }

        // `fresh` (reconnect mode) drops here, closing the per-sign connection.
        drop(fresh);

        ops_counter.fetch_add(1, Ordering::Relaxed);
    }

    stats
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn stops_when_flag_set() {
        let stop = AtomicBool::new(true);
        let deadline = Instant::now() + Duration::from_secs(60);
        assert!(should_stop(&stop, deadline, Instant::now()));
    }

    #[test]
    fn stops_when_deadline_passed() {
        let stop = AtomicBool::new(false);
        let now = Instant::now();
        let deadline = now - Duration::from_millis(1);
        assert!(should_stop(&stop, deadline, now));
    }

    #[test]
    fn continues_when_neither() {
        let stop = AtomicBool::new(false);
        let now = Instant::now();
        let deadline = now + Duration::from_secs(60);
        assert!(!should_stop(&stop, deadline, now));
    }
}
