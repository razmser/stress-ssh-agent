//! Closed-loop signing worker.
//!
//! A worker is a synchronous function meant to run inside
//! [`tokio::task::spawn_blocking`] (the `ssh-agent-client-rs` client is
//! blocking). It owns one assigned [`ssh_key::PublicKey`] and — in persistent
//! mode — one reused [`Client`]. It loops until a shared stop flag flips or the
//! deadline passes, signing 32 random bytes each iteration, timing the sign
//! call, re-verifying the signature out-of-band via [`verify_signature`], and
//! tallying the outcome into a local [`WorkerStats`] that is returned for the
//! end-of-run merge. The only shared state touched in the hot loop is the
//! atomic op counter (drives main's ~1Hz progress line) and the atomic stop
//! flag — `WorkerStats` is worker-local.
//!
//! RSA reality (informational; nothing to configure here):
//! `ssh-agent-client-rs 1.1.2`'s `sign` exposes no algorithm flag, so we cannot
//! request `rsa-sha2-256`/`512`. So if an agent signs an RSA key with `ssh-rsa`
//! (SHA-1), we expect — inferred from `ssh-key` 0.6.7's decode constraints, not
//! observed against a live agent — the client's `sign` to error at the decode
//! layer: `ssh-key`'s `Signature::decode` rejects `Algorithm::Rsa { hash: None }`,
//! and the client shares that decode. Such an attempt would be recorded as a
//! [`VerifyOutcome::SignError`] (counted as a failure). The verify-side hash
//! selection lives in `verify.rs`; there is no flag to set here.

use crate::metrics::WorkerStats;
use crate::verify::{verify_signature, VerifyOutcome};
use rand::RngCore;
use ssh_agent_client_rs::{Client, Identity};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Number of random bytes signed per iteration.
const SIGN_BYTES: usize = 32;

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
/// [`WorkerStats`] for the caller to merge.
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
) -> WorkerStats {
    let mut stats = WorkerStats::new();
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

        // Round-robin to the next key for this iteration.
        let public_key = &keys[key_idx];
        let identity = &identities[key_idx];
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
                let outcome = verify_signature(public_key, &data, &sig);
                stats.record(&outcome, elapsed);
            }
            Err(e) => {
                stats.record(&VerifyOutcome::SignError(e.to_string()), elapsed);
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
