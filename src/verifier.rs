//! Out-of-band verification pool, decoupled from the signing hot loop.
//!
//! Workers used to verify inline, which put client-side verify CPU (nontrivial
//! for P-521/RSA) on the measurement path and suppressed the achievable sign
//! throughput. Instead, each worker pushes every successful sign as a
//! [`VerifyJob`] onto a bounded channel, and a pool of verifier threads (one
//! shared receiver behind a mutex) verifies and tallies outcomes into local
//! [`WorkerStats`] that `main` merges with the workers' own stats (which by
//! then only hold `SignError`s). The channel bound is the memory safety valve:
//! if signing ever outpaces the whole pool, workers block on `send` rather
//! than growing the queue without limit.

use crate::metrics::WorkerStats;
use crate::verify::verify_signature;
use crate::worker::SIGN_BYTES;
use ssh_key::{PublicKey, Signature};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// One message on the worker → verifier channel.
pub enum VerifyJob {
    /// A successful sign to verify out-of-band.
    Signed {
        /// Position of the signing key in the selected key set.
        key_idx: usize,
        /// The random bytes that were signed.
        data: [u8; SIGN_BYTES],
        /// The signature the agent returned.
        signature: Signature,
        /// Duration of the sign call, recorded alongside the outcome.
        sign_latency: Duration,
    },
    /// Drain-and-exit sentinel. `main` sends one per verifier after the
    /// workers are joined; consuming one stops exactly one verifier, and FIFO
    /// order guarantees every real job enqueued before it has already been
    /// dequeued by the pool. Disconnect alone is not enough to stop the pool:
    /// a worker abandoned mid-sign (hung agent) never drops its sender.
    Shutdown,
}

/// Run one verifier until a [`VerifyJob::Shutdown`] sentinel arrives or all
/// senders disconnect. Designed to run on its own `std::thread`.
///
/// `keys` is the selected key set, in the same order the workers index it.
/// The receiver is shared by the whole pool; the mutex is held only for the
/// dequeue itself, never during verification.
pub fn run_verifier(
    keys: Arc<Vec<PublicKey>>,
    jobs: Arc<Mutex<Receiver<VerifyJob>>>,
) -> WorkerStats {
    let mut stats = WorkerStats::new(keys.len());
    loop {
        // The temporary lock guard drops at the end of this statement, so the
        // (potentially slow) verification below runs unlocked.
        let msg = jobs
            .lock()
            .expect("verifier receiver mutex poisoned")
            .recv();
        match msg {
            Ok(VerifyJob::Signed {
                key_idx,
                data,
                signature,
                sign_latency,
            }) => {
                let outcome = verify_signature(&keys[key_idx], &data, &signature);
                stats.record(key_idx, &outcome, sign_latency);
            }
            Ok(VerifyJob::Shutdown) | Err(_) => break,
        }
    }
    stats
}
