//! Closed-loop signing worker.
//!
//! Stub for Task 1; real logic arrives in Task 5.

use crate::metrics::WorkerStats;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

/// Run a closed-loop worker until `stop` flips, recording into `stats`.
///
/// Stub for Task 1; real logic arrives in Task 5.
pub fn run_worker(
    sock: &Path,
    public_key: &ssh_key::PublicKey,
    reconnect: bool,
    stop: &Arc<AtomicBool>,
    op_counter: &Arc<AtomicU64>,
    stats: &mut WorkerStats,
) {
    let _ = (sock, public_key, reconnect, stop, op_counter, stats);
    unimplemented!("run_worker arrives in Task 5")
}
