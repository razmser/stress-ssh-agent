//! Thin binary: parse args, select identities, run closed-loop workers, report.
//!
//! Identity selection and verification live in the library; this file only
//! wires them together: connect to the agent, classify/select keys, spawn one
//! `spawn_blocking` worker per `--parallel`, arm a deadline that flips a shared
//! stop flag, drive a ~1Hz stderr progress line off a shared op counter, then
//! merge the per-worker stats and print the final report.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use clap::Parser;
use ssh_agent_client_rs::{Client, Identity};
use ssh_key::{HashAlg, PublicKey};

use stress_ssh_agent::cli::{format_list, select, Args, IdentityInfo, SelectError};
use stress_ssh_agent::metrics::WorkerStats;
use stress_ssh_agent::verifier::{run_verifier, VerifyJob};
use stress_ssh_agent::worker::run_worker;

/// How long to wait for workers to finish after the deadline before abandoning
/// them. A worker blocked inside a hung `sign` cannot observe the stop flag, so
/// without this bound a single hung agent would make the tool hang forever.
const JOIN_GRACE: Duration = Duration::from_secs(5);

/// Bound on the worker → verifier job queue. Verification runs off the signing
/// path, so a backlog can build if verification is momentarily slower than
/// signing; the bound caps its memory. A worker only blocks on `send` if the
/// queue is full — i.e. signing outpaces every verifier core combined.
const VERIFY_QUEUE_CAP: usize = 64 * 1024;

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<ExitCode, String> {
    let args = Args::parse();

    let sock = std::env::var_os("SSH_AUTH_SOCK").ok_or_else(|| {
        "SSH_AUTH_SOCK is not set; start an ssh-agent and load at least one identity \
         (e.g. `eval $(ssh-agent)` then `ssh-add`)"
            .to_string()
    })?;
    let sock = PathBuf::from(sock);

    // Enumerate identities from the agent.
    let mut client = Client::connect(Path::new(&sock))
        .map_err(|e| format!("failed to connect to ssh-agent at {}: {e}", sock.display()))?;
    let identities = client
        .list_all_identities()
        .map_err(|e| format!("failed to list identities: {e}"))?;

    let infos: Vec<IdentityInfo> = identities
        .into_iter()
        .map(|id| match id {
            Identity::PublicKey(pk) => IdentityInfo::from_public_key((*pk).clone().into_owned()),
            Identity::Certificate(cert) => {
                let pk = PublicKey::from(cert.public_key().clone());
                IdentityInfo {
                    public_key: pk,
                    is_certificate: true,
                }
            }
        })
        .collect();

    // `--list`: print and exit 0.
    if args.list {
        print!("{}", format_list(&infos));
        return Ok(ExitCode::SUCCESS);
    }

    // Select the target key set.
    let selected: Vec<PublicKey> = match select(&infos, &args) {
        Ok(keys) => keys,
        Err(e @ SelectError::NoMatch(_)) => {
            eprintln!("error: {e}");
            return Ok(ExitCode::FAILURE);
        }
        Err(e @ SelectError::EmptySupported) => {
            eprintln!("error: {e}");
            if !infos.is_empty() {
                eprintln!("skipped identities:");
                eprint!("{}", format_list(&infos));
            }
            return Ok(ExitCode::FAILURE);
        }
    };

    let algorithm_desc = describe_algorithm(&selected, args.all);
    let key_labels: Vec<String> = selected.iter().map(key_label).collect();

    // Run header.
    let conn_mode = if args.reconnect {
        "reconnect"
    } else {
        "persistent"
    };
    // Verifier pool size: one thread per available core. Verification runs off
    // the signing path so verify CPU cannot throttle the sign rate; the pool
    // just needs enough parallelism to keep up with the agent overall.
    let n_verifiers = std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(4);

    eprintln!("stress-ssh-agent:");
    eprintln!("  algorithm:   {algorithm_desc}");
    eprintln!("  workers:     {}", args.parallel);
    eprintln!("  verifiers:   {n_verifiers}");
    eprintln!("  connection:  {conn_mode}");
    eprintln!("  duration:    {}s", args.duration);

    // Shared run state.
    let stop = Arc::new(AtomicBool::new(false));
    let ops = Arc::new(AtomicU64::new(0));
    let start = Instant::now();
    let deadline = start + Duration::from_secs(args.duration);

    // Spawn the verifier pool, all draining one shared job queue. Verifiers are
    // plain OS threads, not `spawn_blocking`, so they never take blocking-pool
    // slots away from the signing workers.
    let (jobs_tx, jobs_rx) = mpsc::sync_channel::<VerifyJob>(VERIFY_QUEUE_CAP);
    let jobs_rx = Arc::new(Mutex::new(jobs_rx));
    let verifier_keys = Arc::new(selected.clone());
    let mut verifier_handles = Vec::with_capacity(n_verifiers);
    for _ in 0..n_verifiers {
        let keys = verifier_keys.clone();
        let rx = jobs_rx.clone();
        verifier_handles.push(std::thread::spawn(move || run_verifier(keys, rx)));
    }
    // Only the verifiers may hold the receiver: if they all die, it is dropped
    // and every `send` errors instead of blocking forever on a full queue.
    drop(jobs_rx);

    // Spawn workers. Each worker rotates round-robin through the full selected
    // key set, so every key is exercised even with a single worker (`-p 1
    // --all`).
    let mut handles = Vec::with_capacity(args.parallel);
    for _ in 0..args.parallel {
        let keys = selected.clone();
        let sock = sock.clone();
        let reconnect = args.reconnect;
        let stop = stop.clone();
        let ops = ops.clone();
        let jobs = jobs_tx.clone();
        handles.push(tokio::task::spawn_blocking(move || {
            run_worker(sock, keys, reconnect, deadline, stop, ops, jobs)
        }));
    }

    // Arm the deadline: flip the stop flag when it elapses.
    {
        let stop = stop.clone();
        let tokio_deadline = tokio::time::Instant::from_std(deadline);
        tokio::spawn(async move {
            tokio::time::sleep_until(tokio_deadline).await;
            stop.store(true, Ordering::Release);
        });
    }

    // ~1Hz progress line to stderr until the run stops.
    progress_loop(&stop, &ops, start, deadline).await;

    // Join workers and merge their stats. The `ssh-agent-client-rs` client is
    // blocking and the stop flag is only checked at the top of each loop, so a
    // worker stuck inside a hung `sign` cannot observe the deadline. Bound the
    // joins so the tool still terminates and reports; a worker that is still
    // mid-sign past the grace period is abandoned (its in-flight op is lost).
    let mut aggregate = WorkerStats::new(selected.len());
    let mut any_worker_abandoned = false;
    for handle in handles {
        match tokio::time::timeout(JOIN_GRACE, handle).await {
            Ok(Ok(stats)) => aggregate.merge(&stats),
            Ok(Err(e)) => {
                any_worker_abandoned = true;
                eprintln!("warning: worker task failed: {e}");
            }
            Err(_) => {
                any_worker_abandoned = true;
                eprintln!(
                    "warning: worker did not finish within {}s of the deadline \
                     (agent likely hung mid-sign); abandoning it",
                    JOIN_GRACE.as_secs()
                );
            }
        }
    }

    // The signing phase is over; measure its duration before draining the
    // verifier backlog so ops/s is not diluted by drain time.
    let elapsed = start.elapsed();

    // Stop the verifier pool: one Shutdown sentinel per verifier, queued after
    // every job the joined workers sent, so the pool drains the backlog before
    // exiting. Sentinels (not just dropping `jobs_tx`) are required because an
    // abandoned worker never drops its sender clone. Verifiers are pure CPU
    // with a bounded backlog, so their joins need no timeout.
    let mut verifier_failed = false;
    for _ in 0..n_verifiers {
        let _ = jobs_tx.send(VerifyJob::Shutdown);
    }
    drop(jobs_tx);
    for handle in verifier_handles {
        match handle.join() {
            Ok(stats) => aggregate.merge(&stats),
            Err(_) => {
                verifier_failed = true;
                eprintln!("warning: verifier thread panicked");
            }
        }
    }

    println!(
        "{}",
        aggregate.report(
            &algorithm_desc,
            &key_labels,
            args.parallel,
            args.reconnect,
            elapsed
        )
    );

    if any_worker_abandoned {
        // An abandoned worker is still blocked inside `sign` on Tokio's blocking
        // pool. Returning here would drop the runtime, and the multi-threaded
        // runtime's shutdown *waits* for blocking tasks to finish — re-introducing
        // the exact hang JOIN_GRACE exists to bound. `process::exit` terminates
        // the process immediately without that wait. It skips buffer flushes, so
        // flush stdout (the report) first. An abandoned worker always means
        // failure, so the code is 1.
        use std::io::Write as _;
        let _ = std::io::stdout().flush();
        std::process::exit(1);
    }

    // A failed verifier task means some outcomes were lost unverified, so the
    // run cannot claim success.
    if aggregate.should_exit_nonzero() || verifier_failed {
        Ok(ExitCode::FAILURE)
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

/// Describe the algorithm(s) under test for the report/header.
fn describe_algorithm(selected: &[PublicKey], all: bool) -> String {
    if all && selected.len() > 1 {
        format!("{} keys, round-robin", selected.len())
    } else {
        selected
            .first()
            .map(|k| k.algorithm().to_string())
            .unwrap_or_else(|| "unknown".to_string())
    }
}

/// Label one selected key for the per-key report section: algorithm,
/// fingerprint, and comment (when non-empty).
fn key_label(key: &PublicKey) -> String {
    let comment = key.comment();
    if comment.is_empty() {
        format!(
            "{} {}",
            key.algorithm(),
            key.fingerprint(HashAlg::default())
        )
    } else {
        format!(
            "{} {} ({comment})",
            key.algorithm(),
            key.fingerprint(HashAlg::default())
        )
    }
}

/// Drive a single carriage-return-updated stderr progress line at ~1Hz until
/// the stop flag is set or the deadline passes.
async fn progress_loop(stop: &AtomicBool, ops: &AtomicU64, start: Instant, deadline: Instant) {
    let mut last_ops = 0u64;
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        if stop.load(Ordering::Acquire) || Instant::now() >= deadline {
            break;
        }
        let now_ops = ops.load(Ordering::Relaxed);
        let delta = now_ops.saturating_sub(last_ops);
        last_ops = now_ops;
        let elapsed = start.elapsed().as_secs_f64();
        eprint!("\r  {elapsed:6.1}s  {now_ops} ops  {delta} ops/s   ");
    }
    // Clear the progress line so it doesn't bleed into the report.
    eprintln!();
}
