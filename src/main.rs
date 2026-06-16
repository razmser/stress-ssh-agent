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
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::Parser;
use ssh_agent_client_rs::{Client, Identity};
use ssh_key::PublicKey;

use stress_ssh_agent::cli::{format_list, select, Args, IdentityInfo, SelectError};
use stress_ssh_agent::metrics::WorkerStats;
use stress_ssh_agent::worker::run_worker;

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
        Err(SelectError::NoMatch(q)) => {
            eprintln!("error: no supported identity matches --key {q:?}");
            return Ok(ExitCode::FAILURE);
        }
        Err(SelectError::EmptySupported) => {
            eprintln!("error: no supported identities found in the agent");
            if !infos.is_empty() {
                eprintln!("skipped identities:");
                eprint!("{}", format_list(&infos));
            }
            return Ok(ExitCode::FAILURE);
        }
    };

    let algorithm_desc = describe_algorithm(&selected, args.all);

    // Run header.
    let conn_mode = if args.reconnect {
        "reconnect"
    } else {
        "persistent"
    };
    eprintln!("stress-ssh-agent:");
    eprintln!("  algorithm:   {algorithm_desc}");
    eprintln!("  workers:     {}", args.parallel);
    eprintln!("  connection:  {conn_mode}");
    eprintln!("  duration:    {}s", args.timeout);

    // Shared run state.
    let stop = Arc::new(AtomicBool::new(false));
    let ops = Arc::new(AtomicU64::new(0));
    let start = Instant::now();
    let deadline = start + Duration::from_secs(args.timeout);

    // Spawn workers, round-robin over the selected keys.
    let mut handles = Vec::with_capacity(args.parallel);
    for i in 0..args.parallel {
        let key = selected[i % selected.len()].clone();
        let sock = sock.clone();
        let reconnect = args.reconnect;
        let stop = stop.clone();
        let ops = ops.clone();
        handles.push(tokio::task::spawn_blocking(move || {
            run_worker(sock, key, reconnect, deadline, stop, ops)
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

    // Join workers and merge their stats.
    let mut aggregate = WorkerStats::new();
    for handle in handles {
        match handle.await {
            Ok(stats) => aggregate.merge(&stats),
            Err(e) => eprintln!("warning: worker task failed: {e}"),
        }
    }

    let elapsed = start.elapsed();
    println!(
        "{}",
        aggregate.report(&algorithm_desc, args.parallel, args.reconnect, elapsed)
    );

    if aggregate.should_exit_nonzero() {
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
