# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

This repo uses an [xtask](https://github.com/matklad/cargo-xtask) pattern. The `.cargo/config.toml` aliases `cargo x` to `cargo run --package xtask --`.

- `cargo x ci` — run the full CI suite (fmt check, clippy, test); this is what GitHub Actions runs
- `cargo x fmt` — `cargo fmt --all -- --check`
- `cargo x lint` — `cargo clippy --all-targets --all-features -- -D warnings` (warnings are errors)
- `cargo x test` — `cargo test --all-features`
- `cargo build --release` — binary is at `target/release/stress-ssh-agent`
- Run a single test: `cargo test <name>`

The crate is a library + thin binary: the package is `stress-ssh-agent`, the lib crate is `stress_ssh_agent` (`src/lib.rs`), and the binary is `stress-ssh-agent` (the `[[bin]]` section in `Cargo.toml`).

## Running

Requires `SSH_AUTH_SOCK` set and at least one supported identity loaded in the ssh-agent. If `SSH_AUTH_SOCK` is unset, `main` prints a clear error and exits non-zero (no opaque panic).

```bash
stress-ssh-agent -p 10 -t 120          # 10 workers, 120s (-p/--parallel, -t/--timeout; defaults 1, 60)
stress-ssh-agent --list                # enumerate identities and exit 0
stress-ssh-agent --key <FINGERPRINT>   # one identity by SHA256 fingerprint or comment substring
stress-ssh-agent --all                 # all supported identities, every worker cycles through them
stress-ssh-agent --reconnect           # fresh connection per sign (default: persistent per worker)
```

Exit codes: `0` when every signature verified; `1` if any bad signature or sign error occurred, or if no usable identity was found.

## Architecture

A library (`src/lib.rs`) plus a thin binary (`src/main.rs`) that stress-tests an ssh-agent by repeatedly signing random data and verifying the signatures out-of-band. The library is split into modules:

- `verify.rs` — `verify_signature` + `VerifyOutcome`; RustCrypto-based verification.
- `cli.rs` — `Args` (clap) plus identity classification and selection (kept free of live I/O so it is unit-testable).
- `worker.rs` — the closed-loop signing worker.
- `metrics.rs` — `WorkerStats`: hdrhistogram latency stats, counters, merge, and the report formatter.

Integration tests in `tests/verify.rs` exercise the public `verify_signature` API with in-process keypairs across all supported algorithms (including the P-521 regression and negative/edge cases); no live agent.

### Main loop

`main` connects, enumerates identities, selects the target key set, then spawns `--parallel` workers via `tokio::task::spawn_blocking` (the `ssh-agent-client-rs` client is blocking). Every worker is handed the full selected key set and runs a closed loop: cycle to the next key (round-robin, one key per iteration), sign 32 random bytes, time the sign call, verify, and record into a local `WorkerStats`, until a shared deadline/stop flag (`AtomicBool`) flips. A separate tokio task arms the deadline; a ~1Hz stderr progress line is driven off a shared `Arc<AtomicU64>` op counter. On stop, `main` joins the workers and merges their `WorkerStats` before printing the report. With `--all`, every worker exercises every selected key; by default a single key is used, so each iteration signs with that key.

Connection modes: persistent (default) connects once per worker and reuses the `Client`; `--reconnect` opens a fresh `Client::connect` per sign. Connect/sign errors are recorded as `SignError` and counted as completed ops.

### Signature verification (`verify_signature`)

Verification uses RustCrypto crates (`p256`/`p384`/`p521`, `ed25519-dalek`, `rsa`) and never panics — any malformed input maps to `BadSignature` (or `Unsupported` for key types we cannot handle):

- **ECDSA** (P-256/384/521): build the SEC1 verifying key, then convert the SSH signature into the curve's `ecdsa::Signature` via `ssh-key`'s built-in `TryFrom<&Signature>` impl (no hand-rolled ASN.1). The Verifier hashes with the curve's digest (P-256→SHA-256, P-384→SHA-384, P-521→SHA-512).
- **Ed25519**: verified directly from the raw 32-byte key and 64-byte signature.
- **RSA**: the `RsaPublicKey` is built from the key's `n`/`e` mpints; the hash is chosen from the signature's algorithm name (`rsa-sha2-256`→SHA-256, `rsa-sha2-512`→SHA-512, `ssh-rsa`→SHA-1) and verified via `rsa::pkcs1v15::VerifyingKey`.
- **Certificates / unknown key types**: skipped (with a warning) during selection; the run exits `1` if no usable key remains.

RSA caveat: `ssh-agent-client-rs 1.1`'s `sign` exposes no algorithm flag. An agent that returns a legacy `ssh-rsa`/SHA-1 signature for an RSA key cannot be decoded by `ssh-agent-client-rs`/`ssh-key 0.6`, so the sign call fails at decode and the attempt surfaces as a `sign error` (a failure). RSA keys verify cleanly when the agent returns `rsa-sha2-256`/`512`. The SHA-1 branch in `verify.rs` remains as correct defensive code.
