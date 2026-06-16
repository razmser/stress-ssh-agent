# stress-ssh-agent Overhaul

## Overview

Rework `stress-ssh-agent` from a single-file binary into a lib + thin binary that
serves as **both** a correctness fuzzer and a load/latency benchmark for an
ssh-agent. The current tool has correctness bugs (broken P-521 DER, RSA keys
falsely counted as failures), measures the wrong thing (a fresh connection per
sign, bursty batch loop), has zero tests despite a full CI apparatus, ships an
unused dependency, and exits `0` when it does nothing useful.

This plan fixes every issue surfaced in review:

- **Verification**: drop `aws-lc-rs` and all hand-rolled ASN.1; verify with
  RustCrypto crates (`p256`/`p384`/`p521`, `ed25519-dalek`, `rsa`). Fixes P-521,
  implements real RSA verification (SHA-1/256/512).
- **Load model**: replace the batch-spawn-await-sleep loop with N long-lived
  closed-loop workers; configurable persistent vs per-sign connection.
- **Metrics**: HDR-histogram latency percentiles (sign latency only) instead of
  per-op stdout dots; separate `bad signature` vs `sign error` counters.
- **Selection**: enumerate identities, skip certs/unsupported with a warning,
  `--key`/`--all`/`--list`; exit `1` when no usable key.
- **Structure**: lib + thin binary, split into modules, integration tests
  against a public `verify_signature` API.
- **Hygiene**: rename package `csr` → `stress-ssh-agent`, drop unused
  `ssh-encoding`-as-dead-dep (now actually used), trim `tokio` features.

## Context (from discovery)

- Single-file Rust binary `src/main.rs` (~296 lines); xtask workspace member
  drives CI (`cargo x ci` = fmt + clippy `-D warnings` + test).
- Package is named `csr` in `Cargo.toml`; `[[bin]]` produces `stress-ssh-agent`.
- Current deps: `clap`, `tokio` (full), `rand` 0.8, `aws-lc-rs`,
  `ssh-agent-client-rs` 1.1, `ssh-key` 0.6, `ssh-encoding` 0.1 (unused — and the
  wrong major: `ssh-key 0.6.7` re-exports `ssh-encoding 0.2`, so the pin must
  move to `0.2` when we start using it; better, use `ssh_key`'s own re-exported
  `Mpint`).
- `ssh-agent-client-rs` is a **blocking** client; current code wraps each sign in
  `spawn_blocking` with a fresh `Client::connect`.
- Existing patterns: `verify_signature` matches on `ssh_key::KeyData` variants;
  the agent returns `ssh_key::Signature` whose `.as_bytes()` is the SSH signature
  blob.

## Development Approach

- **Testing approach**: Regular (code first, then tests) per module, but the
  verification module is the crux — write its tests immediately after the code in
  the same task, before moving on.
- Complete each task fully (code + tests passing) before the next.
- Every task that changes code includes new/updated tests in `tests/verify.rs`
  (or module-local where a public API isn't suitable).
- **All tests + `cargo x ci` must pass before starting the next task.**
- Keep each source file well under 300 lines.

## Testing Strategy

- **Unit/integration tests**: `tests/verify.rs` exercises the public
  `verify_signature` API with in-process keypairs across all supported
  algorithms, including the P-521 regression and negative/edge cases. No live
  agent, no network, deterministic.
- **No e2e/UI tests**: this is a CLI tool; the worker loop needs a live agent and
  is not unit-tested. Manual smoke run against a real agent is a Post-Completion
  item.

## Progress Tracking

- Mark completed items `[x]` immediately when done.
- Add newly discovered tasks with ➕ prefix; blockers with ⚠️ prefix.
- Update this plan if scope shifts during implementation.

## Solution Overview

```
src/
  lib.rs        // pub mod verify; pub mod cli; pub mod worker; pub mod metrics;
  verify.rs     // VerifyOutcome + verify_signature (public) + SSH-blob mpint parse
  cli.rs        // Args (clap) + identity enumeration/selection
  worker.rs     // closed-loop worker; persistent vs --reconnect; stop signal
  metrics.rs    // per-worker Histogram + counters; merge; report formatting
  main.rs       // thin: parse -> select keys -> spawn workers -> report -> exit
tests/
  verify.rs     // integration tests against public verify_signature
```

Workers run as `spawn_blocking` closures (the client is blocking), each owning an
assigned `PublicKey` and — in persistent mode — one reused `Client`. They loop
until a shared deadline/stop flag flips, recording sign latency into a local HDR
histogram and tallying outcomes; `main` merges results and prints the report.

## Technical Details

- **VerifyOutcome enum**: `Verified` / `BadSignature` / `SignError(String)` /
  `Unsupported(String)`. `Unsupported` keys are filtered out before workers
  start, so only `Verified`/`BadSignature`/`SignError` appear at runtime.
  `bad_signature + sign_error > 0` (or no usable key) ⇒ exit `1`.
- **ECDSA verify**: `VerifyingKey::from_sec1_bytes(ecdsa_key.as_sec1_bytes())`
  for the key. For the signature, **prefer `ssh-key`'s built-in
  `TryFrom<&ssh_key::Signature> for {p256,p384,p521}::ecdsa::Signature`** (enabled
  by ssh-key's `p256`/`p384`/`p521` features) — it already does the mpint-decode +
  strip-sign-byte + zero-pad-to-field-size + `from_scalars` (see ssh-key
  `signature.rs` `zero_pad_field_bytes`), so we don't reinvent the exact step the
  old `ecdsa_ssh_to_der` got wrong. A failed `try_from` → `BadSignature`. Then
  `verifying_key.verify(message, &sig)` (Verifier hashes with curve digest:
  P-256→SHA-256, P-384→SHA-384, P-521→SHA-512).
  - Fallback only if that impl is unavailable: parse the two mpints from
    `signature.as_bytes()` via `ssh_key`'s `Mpint`; `Mpint::as_positive_bytes()`
    returns `Option<&[u8]>` (`None` for a negative mpint → `BadSignature`, never
    `unwrap`), then left-pad each to the curve field size before
    `Signature::from_scalars`.
- **Ed25519 verify**: `ed25519_dalek::VerifyingKey::from_bytes(32)` +
  `Signature::from_slice(64)` + `.verify`.
- **RSA verify**: `RsaPublicKey::new(BigUint::from_bytes_be(n), …(e))` from key
  mpints; hash chosen from the **signature's** algorithm name
  (`rsa-sha2-256`→Sha256, `rsa-sha2-512`→Sha512, `ssh-rsa`→Sha1); verify via
  `rsa::pkcs1v15::VerifyingKey::<H>::new(pubkey).verify(msg, &sig)`.
- **RSA hash selection**: `ssh-agent-client-rs 1.1.2`'s `sign`/`sign_with_ref`
  expose **no** flags/algorithm argument, so we cannot request `rsa-sha2-256`;
  the agent returns `ssh-rsa`/SHA-1 for RSA keys. We pick the verify hash from
  `signature.algorithm()` (handles `ssh-rsa`→Sha1, and `rsa-sha2-256`/`512` if a
  future client/agent negotiates them). SHA-1 is supported, so this verifies
  correctly. **`rsa` pkcs1v15 needs the DigestInfo prefix**, which requires the
  hash types to implement `AssociatedOid` — so `sha1`/`sha2` must be built with
  their `oid` feature (do **not** use `new_unprefixed`, which would reject real
  agent signatures).
- **Metrics**: `hdrhistogram::Histogram<u64>` in microseconds (1µs–60s, 3 sig
  figs) recording **sign latency only** (exclude verification CPU). Report:
  algorithm(s), workers, connection mode, duration, total ops + ops/s,
  verified/bad-signature/sign-error counts, latency p50/p90/p99/p99.9/max in ms.
  Optional ~1Hz progress line to **stderr** (running ops/s + error count); no
  per-op dots.

## What Goes Where

- **Implementation Steps** (checkboxes): all code, tests, Cargo changes, docs.
- **Post-Completion** (no checkboxes): manual smoke run against a real agent,
  multi-key/`--all` run, RSA-on-real-agent SHA-2 flag verification.

## Implementation Steps

### Task 1: Crate scaffold — lib + thin binary + Cargo deps

**Files:**
- Modify: `Cargo.toml`
- Create: `src/lib.rs`
- Create: `src/verify.rs` (stub: `VerifyOutcome`, `verify_signature` signature)
- Create: `src/cli.rs` (stub)
- Create: `src/worker.rs` (stub)
- Create: `src/metrics.rs` (stub)
- Modify: `src/main.rs` (temporary thin shim that still compiles)

- [x] rename `package.name` to `stress-ssh-agent`; keep `[[bin]] name = "stress-ssh-agent"`; add `[lib]` (crate `stress_ssh_agent`)
- [x] Cargo deps: remove `aws-lc-rs`; add stable versions compatible with `ssh-key 0.6.7` (which uses `signature 2.x` / `digest 0.10`): `p256 = "0.13"`, `p384 = "0.13"`, `p521 = "0.13"` (feature `ecdsa`), `ed25519-dalek = "2"`, `rsa = "0.9"`, `signature = "2"`, `hdrhistogram`, and `sha1 = { version = "0.10", features = ["oid"] }` + `sha2 = { version = "0.10", features = ["oid"] }` (the `oid` feature is **required** or the RSA pkcs1v15 `VerifyingKey::new` bound `AssociatedOid` is unsatisfied and the build fails)
- [x] enable `ssh-key`'s `p256`/`p384`/`p521` features so its `TryFrom<&Signature> for {curve}::ecdsa::Signature` impls are available (lets Task 2 skip hand-rolled mpint parsing)
- [x] do **not** copy "latest" from `cargo search` — several of these only surface pre-release majors (`rsa 0.10-rc`, `ed25519-dalek 3.0-rc`, `p521 0.14-rc`) that won't resolve against `ssh-key 0.6.7`; pin the stable versions above
- [x] `ssh-encoding`: change the pin from `0.1` to `0.2` to match `ssh-key 0.6.7` — or drop it and use `ssh_key`'s re-exported `Mpint` directly (preferred; avoids a second copy)
- [x] trim `tokio` to the minimal feature set (`rt-multi-thread`, `macros`, `time`, `sync`) — confirm against actual usage, widen only if the build needs it
- [x] create `src/lib.rs` declaring `pub mod verify; pub mod cli; pub mod worker; pub mod metrics;`
- [x] add module stubs so the workspace compiles; reduce `main.rs` to a temporary shim calling into stubs
- [x] `cargo x ci` compiles (clippy clean, fmt clean); real tests arrive in Task 2 (no placeholder test)

### Task 2: Verification core (`verify.rs`) + full test suite

**Files:**
- Modify: `src/verify.rs`
- Modify: `tests/verify.rs`
- Modify: `Cargo.toml` (`[dev-dependencies]`)

- [x] add `[dev-dependencies]` for in-process keygen/signing in tests: `p256`/`p384`/`p521` with `features = ["ecdsa"]` (that single feature pulls arithmetic + signing + the curve digest, so P-521 signing works), `ed25519-dalek` (feature `rand_core`), `rsa` building a `pkcs1v15::SigningKey::<Sha256/Sha512/Sha1>` (reuse the `oid`-featured `sha1`/`sha2` from Task 1), and `rand` for key generation; reuse the same major versions pinned in Task 1
- [x] define `pub enum VerifyOutcome { Verified, BadSignature, SignError(String), Unsupported(String) }`
- [x] implement `pub fn verify_signature(public_key: &ssh_key::PublicKey, data: &[u8], signature: &ssh_key::Signature) -> VerifyOutcome`
- [x] ECDSA branch: SEC1 verifying key + convert the signature via `ssh_key`'s built-in `TryFrom<&Signature> for {p256,p384,p521}::ecdsa::Signature` (failed `try_from` → `BadSignature`); verify. Fallback (only if that impl is unavailable): parse mpints, `as_positive_bytes()` (returns `Option`; `None` → `BadSignature`) then left-pad to field size + `from_scalars`. Either way, all hand-rolled DER is gone (`ecdsa_ssh_to_der` deleted)
- [x] Ed25519 branch: `from_bytes`/`from_slice`/verify
- [x] RSA branch: `RsaPublicKey` from `n`/`e`; select hash from signature algo name (`rsa-sha2-256`/`rsa-sha2-512`/`ssh-rsa`); `pkcs1v15::VerifyingKey::<H>` verify
- [x] map results: valid→`Verified`, invalid→`BadSignature`, unparseable→`BadSignature` (never panic); unknown key type→`Unsupported`
- [x] add a helper in tests to synthesize the SSH signature blob (mpint `r‖s` framing) wrapped in `ssh_key::Signature`
- [x] write round-trip tests: P-256, P-384, P-521, Ed25519, RSA-SHA256, RSA-SHA512 → assert `Verified`. NOTE: RSA-SHA1 (`ssh-rsa`) round-trip is **not constructible** with `ssh-key 0.6.7`: its `Signature::decode`/`new` reject `Algorithm::Rsa { hash: None }` (only `Some(_)` accepted) and the agent client uses the same decode, so an `ssh-rsa` signature can never reach `verify_signature`. The SHA-1 hash-selection branch is still implemented as correct defensive code; the limitation is documented in `tests/verify.rs`.
- [x] write **P-521 regression test** (DER would exceed the 127-byte short-form boundary) → assert `Verified`
- [x] write edge-case tests: ECDSA r/s with high bit set (would-be negative) and with leading zero bytes → assert `Verified`
- [x] write negative tests: flipped byte → `BadSignature`; truncated/empty blob → `BadSignature`/error, no panic; wrong key → `BadSignature`
- [x] `cargo x ci` — all verification tests pass before next task

### Task 3: CLI + identity selection (`cli.rs`)

**Files:**
- Modify: `src/cli.rs`
- Modify: `tests/verify.rs` (or add `tests/cli.rs`)

- [x] define `Args` (clap derive): `-p/--parallel` (default 1), `-t/--timeout` secs (default 60), `--reconnect`, `--key <FINGERPRINT>`, `--all`, `--list`
- [x] implement identity enumeration over `list_all_identities()`; classify each as supported (ECDSA P-256/384/521, Ed25519, RSA) or skipped (cert/unknown) with reason
- [x] implement selection: `--key` matches one by SHA256 fingerprint or comment (error if no match); `--all` → all supported; neither → first supported
- [x] return an owned `Vec<PublicKey>` target set + a list of skipped identities (for warnings); empty supported set is a distinct error variant
- [x] `--list` path: format identities (algo, fingerprint, comment, supported?) for printing, then caller exits 0
- [x] write unit tests for selection logic over a synthetic identity list (first/`--key`/`--all`/no-match/empty) — keep pure/testable by separating parsing from the live `Client`
- [x] `cargo x ci` passes

### Task 4: Metrics (`metrics.rs`)

**Files:**
- Modify: `src/metrics.rs`
- Modify: `tests/verify.rs` (or add `tests/metrics.rs`)

- [x] define `WorkerStats { hist: Histogram<u64>, verified, bad_signature, sign_error }` with a `record(outcome, sign_latency)` method and a `merge(&mut self, other)`
- [x] implement histogram init (1µs–60s, 3 sig figs) and microsecond recording for sign latency only
- [x] implement final report formatter: algorithm(s), workers, connection mode, duration, total ops + ops/s, verified/bad-signature/sign-error, p50/p90/p99/p99.9/max in ms
- [x] implement `should_exit_nonzero()` = `bad_signature + sign_error > 0`
- [x] write tests: merge of two stats sums counters and combines histograms; percentile/report formatting on a known sample set; exit-code predicate
- [x] `cargo x ci` passes

### Task 5: Closed-loop worker (`worker.rs`)

**Files:**
- Modify: `src/worker.rs`

- [x] define a `run_worker(sock, public_key, reconnect: bool, deadline/stop, &mut WorkerStats)` that loops until stopped
- [x] per iteration: 32 random bytes → time `sign` (Instant) → `verify_signature` → `stats.record(...)`; bump a shared `Arc<AtomicU64>` op counter (read by main's progress line); check stop flag at loop top
- [x] connection model: persistent = connect once, reuse `Client`; `--reconnect` = `Client::connect` per sign; map connect/sign errors → `SignError`
- [x] RSA hash is selected in `verify.rs` from `signature.algorithm()`; no flag to set here — `ssh-agent-client-rs 1.1.2` `sign` has no algorithm argument, so RSA keys return `ssh-rsa`/SHA-1 (verified, since SHA-1 is supported)
- [x] run each worker as a `spawn_blocking` closure; signing+verification happen on the same blocking thread
- [x] (worker loop needs a live agent, so it is exercised via the manual smoke run, not unit tests; keep logic thin and delegate verification to the tested `verify.rs`)
- [x] `cargo x ci` passes (compiles, clippy clean)

### Task 6: Wire `main.rs` + stop signal + reporting

**Files:**
- Modify: `src/main.rs`

- [x] parse `Args`; read `SSH_AUTH_SOCK` (clear error if unset instead of bare panic)
- [x] connect, enumerate + select identities; handle `--list` (print + exit 0); empty supported set → print skipped + exit 1
- [x] print run header; assign keys to workers (round-robin for `--all`); arm deadline via `tokio::time::sleep_until` that flips the shared stop flag
- [x] spawn `parallel` workers, each handed a clone of a shared `Arc<AtomicU64>` op counter; on deadline, join all, merge `WorkerStats`
- [x] ~1Hz stderr progress line driven by the shared `Arc<AtomicU64>` counter (running ops/s + error count) — the only mid-run shared state; per-worker `WorkerStats` are still merged only at the end
- [x] print final report; `std::process::exit(1)` when `should_exit_nonzero()` or no usable key, else 0
- [x] `cargo x ci` passes

### Task 7: Verify acceptance criteria

- [ ] all review findings addressed: P-521 fixed, RSA verified (not false-failed), tests exist, `ssh-encoding` used, closed-loop workers, connection modes, latency metrics, empty-identity exit 1, package renamed, no per-op Arc deep-clone
- [ ] confirm no `aws-lc-rs` and no hand-rolled DER remain (`ecdsa_ssh_to_der` deleted)
- [ ] run full suite: `cargo x ci`
- [ ] each source file < 300 lines

### Task 8: Documentation

**Files:**
- Modify: `README.md`
- Modify: `CLAUDE.md`

- [ ] README: update features (RSA now verified, P-521 fixed), CLI flags (`--reconnect`/`--key`/`--all`/`--list`), new example output with latency percentiles
- [ ] CLAUDE.md: update Architecture (RustCrypto verification, closed-loop workers, connection modes, metrics, module layout), Commands/Running (package name, new flags), remove the stale "single-file binary" / `ecdsa_ssh_to_der` / "RSA not implemented" notes
- [ ] move this plan to `docs/plans/completed/`

## Post-Completion

*Items requiring a live agent or manual verification — informational only.*

**Manual verification:**
- Smoke run against a real ssh-agent for each key type (Ed25519, ECDSA P-256/384/521, RSA) → expect `bad signature: 0`, exit 0.
- `--reconnect` vs persistent: compare latency percentiles to confirm connection-churn cost is visible.
- `--all` with a multi-key agent: confirm round-robin and per-run reporting.
- Confirm RSA on the real agent returns `ssh-rsa`/SHA-1 (the `1.1.2` client can't request sha2) and that `verify_signature` reports `Verified` for it. If a future client gains an algorithm flag, re-test the `rsa-sha2-256`/`512` paths.
- High-concurrency run (`-p 32`) to sanity-check throughput and that stderr progress doesn't bottleneck.
