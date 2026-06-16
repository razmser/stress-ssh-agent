# stress-ssh-agent

A command-line tool that stress-tests an ssh-agent: it drives parallel signing
workers and independently verifies every signature, doubling as a correctness
fuzzer and a latency/throughput benchmark.

## Features

- **Closed-loop load**: N persistent workers signing random data in a tight loop
  until a timeout, instead of bursty batches.
- **Out-of-band verification**: every signature is re-verified with RustCrypto
  (`p256`/`p384`/`p521`, `ed25519-dalek`, `rsa`), so a buggy or malicious agent
  that returns a bad signature is caught.
- **Latency metrics**: HDR-histogram percentiles (p50/p90/p99/p99.9/max) plus
  ops/s and separate `bad signature` vs `sign error` counters.
- **Identity selection**: pick one key by fingerprint/comment, round-robin all
  supported keys, or just list what the agent holds.
- **Supported key types**:
  - ECDSA (P-256, P-384, P-521)
  - Ed25519
  - RSA (`rsa-sha2-256` / `rsa-sha2-512`)

> RSA note: the verifier checks RSA signatures by selecting the hash from the
> signature's algorithm name. RSA keys verify cleanly when the agent returns an
> `rsa-sha2-256`/`rsa-sha2-512` signature. If an agent returns a legacy
> `ssh-rsa`/SHA-1 signature, `ssh-agent-client-rs`/`ssh-key 0.6` cannot decode
> it, so the sign call fails before verification and the attempt is counted as a
> `sign error` (a failure). This is a client/library limitation, not an agent
> fault.

## Installation

### From Source

```bash
cargo build --release
```

The binary will be available at `target/release/stress-ssh-agent`.

## Usage

Run with default settings (1 worker for 60 seconds, persistent connection):

```bash
stress-ssh-agent
```

Stress test with 10 parallel workers for 120 seconds:

```bash
stress-ssh-agent --parallel 10 --timeout 120   # -p / -t
```

### Flags

- `-p, --parallel <N>` — number of parallel signing workers (default `1`).
- `-t, --timeout <SECS>` — run duration in seconds (default `60`).
- `--reconnect` — open a fresh connection per sign (measures connection-churn
  cost) instead of the default persistent connection per worker.
- `--key <FINGERPRINT>` — select one identity by SHA256 fingerprint or by comment
  (substring match).
- `--all` — use all supported identities; every worker cycles through them
  round-robin (one key per iteration).
- `--list` — enumerate identities (algorithm, fingerprint, comment, supported or
  skip reason) and exit.

Examples:

```bash
stress-ssh-agent --list
stress-ssh-agent --key SHA256:abc123... -p 8
stress-ssh-agent --all -p 16 -t 30
stress-ssh-agent --reconnect -p 4
```

## Requirements

- An ssh-agent must be running with `SSH_AUTH_SOCK` set (the tool prints a clear
  error and exits non-zero if it is unset).
- At least one supported identity loaded in the agent.

## Example Output

```
stress-ssh-agent:
  algorithm:   ssh-ed25519
  workers:     8
  connection:  persistent
  duration:    30s
Results:
  algorithm:     ssh-ed25519
  workers:       8
  connection:    persistent
  duration:      30.00s
  total ops:     142318 (4743.93 ops/s)
  verified:      142318
  bad signature: 0
  sign error:    0
  latency (ms):
    p50:   1.612
    p90:   2.487
    p99:   4.901
    p99.9: 9.760
    max:   18.350
```

A ~1Hz progress line is printed to stderr during the run; the run header and
final report go to stderr and stdout respectively.

## Exit Codes

- `0` — every signature verified.
- `1` — any bad signature or sign error occurred, or no usable identity was
  found in the agent.

## How It Works

1. Connects to the agent via `SSH_AUTH_SOCK` and enumerates all identities.
2. Classifies each identity; certificates and unknown key types are skipped with
   a warning. If no supported key remains, it exits `1`.
3. Selects the target key set: the first supported key by default, one specific
   key with `--key`, or all supported keys with `--all`. Every worker is handed
   the full selected set and cycles through it round-robin, one key per
   iteration (with a single key, that key every iteration).
4. Spawns `--parallel` closed-loop workers. Each worker signs 32 random bytes in
   a tight loop until a shared deadline/stop flag flips, reusing one persistent
   connection (or reconnecting per sign with `--reconnect`).
5. Re-verifies each returned signature out-of-band with RustCrypto and records
   the sign latency and outcome into a per-worker HDR histogram.
6. Merges the per-worker stats at the end and prints the report.
