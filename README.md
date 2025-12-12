# stress-ssh-agent

A command-line tool to stress test SSH agents by performing parallel signing operations with cryptographic verification.

## Features

- **Parallel Signing**: Configurable number of concurrent signing operations
- **Cryptographic Verification**: Validates all signatures using `aws-lc-rs`
- **Supported Key Types**:
  - ECDSA (P-256, P-384, P-521)
  - Ed25519
  - RSA (signing only, verification not yet implemented)

## Installation

### From Source

```bash
cargo build --release
```

The binary will be available at `target/release/stress-ssh-agent`.

## Usage

Run with default settings (1 parallel operation for 60 seconds):
```bash
stress-ssh-agent
```

Stress test with 10 parallel operations for 120 seconds:
```bash
stress-ssh-agent --parallel 10 --timeout 120
```

## Requirements

- SSH agent must be running with `SSH_AUTH_SOCK` environment variable set
- At least one identity loaded in the SSH agent

## Example Output

```
Using identity from ssh-agent
Key algorithm: ssh-ed25519
Signing 5 data blobs in parallel for 60 seconds...
.................................................................................

Results:
  Successful: 1250
  Failed: 0
  Total: 1250
  Iterations: 250
  Duration: 60.01s
  Rate: 20.83 ops/s
```

## Exit Codes

- `0` - All operations succeeded
- `1` - One or more operations failed

## How It Works

1. Connects to the SSH agent via `SSH_AUTH_SOCK`
2. Retrieves the first available identity
3. Continuously generates random 32-byte data blobs
4. Signs each blob using the SSH agent
5. Verifies each signature using cryptographic primitives
6. Reports statistics upon completion or timeout

