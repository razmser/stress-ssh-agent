//! Command-line arguments and identity selection.
//!
//! Stub for Task 1; real logic arrives in Task 3.

use clap::Parser;

/// Stress-test an ssh-agent: repeatedly sign random data and verify the
/// signatures out-of-band.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Number of parallel signing workers.
    #[arg(short = 'p', long = "parallel", default_value_t = 1)]
    pub parallel: usize,

    /// Run duration in seconds.
    #[arg(short = 't', long = "timeout", default_value_t = 60)]
    pub timeout: u64,

    /// Open a fresh connection per sign instead of reusing one.
    #[arg(long = "reconnect", default_value_t = false)]
    pub reconnect: bool,

    /// Select one identity by SHA256 fingerprint or comment.
    #[arg(long = "key")]
    pub key: Option<String>,

    /// Use all supported identities (round-robin across workers).
    #[arg(long = "all", default_value_t = false)]
    pub all: bool,

    /// List identities and exit.
    #[arg(long = "list", default_value_t = false)]
    pub list: bool,
}
