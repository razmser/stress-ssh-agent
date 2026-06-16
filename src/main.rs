//! Thin binary shim.
//!
//! Task 1 scaffold: parses args and exits. Real wiring (identity selection,
//! worker spawning, reporting) arrives in Task 6.

use clap::Parser;
use stress_ssh_agent::cli::Args;

fn main() {
    let args = Args::parse();
    let _ = args;
    eprintln!("stress-ssh-agent: scaffold build; functionality lands in later tasks");
}
