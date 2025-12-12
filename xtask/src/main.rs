use std::env;
use std::process::{exit, Command};

fn main() {
    let task = env::args().nth(1);
    match task.as_deref() {
        Some("ci") => {
            if !run_ci() {
                exit(1);
            }
        }
        Some("fmt") => {
            if !run_fmt() {
                exit(1);
            }
        }
        Some("lint") => {
            if !run_lint() {
                exit(1);
            }
        }
        Some("test") => {
            if !run_test() {
                exit(1);
            }
        }
        _ => {
            eprintln!("Usage: cargo xtask <task>");
            eprintln!("Tasks:");
            eprintln!("  ci    - Run all checks (fmt, lint, test)");
            eprintln!("  fmt   - Check formatting");
            eprintln!("  lint  - Run clippy lints");
            eprintln!("  test  - Run tests");
            exit(1);
        }
    }
}

fn run_ci() -> bool {
    println!("=== Running CI checks ===\n");

    println!("--- Checking formatting ---");
    if !run_fmt() {
        return false;
    }
    println!();

    println!("--- Running lints ---");
    if !run_lint() {
        return false;
    }
    println!();

    println!("--- Running tests ---");
    if !run_test() {
        return false;
    }
    println!();

    println!("=== All CI checks passed ===");
    true
}

fn run_fmt() -> bool {
    let status = Command::new("cargo")
        .args(&["fmt", "--all", "--", "--check"])
        .status()
        .expect("Failed to run cargo fmt");

    status.success()
}

fn run_lint() -> bool {
    let status = Command::new("cargo")
        .args(&[
            "clippy",
            "--all-targets",
            "--all-features",
            "--",
            "-D",
            "warnings",
        ])
        .status()
        .expect("Failed to run cargo clippy");

    status.success()
}

fn run_test() -> bool {
    let status = Command::new("cargo")
        .args(&["test", "--all-features"])
        .status()
        .expect("Failed to run cargo test");

    status.success()
}
