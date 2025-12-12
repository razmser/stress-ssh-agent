extern crate alloc;

use alloc::sync::Arc;
use aws_lc_rs::signature::{self, UnparsedPublicKey};
use clap::Parser;
use rand::Rng;
use ssh_agent_client_rs::{Client, Identity};
use ssh_key::public::KeyData;
use std::env;
use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant};
use tokio::task;
use tokio::time;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Number of parallel signing operations
    #[arg(short = 'p', long = "parallel", default_value_t = 1)]
    parallel: usize,

    /// Timeout in seconds
    #[arg(short = 't', long = "timeout", default_value_t = 60)]
    timeout: u64,
}

/// Convert ECDSA signature from SSH format (r || s as mpints) to DER format
fn ecdsa_ssh_to_der(sig_bytes: &[u8]) -> Option<Vec<u8>> {
    // SSH ECDSA signature format: r_len (4 bytes BE) + r + s_len (4 bytes BE) + s
    if sig_bytes.len() < 4 {
        return None;
    }

    let r_len =
        u32::from_be_bytes([sig_bytes[0], sig_bytes[1], sig_bytes[2], sig_bytes[3]]) as usize;
    if sig_bytes.len() < 4 + r_len + 4 {
        return None;
    }
    let r = &sig_bytes[4..4 + r_len];

    let s_start = 4 + r_len;
    let s_len = u32::from_be_bytes([
        sig_bytes[s_start],
        sig_bytes[s_start + 1],
        sig_bytes[s_start + 2],
        sig_bytes[s_start + 3],
    ]) as usize;
    if sig_bytes.len() < s_start + 4 + s_len {
        return None;
    }
    let s = &sig_bytes[s_start + 4..s_start + 4 + s_len];

    // Convert to DER format
    // Remove leading zeros but ensure positive (add 0x00 if high bit set)
    let r_trimmed: Vec<u8> = r.iter().skip_while(|&&b| b == 0).copied().collect();
    let s_trimmed: Vec<u8> = s.iter().skip_while(|&&b| b == 0).copied().collect();

    let r_final = if r_trimmed.is_empty() {
        vec![0]
    } else if r_trimmed[0] & 0x80 != 0 {
        let mut v = vec![0];
        v.extend_from_slice(&r_trimmed);
        v
    } else {
        r_trimmed
    };

    let s_final = if s_trimmed.is_empty() {
        vec![0]
    } else if s_trimmed[0] & 0x80 != 0 {
        let mut v = vec![0];
        v.extend_from_slice(&s_trimmed);
        v
    } else {
        s_trimmed
    };

    // Build DER SEQUENCE: 0x30 len (0x02 r_len r) (0x02 s_len s)
    let mut content = Vec::new();
    content.push(0x02);
    content.push(r_final.len() as u8);
    content.extend_from_slice(&r_final);
    content.push(0x02);
    content.push(s_final.len() as u8);
    content.extend_from_slice(&s_final);

    let mut der = Vec::new();
    der.push(0x30);
    der.push(content.len() as u8);
    der.extend_from_slice(&content);

    Some(der)
}

fn verify_signature(
    public_key: &ssh_key::PublicKey,
    data: &[u8],
    signature: &ssh_key::Signature,
) -> Result<bool, String> {
    let sig_bytes = signature.as_bytes();

    match public_key.key_data() {
        KeyData::Ecdsa(ecdsa_key) => {
            let (algorithm, _curve_name): (&dyn signature::VerificationAlgorithm, &str) =
                match ecdsa_key.curve() {
                    ssh_key::EcdsaCurve::NistP256 => (&signature::ECDSA_P256_SHA256_ASN1, "P-256"),
                    ssh_key::EcdsaCurve::NistP384 => (&signature::ECDSA_P384_SHA384_ASN1, "P-384"),
                    ssh_key::EcdsaCurve::NistP521 => (&signature::ECDSA_P521_SHA512_ASN1, "P-521"),
                };

            // Get the raw public key point (uncompressed format)
            let pubkey_bytes = ecdsa_key.as_sec1_bytes();

            // Convert signature from SSH mpint format to DER
            let der_sig = ecdsa_ssh_to_der(sig_bytes).ok_or("Failed to parse ECDSA signature")?;

            let result = UnparsedPublicKey::new(algorithm, pubkey_bytes).verify(data, &der_sig);
            Ok(result.is_ok())
        }
        KeyData::Ed25519(ed25519_key) => {
            let pubkey_bytes = ed25519_key.as_ref();
            let result =
                UnparsedPublicKey::new(&signature::ED25519, pubkey_bytes).verify(data, sig_bytes);
            Ok(result.is_ok())
        }
        KeyData::Rsa(rsa_key) => {
            // RSA verification requires DER-encoded public key
            // For simplicity, we'll skip RSA verification complexity
            // The ssh-agent signed the data, so we trust it for RSA
            let _ = rsa_key;
            Err("RSA signature verification not implemented".to_string())
        }
        _ => Err(format!("Unsupported key type: {}", public_key.algorithm())),
    }
}

async fn sign_and_verify_task(
    ssh_auth_sock: String,
    public_key: ssh_key::PublicKey,
    task_id: usize,
) -> Result<bool, String> {
    // Generate random data before the blocking task
    let data: Vec<u8> = {
        let mut rng = rand::thread_rng();
        (0..32).map(|_| rng.gen()).collect()
    };

    let data_clone = data.clone();
    let public_key_clone = public_key.clone();

    // Connect to ssh-agent and sign (blocking operation)
    let signature = task::spawn_blocking(move || {
        let path = Path::new(&ssh_auth_sock);
        let mut client = Client::connect(path)
            .map_err(|e| format!("Task {task_id}: Failed to connect to ssh-agent: {e}"))?;

        // Create identity from public key for signing
        let identity = Identity::from(public_key_clone);

        // Sign the data
        let signature = client
            .sign(identity, &data_clone)
            .map_err(|e| format!("Task {task_id}: Failed to sign data: {e}"))?;

        Ok::<ssh_key::Signature, String>(signature)
    })
    .await
    .map_err(|e| format!("Task {task_id}: Task join error: {e}"))??;

    // Verify the signature using aws-lc-rs
    verify_signature(&public_key, &data, &signature)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Get SSH_AUTH_SOCK
    let ssh_auth_sock =
        env::var("SSH_AUTH_SOCK").expect("SSH_AUTH_SOCK environment variable not set");

    // Connect to ssh-agent and list identities
    let path = Path::new(&ssh_auth_sock);
    let mut client = Client::connect(path).map_err(|e| {
        Box::new(std::io::Error::other(format!("Failed to connect: {e}")))
            as Box<dyn std::error::Error>
    })?;
    let identities = client.list_all_identities().map_err(|e| {
        Box::new(std::io::Error::other(format!(
            "Failed to list identities: {e}"
        ))) as Box<dyn std::error::Error>
    })?;

    if identities.is_empty() {
        eprintln!("No identities found in ssh-agent");
        return Ok(());
    }

    // Get the public key from the first identity
    let public_key: ssh_key::PublicKey = match &identities[0] {
        Identity::PublicKey(pk) => {
            let cow = (**pk).clone();
            cow.into_owned()
        }
        Identity::Certificate(_cert) => {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "Certificate identities not yet supported",
            )) as Box<dyn std::error::Error>);
        }
    };

    let key_algorithm = public_key.algorithm();
    let public_key = Arc::new(public_key);

    println!("Using identity from ssh-agent");
    println!("Key algorithm: {key_algorithm}");
    println!(
        "Signing {} data blobs in parallel for {} seconds...",
        args.parallel, args.timeout
    );

    let start_time = Instant::now();
    let timeout_duration = Duration::from_secs(args.timeout);
    let mut total_success = 0u64;
    let mut total_fail = 0u64;
    let mut iteration = 0u64;

    loop {
        if start_time.elapsed() >= timeout_duration {
            break;
        }

        iteration += 1;
        let mut handles = Vec::new();

        // Create tasks for parallel signing
        for i in 0..args.parallel {
            let sock = ssh_auth_sock.clone();
            let pubkey_clone = Arc::clone(&public_key);
            let handle =
                task::spawn(
                    async move { sign_and_verify_task(sock, (*pubkey_clone).clone(), i).await },
                );
            handles.push(handle);
        }

        // Wait for all tasks to complete
        for handle in handles {
            match handle.await {
                Ok(Ok(true)) => {
                    total_success += 1;
                    print!(".");
                    std::io::stdout().flush().expect("Failed to flush stdout");
                }
                Ok(Ok(false)) => {
                    total_fail += 1;
                    print!("F");
                    std::io::stdout().flush().expect("Failed to flush stdout");
                }
                Ok(Err(e)) => {
                    total_fail += 1;
                    eprintln!("\nError: {e}");
                }
                Err(e) => {
                    total_fail += 1;
                    eprintln!("\nTask join error: {e}");
                }
            }
        }

        // Small delay to prevent tight loop
        time::sleep(Duration::from_millis(10)).await;
    }

    let elapsed = start_time.elapsed();
    println!("\n\nResults:");
    println!("  Successful: {total_success}");
    println!("  Failed: {total_fail}");
    println!("  Total: {}", total_success + total_fail);
    println!("  Iterations: {iteration}");
    println!("  Duration: {:.2}s", elapsed.as_secs_f64());
    if total_success + total_fail > 0 {
        println!(
            "  Rate: {:.2} ops/s",
            (total_success + total_fail) as f64 / elapsed.as_secs_f64()
        );
    }

    if total_fail > 0 {
        std::process::exit(1);
    }

    Ok(())
}
