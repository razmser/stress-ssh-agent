//! Integration tests for the verifier pool (`stress_ssh_agent::verifier`).
//!
//! Jobs are built from in-process Ed25519 keypairs (no live agent) and fed
//! through the same channel shape `main` uses: a shared `Receiver` behind a
//! mutex, drained until a `Shutdown` sentinel or sender disconnect.

use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::Signer;
use ssh_key::public::{Ed25519PublicKey, KeyData};
use ssh_key::{Algorithm, PublicKey, Signature};
use stress_ssh_agent::verifier::{run_verifier, VerifyJob};
use stress_ssh_agent::worker::SIGN_BYTES;

fn keypair(seed: u8) -> (ed25519_dalek::SigningKey, PublicKey) {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    let vk = sk.verifying_key();
    let pk = PublicKey::from(KeyData::Ed25519(Ed25519PublicKey(vk.to_bytes())));
    (sk, pk)
}

/// A `Signed` job for `data` signed by `sk`, attributed to `key_idx`.
fn signed_job(sk: &ed25519_dalek::SigningKey, key_idx: usize, data: [u8; SIGN_BYTES]) -> VerifyJob {
    let sig = sk.sign(&data);
    let signature =
        Signature::new(Algorithm::Ed25519, sig.to_bytes().to_vec()).expect("frame ed25519 sig");
    VerifyJob::Signed {
        key_idx,
        data,
        signature,
        sign_latency: Duration::from_micros(1000),
    }
}

fn shared_receiver(rx: mpsc::Receiver<VerifyJob>) -> Arc<Mutex<mpsc::Receiver<VerifyJob>>> {
    Arc::new(Mutex::new(rx))
}

#[test]
fn verifies_backlog_then_stops_on_shutdown() {
    let (sk, pk) = keypair(1);
    let (tx, rx) = mpsc::channel();

    for i in 0..3u8 {
        tx.send(signed_job(&sk, 0, [i; SIGN_BYTES])).expect("send");
    }
    // A signature from the wrong key must come back as a bad signature.
    let (wrong_sk, _) = keypair(2);
    tx.send(signed_job(&wrong_sk, 0, [9; SIGN_BYTES]))
        .expect("send");
    tx.send(VerifyJob::Shutdown).expect("send");

    let stats = run_verifier(Arc::new(vec![pk]), shared_receiver(rx));

    let report = stats.report(
        "ssh-ed25519",
        &["ssh-ed25519 SHA256:x".to_string()],
        1,
        false,
        Duration::from_secs(1),
    );
    assert!(report.contains("verified:      3"), "report:\n{report}");
    assert!(report.contains("bad signature: 1"), "report:\n{report}");
    assert!(stats.should_exit_nonzero());
    // The sender is still alive: the verifier stopped on the sentinel, not on
    // disconnect.
    drop(tx);
}

#[test]
fn stops_on_sender_disconnect() {
    let (sk, pk) = keypair(3);
    let (tx, rx) = mpsc::channel();
    tx.send(signed_job(&sk, 0, [0; SIGN_BYTES])).expect("send");
    drop(tx);

    let stats = run_verifier(Arc::new(vec![pk]), shared_receiver(rx));
    assert!(!stats.should_exit_nonzero());
}

#[test]
fn jobs_are_attributed_per_key() {
    let (sk_a, pk_a) = keypair(4);
    let (sk_b, pk_b) = keypair(5);
    let (tx, rx) = mpsc::channel();

    tx.send(signed_job(&sk_a, 0, [1; SIGN_BYTES]))
        .expect("send");
    tx.send(signed_job(&sk_b, 1, [2; SIGN_BYTES]))
        .expect("send");
    tx.send(signed_job(&sk_b, 1, [3; SIGN_BYTES]))
        .expect("send");
    tx.send(VerifyJob::Shutdown).expect("send");

    let stats = run_verifier(Arc::new(vec![pk_a, pk_b]), shared_receiver(rx));

    let labels = vec!["key-a".to_string(), "key-b".to_string()];
    let report = stats.report(
        "2 keys, round-robin",
        &labels,
        1,
        false,
        Duration::from_secs(1),
    );
    assert!(
        report.contains("ops: 1  verified: 1  bad signature: 0"),
        "report:\n{report}"
    );
    assert!(
        report.contains("ops: 2  verified: 2  bad signature: 0"),
        "report:\n{report}"
    );
    assert!(!stats.should_exit_nonzero());
}

#[test]
fn pool_shares_one_receiver_and_each_sentinel_stops_one_verifier() {
    let (sk, pk) = keypair(6);
    let (tx, rx) = mpsc::channel();
    let rx = shared_receiver(rx);
    let keys = Arc::new(vec![pk]);

    for i in 0..20u8 {
        tx.send(signed_job(&sk, 0, [i; SIGN_BYTES])).expect("send");
    }
    tx.send(VerifyJob::Shutdown).expect("send");
    tx.send(VerifyJob::Shutdown).expect("send");

    let handles: Vec<_> = (0..2)
        .map(|_| {
            let keys = keys.clone();
            let rx = rx.clone();
            std::thread::spawn(move || run_verifier(keys, rx))
        })
        .collect();

    let mut merged = stress_ssh_agent::metrics::WorkerStats::new(1);
    for handle in handles {
        merged.merge(&handle.join().expect("verifier thread panicked"));
    }

    let report = merged.report(
        "ssh-ed25519",
        &["ssh-ed25519 SHA256:x".to_string()],
        1,
        false,
        Duration::from_secs(1),
    );
    assert!(report.contains("verified:      20"), "report:\n{report}");
    assert!(!merged.should_exit_nonzero());
    drop(tx);
}
