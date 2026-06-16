//! Integration tests for identity selection (`stress_ssh_agent::cli`).
//!
//! Exercises the pure selection/classification logic over synthetic identity
//! lists, so no live agent is needed.

use clap::Parser;
use ssh_key::public::{Ed25519PublicKey, KeyData};
use ssh_key::PublicKey;
use stress_ssh_agent::cli::{
    classify, format_list, select, Args, Classification, IdentityInfo, SelectError,
};

fn args() -> Args {
    Args {
        parallel: 1,
        timeout: 60,
        reconnect: false,
        key: None,
        all: false,
        list: false,
    }
}

/// Build an Ed25519 identity with a deterministic key + comment.
fn ed25519_identity(seed: u8, comment: &str) -> IdentityInfo {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    let vk = sk.verifying_key();
    let mut pk = PublicKey::from(KeyData::Ed25519(Ed25519PublicKey(vk.to_bytes())));
    pk.set_comment(comment);
    IdentityInfo::from_public_key(pk)
}

/// An identity marked as a certificate (its underlying key is irrelevant).
fn cert_identity() -> IdentityInfo {
    let mut info = ed25519_identity(99, "cert-key");
    info.is_certificate = true;
    info
}

#[test]
fn first_key_default_selection() {
    let infos = vec![ed25519_identity(1, "first"), ed25519_identity(2, "second")];
    let selected = select(&infos, &args()).expect("select");
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].comment(), "first");
}

#[test]
fn select_by_fingerprint() {
    let infos = vec![ed25519_identity(1, "first"), ed25519_identity(2, "second")];
    let target_fp = infos[1].fingerprint();
    let mut a = args();
    a.key = Some(target_fp);
    let selected = select(&infos, &a).expect("select");
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].comment(), "second");
}

#[test]
fn select_by_comment_substring() {
    let infos = vec![
        ed25519_identity(1, "alice@host"),
        ed25519_identity(2, "bob@host"),
    ];
    let mut a = args();
    a.key = Some("bob".to_string());
    let selected = select(&infos, &a).expect("select");
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].comment(), "bob@host");
}

#[test]
fn select_by_comment_multi_match_is_deterministic() {
    // Two identities whose comments both contain "host"; the first in
    // enumeration order must win, deterministically.
    let infos = vec![
        ed25519_identity(1, "alice@host"),
        ed25519_identity(2, "bob@host"),
    ];
    let mut a = args();
    a.key = Some("host".to_string());
    let selected = select(&infos, &a).expect("select");
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].comment(), "alice@host");
}

#[test]
fn key_and_all_are_mutually_exclusive() {
    // clap must reject `--key` together with `--all`.
    let result = Args::try_parse_from(["prog", "--key", "x", "--all"]);
    assert!(result.is_err(), "expected --key + --all to conflict");
}

#[test]
fn parallel_zero_is_rejected() {
    // `--parallel 0` would idle and exit 0; clap must reject it.
    let result = Args::try_parse_from(["prog", "--parallel", "0"]);
    assert!(result.is_err(), "expected --parallel 0 to be rejected");
    // A positive value is accepted.
    let ok = Args::try_parse_from(["prog", "--parallel", "4"]).expect("parse");
    assert_eq!(ok.parallel, 4);
}

#[test]
fn select_key_no_match_errors() {
    let infos = vec![ed25519_identity(1, "alice")];
    let mut a = args();
    a.key = Some("nonexistent".to_string());
    assert_eq!(
        select(&infos, &a),
        Err(SelectError::NoMatch("nonexistent".to_string()))
    );
}

#[test]
fn select_all_returns_every_supported() {
    let infos = vec![
        ed25519_identity(1, "first"),
        cert_identity(),
        ed25519_identity(2, "second"),
    ];
    let mut a = args();
    a.all = true;
    let selected = select(&infos, &a).expect("select");
    // Certificate is skipped; only the two supported keys are returned.
    assert_eq!(selected.len(), 2);
}

#[test]
fn certificate_is_skipped() {
    assert_eq!(
        classify(&cert_identity()),
        Classification::Skipped("certificate identity".to_string())
    );
}

#[test]
fn empty_supported_errors() {
    let infos = vec![cert_identity()];
    assert_eq!(select(&infos, &args()), Err(SelectError::EmptySupported));
    // And with no identities at all.
    assert_eq!(select(&[], &args()), Err(SelectError::EmptySupported));
}

#[test]
fn ed25519_classified_supported() {
    assert_eq!(
        classify(&ed25519_identity(1, "x")),
        Classification::Supported
    );
}

#[test]
fn format_list_includes_status_and_fingerprint() {
    let infos = vec![ed25519_identity(1, "alice"), cert_identity()];
    let listed = format_list(&infos);
    assert!(listed.contains("ssh-ed25519"));
    assert!(listed.contains("SHA256:"));
    assert!(listed.contains("supported"));
    assert!(listed.contains("skipped: certificate identity"));
}
