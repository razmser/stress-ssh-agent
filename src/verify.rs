//! Out-of-band verification of ssh-agent signatures using RustCrypto crates.
//!
//! The agent returns an [`ssh_key::Signature`] for a message we signed. We
//! independently re-verify that signature against the message and the public
//! key, so a buggy or malicious agent that returns a bad signature is caught.
//!
//! Verification never panics: any malformed/truncated/garbage input maps to
//! [`VerifyOutcome::BadSignature`] (or [`VerifyOutcome::Unsupported`] for key
//! types we cannot handle).

use rsa::BigUint;
use signature::Verifier;
use ssh_key::public::{EcdsaPublicKey, KeyData};
use ssh_key::Algorithm;

/// Outcome of verifying a signature produced by the agent against the message
/// that was signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// Signature is valid for the message and key.
    Verified,
    /// The agent returned a signature that does not verify (correctness bug).
    BadSignature,
    /// Signing or signature-parsing failed at runtime.
    SignError(String),
    /// The key type is not something we can verify; filtered out before workers run.
    Unsupported(String),
}

/// Verify a signature returned by the agent against `data` for `public_key`.
///
/// Returns [`VerifyOutcome::Verified`] for a good signature,
/// [`VerifyOutcome::BadSignature`] for a bad or unparseable one, and
/// [`VerifyOutcome::Unsupported`] for key types we do not handle.
pub fn verify_signature(
    public_key: &ssh_key::PublicKey,
    data: &[u8],
    signature: &ssh_key::Signature,
) -> VerifyOutcome {
    match public_key.key_data() {
        KeyData::Ecdsa(ecdsa_key) => verify_ecdsa(ecdsa_key, data, signature),
        KeyData::Ed25519(ed_key) => verify_ed25519(ed_key.as_ref(), data, signature),
        KeyData::Rsa(rsa_key) => verify_rsa(rsa_key, data, signature),
        other => VerifyOutcome::Unsupported(other.algorithm().to_string()),
    }
}

fn verify_ecdsa(
    key: &EcdsaPublicKey,
    data: &[u8],
    signature: &ssh_key::Signature,
) -> VerifyOutcome {
    // For each curve: build the SEC1 verifying key, then convert the SSH
    // signature (mpint-framed r||s) into the curve's ecdsa::Signature using
    // ssh-key's built-in TryFrom impl. The Verifier hashes with the curve's
    // digest (P-256→SHA-256, P-384→SHA-384, P-521→SHA-512). The arms differ
    // only in the curve module path, so a local macro keeps them in lockstep.
    let sec1 = key.as_sec1_bytes();
    macro_rules! verify_curve {
        ($curve:path) => {{
            use $curve as curve;
            let vk = match curve::ecdsa::VerifyingKey::from_sec1_bytes(sec1) {
                Ok(vk) => vk,
                Err(_) => return VerifyOutcome::BadSignature,
            };
            let sig = match curve::ecdsa::Signature::try_from(signature) {
                Ok(sig) => sig,
                Err(_) => return VerifyOutcome::BadSignature,
            };
            outcome(vk.verify(data, &sig).is_ok())
        }};
    }
    match key {
        EcdsaPublicKey::NistP256(_) => verify_curve!(p256),
        EcdsaPublicKey::NistP384(_) => verify_curve!(p384),
        EcdsaPublicKey::NistP521(_) => verify_curve!(p521),
    }
}

fn verify_ed25519(
    key_bytes: &[u8; 32],
    data: &[u8],
    signature: &ssh_key::Signature,
) -> VerifyOutcome {
    let vk = match ed25519_dalek::VerifyingKey::from_bytes(key_bytes) {
        Ok(vk) => vk,
        Err(_) => return VerifyOutcome::BadSignature,
    };
    let sig = match ed25519_dalek::Signature::from_slice(signature.as_bytes()) {
        Ok(sig) => sig,
        Err(_) => return VerifyOutcome::BadSignature,
    };
    outcome(vk.verify(data, &sig).is_ok())
}

fn verify_rsa(
    key: &ssh_key::public::RsaPublicKey,
    data: &[u8],
    signature: &ssh_key::Signature,
) -> VerifyOutcome {
    // The `rsa` feature on ssh-key is not enabled, so build the public key
    // ourselves from the n/e mpints.
    let (n, e) = match (key.n.as_positive_bytes(), key.e.as_positive_bytes()) {
        (Some(n), Some(e)) => (n, e),
        _ => return VerifyOutcome::BadSignature,
    };
    let pubkey = match rsa::RsaPublicKey::new(BigUint::from_bytes_be(n), BigUint::from_bytes_be(e))
    {
        Ok(pubkey) => pubkey,
        Err(_) => return VerifyOutcome::BadSignature,
    };

    let sig = match rsa::pkcs1v15::Signature::try_from(signature.as_bytes()) {
        Ok(sig) => sig,
        Err(_) => return VerifyOutcome::BadSignature,
    };

    // Choose the hash from the signature's algorithm name. The 1.1 agent client
    // can't request sha2, so real signatures come back as `ssh-rsa`/SHA-1, but
    // we still honour `rsa-sha2-256`/`512` if a future client negotiates them.
    match signature.algorithm() {
        Algorithm::Rsa { hash: None } => {
            let vk = rsa::pkcs1v15::VerifyingKey::<sha1::Sha1>::new(pubkey);
            outcome(vk.verify(data, &sig).is_ok())
        }
        Algorithm::Rsa {
            hash: Some(ssh_key::HashAlg::Sha256),
        } => {
            let vk = rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(pubkey);
            outcome(vk.verify(data, &sig).is_ok())
        }
        Algorithm::Rsa {
            hash: Some(ssh_key::HashAlg::Sha512),
        } => {
            let vk = rsa::pkcs1v15::VerifyingKey::<sha2::Sha512>::new(pubkey);
            outcome(vk.verify(data, &sig).is_ok())
        }
        other => VerifyOutcome::Unsupported(other.to_string()),
    }
}

fn outcome(valid: bool) -> VerifyOutcome {
    if valid {
        VerifyOutcome::Verified
    } else {
        VerifyOutcome::BadSignature
    }
}
