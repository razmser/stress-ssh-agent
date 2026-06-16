//! Out-of-band verification of ssh-agent signatures using RustCrypto crates.
//!
//! Stub for Task 1; real logic arrives in Task 2.

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
/// Stub: returns `Unsupported` until Task 2 implements the real logic.
pub fn verify_signature(
    public_key: &ssh_key::PublicKey,
    data: &[u8],
    signature: &ssh_key::Signature,
) -> VerifyOutcome {
    let _ = (data, signature);
    VerifyOutcome::Unsupported(public_key.algorithm().to_string())
}
