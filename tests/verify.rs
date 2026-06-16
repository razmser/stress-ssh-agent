//! Integration tests for the public `verify_signature` API. Keypairs are
//! generated and messages signed in-process with RustCrypto, then framed into
//! the exact SSH wire format an agent returns — deterministic, no live agent.

use rsa::signature::{RandomizedSigner, SignatureEncoding};
use ssh_key::public::{EcdsaPublicKey, KeyData, RsaPublicKey};
use ssh_key::{Algorithm, Mpint, PublicKey, Signature};
use stress_ssh_agent::verify::{verify_signature, VerifyOutcome};

const MSG: &[u8] = b"the quick brown fox jumps over the lazy dog";

/// Encode a length-prefixed SSH string (`u32` big-endian length || bytes).
fn ssh_string(bytes: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Build an `ssh_key::Signature` from the raw signature blob and algorithm name,
/// going through the OpenSSH-encoded wire format (`string(name) || string(blob)`)
/// exactly as the agent returns it.
fn wire_signature(algorithm_name: &str, blob: &[u8]) -> Signature {
    let mut wire = Vec::new();
    ssh_string(algorithm_name.as_bytes(), &mut wire);
    ssh_string(blob, &mut wire);
    Signature::try_from(wire.as_slice()).expect("decode signature wire format")
}

// ---- ECDSA helpers + round-trip tests ------------------------------------

fn ecdsa_public_key(sec1: &[u8]) -> PublicKey {
    let key = EcdsaPublicKey::from_sec1_bytes(sec1).expect("sec1 point");
    PublicKey::from(KeyData::Ecdsa(key))
}

#[test]
fn p256_round_trip() {
    use p256::ecdsa::{signature::Signer, Signature as Sig, SigningKey, VerifyingKey};
    let sk = SigningKey::random(&mut rand::thread_rng());
    let vk = VerifyingKey::from(&sk);
    let sec1 = vk.to_encoded_point(false);
    let pubkey = ecdsa_public_key(sec1.as_bytes());

    let sig: Sig = sk.sign(MSG);
    let ssh_sig = Signature::try_from(&sig).expect("frame p256 sig");
    assert_eq!(
        verify_signature(&pubkey, MSG, &ssh_sig),
        VerifyOutcome::Verified
    );
}

#[test]
fn p384_round_trip() {
    use p384::ecdsa::{signature::Signer, Signature as Sig, SigningKey, VerifyingKey};
    let sk = SigningKey::random(&mut rand::thread_rng());
    let vk = VerifyingKey::from(&sk);
    let sec1 = vk.to_encoded_point(false);
    let pubkey = ecdsa_public_key(sec1.as_bytes());

    let sig: Sig = sk.sign(MSG);
    let ssh_sig = Signature::try_from(&sig).expect("frame p384 sig");
    assert_eq!(
        verify_signature(&pubkey, MSG, &ssh_sig),
        VerifyOutcome::Verified
    );
}

#[test]
fn p521_round_trip() {
    use p521::ecdsa::{signature::Signer, Signature as Sig, SigningKey, VerifyingKey};
    let sk = SigningKey::random(&mut rand::thread_rng());
    let vk = VerifyingKey::from(&sk);
    let sec1 = vk.to_encoded_point(false);
    let pubkey = ecdsa_public_key(sec1.as_bytes());

    let sig: Sig = sk.sign(MSG);
    let ssh_sig = Signature::try_from(&sig).expect("frame p521 sig");
    assert_eq!(
        verify_signature(&pubkey, MSG, &ssh_sig),
        VerifyOutcome::Verified
    );
}

/// P-521 regression: the original tool's hand-rolled DER broke when the DER
/// length crossed the 127-byte short-form boundary. Sign many messages so some
/// r/s pairs hit the high-bit / leading-zero edges; every one must verify.
#[test]
fn p521_regression_and_edge_cases() {
    use p521::ecdsa::{signature::Signer, Signature as Sig, SigningKey, VerifyingKey};
    let sk = SigningKey::random(&mut rand::thread_rng());
    let vk = VerifyingKey::from(&sk);
    let sec1 = vk.to_encoded_point(false);
    let pubkey = ecdsa_public_key(sec1.as_bytes());

    for i in 0..200u32 {
        let msg = format!("p521 regression message {i}");
        let sig: Sig = sk.sign(msg.as_bytes());
        let ssh_sig = Signature::try_from(&sig).expect("frame p521 sig");
        assert_eq!(
            verify_signature(&pubkey, msg.as_bytes(), &ssh_sig),
            VerifyOutcome::Verified,
            "iteration {i}"
        );
    }
}

/// Many signatures naturally produce r/s with the high bit set and with leading
/// zero bytes; all must still verify. Sweep this for each curve (the macro keeps
/// the per-curve bodies identical).
macro_rules! ecdsa_edge_case_test {
    ($name:ident, $curve:ident) => {
        #[test]
        fn $name() {
            use $curve::ecdsa::{signature::Signer, Signature as Sig, SigningKey, VerifyingKey};
            let sk = SigningKey::random(&mut rand::thread_rng());
            let vk = VerifyingKey::from(&sk);
            let sec1 = vk.to_encoded_point(false);
            let pubkey = ecdsa_public_key(sec1.as_bytes());

            for i in 0..200u32 {
                let msg = format!("{} edge case message {i}", stringify!($name));
                let sig: Sig = sk.sign(msg.as_bytes());
                let ssh_sig = Signature::try_from(&sig).expect("frame sig");
                assert_eq!(
                    verify_signature(&pubkey, msg.as_bytes(), &ssh_sig),
                    VerifyOutcome::Verified,
                    "iteration {i}"
                );
            }
        }
    };
}

ecdsa_edge_case_test!(ecdsa_p256_high_bit_and_leading_zero_edge_cases, p256);
ecdsa_edge_case_test!(ecdsa_p384_high_bit_and_leading_zero_edge_cases, p384);

// ---- Unsupported key type ------------------------------------------------

/// A DSA key is not a handled type (ECDSA / Ed25519 / RSA), so it must classify
/// as `Unsupported` rather than panic. Params are arbitrary positive mpints: the
/// match only inspects the key-data variant, not the values.
#[test]
fn dsa_key_is_unsupported() {
    use ssh_key::public::DsaPublicKey;

    let one = Mpint::from_positive_bytes(&[1]).expect("mpint");
    let dsa = DsaPublicKey {
        p: one.clone(),
        q: one.clone(),
        g: one.clone(),
        y: one,
    };
    let pubkey = PublicKey::from(KeyData::Dsa(dsa));
    let ssh_sig = wire_signature("ssh-ed25519", &[0u8; 64]);
    match verify_signature(&pubkey, MSG, &ssh_sig) {
        VerifyOutcome::Unsupported(_) => {}
        other => panic!("expected Unsupported, got {other:?}"),
    }
}

// ---- Ed25519 round-trip --------------------------------------------------

#[test]
fn ed25519_round_trip() {
    use ed25519_dalek::{Signer as _, SigningKey};
    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    let vk = sk.verifying_key();

    let pubkey = PublicKey::from(KeyData::Ed25519(ssh_key::public::Ed25519PublicKey(
        vk.to_bytes(),
    )));

    let sig = sk.sign(MSG);
    let ssh_sig = wire_signature("ssh-ed25519", &sig.to_bytes());
    assert_eq!(
        verify_signature(&pubkey, MSG, &ssh_sig),
        VerifyOutcome::Verified
    );
}

// ---- RSA helpers + round-trips -------------------------------------------

fn rsa_public_key(pk: &rsa::RsaPublicKey) -> PublicKey {
    use rsa::traits::PublicKeyParts;
    let n = Mpint::from_positive_bytes(&pk.n().to_bytes_be()).expect("n mpint");
    let e = Mpint::from_positive_bytes(&pk.e().to_bytes_be()).expect("e mpint");
    PublicKey::from(KeyData::Rsa(RsaPublicKey { e, n }))
}

fn rsa_key() -> rsa::RsaPrivateKey {
    rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).expect("generate rsa key")
}

#[test]
fn rsa_sha256_round_trip() {
    let sk = rsa_key();
    let pubkey = rsa_public_key(&sk.to_public_key());
    let signing = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(sk);
    let sig = signing.sign_with_rng(&mut rand::thread_rng(), MSG);
    let ssh_sig = wire_signature("rsa-sha2-256", &sig.to_bytes());
    assert_eq!(
        verify_signature(&pubkey, MSG, &ssh_sig),
        VerifyOutcome::Verified
    );
}

#[test]
fn rsa_sha512_round_trip() {
    let sk = rsa_key();
    let pubkey = rsa_public_key(&sk.to_public_key());
    let signing = rsa::pkcs1v15::SigningKey::<sha2::Sha512>::new(sk);
    let sig = signing.sign_with_rng(&mut rand::thread_rng(), MSG);
    let ssh_sig = wire_signature("rsa-sha2-512", &sig.to_bytes());
    assert_eq!(
        verify_signature(&pubkey, MSG, &ssh_sig),
        VerifyOutcome::Verified
    );
}

// NOTE on `ssh-rsa` / SHA-1: `ssh-key` 0.6.7 rejects `Algorithm::Rsa { hash:
// None }` in `Signature::decode`/`new` (only `Some(_)` accepted), and the agent
// client uses the same decode, so no `ssh-rsa` signature can reach
// `verify_signature` — its SHA-1 branch is kept as defensive code only.

// ---- Negative / malformed-input tests ------------------------------------

#[test]
fn flipped_byte_is_bad_signature() {
    use p256::ecdsa::{signature::Signer, Signature as Sig, SigningKey, VerifyingKey};
    let sk = SigningKey::random(&mut rand::thread_rng());
    let vk = VerifyingKey::from(&sk);
    let sec1 = vk.to_encoded_point(false);
    let pubkey = ecdsa_public_key(sec1.as_bytes());

    let sig: Sig = sk.sign(MSG);
    let ssh_sig = Signature::try_from(&sig).expect("frame p256 sig");

    // Flip a byte inside the signature blob and rebuild.
    let mut blob = ssh_sig.as_bytes().to_vec();
    let last = blob.len() - 1;
    blob[last] ^= 0xff;
    let tampered = Signature::new(
        Algorithm::Ecdsa {
            curve: ssh_key::EcdsaCurve::NistP256,
        },
        blob,
    )
    .unwrap();
    assert_eq!(
        verify_signature(&pubkey, MSG, &tampered),
        VerifyOutcome::BadSignature
    );
}

#[test]
fn empty_signature_blob_does_not_panic() {
    // `rsa-sha2-256` accepts an empty blob through `Signature::decode`; verify
    // must reject it as BadSignature without panicking.
    let sk = rsa_key();
    let pubkey = rsa_public_key(&sk.to_public_key());
    let ssh_sig = wire_signature("rsa-sha2-256", &[]);
    assert_eq!(
        verify_signature(&pubkey, MSG, &ssh_sig),
        VerifyOutcome::BadSignature
    );
}

#[test]
fn truncated_signature_blob_does_not_panic() {
    let sk = rsa_key();
    let pubkey = rsa_public_key(&sk.to_public_key());
    let signing = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(sk);
    let sig = signing.sign_with_rng(&mut rand::thread_rng(), MSG);
    let mut blob = sig.to_bytes().to_vec();
    blob.truncate(blob.len() / 2);
    let ssh_sig = wire_signature("rsa-sha2-256", &blob);
    assert_eq!(
        verify_signature(&pubkey, MSG, &ssh_sig),
        VerifyOutcome::BadSignature
    );
}

#[test]
fn wrong_key_is_bad_signature() {
    use ed25519_dalek::{Signer as _, SigningKey};
    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    let other = SigningKey::generate(&mut rand::rngs::OsRng);
    let wrong_vk = other.verifying_key();

    let pubkey = PublicKey::from(KeyData::Ed25519(ssh_key::public::Ed25519PublicKey(
        wrong_vk.to_bytes(),
    )));

    let sig = sk.sign(MSG);
    let ssh_sig = wire_signature("ssh-ed25519", &sig.to_bytes());
    assert_eq!(
        verify_signature(&pubkey, MSG, &ssh_sig),
        VerifyOutcome::BadSignature
    );
}
