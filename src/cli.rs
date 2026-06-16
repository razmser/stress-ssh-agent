//! Command-line arguments and identity selection.
//!
//! The selection logic is kept free of live I/O so it can be unit-tested
//! without a running agent: enumeration against a live `Client` happens in
//! `main`, which converts the borrowed `ssh_agent_client_rs::Identity` values
//! into the owned [`IdentityInfo`] form this module operates on.

use clap::Parser;
use ssh_key::{HashAlg, PublicKey};

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

/// Owned, agent-independent view of one identity returned by the agent.
///
/// In `main` this is built from `ssh_agent_client_rs::Identity`; in tests it is
/// constructed directly so the selection logic can be exercised without a live
/// agent.
#[derive(Debug, Clone)]
pub struct IdentityInfo {
    /// Underlying public key (for a certificate identity, the certified key).
    pub public_key: PublicKey,
    /// Whether the agent returned this as a certificate (unsupported here).
    pub is_certificate: bool,
}

impl IdentityInfo {
    /// Construct from a plain public key.
    pub fn from_public_key(public_key: PublicKey) -> Self {
        Self {
            public_key,
            is_certificate: false,
        }
    }

    /// SHA256 fingerprint string (e.g. `SHA256:...`).
    pub fn fingerprint(&self) -> String {
        self.public_key.fingerprint(HashAlg::default()).to_string()
    }

    /// Algorithm name (e.g. `ssh-ed25519`).
    pub fn algorithm(&self) -> String {
        self.public_key.algorithm().to_string()
    }

    /// Key comment, possibly empty.
    pub fn comment(&self) -> &str {
        self.public_key.comment()
    }
}

/// Whether an identity can be stress-tested, or why it is skipped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Classification {
    /// Usable: ECDSA P-256/384/521, Ed25519, or RSA.
    Supported,
    /// Not usable; the string explains why (cert / unknown key type).
    Skipped(String),
}

/// Classify a single identity as supported or skipped.
///
/// Certificates are skipped (the agent client cannot sign for them here), as
/// are key types we cannot verify. RSA public keys are treated as supported:
/// the verify path handles RSA, and the runtime `ssh-rsa`/SHA-1 quirk is a
/// signing concern, not a classification one.
pub fn classify(info: &IdentityInfo) -> Classification {
    use ssh_key::public::KeyData;

    if info.is_certificate {
        return Classification::Skipped("certificate identity".to_string());
    }
    match info.public_key.key_data() {
        KeyData::Ecdsa(_) | KeyData::Ed25519(_) | KeyData::Rsa(_) => Classification::Supported,
        other => Classification::Skipped(format!("unsupported key type: {}", other.algorithm())),
    }
}

/// Error returned when no key can be selected for a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectError {
    /// `--key` was given but matched no supported identity.
    NoMatch(String),
    /// The agent exposed no supported identity at all.
    EmptySupported,
}

impl std::fmt::Display for SelectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SelectError::NoMatch(q) => {
                write!(f, "no supported identity matches --key {q:?}")
            }
            SelectError::EmptySupported => {
                write!(f, "no supported identities found in the agent")
            }
        }
    }
}

impl std::error::Error for SelectError {}

/// Filter `infos` down to the supported identities, preserving order.
pub fn supported(infos: &[IdentityInfo]) -> Vec<IdentityInfo> {
    infos
        .iter()
        .filter(|i| classify(i) == Classification::Supported)
        .cloned()
        .collect()
}

/// Choose the public keys to stress-test from the full identity list.
///
/// - `--key <q>`: the single supported identity whose SHA256 fingerprint equals
///   `q` or whose comment contains `q` (substring). No match → [`SelectError::NoMatch`].
/// - `--all`: every supported identity.
/// - neither: the first supported identity only (today's behavior).
///
/// An empty supported set is always [`SelectError::EmptySupported`].
pub fn select(infos: &[IdentityInfo], args: &Args) -> Result<Vec<PublicKey>, SelectError> {
    let supported = supported(infos);
    if supported.is_empty() {
        return Err(SelectError::EmptySupported);
    }

    if let Some(query) = &args.key {
        let matched = supported
            .iter()
            .find(|i| &i.fingerprint() == query || i.comment().contains(query.as_str()))
            .ok_or_else(|| SelectError::NoMatch(query.clone()))?;
        return Ok(vec![matched.public_key.clone()]);
    }

    if args.all {
        return Ok(supported.into_iter().map(|i| i.public_key).collect());
    }

    Ok(vec![supported[0].public_key.clone()])
}

/// Render the identity list for `--list`: one line per identity with algorithm,
/// fingerprint, comment, and supported/skip status.
pub fn format_list(infos: &[IdentityInfo]) -> String {
    let mut out = String::new();
    for info in infos {
        let status = match classify(info) {
            Classification::Supported => "supported".to_string(),
            Classification::Skipped(reason) => format!("skipped: {reason}"),
        };
        let comment = info.comment();
        let comment = if comment.is_empty() {
            "(no comment)"
        } else {
            comment
        };
        out.push_str(&format!(
            "{}  {}  {}  [{}]\n",
            info.algorithm(),
            info.fingerprint(),
            comment,
            status
        ));
    }
    out
}
