use serde::{Deserialize, Serialize};

/// A payload string plus the signatures over it. The payload stays a string so the signed bytes are never re-encoded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct SignedEnvelope {
    pub payload: String,
    pub signatures: Vec<SignatureEntry>,
    /// Hosted mode: a root-signed certificate for the key that signed `payload`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation: Option<Delegation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct SignatureEntry {
    pub key_id: String,
    /// Base64 Ed25519 signature.
    pub signature: String,
}

/// Lets an offline root key authorise a short-lived signing key without the client being re-pinned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct Delegation {
    pub key_id: String,
    /// Base64 Ed25519 public key being delegated.
    pub public_key: String,
    pub not_before: u64,
    pub not_after: u64,
    /// When set, the delegated key may only sign snapshots for this audience.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    pub root_key_id: String,
    /// Base64 root signature over the canonical delegation fields.
    pub signature: String,
}
