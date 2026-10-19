use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const MANIFEST_SCHEMA: u8 = 1;

/// A raw binary for one target. Archives are never referenced: the updater parses no container formats.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub url: String,
    /// Lower-case hex SHA-256 of the binary.
    pub sha256: String,
    pub size: u64,
}

/// The payload of a signed update manifest.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct UpdateManifest {
    pub schema: u8,
    pub channel: String,
    /// Semantic version of the release.
    pub version: String,
    pub published_at: u64,
    pub expires_at: u64,
    /// Versions below this must update before anything else.
    #[serde(default)]
    pub min_supported: Option<String>,
    /// Distinct pinned update keys that must have signed this manifest.
    pub threshold: u8,
    /// Keyed by `<os>-<arch>`, e.g. `macos-aarch64`, `windows-x86_64`, `linux-x86_64`.
    pub artifacts: BTreeMap<String, Artifact>,
    #[serde(default)]
    pub notes_url: Option<String>,
    #[serde(default)]
    pub revoked_key_ids: Vec<String>,
}
