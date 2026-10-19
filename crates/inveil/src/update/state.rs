//! What the updater remembers between runs: the newest release seen per channel and every key ever revoked (by id and by public key). It is
//! what makes replaying an old but validly signed manifest fail, and it is kept in a `StateStore`, which refuses a
//! file that was deleted or rolled back.
use engine::signing::PublicKeyBytes;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct UpdateState {
    pub releases: BTreeMap<String, SeenRelease>,
    pub revoked_key_ids: BTreeSet<String>,
    pub revoked_public_keys: BTreeSet<PublicKeyBytes>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SeenRelease {
    pub version: String,
    pub artifact_sha256: String,
}
