//! The policy a request is checked against: a verified snapshot compiled for the hot path together with the
//! effective settings (local configuration merged with the signed server settings). Built off the request path and
//! swapped in as one value, so a request takes one `Arc` and uses it for its whole life.
use crate::backend::VerifiedSnapshot;
use crate::config::Config;
use crate::proxy::browser_ca;
use contract::{Snapshot, UpdatePolicy};
use engine::{effective_config_hash, merge_settings, Effective, MergeError, PatternError, Policy};
use std::path::PathBuf;

const BUILTIN_RULES: &str = include_str!("builtin_rules.json");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyOrigin {
    /// Rules shipped in the binary, used until a signed snapshot is available.
    Builtin,
    /// The last good snapshot read back from the data directory.
    Cache,
    LocalFile,
    Backend,
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyBuildError {
    #[error(transparent)]
    Settings(#[from] MergeError),
    #[error(transparent)]
    Pattern(#[from] PatternError),
    #[error("the effective settings cannot be fingerprinted: {0}")]
    Fingerprint(serde_json::Error),
    #[error("the built-in rules are unreadable: {0}")]
    Builtin(serde_json::Error),
}

pub struct ActivePolicy {
    pub policy: Policy,
    pub effective: Effective,
    /// Sent with usage so the backend can detect clients running a different configuration than it published.
    pub config_hash: String,
    pub version: u64,
    /// SHA-256 of the signed payload, used as the ETag. `None` for the built-in rules.
    pub payload_sha256: Option<String>,
    /// `None` for the built-in rules, which do not expire.
    pub expires_at: Option<u64>,
    pub origin: PolicyOrigin,
    /// The person asked for debug logging but the signed settings do not allow it.
    pub debug_forbidden: bool,
    /// The administrator's update choices, read by the update loop on every check.
    pub update: UpdatePolicy,
}

impl ActivePolicy {
    /// Past `expires_at`; what that means for traffic is the `policy_expired` failure mode.
    pub fn is_expired(&self, now: u64) -> bool {
        self.expires_at.is_some_and(|expiry| now >= expiry)
    }
}

pub(crate) fn builtin_snapshot() -> Result<Snapshot, PolicyBuildError> {
    serde_json::from_str(BUILTIN_RULES).map_err(PolicyBuildError::Builtin)
}

/// Compiles snapshots the way this installation is configured.
pub struct PolicyBuilder {
    config: std::sync::Arc<Config>,
    ca_directory: PathBuf,
}

impl PolicyBuilder {
    pub fn new(config: std::sync::Arc<Config>, ca_directory: PathBuf) -> Self {
        Self {
            config,
            ca_directory,
        }
    }

    pub fn build(
        &self,
        verified: &VerifiedSnapshot,
        origin: PolicyOrigin,
    ) -> Result<ActivePolicy, PolicyBuildError> {
        self.compile(
            &verified.snapshot,
            origin,
            Some(verified.mark.payload_sha256.clone()),
            Some(verified.snapshot.expires_at),
        )
    }

    pub fn builtin(&self) -> Result<ActivePolicy, PolicyBuildError> {
        self.compile(&builtin_snapshot()?, PolicyOrigin::Builtin, None, None)
    }

    pub(crate) fn compile(
        &self,
        snapshot: &Snapshot,
        origin: PolicyOrigin,
        payload_sha256: Option<String>,
        expires_at: Option<u64>,
    ) -> Result<ActivePolicy, PolicyBuildError> {
        let effective = merge_settings(&self.config.local_settings(), &snapshot.settings)?;
        let ca_on_disk = browser_ca::domains_on_disk(&self.ca_directory);
        let policy = Policy::build(snapshot, &effective.deny, &ca_on_disk)?;
        let config_hash =
            effective_config_hash(&effective).map_err(PolicyBuildError::Fingerprint)?;
        let debug_forbidden = self.config.logging.debug && !effective.debug;
        Ok(ActivePolicy {
            policy,
            effective,
            config_hash,
            version: snapshot.version,
            payload_sha256,
            expires_at,
            origin,
            debug_forbidden,
            update: snapshot.settings.update.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine::validate;

    #[test]
    fn the_builtin_rules_are_a_valid_snapshot_that_blocks_the_core_pii() {
        let snapshot: Snapshot = serde_json::from_str(BUILTIN_RULES).unwrap();
        validate(&snapshot).unwrap();
        let ids: Vec<&str> = snapshot.pii.iter().map(|rule| rule.id.as_str()).collect();
        for core in ["card", "ssn", "iban", "aws_key", "api_key"] {
            assert!(ids.contains(&core), "{core}");
        }
    }

    #[test]
    fn the_builtin_policy_builds_with_default_configuration() {
        let builder = PolicyBuilder::new(std::sync::Arc::new(Config::default()), PathBuf::new());
        let active = builder.builtin().unwrap();
        assert_eq!(active.origin, PolicyOrigin::Builtin);
        assert!(active.payload_sha256.is_none() && active.expires_at.is_none());
        assert!(!active.is_expired(u64::MAX));
    }
}
