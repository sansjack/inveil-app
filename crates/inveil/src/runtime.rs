//! Everything the proxy and the setup commands share: where state lives, which keys are trusted, and which policy
//! is in force at startup. No network happens here.
use crate::backend::{
    stored_org_id, BackendError, Credentials, Expiry, HttpPolicySource, PolicyUpdater,
    SnapshotStore,
};
use crate::config::{AuthMode, Config, Mode};
use crate::error::AppError;
use crate::platform;
use crate::policy::{builtin_snapshot, ActivePolicy, PolicyBuilder, PolicyOrigin};
use crate::proxy::browser_ca;
use crate::util::unix_seconds;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

/// How long startup waits for the first fetch from the backend before serving with what it already has.
const STARTUP_FETCH_TIMEOUT: Duration = Duration::from_secs(10);

pub struct Runtime {
    pub config: Arc<Config>,
    pub data_dir: PathBuf,
    pub store: Arc<SnapshotStore>,
}

impl Runtime {
    pub fn new(config: Arc<Config>) -> Result<Self, AppError> {
        let data_dir = match &config.data_dir {
            Some(directory) => directory.clone(),
            None => platform::data_dir()?,
        };
        let audience = match config.auth.mode {
            AuthMode::Enrolled if config.backend.url.is_some() => stored_org_id(&config)?,
            _ => None,
        };
        let use_keychain = config.state_keychain;
        let store = Arc::new(SnapshotStore::open(
            data_dir.clone(),
            config.trust()?,
            audience,
            use_keychain,
        ));
        Ok(Self {
            config,
            data_dir,
            store,
        })
    }

    pub fn ca_directory(&self) -> PathBuf {
        browser_ca::ca_directory(&self.data_dir)
    }

    pub fn policy_builder(&self) -> PolicyBuilder {
        PolicyBuilder::new(self.config.clone(), self.ca_directory())
    }

    /// The signed file named by `rules_file`, else the last good snapshot from the backend. When trusted keys are
    /// configured the built-in rules are never a fallback for a cache that is missing, unreadable or unverifiable:
    /// that is an error. The only exception is a first start, before any signed snapshot was ever accepted.
    pub fn initial_policy(&self) -> Result<ActivePolicy, AppError> {
        let builder = self.policy_builder();
        let now = unix_seconds();
        if let Some(path) = &self.config.rules_file {
            let raw = std::fs::read_to_string(path).map_err(|source| AppError::ReadFile {
                path: path.clone(),
                source,
            })?;
            let verified = self.store.verify(&raw, now, Expiry::Allow)?;
            self.store.commit(&verified)?;
            return Ok(builder.build(&verified, PolicyOrigin::LocalFile)?);
        }
        if self.config.backend.pinned_keys.is_empty() && self.config.backend.root_keys.is_empty() {
            return Ok(builder.builtin()?);
        }
        match self.store.load_cached(now) {
            Ok(Some(cached)) => Ok(builder.build(&cached, PolicyOrigin::Cache)?),
            Ok(None) if self.config.mode == Mode::Managed => {
                tracing::warn!(
                    "no signed rules have been received yet; until they arrive the policy counts as expired and the policy_expired failure mode applies"
                );
                Ok(builder.compile(&builtin_snapshot()?, PolicyOrigin::Builtin, None, Some(0))?)
            }
            Ok(None) => {
                tracing::warn!(
                    "no signed rules have been received yet; running the built-in rules until the first snapshot arrives"
                );
                Ok(builder.builtin()?)
            }
            Err(error) => {
                tracing::error!("refusing to start without trustworthy rules: {error}");
                Err(error.into())
            }
        }
    }

    pub fn credentials(&self) -> Result<Arc<Credentials>, BackendError> {
        Credentials::from_config(&self.config).map(Arc::new)
    }

    /// One fetch from the backend, bounded by `STARTUP_FETCH_TIMEOUT`. A refusal by the policy is an error;
    /// anything else (backend down, snapshot unusable) is logged and the policy in `active` stays.
    pub async fn refresh_from_backend(
        &self,
        active: &Arc<watch::Sender<Arc<ActivePolicy>>>,
        credentials: Arc<Credentials>,
    ) -> Result<PolicyUpdater<HttpPolicySource>, AppError> {
        let updater = PolicyUpdater::new(
            HttpPolicySource::new(&self.config, credentials)?,
            self.store.clone(),
            self.policy_builder(),
            active.clone(),
            PolicyOrigin::Backend,
        );
        match tokio::time::timeout(STARTUP_FETCH_TIMEOUT, updater.refresh()).await {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                if let Some(reason) = error.refusal() {
                    return Err(AppError::Refused(reason));
                }
                tracing::warn!("could not refresh the rules at startup: {error}");
            }
            Err(_) => {
                tracing::warn!("the backend did not answer in time; using the rules already held")
            }
        }
        Ok(updater)
    }

    /// The freshest policy available right now, for commands that need to know the signed domain list.
    pub async fn latest_policy(&self) -> Result<Arc<ActivePolicy>, AppError> {
        let initial = self.initial_policy()?;
        let online = !initial.effective.offline
            && self.config.rules_file.is_none()
            && self.config.backend.url.is_some();
        let (sender, receiver) = watch::channel(Arc::new(initial));
        let sender = Arc::new(sender);
        if online {
            self.refresh_from_backend(&sender, self.credentials()?)
                .await?;
        }
        let latest = receiver.borrow().clone();
        Ok(latest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::SnapshotError;
    use crate::config::{BackendConfig, PinnedKeyConfig};
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use contract::SignedEnvelope;
    use engine::signing::{public_key_of, sign_payload, Role};
    use ring::rand::SystemRandom;
    use ring::signature::Ed25519KeyPair;

    const ONE_HOUR: u64 = 3600;

    struct Installation {
        directory: tempfile::TempDir,
        pkcs8: Vec<u8>,
        runtime: Runtime,
    }

    fn installation(mode: Mode) -> Installation {
        let directory = tempfile::tempdir().unwrap();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .unwrap()
            .as_ref()
            .to_vec();
        let config = Config {
            mode,
            state_keychain: false,
            data_dir: Some(directory.path().to_path_buf()),
            backend: BackendConfig {
                pinned_keys: vec![PinnedKeyConfig {
                    key_id: "policy".into(),
                    public_key: STANDARD.encode(public_key_of(&pkcs8).unwrap()),
                }],
                ..BackendConfig::default()
            },
            ..Config::default()
        };
        let runtime = Runtime::new(Arc::new(config)).unwrap();
        Installation {
            directory,
            pkcs8,
            runtime,
        }
    }

    impl Installation {
        fn signed(&self, version: u64) -> String {
            let now = unix_seconds();
            let mut snapshot = builtin_snapshot().unwrap();
            snapshot.version = version;
            snapshot.issued_at = now - 10;
            snapshot.expires_at = now + ONE_HOUR;
            let payload = serde_json::to_string(&snapshot).unwrap();
            let signature = sign_payload(Role::Policy, "policy", &self.pkcs8, &payload).unwrap();
            serde_json::to_string(&SignedEnvelope {
                payload,
                signatures: vec![signature],
                delegation: None,
            })
            .unwrap()
        }

        fn accept(&self, version: u64) {
            let verified = self
                .runtime
                .store
                .verify(&self.signed(version), unix_seconds(), Expiry::Reject)
                .unwrap();
            self.runtime.store.commit(&verified).unwrap();
        }

        fn cache(&self) -> std::path::PathBuf {
            self.directory.path().join("rules.cache.json")
        }
    }

    #[test]
    fn the_first_start_of_a_standalone_install_runs_the_builtin_rules() {
        let installation = installation(Mode::Standalone);
        let policy = installation.runtime.initial_policy().unwrap();
        assert_eq!(policy.origin, PolicyOrigin::Builtin);
        assert!(!policy.is_expired(unix_seconds()));
    }

    #[test]
    fn the_first_start_of_a_managed_install_counts_as_expired_until_rules_arrive() {
        let installation = installation(Mode::Managed);
        let policy = installation.runtime.initial_policy().unwrap();
        assert_eq!(policy.origin, PolicyOrigin::Builtin);
        assert!(policy.is_expired(unix_seconds()));
    }

    #[test]
    fn an_accepted_snapshot_is_used_from_the_cache() {
        let installation = installation(Mode::Managed);
        installation.accept(3);
        let policy = installation.runtime.initial_policy().unwrap();
        assert_eq!(policy.origin, PolicyOrigin::Cache);
        assert_eq!(policy.version, 3);
    }

    #[test]
    fn a_deleted_cache_never_falls_back_to_the_builtin_rules() {
        for mode in [Mode::Standalone, Mode::Managed] {
            let installation = installation(mode);
            installation.accept(3);
            std::fs::remove_file(installation.cache()).unwrap();
            assert!(matches!(
                installation.runtime.initial_policy(),
                Err(AppError::Snapshot(SnapshotError::CacheMissing { .. }))
            ));
        }
    }

    #[test]
    fn a_corrupt_or_rolled_back_cache_never_falls_back_to_the_builtin_rules() {
        for mode in [Mode::Standalone, Mode::Managed] {
            let installation = installation(mode);
            installation.accept(5);
            std::fs::write(installation.cache(), "not an envelope").unwrap();
            assert!(installation.runtime.initial_policy().is_err());

            std::fs::write(installation.cache(), installation.signed(4)).unwrap();
            assert!(matches!(
                installation.runtime.initial_policy(),
                Err(AppError::Snapshot(SnapshotError::Stale(_)))
            ));
        }
    }

    #[test]
    fn a_damaged_trust_state_stops_the_start_with_a_way_out() {
        let installation = installation(Mode::Standalone);
        installation.accept(3);
        std::fs::write(
            installation.directory.path().join("rules.trust-state.json"),
            "{ torn",
        )
        .unwrap();

        let Err(error) = installation.runtime.initial_policy() else {
            panic!("a damaged trust state must stop the start");
        };

        assert!(error.to_string().contains("delete"), "{error}");
    }

    #[test]
    fn without_pinned_keys_the_builtin_rules_are_the_policy() {
        let directory = tempfile::tempdir().unwrap();
        let config = Config {
            data_dir: Some(directory.path().to_path_buf()),
            ..Config::default()
        };
        let runtime = Runtime::new(Arc::new(config)).unwrap();
        assert_eq!(
            runtime.initial_policy().unwrap().origin,
            PolicyOrigin::Builtin
        );
    }
}
