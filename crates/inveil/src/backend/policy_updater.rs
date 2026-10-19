use super::snapshot::Expiry;
use super::{BackendError, Fetched, PolicySource, SnapshotError, SnapshotStore};
use crate::error::EXIT_POLICY_REFUSED;
use crate::logging;
use crate::policy::{ActivePolicy, PolicyBuildError, PolicyBuilder, PolicyOrigin};
use crate::util::unix_seconds;
use engine::MergeError;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

const MIN_POLL_SECONDS: u64 = 1;

#[derive(Debug, thiserror::Error)]
pub enum RefreshError {
    #[error(transparent)]
    Fetch(#[from] BackendError),
    #[error(transparent)]
    Snapshot(#[from] SnapshotError),
    #[error(transparent)]
    Build(#[from] PolicyBuildError),
    #[error("the backend says the rules are unchanged, but the rules held have expired; a newly signed snapshot is needed")]
    ExpiredNotModified,
}

impl RefreshError {
    /// Set when the policy forbids this device's configuration or version, as opposed to the snapshot being unusable.
    pub fn refusal(&self) -> Option<String> {
        match self {
            Self::Build(PolicyBuildError::Settings(
                reason @ (MergeError::UpstreamNotAllowed { .. } | MergeError::ClientTooOld { .. }),
            )) => Some(reason.to_string()),
            _ => None,
        }
    }
}

/// Fetches signed snapshots from a `PolicySource` and swaps the verified result into the live policy. A snapshot
/// that fails any check is ignored and the previous policy keeps running.
pub struct PolicyUpdater<S: PolicySource> {
    source: S,
    store: Arc<SnapshotStore>,
    builder: PolicyBuilder,
    active: Arc<watch::Sender<Arc<ActivePolicy>>>,
    origin: PolicyOrigin,
}

impl<S: PolicySource + 'static> PolicyUpdater<S> {
    pub fn new(
        source: S,
        store: Arc<SnapshotStore>,
        builder: PolicyBuilder,
        active: Arc<watch::Sender<Arc<ActivePolicy>>>,
        origin: PolicyOrigin,
    ) -> Self {
        Self {
            source,
            store,
            builder,
            active,
            origin,
        }
    }

    /// Returns true when a new snapshot was applied.
    pub async fn refresh(&self) -> Result<bool, RefreshError> {
        let held = self.active.borrow().clone();
        let now = unix_seconds();
        let held_expired = held.is_expired(now);
        let etag = held.payload_sha256.as_deref().filter(|_| !held_expired);
        let raw = match self.source.fetch(etag).await? {
            Fetched::NotModified if held_expired => return Err(RefreshError::ExpiredNotModified),
            Fetched::NotModified => return Ok(false),
            Fetched::Envelope(raw) => raw,
        };
        let verified = self.store.verify(&raw, now, Expiry::Reject)?;
        if held.payload_sha256.as_deref() == Some(verified.mark.payload_sha256.as_str()) {
            return Ok(false);
        }
        let next = self.builder.build(&verified, self.origin)?;
        self.store.commit(&verified)?;
        tracing::info!(
            "rules updated: version {} ({} rules)",
            next.version,
            verified.snapshot.pii.len()
        );
        logging::forbid_debug(next.debug_forbidden);
        self.active.send_replace(Arc::new(next));
        Ok(true)
    }

    fn poll_interval(&self) -> Duration {
        Duration::from_secs(
            self.active
                .borrow()
                .effective
                .poll_seconds
                .max(MIN_POLL_SECONDS),
        )
    }

    /// Checks again every poll interval for as long as the process runs.
    pub fn spawn(self) {
        tokio::spawn(async move {
            let mut last_error: Option<String> = None;
            loop {
                tokio::time::sleep(self.poll_interval()).await;
                match self.refresh().await {
                    Ok(_) => last_error = None,
                    Err(error) => {
                        if let Some(reason) = error.refusal() {
                            tracing::error!("the policy no longer permits this client: {reason}");
                            std::process::exit(i32::from(EXIT_POLICY_REFUSED));
                        }
                        let reason = error.to_string();
                        if last_error.as_deref() != Some(reason.as_str()) {
                            tracing::warn!("rules not refreshed: {reason}");
                            last_error = Some(reason);
                        }
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::snapshot::tests::{expired_snapshot, snapshot, TestKey};
    use crate::config::{Config, PinnedKeyConfig};
    use crate::policy::builtin_snapshot;
    use crate::trust_state::StateStore;
    use std::sync::Mutex;

    /// Answers each fetch from a script: `Some(envelope)` or `None` for a 304. Remembers the etags it was sent.
    struct ScriptedSource {
        script: Mutex<Vec<Option<String>>>,
        etags: Mutex<Vec<Option<String>>>,
    }

    impl ScriptedSource {
        fn new(script: Vec<Option<String>>) -> Self {
            Self {
                script: Mutex::new(script),
                etags: Mutex::default(),
            }
        }
    }

    impl PolicySource for ScriptedSource {
        async fn fetch(&self, etag: Option<&str>) -> Result<Fetched, BackendError> {
            self.etags.lock().unwrap().push(etag.map(String::from));
            let mut script = self.script.lock().unwrap();
            if script.is_empty() {
                return Ok(Fetched::NotModified);
            }
            Ok(script
                .remove(0)
                .map_or(Fetched::NotModified, Fetched::Envelope))
        }
    }

    fn updater(
        key: &TestKey,
        script: Vec<String>,
    ) -> (
        tempfile::TempDir,
        PolicyUpdater<ScriptedSource>,
        watch::Receiver<Arc<ActivePolicy>>,
    ) {
        let script = script.into_iter().map(Some).collect();
        updater_with_script(key, script)
    }

    fn updater_with_script(
        key: &TestKey,
        script: Vec<Option<String>>,
    ) -> (
        tempfile::TempDir,
        PolicyUpdater<ScriptedSource>,
        watch::Receiver<Arc<ActivePolicy>>,
    ) {
        let directory = tempfile::tempdir().unwrap();
        let mut config = Config::default();
        config.backend.pinned_keys = vec![PinnedKeyConfig {
            key_id: "k1".into(),
            public_key: key.public_base64(),
        }];
        let config = Arc::new(config);
        let store = Arc::new(SnapshotStore::new(
            directory.path().to_path_buf(),
            config.trust().unwrap(),
            None,
            StateStore::new(directory.path().join("state.json"), None),
        ));
        let builder = PolicyBuilder::new(config, directory.path().join("ca"));
        let (sender, receiver) = watch::channel(Arc::new(builder.builtin().unwrap()));
        let updater = PolicyUpdater::new(
            ScriptedSource::new(script),
            store,
            builder,
            Arc::new(sender),
            PolicyOrigin::Backend,
        );
        (directory, updater, receiver)
    }

    #[tokio::test]
    async fn a_newer_signed_snapshot_replaces_the_live_policy() {
        let key = TestKey::generate("k1");
        let (_directory, updater, live) = updater(&key, vec![key.sign(&snapshot(2))]);
        assert!(updater.refresh().await.unwrap());
        assert_eq!(live.borrow().version, 2);
    }

    #[tokio::test]
    async fn unsigned_rolled_back_and_expired_snapshots_are_ignored() {
        let key = TestKey::generate("k1");
        let stranger = TestKey::generate("k1");
        let script = vec![
            key.sign(&snapshot(5)),
            stranger.sign(&snapshot(6)),
            key.sign(&snapshot(4)),
            key.sign(&expired_snapshot(7)),
            "garbage".into(),
        ];
        let (_directory, updater, live) = updater(&key, script);
        assert!(updater.refresh().await.unwrap());
        for _ in 0..4 {
            assert!(updater.refresh().await.is_err());
            assert_eq!(live.borrow().version, 5, "the held policy keeps running");
        }
    }

    #[tokio::test]
    async fn the_same_snapshot_again_changes_nothing() {
        let key = TestKey::generate("k1");
        let signed = key.sign(&snapshot(2));
        let (_directory, updater, _live) = updater(&key, vec![signed.clone(), signed]);
        assert!(updater.refresh().await.unwrap());
        assert!(!updater.refresh().await.unwrap());
    }

    #[tokio::test]
    async fn a_bare_304_is_fine_while_the_held_rules_are_current() {
        let key = TestKey::generate("k1");
        let (_directory, updater, _live) =
            updater_with_script(&key, vec![Some(key.sign(&snapshot(2))), None]);
        assert!(updater.refresh().await.unwrap());
        assert!(!updater.refresh().await.unwrap());
    }

    #[tokio::test]
    async fn a_bare_304_does_not_keep_expired_rules_alive() {
        let key = TestKey::generate("k1");
        let (_directory, updater, _live) =
            updater_with_script(&key, vec![Some(key.sign(&snapshot(2))), None]);
        assert!(updater.refresh().await.unwrap());
        let expired = updater
            .builder
            .compile(
                &builtin_snapshot().unwrap(),
                PolicyOrigin::Backend,
                Some("held-hash".into()),
                Some(1),
            )
            .unwrap();
        updater.active.send_replace(Arc::new(expired));

        let error = updater.refresh().await.unwrap_err();

        assert!(matches!(error, RefreshError::ExpiredNotModified));
        let etags = updater.source.etags.lock().unwrap();
        assert_eq!(etags[1], None, "an expired policy must not ask for a 304");
    }
}
