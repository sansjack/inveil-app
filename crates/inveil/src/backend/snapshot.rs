//! Verification and persistence of signed rules snapshots. The signature is checked before anything is parsed; the
//! persisted high-water mark and revoked key ids mean an older (but validly signed) snapshot can never be swapped in
//! later, whether it arrives from the network or is planted in the cache file.
use crate::trust_state::{StateError, StateStore};
use crate::util::write_atomically;
use contract::Snapshot;
use engine::freshness::{check, Candidate, HighWaterMark, LocalAnchors, Rejection, Verdict};
use engine::signing::{PublicKeyBytes, Trust, Verified};
use engine::validate::POLICY_SIGNATURE_THRESHOLD;
use engine::{verify_snapshot, verify_snapshot_as_issued};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::PathBuf;

const CACHE_FILE: &str = "rules.cache.json";
pub const STATE_FILE: &str = "rules.trust-state.json";

#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    #[error("snapshot rejected: {0}")]
    Invalid(#[from] engine::SnapshotError),
    #[error("snapshot not accepted: {0}")]
    Stale(#[from] Rejection),
    #[error(transparent)]
    State(#[from] StateError),
    #[error("cannot store the rules snapshot in {path}: {source}")]
    Storage {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("a signed snapshot was accepted before but the cache {path} is gone; refusing to fall back to the built-in rules. Fetch the rules again from the backend, or delete the trust state to start afresh")]
    CacheMissing { path: PathBuf },
}

/// Whether a snapshot past its `expires_at` may still be used.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Expiry {
    /// A snapshot just fetched must be fresh.
    Reject,
    /// The cached last-good snapshot may have expired while the backend was unreachable; `fail_closed_on_expiry`
    /// decides what that means.
    Allow,
}

#[derive(Debug, Clone)]
pub struct VerifiedSnapshot {
    pub snapshot: Snapshot,
    pub mark: HighWaterMark,
    /// The envelope exactly as received, so the cache is byte for byte what was signed.
    pub raw: String,
}

/// What survives restarts: the newest snapshot accepted and every key a snapshot has revoked, by id and by public key.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct PolicyState {
    mark: Option<HighWaterMark>,
    revoked_key_ids: BTreeSet<String>,
    revoked_public_keys: BTreeSet<PublicKeyBytes>,
}

/// A delegated key's certificate may have lapsed since the cached snapshot was accepted, so the window is judged at
/// the snapshot's `issued_at`, but only for the exact content the high-water mark records: a key that has lapsed (or
/// leaked) cannot sign anything new into the cache file. Anything else must verify as of `now`.
fn verify_cached(
    trust: &Trust,
    now: u64,
    raw: &str,
    mark: Option<&HighWaterMark>,
) -> Result<Verified<Snapshot>, engine::SnapshotError> {
    let as_issued = verify_snapshot_as_issued(trust, raw)?;
    let accepted_before = mark.is_some_and(|mark| mark.payload_sha256 == as_issued.payload_sha256);
    match accepted_before {
        true => Ok(as_issued),
        false => verify_snapshot(trust, now, raw),
    }
}

pub struct SnapshotStore {
    directory: PathBuf,
    trust: Trust,
    /// The organisation recorded at enrollment; `None` when the client is not enrolled in one.
    audience: Option<String>,
    state: StateStore,
}

impl SnapshotStore {
    /// The store for the installation whose files live in `directory`.
    pub fn open(
        directory: PathBuf,
        trust: Trust,
        audience: Option<String>,
        use_keychain: bool,
    ) -> Self {
        let state = StateStore::open(&directory, STATE_FILE, use_keychain);
        Self::new(directory, trust, audience, state)
    }

    pub fn new(
        directory: PathBuf,
        trust: Trust,
        audience: Option<String>,
        state: StateStore,
    ) -> Self {
        Self {
            directory,
            trust,
            audience,
            state,
        }
    }

    /// Checks the signature, then the snapshot's shape, then that it does not roll back what was accepted before,
    /// belongs to this client's organisation and revokes keys only the way the local threshold allows.
    pub fn verify(
        &self,
        raw: &str,
        now: u64,
        expiry: Expiry,
    ) -> Result<VerifiedSnapshot, SnapshotError> {
        let stored = self.state.load::<PolicyState>()?.state;
        let trust = self
            .trust
            .without_revoked(&stored.revoked_key_ids, &stored.revoked_public_keys);
        let verified = match expiry {
            Expiry::Reject => verify_snapshot(&trust, now, raw)?,
            Expiry::Allow => verify_cached(&trust, now, raw, stored.mark.as_ref())?,
        };
        let candidate = Candidate::from_snapshot(&verified);
        let checked_at = match expiry {
            Expiry::Reject => now,
            Expiry::Allow => verified.value.issued_at,
        };
        let pinned_key_ids: Vec<String> = trust
            .keys
            .iter()
            .chain(&trust.roots)
            .map(|key| key.key_id.clone())
            .collect();
        let anchors = LocalAnchors {
            audience: self.audience.as_deref(),
            pinned_key_ids: &pinned_key_ids,
            required_signatures: POLICY_SIGNATURE_THRESHOLD,
        };
        match check(&candidate, stored.mark.as_ref(), &anchors, checked_at) {
            Verdict::Accept(mark) => Ok(VerifiedSnapshot {
                snapshot: verified.value,
                mark,
                raw: raw.to_string(),
            }),
            Verdict::Reject(rejection) => Err(rejection.into()),
        }
    }

    /// Records an accepted snapshot and the key ids it revokes. The cache is written first: a crash in between
    /// leaves a cache that is still newer than the high-water mark, never older.
    pub fn commit(&self, accepted: &VerifiedSnapshot) -> Result<(), SnapshotError> {
        let storage = |path: PathBuf| move |source| SnapshotError::Storage { path, source };
        std::fs::create_dir_all(&self.directory).map_err(storage(self.directory.clone()))?;
        let cache = self.directory.join(CACHE_FILE);
        write_atomically(&cache, accepted.raw.as_bytes()).map_err(storage(cache))?;

        let mut stored = self.state.load::<PolicyState>()?;
        stored.state.mark = Some(accepted.mark.clone());
        let revoked = &accepted.snapshot.revoked_key_ids;
        stored.state.revoked_key_ids.extend(revoked.iter().cloned());
        stored
            .state
            .revoked_public_keys
            .extend(self.trust.public_keys_of(revoked));
        Ok(self.state.save(&mut stored)?)
    }

    /// The last accepted snapshot. `None` only when no snapshot was ever accepted; a cache that has vanished since
    /// is an error, because the alternative would be dropping back to the built-in rules.
    pub fn load_cached(&self, now: u64) -> Result<Option<VerifiedSnapshot>, SnapshotError> {
        let path = self.directory.join(CACHE_FILE);
        let raw = match std::fs::read_to_string(&path) {
            Ok(raw) => raw,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let accepted_before = self.state.load::<PolicyState>()?.state.mark.is_some();
                return match accepted_before {
                    true => Err(SnapshotError::CacheMissing { path }),
                    false => Ok(None),
                };
            }
            Err(source) => return Err(SnapshotError::Storage { path, source }),
        };
        self.verify(&raw, now, Expiry::Allow).map(Some)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::trust_state::tests::MemoryVault;
    use crate::util::unix_seconds;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use contract::{Delegation, Settings, SignedEnvelope, SNAPSHOT_SCHEMA};
    use engine::signing::{public_key_of, sign_delegation, sign_payload, PinnedKey, Role};
    use ring::rand::SystemRandom;
    use ring::signature::Ed25519KeyPair;
    use std::sync::Arc;

    const ONE_HOUR: u64 = 3600;

    pub struct TestKey {
        pub pkcs8: Vec<u8>,
        pub pinned: PinnedKey,
    }

    impl TestKey {
        pub fn generate(key_id: &str) -> Self {
            let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
                .unwrap()
                .as_ref()
                .to_vec();
            let public_key = public_key_of(&pkcs8).unwrap();
            Self {
                pkcs8,
                pinned: PinnedKey {
                    key_id: key_id.into(),
                    public_key,
                },
            }
        }

        pub fn public_base64(&self) -> String {
            STANDARD.encode(self.pinned.public_key)
        }

        pub fn sign(&self, snapshot: &Snapshot) -> String {
            sign_all(&[self], snapshot)
        }
    }

    pub fn sign_all(keys: &[&TestKey], snapshot: &Snapshot) -> String {
        let payload = serde_json::to_string(snapshot).unwrap();
        let signatures = keys
            .iter()
            .map(|key| {
                sign_payload(Role::Policy, &key.pinned.key_id, &key.pkcs8, &payload).unwrap()
            })
            .collect();
        serde_json::to_string(&SignedEnvelope {
            payload,
            signatures,
            delegation: None,
        })
        .unwrap()
    }

    pub fn snapshot(version: u64) -> Snapshot {
        let now = unix_seconds();
        Snapshot {
            schema: SNAPSHOT_SCHEMA,
            version,
            issued_at: now - 10,
            expires_at: now + ONE_HOUR,
            audience: None,
            pii: vec![],
            tools: vec![],
            ca_domains: vec![],
            settings: Settings::default(),
            revoked_key_ids: vec![],
        }
    }

    pub fn expired_snapshot(version: u64) -> Snapshot {
        let now = unix_seconds();
        Snapshot {
            issued_at: now - 2 * ONE_HOUR,
            expires_at: now - ONE_HOUR,
            ..snapshot(version)
        }
    }

    fn snapshot_for(version: u64, audience: &str) -> Snapshot {
        Snapshot {
            audience: Some(audience.into()),
            ..snapshot(version)
        }
    }

    fn trusting(keys: &[&TestKey]) -> Trust {
        Trust {
            keys: keys.iter().map(|key| key.pinned.clone()).collect(),
            roots: vec![],
            ..Trust::default()
        }
    }

    fn store_for(
        directory: &tempfile::TempDir,
        trust: Trust,
        audience: Option<&str>,
    ) -> SnapshotStore {
        let state = StateStore::new(directory.path().join(STATE_FILE), None);
        SnapshotStore::new(
            directory.path().to_path_buf(),
            trust,
            audience.map(String::from),
            state,
        )
    }

    fn store(key: &TestKey) -> (tempfile::TempDir, SnapshotStore) {
        let directory = tempfile::tempdir().unwrap();
        let store = store_for(&directory, trusting(&[key]), None);
        (directory, store)
    }

    fn verify_fresh(store: &SnapshotStore, raw: &str) -> Result<VerifiedSnapshot, SnapshotError> {
        store.verify(raw, unix_seconds(), Expiry::Reject)
    }

    #[test]
    fn accepts_a_signed_snapshot_and_remembers_it() {
        let key = TestKey::generate("k1");
        let (_directory, store) = store(&key);
        let accepted = verify_fresh(&store, &key.sign(&snapshot(1))).unwrap();
        store.commit(&accepted).unwrap();
        let cached = store.load_cached(unix_seconds()).unwrap().unwrap();
        assert_eq!(cached.snapshot.version, 1);
        assert_eq!(cached.mark, accepted.mark);
    }

    #[test]
    fn rejects_snapshots_signed_by_an_unpinned_key_or_tampered_with() {
        let key = TestKey::generate("k1");
        let stranger = TestKey::generate("k1");
        let (_directory, store) = store(&key);
        assert!(verify_fresh(&store, &stranger.sign(&snapshot(1))).is_err());
        let tampered = key
            .sign(&snapshot(1))
            .replace("\\\"version\\\":1", "\\\"version\\\":9");
        assert!(verify_fresh(&store, &tampered).is_err());
        assert!(verify_fresh(&store, "not json").is_err());
    }

    #[test]
    fn a_rolled_back_or_conflicting_snapshot_is_refused_even_from_the_cache() {
        let key = TestKey::generate("k1");
        let (directory, store) = store(&key);
        let newest = verify_fresh(&store, &key.sign(&snapshot(5))).unwrap();
        store.commit(&newest).unwrap();

        let older = key.sign(&snapshot(4));
        assert!(matches!(
            verify_fresh(&store, &older),
            Err(SnapshotError::Stale(Rejection::Rollback {
                held: 5,
                offered: 4
            }))
        ));

        let mut altered = snapshot(5);
        altered.ca_domains = vec!["example.com".into()];
        assert!(matches!(
            verify_fresh(&store, &key.sign(&altered)),
            Err(SnapshotError::Stale(
                Rejection::SameVersionDifferentContent { version: 5 }
            ))
        ));

        std::fs::write(directory.path().join(CACHE_FILE), older).unwrap();
        assert!(store.load_cached(unix_seconds()).is_err());
    }

    #[test]
    fn expired_snapshots_are_rejected_when_fetched_but_usable_from_the_cache() {
        let key = TestKey::generate("k1");
        let (_directory, store) = store(&key);
        let expired = key.sign(&expired_snapshot(1));
        assert!(matches!(
            verify_fresh(&store, &expired),
            Err(SnapshotError::Stale(Rejection::Expired { .. }))
        ));
        let cached = store
            .verify(&expired, unix_seconds(), Expiry::Allow)
            .unwrap();
        assert!(cached.snapshot.expires_at <= unix_seconds());
    }

    #[test]
    fn a_snapshot_for_another_organisation_is_rejected() {
        let key = TestKey::generate("k1");
        let directory = tempfile::tempdir().unwrap();
        let globex = store_for(&directory, trusting(&[&key]), Some("globex"));

        let acme_snapshot = key.sign(&snapshot_for(1, "acme"));
        assert!(matches!(
            verify_fresh(&globex, &acme_snapshot),
            Err(SnapshotError::Stale(Rejection::WrongAudience { .. }))
        ));
        let unscoped = key.sign(&snapshot(1));
        assert!(matches!(
            verify_fresh(&globex, &unscoped),
            Err(SnapshotError::Stale(Rejection::WrongAudience {
                offered: None,
                ..
            }))
        ));
        assert!(verify_fresh(&globex, &key.sign(&snapshot_for(1, "globex"))).is_ok());
    }

    #[test]
    fn a_client_without_an_organisation_accepts_scoped_and_unscoped_snapshots() {
        let key = TestKey::generate("k1");
        let (_directory, store) = store(&key);
        assert!(verify_fresh(&store, &key.sign(&snapshot(1))).is_ok());
        assert!(verify_fresh(&store, &key.sign(&snapshot_for(2, "acme"))).is_ok());
    }

    fn delegated_store(
        directory: &tempfile::TempDir,
        audience: Option<&str>,
        delegated_for: &str,
    ) -> (SnapshotStore, TestKey, Delegation) {
        let root = TestKey::generate("root");
        let delegated = TestKey::generate("policy-1");
        let now = unix_seconds();
        let mut delegation = Delegation {
            key_id: "policy-1".into(),
            public_key: delegated.public_base64(),
            not_before: now - 100,
            not_after: now + ONE_HOUR,
            audience: Some(delegated_for.into()),
            root_key_id: "root".into(),
            signature: String::new(),
        };
        delegation.signature = sign_delegation("root", &root.pkcs8, &delegation)
            .unwrap()
            .signature;
        let trust = Trust {
            keys: vec![],
            roots: vec![root.pinned],
            ..Trust::default()
        };
        (store_for(directory, trust, audience), delegated, delegation)
    }

    fn delegated_envelope(key: &TestKey, delegation: Delegation, snapshot: &Snapshot) -> String {
        let payload = serde_json::to_string(snapshot).unwrap();
        let signature = sign_payload(Role::Policy, "policy-1", &key.pkcs8, &payload).unwrap();
        serde_json::to_string(&SignedEnvelope {
            payload,
            signatures: vec![signature],
            delegation: Some(delegation),
        })
        .unwrap()
    }

    #[test]
    fn a_key_delegated_for_one_organisation_cannot_sign_for_another() {
        let directory = tempfile::tempdir().unwrap();
        let (globex, delegated, delegation) = delegated_store(&directory, Some("globex"), "acme");

        let for_globex =
            delegated_envelope(&delegated, delegation.clone(), &snapshot_for(1, "globex"));
        assert!(matches!(
            verify_fresh(&globex, &for_globex),
            Err(SnapshotError::Invalid(
                engine::SnapshotError::DelegationAudience { .. }
            ))
        ));
        let for_acme = delegated_envelope(&delegated, delegation, &snapshot_for(1, "acme"));
        assert!(matches!(
            verify_fresh(&globex, &for_acme),
            Err(SnapshotError::Stale(Rejection::WrongAudience { .. }))
        ));
    }

    #[test]
    fn a_key_delegated_for_an_organisation_signs_for_it() {
        let directory = tempfile::tempdir().unwrap();
        let (acme, delegated, delegation) = delegated_store(&directory, Some("acme"), "acme");
        let envelope = delegated_envelope(&delegated, delegation, &snapshot_for(1, "acme"));
        assert!(verify_fresh(&acme, &envelope).is_ok());
    }

    fn revoking(version: u64, revoked: &[&str]) -> Snapshot {
        Snapshot {
            revoked_key_ids: revoked.iter().map(|id| id.to_string()).collect(),
            ..snapshot(version)
        }
    }

    #[test]
    fn accepted_revocations_persist_and_stop_the_revoked_key_for_good() {
        let (healthy, compromised) = (TestKey::generate("healthy"), TestKey::generate("old"));
        let directory = tempfile::tempdir().unwrap();
        let store = store_for(&directory, trusting(&[&healthy, &compromised]), None);

        let revocation = sign_all(&[&healthy, &compromised], &revoking(2, &["old"]));
        let accepted = verify_fresh(&store, &revocation).unwrap();
        store.commit(&accepted).unwrap();

        let later = compromised.sign(&snapshot(3));
        assert!(matches!(
            verify_fresh(&store, &later),
            Err(SnapshotError::Invalid(engine::SnapshotError::Verify(_)))
        ));
        assert!(verify_fresh(&store, &healthy.sign(&snapshot(3))).is_ok());
    }

    #[test]
    fn a_snapshot_that_is_not_committed_does_not_revoke_anything() {
        let (healthy, other) = (TestKey::generate("healthy"), TestKey::generate("other"));
        let directory = tempfile::tempdir().unwrap();
        let store = store_for(&directory, trusting(&[&healthy, &other]), None);

        let expired_revocation = Snapshot {
            revoked_key_ids: vec!["other".into()],
            ..expired_snapshot(2)
        };
        assert!(verify_fresh(&store, &healthy.sign(&expired_revocation)).is_err());
        verify_fresh(&store, &healthy.sign(&revoking(2, &["other"]))).unwrap();

        assert!(verify_fresh(&store, &other.sign(&snapshot(3))).is_ok());
    }

    #[test]
    fn a_key_cannot_revoke_itself_or_every_pinned_key() {
        let only = TestKey::generate("only");
        let (_directory, store) = store(&only);
        assert!(matches!(
            verify_fresh(&store, &only.sign(&revoking(2, &["only"]))),
            Err(SnapshotError::Stale(
                Rejection::RevocationBelowThreshold { .. }
            ))
        ));

        let (first, second) = (TestKey::generate("first"), TestKey::generate("second"));
        let directory = tempfile::tempdir().unwrap();
        let store = store_for(&directory, trusting(&[&first, &second]), None);
        let wipe = sign_all(&[&first], &revoking(2, &["first", "second"]));
        assert!(verify_fresh(&store, &wipe).is_err());
    }

    fn lapsing_delegation(directory: &tempfile::TempDir) -> (SnapshotStore, TestKey, Delegation) {
        let root = TestKey::generate("root");
        let delegated = TestKey::generate("policy-1");
        let now = unix_seconds();
        let mut delegation = Delegation {
            key_id: "policy-1".into(),
            public_key: delegated.public_base64(),
            not_before: now - 100,
            not_after: now - 5,
            audience: None,
            root_key_id: "root".into(),
            signature: String::new(),
        };
        delegation.signature = sign_delegation("root", &root.pkcs8, &delegation)
            .unwrap()
            .signature;
        let trust = Trust {
            roots: vec![root.pinned],
            ..Trust::default()
        };
        (store_for(directory, trust, None), delegated, delegation)
    }

    #[test]
    fn a_cached_snapshot_stays_loadable_after_its_delegation_lapses() {
        let directory = tempfile::tempdir().unwrap();
        let (store, delegated, delegation) = lapsing_delegation(&directory);
        let raw = delegated_envelope(&delegated, delegation, &snapshot(1));
        let issued_at = unix_seconds() - 10;

        let accepted = store.verify(&raw, issued_at, Expiry::Reject).unwrap();
        store.commit(&accepted).unwrap();

        assert!(verify_fresh(&store, &raw).is_err());
        assert_eq!(
            store
                .load_cached(unix_seconds())
                .unwrap()
                .unwrap()
                .snapshot
                .version,
            1
        );
    }

    #[test]
    fn a_lapsed_delegated_key_cannot_plant_a_newer_snapshot_in_the_cache() {
        let directory = tempfile::tempdir().unwrap();
        let (store, delegated, delegation) = lapsing_delegation(&directory);
        let genuine = delegated_envelope(&delegated, delegation.clone(), &snapshot(1));
        let accepted = store
            .verify(&genuine, unix_seconds() - 10, Expiry::Reject)
            .unwrap();
        store.commit(&accepted).unwrap();

        let forged = delegated_envelope(&delegated, delegation, &snapshot(9));
        std::fs::write(directory.path().join(CACHE_FILE), forged).unwrap();

        assert!(store.load_cached(unix_seconds()).is_err());
    }

    #[test]
    fn a_revoked_delegated_key_stops_signing_snapshots() {
        let directory = tempfile::tempdir().unwrap();
        let healthy = TestKey::generate("healthy");
        let (store, delegated, delegation) = delegated_store(&directory, None, "acme");
        let mut trust = store.trust.clone();
        trust.keys = vec![healthy.pinned.clone()];
        let store = store_for(&directory, trust, None);

        let first = delegated_envelope(&delegated, delegation.clone(), &snapshot_for(1, "acme"));
        store
            .commit(&verify_fresh(&store, &first).unwrap())
            .unwrap();
        let revocation = healthy.sign(&revoking(2, &["policy-1"]));
        store
            .commit(&verify_fresh(&store, &revocation).unwrap())
            .unwrap();

        let later = delegated_envelope(&delegated, delegation, &snapshot_for(3, "acme"));
        assert!(matches!(
            verify_fresh(&store, &later),
            Err(SnapshotError::Invalid(engine::SnapshotError::Verify(_)))
        ));
    }

    #[test]
    fn a_key_revoked_by_id_stays_revoked_by_public_key_when_pinned_under_another_id() {
        let (healthy, compromised) = (TestKey::generate("healthy"), TestKey::generate("old"));
        let directory = tempfile::tempdir().unwrap();
        let store = store_for(&directory, trusting(&[&healthy, &compromised]), None);
        let revocation = sign_all(&[&healthy, &compromised], &revoking(2, &["old"]));
        store
            .commit(&verify_fresh(&store, &revocation).unwrap())
            .unwrap();

        let renamed = TestKey {
            pkcs8: compromised.pkcs8.clone(),
            pinned: PinnedKey {
                key_id: "new-name".into(),
                ..compromised.pinned.clone()
            },
        };
        let repinned = store_for(&directory, trusting(&[&healthy, &renamed]), None);

        assert!(verify_fresh(&repinned, &renamed.sign(&snapshot(3))).is_err());
        assert!(verify_fresh(&repinned, &healthy.sign(&snapshot(3))).is_ok());
    }

    #[test]
    fn a_vanished_cache_is_an_error_once_a_snapshot_was_accepted() {
        let key = TestKey::generate("k1");
        let (directory, store) = store(&key);
        assert!(store.load_cached(unix_seconds()).unwrap().is_none());

        let accepted = verify_fresh(&store, &key.sign(&snapshot(1))).unwrap();
        store.commit(&accepted).unwrap();
        std::fs::remove_file(directory.path().join(CACHE_FILE)).unwrap();

        assert!(matches!(
            store.load_cached(unix_seconds()),
            Err(SnapshotError::CacheMissing { .. })
        ));
    }

    #[test]
    fn restoring_an_older_state_file_is_detected_through_the_keychain() {
        let key = TestKey::generate("k1");
        let directory = tempfile::tempdir().unwrap();
        let vault = Arc::new(MemoryVault::default());
        let state = StateStore::new(directory.path().join(STATE_FILE), Some(vault));
        let store = SnapshotStore::new(
            directory.path().to_path_buf(),
            trusting(&[&key]),
            None,
            state,
        );
        let first = verify_fresh(&store, &key.sign(&snapshot(1))).unwrap();
        store.commit(&first).unwrap();
        let old_state = std::fs::read(directory.path().join(STATE_FILE)).unwrap();
        let second = verify_fresh(&store, &key.sign(&snapshot(2))).unwrap();
        store.commit(&second).unwrap();

        std::fs::write(directory.path().join(STATE_FILE), old_state).unwrap();

        assert!(matches!(
            verify_fresh(&store, &key.sign(&snapshot(1))),
            Err(SnapshotError::State(StateError::RolledBack { .. }))
        ));
        assert!(matches!(
            store.load_cached(unix_seconds()),
            Err(SnapshotError::State(StateError::RolledBack { .. }))
        ));
    }
}
