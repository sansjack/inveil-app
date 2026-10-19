//! State that protects against rollback (high-water marks, revoked key ids, the newest update seen). It lives in the
//! user-writable data directory, so each file also has an anchor in the OS keychain: a monotonic counter, a digest of
//! the file and a random key. Every record carries a MAC under that key. A file is accepted only if it is exactly the
//! anchored record, or one record ahead of it (a crash between writing the file and the anchor) *and* authenticated by
//! the key. A file that is missing, older, different or merely claims a higher counter is refused: an attacker who can
//! write the data directory but not the keychain can neither roll back nor forge state.
//!
//! When the keychain cannot be used the file is the only protection; that is logged as `state_protection = "file_only"`.
use crate::brand;
use crate::util::write_atomically;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use engine::signing::sha256_hex;
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;

const KEYCHAIN_SERVICE_SUFFIX: &str = "state";
const DIRECTORY_DIGEST_HEX_LEN: usize = 16;
const MAC_KEY_LEN: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("cannot read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("cannot write {path}: {source}")]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("{path} is unreadable ({reason}). {recovery}")]
    Corrupt {
        path: PathBuf,
        reason: String,
        recovery: String,
    },
    #[error("{path} is missing or older than the record kept in the OS keychain ({reason}), which looks like a rollback. {recovery}")]
    RolledBack {
        path: PathBuf,
        reason: String,
        recovery: String,
    },
    #[error("cannot serialise the state: {0}")]
    Serialize(serde_json::Error),
}

/// A secret the OS keeps outside the data directory.
pub trait Vault: Send + Sync {
    fn read(&self) -> Result<Option<String>, keyring::Error>;
    fn write(&self, secret: &str) -> Result<(), keyring::Error>;
    /// Names the item, for the recovery instructions in error messages.
    fn label(&self) -> String;
}

pub struct KeychainVault {
    service: String,
    user: String,
}

impl KeychainVault {
    /// Each directory gets its own item, so two installations on one machine never see each other's counters.
    fn anchor_of(directory: &Path, file_name: &str) -> Self {
        let directory_digest = sha256_hex(directory.as_os_str().as_encoded_bytes());
        Self {
            service: format!(
                "{}.{KEYCHAIN_SERVICE_SUFFIX}",
                brand::KEYCHAIN_SERVICE_PREFIX
            ),
            user: format!(
                "{file_name}-{}",
                &directory_digest[..DIRECTORY_DIGEST_HEX_LEN]
            ),
        }
    }

    fn entry(&self) -> Result<keyring::Entry, keyring::Error> {
        keyring::Entry::new(&self.service, &self.user)
    }
}

impl Vault for KeychainVault {
    fn read(&self) -> Result<Option<String>, keyring::Error> {
        match self.entry()?.get_password() {
            Ok(secret) => Ok(Some(secret)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn write(&self, secret: &str) -> Result<(), keyring::Error> {
        self.entry()?.set_password(secret)
    }

    fn label(&self) -> String {
        format!("keychain item \"{}\" / \"{}\"", self.service, self.user)
    }
}

/// What the keychain remembers about a state file: how far it got, a digest of it, and the key that authenticates it.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Anchor {
    counter: u64,
    sha256: String,
    mac_key: String,
}

/// What the keychain said when asked for the anchor.
enum AnchorState {
    /// No keychain is configured, or it cannot be reached: the file is the only protection.
    Unavailable,
    /// The keychain works but holds nothing for this file yet.
    Missing,
    Found(Anchor),
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Stamped<T> {
    pub counter: u64,
    pub state: T,
}

/// The file as stored. `mac` authenticates `counter` and `state` with the key held in the keychain, so an attacker
/// who can write the data directory but not the keychain cannot produce a record newer than the anchor. It is absent
/// when the keychain was unavailable at the time of writing.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredRecord {
    counter: u64,
    state: serde_json::Value,
    #[serde(default)]
    mac: Option<String>,
}

#[derive(Serialize)]
struct RecordToStore<'a> {
    counter: u64,
    state: &'a serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    mac: Option<String>,
}

fn mac_message(counter: u64, state: &serde_json::Value) -> String {
    format!("{counter}\n{state}")
}

pub struct StateStore {
    path: PathBuf,
    vault: Option<Arc<dyn Vault>>,
}

impl StateStore {
    pub fn new(path: PathBuf, vault: Option<Arc<dyn Vault>>) -> Self {
        Self { path, vault }
    }

    /// The state file `file_name` in `directory`, anchored in the keychain when `use_keychain` is set.
    pub fn open(directory: &Path, file_name: &str, use_keychain: bool) -> Self {
        let path = directory.join(file_name);
        if !use_keychain {
            return Self::new(path, None);
        }
        Self::new(
            path,
            Some(Arc::new(KeychainVault::anchor_of(directory, file_name))),
        )
    }

    /// Deletes the keychain anchor of `file_name` in `directory`, for `inveil uninstall`. True when one was there.
    pub fn remove_anchor(directory: &Path, file_name: &str) -> Result<bool, keyring::Error> {
        match KeychainVault::anchor_of(directory, file_name)
            .entry()?
            .delete_credential()
        {
            Ok(()) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn recovery(&self) -> String {
        let anchor = self
            .vault
            .as_ref()
            .map(|vault| format!(" and the {}", vault.label()))
            .unwrap_or_default();
        format!(
            "If nobody tampered with it, delete {}{anchor} to start rollback protection afresh; \
             everything signed before then will be accepted again.",
            self.path.display()
        )
    }

    fn rolled_back(&self, reason: String) -> StateError {
        StateError::RolledBack {
            path: self.path.clone(),
            reason,
            recovery: self.recovery(),
        }
    }

    fn corrupt(&self, reason: String) -> StateError {
        StateError::Corrupt {
            path: self.path.clone(),
            reason,
            recovery: self.recovery(),
        }
    }

    fn read_anchor(&self) -> Result<AnchorState, StateError> {
        let Some(vault) = &self.vault else {
            return Ok(AnchorState::Unavailable);
        };
        let raw = match vault.read() {
            Ok(Some(raw)) => raw,
            Ok(None) => return Ok(AnchorState::Missing),
            Err(error) => {
                tracing::warn!(
                    state_protection = "file_only",
                    "the OS keychain is not available ({error}); {} is protected by the file alone, so an attacker \
                     who can write that directory could roll it back",
                    self.path.display()
                );
                return Ok(AnchorState::Unavailable);
            }
        };
        serde_json::from_str(&raw)
            .map(AnchorState::Found)
            .map_err(|error| self.corrupt(format!("its keychain record is unreadable: {error}")))
    }

    /// Whether the keychain took the record; a failure is logged and leaves the file as the only protection.
    fn write_anchor(&self, anchor: &Anchor) -> bool {
        let Some(vault) = &self.vault else {
            return false;
        };
        let serialized = match serde_json::to_string(anchor) {
            Ok(serialized) => serialized,
            Err(error) => {
                tracing::warn!("cannot serialise the keychain record: {error}");
                return false;
            }
        };
        if let Err(error) = vault.write(&serialized) {
            tracing::warn!(
                state_protection = "file_only",
                "cannot update the keychain record for {}: {error}",
                self.path.display()
            );
            return false;
        }
        true
    }

    fn mac_key(&self, anchor: &Anchor) -> Result<hmac::Key, StateError> {
        let bytes = STANDARD
            .decode(&anchor.mac_key)
            .map_err(|error| self.corrupt(format!("its keychain key is unreadable: {error}")))?;
        Ok(hmac::Key::new(hmac::HMAC_SHA256, &bytes))
    }

    fn mac_is_valid(&self, anchor: &Anchor, record: &StoredRecord) -> Result<bool, StateError> {
        let Some(mac) = record
            .mac
            .as_deref()
            .and_then(|mac| STANDARD.decode(mac).ok())
        else {
            return Ok(false);
        };
        let message = mac_message(record.counter, &record.state);
        Ok(hmac::verify(&self.mac_key(anchor)?, message.as_bytes(), &mac).is_ok())
    }

    fn new_anchor(&self, counter: u64, text: Option<&str>) -> Result<Anchor, StateError> {
        let mut key = [0u8; MAC_KEY_LEN];
        SystemRandom::new()
            .fill(&mut key)
            .map_err(|_| self.corrupt("the system random generator failed".into()))?;
        Ok(Anchor {
            counter,
            sha256: text
                .map(|text| sha256_hex(text.as_bytes()))
                .unwrap_or_default(),
            mac_key: STANDARD.encode(key),
        })
    }

    fn read_file(&self) -> Result<Option<String>, StateError> {
        match std::fs::read_to_string(&self.path) {
            Ok(text) => Ok(Some(text)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(StateError::Read {
                path: self.path.clone(),
                source,
            }),
        }
    }

    /// The saved state, or the default when nothing was ever saved. With a working keychain the file is accepted only
    /// if it is exactly what the anchor describes, or the next record in the chain, proven by its MAC.
    pub fn load<T: DeserializeOwned + Default>(&self) -> Result<Stamped<T>, StateError> {
        let text = self.read_file()?;
        let anchor = self.read_anchor()?;
        let Some(text) = text else {
            return match anchor {
                AnchorState::Found(anchor) if anchor.counter > 0 => Err(self.rolled_back(format!(
                    "the file is gone but the keychain has record {}",
                    anchor.counter
                ))),
                _ => Ok(Stamped::default()),
            };
        };
        let record: StoredRecord =
            serde_json::from_str(&text).map_err(|error| self.corrupt(error.to_string()))?;
        match anchor {
            AnchorState::Unavailable => {}
            AnchorState::Missing => {
                if record.mac.is_some() {
                    return Err(self.rolled_back(
                        "the file is authenticated by a key the keychain no longer holds".into(),
                    ));
                }
                self.write_anchor(&self.new_anchor(record.counter, Some(&text))?);
            }
            AnchorState::Found(anchor) => self.check_against_anchor(&anchor, &record, &text)?,
        }
        let state = serde_json::from_value(record.state)
            .map_err(|error| self.corrupt(error.to_string()))?;
        Ok(Stamped {
            counter: record.counter,
            state,
        })
    }

    fn check_against_anchor(
        &self,
        anchor: &Anchor,
        record: &StoredRecord,
        text: &str,
    ) -> Result<(), StateError> {
        if record.counter < anchor.counter {
            return Err(self.rolled_back(format!(
                "the file is at record {}, the keychain at {}",
                record.counter, anchor.counter
            )));
        }
        if record.counter == anchor.counter {
            return match sha256_hex(text.as_bytes()) == anchor.sha256 {
                true => Ok(()),
                false => Err(self.rolled_back(format!(
                    "record {} differs from what the keychain saw",
                    record.counter
                ))),
            };
        }
        if !self.mac_is_valid(anchor, record)? {
            return Err(self.rolled_back(format!(
                "record {} is newer than the keychain's {} but is not authenticated by its key; it was forged, \
                 or written while the keychain was unavailable",
                record.counter, anchor.counter
            )));
        }
        self.write_anchor(&Anchor {
            counter: record.counter,
            sha256: sha256_hex(text.as_bytes()),
            mac_key: anchor.mac_key.clone(),
        });
        Ok(())
    }

    /// The anchor to authenticate the next record with: the existing one, or a fresh one stored before the file is
    /// written, so a file carrying a MAC never exists without its key. `None` means the file alone must do.
    fn anchor_for_save(&self, counter: u64) -> Result<Option<Anchor>, StateError> {
        match self.read_anchor()? {
            AnchorState::Found(anchor) => Ok(Some(anchor)),
            AnchorState::Unavailable => Ok(None),
            AnchorState::Missing => {
                let current = self.read_file()?;
                let anchor = self.new_anchor(counter, current.as_deref())?;
                Ok(self.write_anchor(&anchor).then_some(anchor))
            }
        }
    }

    /// Writes `stamped.state` as the next record: the file first, then the keychain, so a crash between the two
    /// leaves a file that is one record ahead of its anchor, which its MAC vouches for and the next load heals.
    pub fn save<T: Serialize>(&self, stamped: &mut Stamped<T>) -> Result<(), StateError> {
        let counter = stamped.counter.saturating_add(1);
        let anchor = self.anchor_for_save(stamped.counter)?;
        let state = serde_json::to_value(&stamped.state).map_err(StateError::Serialize)?;
        let mac = match &anchor {
            Some(anchor) => {
                let message = mac_message(counter, &state);
                let tag = hmac::sign(&self.mac_key(anchor)?, message.as_bytes());
                Some(STANDARD.encode(tag.as_ref()))
            }
            None => None,
        };
        let text = serde_json::to_string_pretty(&RecordToStore {
            counter,
            state: &state,
            mac,
        })
        .map_err(StateError::Serialize)?;
        if let Some(directory) = self.path.parent() {
            std::fs::create_dir_all(directory).map_err(|source| StateError::Write {
                path: directory.to_path_buf(),
                source,
            })?;
        }
        write_atomically(&self.path, text.as_bytes()).map_err(|source| StateError::Write {
            path: self.path.clone(),
            source,
        })?;
        stamped.counter = counter;
        if let Some(anchor) = anchor {
            self.write_anchor(&Anchor {
                counter,
                sha256: sha256_hex(text.as_bytes()),
                mac_key: anchor.mac_key,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::sync::Mutex;

    #[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
    struct Sample {
        revoked: BTreeSet<String>,
    }

    /// A keychain that lives in memory and can be made unavailable.
    #[derive(Default)]
    pub struct MemoryVault {
        secret: Mutex<Option<String>>,
        unavailable: bool,
    }

    impl MemoryVault {
        pub fn unavailable() -> Self {
            Self {
                secret: Mutex::default(),
                unavailable: true,
            }
        }
    }

    impl Vault for MemoryVault {
        fn read(&self) -> Result<Option<String>, keyring::Error> {
            if self.unavailable {
                return Err(keyring::Error::NoStorageAccess("locked".into()));
            }
            Ok(self.secret.lock().unwrap().clone())
        }

        fn write(&self, secret: &str) -> Result<(), keyring::Error> {
            if self.unavailable {
                return Err(keyring::Error::NoStorageAccess("locked".into()));
            }
            *self.secret.lock().unwrap() = Some(secret.to_string());
            Ok(())
        }

        fn label(&self) -> String {
            "test keychain item".into()
        }
    }

    fn store_in(directory: &Path, vault: &Arc<MemoryVault>) -> StateStore {
        let shared: Arc<dyn Vault> = vault.clone();
        StateStore::new(directory.join("state.json"), Some(shared))
    }

    fn saved(store: &StateStore, revoked: &str) -> Stamped<Sample> {
        let mut stamped: Stamped<Sample> = store.load().unwrap();
        stamped.state.revoked.insert(revoked.to_string());
        store.save(&mut stamped).unwrap();
        stamped
    }

    #[test]
    fn nothing_saved_yet_loads_the_default() {
        let directory = tempfile::tempdir().unwrap();
        let store = store_in(directory.path(), &Arc::default());
        let loaded: Stamped<Sample> = store.load().unwrap();
        assert_eq!(loaded, Stamped::default());
    }

    #[test]
    fn saved_state_round_trips_with_an_increasing_counter() {
        let directory = tempfile::tempdir().unwrap();
        let store = store_in(directory.path(), &Arc::default());
        assert_eq!(saved(&store, "a").counter, 1);
        assert_eq!(saved(&store, "b").counter, 2);
        let loaded: Stamped<Sample> = store.load().unwrap();
        assert_eq!(loaded.counter, 2);
        assert_eq!(loaded.state.revoked.len(), 2);
    }

    #[test]
    fn restoring_an_older_file_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let vault = Arc::new(MemoryVault::default());
        let store = store_in(directory.path(), &vault);
        saved(&store, "a");
        let old_copy = std::fs::read_to_string(directory.path().join("state.json")).unwrap();
        saved(&store, "b");

        std::fs::write(directory.path().join("state.json"), old_copy).unwrap();

        let error = store.load::<Sample>().unwrap_err();
        assert!(matches!(error, StateError::RolledBack { .. }), "{error}");
        assert!(error.to_string().contains("test keychain item"));
    }

    #[test]
    fn deleting_the_file_is_refused_while_the_keychain_remembers_it() {
        let directory = tempfile::tempdir().unwrap();
        let vault = Arc::new(MemoryVault::default());
        let store = store_in(directory.path(), &vault);
        saved(&store, "a");

        std::fs::remove_file(directory.path().join("state.json")).unwrap();

        assert!(matches!(
            store.load::<Sample>().unwrap_err(),
            StateError::RolledBack { .. }
        ));
    }

    #[test]
    fn a_rewritten_file_with_the_same_counter_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let vault = Arc::new(MemoryVault::default());
        let store = store_in(directory.path(), &vault);
        saved(&store, "a");

        std::fs::write(
            directory.path().join("state.json"),
            r#"{"counter":1,"state":{"revoked":[]}}"#,
        )
        .unwrap();

        assert!(matches!(
            store.load::<Sample>().unwrap_err(),
            StateError::RolledBack { .. }
        ));
    }

    #[test]
    fn a_file_newer_than_the_keychain_heals_the_keychain() {
        let directory = tempfile::tempdir().unwrap();
        let vault = Arc::new(MemoryVault::default());
        let store = store_in(directory.path(), &vault);
        saved(&store, "a");
        let after_first = vault.read().unwrap();
        saved(&store, "b");
        vault.write(&after_first.unwrap()).unwrap();

        assert_eq!(store.load::<Sample>().unwrap().counter, 2);
        assert_eq!(store.load::<Sample>().unwrap().counter, 2);
    }

    #[test]
    fn a_forged_file_with_a_higher_counter_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let vault = Arc::new(MemoryVault::default());
        let store = store_in(directory.path(), &vault);
        saved(&store, "a");

        std::fs::write(
            directory.path().join("state.json"),
            r#"{"counter":9,"state":{"revoked":[]}}"#,
        )
        .unwrap();

        let error = store.load::<Sample>().unwrap_err();
        assert!(matches!(error, StateError::RolledBack { .. }), "{error}");
        assert!(error.to_string().contains("not authenticated"), "{error}");
    }

    #[test]
    fn a_higher_counter_with_a_mac_from_another_key_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let vault = Arc::new(MemoryVault::default());
        let store = store_in(directory.path(), &vault);
        saved(&store, "a");
        let attacker_key = hmac::Key::new(hmac::HMAC_SHA256, b"not the keychain key");
        let state = serde_json::json!({"revoked": []});
        let tag = hmac::sign(&attacker_key, mac_message(2, &state).as_bytes());
        let forged = serde_json::json!({
            "counter": 2,
            "state": state,
            "mac": STANDARD.encode(tag.as_ref()),
        });
        std::fs::write(directory.path().join("state.json"), forged.to_string()).unwrap();

        assert!(matches!(
            store.load::<Sample>().unwrap_err(),
            StateError::RolledBack { .. }
        ));
    }

    #[test]
    fn editing_the_state_of_the_next_record_invalidates_its_mac() {
        let directory = tempfile::tempdir().unwrap();
        let vault = Arc::new(MemoryVault::default());
        let store = store_in(directory.path(), &vault);
        saved(&store, "a");
        let after_first = vault.read().unwrap().unwrap();
        saved(&store, "b");
        vault.write(&after_first).unwrap();
        let path = directory.path().join("state.json");
        let edited = std::fs::read_to_string(&path).unwrap().replace('b', "c");
        std::fs::write(&path, edited).unwrap();

        assert!(matches!(
            store.load::<Sample>().unwrap_err(),
            StateError::RolledBack { .. }
        ));
    }

    #[test]
    fn a_file_authenticated_by_a_key_the_keychain_lost_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let store = store_in(directory.path(), &Arc::default());
        saved(&store, "a");

        let wiped = store_in(directory.path(), &Arc::default());

        assert!(matches!(
            wiped.load::<Sample>().unwrap_err(),
            StateError::RolledBack { .. }
        ));
    }

    #[test]
    fn a_file_written_without_a_keychain_is_adopted_once_one_appears() {
        let directory = tempfile::tempdir().unwrap();
        let unavailable = store_in(directory.path(), &Arc::new(MemoryVault::unavailable()));
        saved(&unavailable, "a");

        let vault = Arc::new(MemoryVault::default());
        let store = store_in(directory.path(), &vault);
        assert_eq!(store.load::<Sample>().unwrap().counter, 1);
        assert_eq!(saved(&store, "b").counter, 2);
        std::fs::write(
            directory.path().join("state.json"),
            r#"{"counter":9,"state":{"revoked":[]}}"#,
        )
        .unwrap();
        assert!(store.load::<Sample>().is_err());
    }

    #[test]
    fn an_unauthenticated_record_written_while_the_keychain_was_locked_is_refused_afterwards() {
        let directory = tempfile::tempdir().unwrap();
        let store = store_in(directory.path(), &Arc::default());
        saved(&store, "a");

        let locked = store_in(directory.path(), &Arc::new(MemoryVault::unavailable()));
        saved(&locked, "b");

        let error = store.load::<Sample>().unwrap_err();
        assert!(error.to_string().contains("unavailable"), "{error}");
    }

    #[test]
    fn a_corrupt_file_names_how_to_recover() {
        let directory = tempfile::tempdir().unwrap();
        let store = store_in(directory.path(), &Arc::default());
        std::fs::write(directory.path().join("state.json"), "{ not json").unwrap();

        let error = store.load::<Sample>().unwrap_err();

        assert!(matches!(error, StateError::Corrupt { .. }));
        assert!(error.to_string().contains("delete"), "{error}");
        std::fs::remove_file(directory.path().join("state.json")).unwrap();
        assert_eq!(store.load::<Sample>().unwrap(), Stamped::default());
    }

    #[test]
    fn without_a_usable_keychain_the_file_alone_is_trusted() {
        let directory = tempfile::tempdir().unwrap();
        let vault = Arc::new(MemoryVault::unavailable());
        let store = store_in(directory.path(), &vault);
        saved(&store, "a");
        assert_eq!(store.load::<Sample>().unwrap().counter, 1);
    }

    #[test]
    fn a_store_without_a_keychain_works_from_the_file() {
        let directory = tempfile::tempdir().unwrap();
        let store = StateStore::open(directory.path(), "state.json", false);
        saved(&store, "a");
        assert_eq!(store.load::<Sample>().unwrap().counter, 1);
    }
}
