#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::fetch::{FetchError, Fetcher, HttpFetcher};
use super::health::HealthError;
use super::manifest::ManifestError;
use super::pending::PendingUpdate;
use super::*;
use crate::config;
use crate::trust_state::StateStore;
use crate::util::unix_seconds;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use contract::{Artifact, SignedEnvelope, UpdateManifest, MANIFEST_SCHEMA};
use engine::signing::{public_key_of, sha256_hex, sign_payload, PinnedKey, Role};
use ring::rand::SystemRandom;
use ring::signature::Ed25519KeyPair;
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::io::{Cursor, Read};
use std::rc::Rc;
use tempfile::TempDir;

const NOW: u64 = 1_000_000;
const TARGET: &str = "linux-x86_64";
const PENDING: &str = ".inveil-update-pending";
const MANIFEST_URL: &str = "https://updates.example.com/update-manifest.json";
const ARTIFACT_URL: &str = "https://updates.example.com/inveil-linux-x86_64";
const OLD_BINARY: &[u8] = b"old inveil binary, version 0.1.0";
const NEW_BINARY: &[u8] = b"new inveil binary, version 0.2.0";

struct Key {
    pkcs8: Vec<u8>,
    pinned: PinnedKey,
}

fn key(key_id: &str) -> Key {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
        .unwrap()
        .as_ref()
        .to_vec();
    let public_key = public_key_of(&pkcs8).unwrap();
    Key {
        pkcs8,
        pinned: PinnedKey {
            key_id: key_id.to_string(),
            public_key,
        },
    }
}

fn manifest(version: &str, binary: &[u8]) -> UpdateManifest {
    UpdateManifest {
        schema: MANIFEST_SCHEMA,
        channel: "stable".to_string(),
        version: version.to_string(),
        published_at: NOW - 10,
        expires_at: NOW + 1_000,
        min_supported: None,
        threshold: 1,
        artifacts: BTreeMap::from([(
            TARGET.to_string(),
            Artifact {
                url: ARTIFACT_URL.to_string(),
                sha256: sha256_hex(binary),
                size: binary.len() as u64,
            },
        )]),
        notes_url: None,
        revoked_key_ids: vec![],
    }
}

fn signed_by(manifest: &UpdateManifest, signers: &[&Key]) -> String {
    let payload = serde_json::to_string(manifest).unwrap();
    let signatures = signers
        .iter()
        .map(|signer| {
            sign_payload(Role::Update, &signer.pinned.key_id, &signer.pkcs8, &payload).unwrap()
        })
        .collect();
    serde_json::to_string(&SignedEnvelope {
        payload,
        signatures,
        delegation: None,
    })
    .unwrap()
}

struct Observed {
    data: Cursor<Vec<u8>>,
    observer: Option<Rc<dyn Fn()>>,
}

impl Read for Observed {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if let Some(observer) = &self.observer {
            observer();
        }
        self.data.read(buffer)
    }
}

#[derive(Default)]
struct FakeFetcher {
    files: BTreeMap<String, Vec<u8>>,
    observer: Option<Rc<dyn Fn()>>,
}

impl Fetcher for FakeFetcher {
    fn open(&self, url: &str, _timeout: Duration) -> Result<Box<dyn Read>, FetchError> {
        let data = self.files.get(url).ok_or(FetchError::Status(404))?;
        Ok(Box::new(Observed {
            data: Cursor::new(data.clone()),
            observer: self.observer.clone(),
        }))
    }
}

#[derive(Default)]
struct FakeHealth {
    unhealthy: bool,
    wont_run: bool,
    restarts: Cell<u32>,
}

impl HealthCheck for FakeHealth {
    fn smoke_test(
        &self,
        _binary: &std::path::Path,
        _expected: &Version,
    ) -> Result<(), HealthError> {
        if self.wont_run {
            return Err(HealthError::CannotRun("exec format error".to_string()));
        }
        Ok(())
    }

    fn restart(&self) -> Result<(), HealthError> {
        self.restarts.set(self.restarts.get() + 1);
        Ok(())
    }

    fn confirm(&self, _expected: &Version) -> Result<(), HealthError> {
        if self.unhealthy {
            return Err(HealthError::NotListening(Duration::from_secs(1)));
        }
        Ok(())
    }
}

struct Fixture {
    _temp_dir: TempDir,
    context: UpdateContext,
    fetcher: FakeFetcher,
    health: FakeHealth,
}

impl Fixture {
    fn new(trusted: &[&Key]) -> Self {
        let dir = TempDir::new().unwrap();
        let install_dir = dir.path().join("bin");
        std::fs::create_dir(&install_dir).unwrap();
        let install_path = install_dir.join("inveil");
        std::fs::write(&install_path, OLD_BINARY).unwrap();
        let context = UpdateContext {
            trust: Trust {
                keys: trusted.iter().map(|key| key.pinned.clone()).collect(),
                roots: vec![],
                ..Trust::default()
            },
            min_signatures: 1,
            channel: "stable".to_string(),
            current: Version::new(0, 1, 0),
            target: TARGET.to_string(),
            layout: InstallLayout::new(&install_path).unwrap(),
            state: StateStore::new(dir.path().join("data").join("update-state.json"), None),
            now: NOW,
            running_as_service: false,
        };
        Self {
            _temp_dir: dir,
            context,
            fetcher: FakeFetcher::default(),
            health: FakeHealth::default(),
        }
    }

    fn serve(&mut self, envelope: String, binary: &[u8]) {
        self.fetcher
            .files
            .insert(MANIFEST_URL.to_string(), envelope.into_bytes());
        self.fetcher
            .files
            .insert(ARTIFACT_URL.to_string(), binary.to_vec());
    }

    fn run(&self, action: Action) -> Result<Outcome, UpdateError> {
        perform(
            &self.context,
            &self.fetcher,
            &self.health,
            MANIFEST_URL,
            action,
        )
    }

    fn installed(&self) -> Vec<u8> {
        std::fs::read(&self.context.layout.install_path).unwrap()
    }

    fn install_dir_entries(&self) -> Vec<String> {
        list_dir(&self.context.layout.install_dir)
    }
}

fn list_dir(dir: &std::path::Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// The install directory after a swap. Windows cannot overwrite the running executable, so it moves it aside to
/// `inveil.old` (deleted on the next start) and Unix leaves nothing behind.
fn entries_after_swap(entries: &[&str]) -> Vec<String> {
    let mut names: Vec<String> = entries.iter().map(|name| name.to_string()).collect();
    if cfg!(windows) {
        names.push("inveil.old".to_string());
    }
    names.sort();
    names
}

fn fixture_with_release(version: &str) -> (Fixture, Key) {
    let signer = key("release");
    let mut fixture = Fixture::new(&[&signer]);
    let envelope = signed_by(&manifest(version, NEW_BINARY), &[&signer]);
    fixture.serve(envelope, NEW_BINARY);
    (fixture, signer)
}

#[test]
fn installs_a_newer_release_and_keeps_the_previous_binary() {
    let (fixture, _) = fixture_with_release("0.2.0");

    let outcome = fixture.run(Action::Install).unwrap();

    assert!(matches!(outcome, Outcome::Installed(_)));
    assert_eq!(fixture.installed(), NEW_BINARY);
    let previous = fixture.context.layout.previous();
    assert_eq!(std::fs::read(previous).unwrap(), OLD_BINARY);
    assert_eq!(
        fixture.install_dir_entries(),
        entries_after_swap(&[PENDING, "inveil", "inveil.prev"])
    );
    assert_eq!(fixture.health.restarts.get(), 1);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&fixture.context.layout.install_path)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o111, 0o111);
    }
}

#[test]
fn reports_without_touching_the_install_dir() {
    let (fixture, _) = fixture_with_release("0.2.0");

    let outcome = fixture.run(Action::Report).unwrap();

    assert!(matches!(outcome, Outcome::Available(_)));
    assert_eq!(fixture.install_dir_entries(), ["inveil"]);
    assert_eq!(fixture.installed(), OLD_BINARY);
}

#[test]
fn staged_download_is_installed_later_without_downloading_again() {
    let (mut fixture, _) = fixture_with_release("0.2.0");
    assert!(matches!(
        fixture.run(Action::Stage).unwrap(),
        Outcome::Staged(_)
    ));
    assert_eq!(fixture.installed(), OLD_BINARY);

    fixture.fetcher.files.remove(ARTIFACT_URL);
    fixture.run(Action::Install).unwrap();

    assert_eq!(fixture.installed(), NEW_BINARY);
    assert_eq!(
        fixture.install_dir_entries(),
        entries_after_swap(&[PENDING, "inveil", "inveil.prev"])
    );
}

#[test]
fn leftover_partial_download_does_not_block_the_next_attempt() {
    let (fixture, _) = fixture_with_release("0.2.0");
    let staging = fixture.context.layout.staging_dir();
    std::fs::create_dir(&staging).unwrap();
    std::fs::write(fixture.context.layout.partial(), b"half a binary").unwrap();

    fixture.run(Action::Install).unwrap();

    assert_eq!(fixture.installed(), NEW_BINARY);
}

#[test]
fn same_version_is_up_to_date() {
    let (fixture, _) = fixture_with_release("0.1.0");
    assert!(matches!(
        fixture.run(Action::Install).unwrap(),
        Outcome::UpToDate
    ));
    assert_eq!(fixture.installed(), OLD_BINARY);
}

#[test]
fn tampered_manifest_is_rejected_before_parsing() {
    let (mut fixture, _) = fixture_with_release("0.2.0");
    let text = String::from_utf8(fixture.fetcher.files[MANIFEST_URL].clone()).unwrap();
    let mut envelope: SignedEnvelope = serde_json::from_str(&text).unwrap();
    envelope.payload = envelope.payload.replace("0.2.0", "9.9.9");
    fixture.serve(serde_json::to_string(&envelope).unwrap(), NEW_BINARY);

    let error = fixture.run(Action::Install).unwrap_err();

    assert!(matches!(
        error,
        UpdateError::Manifest(ManifestError::Signature(_))
    ));
    assert_eq!(fixture.install_dir_entries(), ["inveil"]);
}

#[test]
fn tampered_artifact_is_rejected_and_nothing_is_written_to_the_install_dir() {
    let signer = key("release");
    let mut fixture = Fixture::new(&[&signer]);
    let mut tampered = NEW_BINARY.to_vec();
    tampered[0] ^= 0xff;
    let envelope = signed_by(&manifest("0.2.0", NEW_BINARY), &[&signer]);
    fixture.serve(envelope, &tampered);

    let install_dir = fixture.context.layout.install_dir.clone();
    let install_path = fixture.context.layout.install_path.clone();
    let snapshots = Rc::new(RefCell::new(vec![]));
    let recorded = Rc::clone(&snapshots);
    fixture.fetcher.observer = Some(Rc::new(move || {
        recorded.borrow_mut().push((
            list_dir(&install_dir),
            std::fs::read(&install_path).unwrap(),
        ));
    }));

    let error = fixture.run(Action::Install).unwrap_err();

    assert!(matches!(
        error,
        UpdateError::Download(download::DownloadError::HashMismatch { .. })
    ));
    assert!(!snapshots.borrow().is_empty());
    for (entries, contents) in snapshots.borrow().iter() {
        assert!(entries
            .iter()
            .all(|name| name == "inveil" || name == ".inveil-update"));
        assert_eq!(contents, OLD_BINARY);
    }
    assert_eq!(fixture.install_dir_entries(), ["inveil"]);
    assert_eq!(fixture.installed(), OLD_BINARY);
}

#[test]
fn signed_hash_that_does_not_match_the_binary_is_rejected() {
    let signer = key("release");
    let mut fixture = Fixture::new(&[&signer]);
    let mut wrong_hash = manifest("0.2.0", NEW_BINARY);
    wrong_hash.artifacts.get_mut(TARGET).unwrap().sha256 = sha256_hex(b"something else");
    fixture.serve(signed_by(&wrong_hash, &[&signer]), NEW_BINARY);

    let error = fixture.run(Action::Install).unwrap_err();

    assert!(matches!(
        error,
        UpdateError::Download(download::DownloadError::HashMismatch { .. })
    ));
    assert_eq!(fixture.install_dir_entries(), ["inveil"]);
}

#[test]
fn download_larger_than_the_signed_size_is_rejected() {
    let signer = key("release");
    let mut fixture = Fixture::new(&[&signer]);
    let mut understated = manifest("0.2.0", NEW_BINARY);
    understated.artifacts.get_mut(TARGET).unwrap().size = 4;
    fixture.serve(signed_by(&understated, &[&signer]), NEW_BINARY);

    let error = fixture.run(Action::Install).unwrap_err();

    assert!(matches!(
        error,
        UpdateError::Download(download::DownloadError::SizeExceeded { expected: 4 })
    ));
    assert_eq!(fixture.install_dir_entries(), ["inveil"]);
}

#[test]
fn truncated_download_is_rejected() {
    let signer = key("release");
    let mut fixture = Fixture::new(&[&signer]);
    let envelope = signed_by(&manifest("0.2.0", NEW_BINARY), &[&signer]);
    fixture.serve(envelope, &NEW_BINARY[..10]);

    let error = fixture.run(Action::Install).unwrap_err();

    assert!(matches!(
        error,
        UpdateError::Download(download::DownloadError::Truncated { received: 10, .. })
    ));
    assert_eq!(fixture.install_dir_entries(), ["inveil"]);
}

#[test]
fn manifest_without_a_binary_for_this_target_is_rejected() {
    let signer = key("release");
    let mut fixture = Fixture::new(&[&signer]);
    let mut other_target = manifest("0.2.0", NEW_BINARY);
    let artifact = other_target.artifacts.remove(TARGET).unwrap();
    other_target
        .artifacts
        .insert("plan9-mips".to_string(), artifact);
    fixture.serve(signed_by(&other_target, &[&signer]), NEW_BINARY);

    let error = fixture.run(Action::Install).unwrap_err();

    assert!(matches!(
        error,
        UpdateError::Manifest(ManifestError::NoArtifactForTarget(_))
    ));
}

#[test]
fn older_version_is_a_refused_downgrade() {
    let (fixture, _) = fixture_with_release("0.0.9");
    let error = fixture.run(Action::Install).unwrap_err();
    assert!(matches!(
        error,
        UpdateError::Manifest(ManifestError::Downgrade { .. })
    ));
}

#[test]
fn expired_manifest_is_refused() {
    let signer = key("release");
    let mut fixture = Fixture::new(&[&signer]);
    let mut expired = manifest("0.2.0", NEW_BINARY);
    expired.expires_at = NOW;
    fixture.serve(signed_by(&expired, &[&signer]), NEW_BINARY);

    let error = fixture.run(Action::Install).unwrap_err();

    assert!(matches!(
        error,
        UpdateError::Manifest(ManifestError::Expired { .. })
    ));
}

#[test]
fn manifest_for_another_channel_is_refused() {
    let signer = key("release");
    let mut fixture = Fixture::new(&[&signer]);
    let mut beta = manifest("0.2.0", NEW_BINARY);
    beta.channel = "beta".to_string();
    fixture.serve(signed_by(&beta, &[&signer]), NEW_BINARY);

    let error = fixture.run(Action::Install).unwrap_err();

    assert!(matches!(
        error,
        UpdateError::Manifest(ManifestError::WrongChannel { .. })
    ));
}

#[test]
fn replaying_an_older_valid_manifest_after_a_newer_one_is_refused() {
    let signer = key("release");
    let mut fixture = Fixture::new(&[&signer]);
    fixture.serve(
        signed_by(&manifest("0.5.0", NEW_BINARY), &[&signer]),
        NEW_BINARY,
    );
    fixture.run(Action::Report).unwrap();

    fixture.serve(
        signed_by(&manifest("0.2.0", NEW_BINARY), &[&signer]),
        NEW_BINARY,
    );
    let error = fixture.run(Action::Report).unwrap_err();

    assert!(matches!(
        error,
        UpdateError::Manifest(ManifestError::Replay { .. })
    ));
}

#[test]
fn same_version_with_a_different_binary_is_refused_but_a_renewed_manifest_is_fine() {
    let signer = key("release");
    let mut fixture = Fixture::new(&[&signer]);
    fixture.serve(
        signed_by(&manifest("0.2.0", NEW_BINARY), &[&signer]),
        NEW_BINARY,
    );
    fixture.run(Action::Report).unwrap();

    let mut renewed = manifest("0.2.0", NEW_BINARY);
    renewed.expires_at += 500;
    fixture.serve(signed_by(&renewed, &[&signer]), NEW_BINARY);
    assert!(fixture.run(Action::Report).is_ok());

    let swapped = b"a different binary of the same version";
    fixture.serve(signed_by(&manifest("0.2.0", swapped), &[&signer]), swapped);
    let error = fixture.run(Action::Report).unwrap_err();
    assert!(matches!(
        error,
        UpdateError::Manifest(ManifestError::ConflictingArtifact(_))
    ));
}

#[test]
fn mandatory_flag_is_set_when_running_below_min_supported() {
    let signer = key("release");
    let mut fixture = Fixture::new(&[&signer]);
    let mut required = manifest("0.3.0", NEW_BINARY);
    required.min_supported = Some("0.2.0".to_string());
    fixture.serve(signed_by(&required, &[&signer]), NEW_BINARY);

    let outcome = fixture.run(Action::Report).unwrap();

    assert!(matches!(outcome, Outcome::Available(candidate) if candidate.mandatory));
}

#[test]
fn single_signature_does_not_meet_a_threshold_of_two() {
    let (first, second) = (key("ci"), key("maintainer"));
    let mut fixture = Fixture::new(&[&first, &second]);
    let mut two_required = manifest("0.2.0", NEW_BINARY);
    two_required.threshold = 2;
    fixture.serve(signed_by(&two_required, &[&first]), NEW_BINARY);

    let error = fixture.run(Action::Install).unwrap_err();

    assert!(matches!(
        error,
        UpdateError::Manifest(ManifestError::Signature(VerifyError::NotEnoughSignatures {
            valid: 1,
            required: 2
        }))
    ));
    fixture.serve(signed_by(&two_required, &[&first, &second]), NEW_BINARY);
    assert!(fixture.run(Action::Install).is_ok());
}

#[test]
fn the_same_key_signing_twice_counts_once() {
    let (first, second) = (key("ci"), key("maintainer"));
    let mut fixture = Fixture::new(&[&first, &second]);
    let mut two_required = manifest("0.2.0", NEW_BINARY);
    two_required.threshold = 2;
    fixture.serve(signed_by(&two_required, &[&first, &first]), NEW_BINARY);

    let error = fixture.run(Action::Install).unwrap_err();

    assert!(matches!(
        error,
        UpdateError::Manifest(ManifestError::Signature(VerifyError::NotEnoughSignatures {
            valid: 1,
            ..
        }))
    ));
}

#[test]
fn key_rotation_accepts_the_new_key_and_rejects_the_dropped_one() {
    let (old, new) = (key("old"), key("new"));
    let release = signed_by(&manifest("0.2.0", NEW_BINARY), &[&new]);
    let mut during_rotation = Fixture::new(&[&old, &new]);
    during_rotation.serve(release.clone(), NEW_BINARY);
    assert!(during_rotation.run(Action::Report).is_ok());

    let mut after_rotation = Fixture::new(&[&new]);
    after_rotation.serve(release, NEW_BINARY);
    assert!(after_rotation.run(Action::Report).is_ok());
    after_rotation.serve(
        signed_by(&manifest("0.3.0", NEW_BINARY), &[&old]),
        NEW_BINARY,
    );
    assert!(after_rotation.run(Action::Report).is_err());
}

#[test]
fn revoked_key_signatures_stop_counting_immediately_and_forever() {
    let (compromised, healthy) = (key("compromised"), key("healthy"));
    let mut fixture = Fixture::new(&[&compromised, &healthy]);

    let mut revoking = manifest("0.2.0", NEW_BINARY);
    revoking.threshold = 2;
    revoking.revoked_key_ids = vec!["compromised".to_string()];
    fixture.serve(signed_by(&revoking, &[&compromised, &healthy]), NEW_BINARY);
    assert!(fixture.run(Action::Report).is_err());

    let mut recovered = manifest("0.2.0", NEW_BINARY);
    recovered.revoked_key_ids = vec!["compromised".to_string()];
    fixture.serve(signed_by(&recovered, &[&healthy]), NEW_BINARY);
    assert!(fixture.run(Action::Report).is_ok());

    fixture.serve(
        signed_by(&manifest("0.3.0", NEW_BINARY), &[&compromised]),
        NEW_BINARY,
    );
    assert!(matches!(
        fixture.run(Action::Report).unwrap_err(),
        UpdateError::Manifest(ManifestError::Signature(_))
    ));
}

#[test]
fn a_revoked_key_is_remembered_by_public_key_and_stays_revoked_under_another_id() {
    let (compromised, healthy) = (key("compromised"), key("healthy"));
    let mut fixture = Fixture::new(&[&compromised, &healthy]);
    let mut recovered = manifest("0.2.0", NEW_BINARY);
    recovered.revoked_key_ids = vec!["compromised".to_string()];
    fixture.serve(signed_by(&recovered, &[&healthy]), NEW_BINARY);
    fixture.run(Action::Report).unwrap();

    let stored = fixture
        .context
        .state
        .load::<state::UpdateState>()
        .unwrap()
        .state;
    assert_eq!(
        stored.revoked_public_keys,
        std::collections::BTreeSet::from([compromised.pinned.public_key])
    );

    let renamed = Key {
        pkcs8: compromised.pkcs8.clone(),
        pinned: PinnedKey {
            key_id: "renamed".to_string(),
            ..compromised.pinned.clone()
        },
    };
    fixture.context.trust.keys = vec![renamed.pinned.clone(), healthy.pinned.clone()];
    fixture.serve(
        signed_by(&manifest("0.3.0", NEW_BINARY), &[&renamed]),
        NEW_BINARY,
    );
    assert!(matches!(
        fixture.run(Action::Report).unwrap_err(),
        UpdateError::Manifest(ManifestError::Signature(_))
    ));
}

#[test]
fn unhealthy_new_version_is_rolled_back_to_the_previous_binary() {
    let (mut fixture, _) = fixture_with_release("0.2.0");
    fixture.health.unhealthy = true;

    let error = fixture.run(Action::Install).unwrap_err();

    assert!(matches!(
        error,
        UpdateError::Apply(apply::ApplyError::RolledBack { .. })
    ));
    assert_eq!(fixture.installed(), OLD_BINARY);
    assert_eq!(fixture.health.restarts.get(), 2);
    assert_eq!(
        fixture.install_dir_entries(),
        entries_after_swap(&["inveil", "inveil.prev"])
    );
}

#[test]
fn replaced_executable_left_by_a_windows_update_is_cleaned_up() {
    let (fixture, _) = fixture_with_release("0.2.0");
    let replaced = fixture.context.layout.replaced();
    std::fs::write(&replaced, OLD_BINARY).unwrap();

    remove_replaced(&fixture.context.layout);

    assert!(!replaced.exists());
}

#[test]
fn removing_the_replaced_executable_reports_whether_it_existed() {
    let (fixture, _) = fixture_with_release("0.2.0");
    let layout = &fixture.context.layout;
    std::fs::write(layout.replaced(), OLD_BINARY).unwrap();

    assert!(remove_replaced_file(layout).unwrap());
    assert!(!layout.replaced().exists());
    assert!(!remove_replaced_file(layout).unwrap());
}

#[test]
fn removing_the_replaced_executable_reports_a_failure_instead_of_panicking() {
    let (fixture, _) = fixture_with_release("0.2.0");
    let layout = &fixture.context.layout;
    std::fs::create_dir(layout.replaced()).unwrap();

    assert!(matches!(
        remove_replaced_file(layout),
        Err(UpdateError::File(_))
    ));
}

#[test]
fn off_mode_and_apply_flag_are_validated() {
    assert_eq!(
        requested_action(UpdateMode::Off, false, false).unwrap(),
        None
    );
    assert_eq!(
        requested_action(UpdateMode::Notify, false, false).unwrap(),
        Some(Action::Report)
    );
    assert_eq!(
        requested_action(UpdateMode::Download, false, false).unwrap(),
        Some(Action::Stage)
    );
    assert_eq!(
        requested_action(UpdateMode::Download, false, true).unwrap(),
        Some(Action::Install)
    );
    assert_eq!(
        requested_action(UpdateMode::Install, true, false).unwrap(),
        Some(Action::Report)
    );
    assert!(requested_action(UpdateMode::Notify, false, true).is_err());
}

#[test]
fn check_is_due_when_never_checked_or_the_interval_has_passed() {
    let hour = Duration::from_secs(SECONDS_PER_HOUR);
    assert!(check_due(None, 24));
    assert!(!check_due(Some(SystemTime::now() - hour), 24));
    assert!(check_due(Some(SystemTime::now() - hour * 25), 24));
    assert!(check_due(Some(SystemTime::now() + hour), 24));
}

fn spawn_redirecting_server() -> u16 {
    let (port_sender, port_receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let app = axum::Router::new()
                .route(
                    "/ok",
                    axum::routing::get(|| async { "plain loopback body" }),
                )
                .route(
                    "/redirect",
                    axum::routing::get(|| async {
                        axum::response::Redirect::temporary("http://127.0.0.1:9/elsewhere")
                    }),
                );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            port_sender
                .send(listener.local_addr().unwrap().port())
                .unwrap();
            axum::serve(listener, app).await.unwrap();
        });
    });
    port_receiver.recv().unwrap()
}

#[test]
fn http_fetcher_refuses_remote_http_and_redirects_to_http() {
    let timeout = Duration::from_secs(5);
    let remote = HttpFetcher.open("http://example.com/manifest.json", timeout);
    assert!(matches!(remote, Err(FetchError::InsecureUrl(_))));

    let port = spawn_redirecting_server();
    let mut body = String::new();
    HttpFetcher
        .open(&format!("http://127.0.0.1:{port}/ok"), timeout)
        .unwrap()
        .read_to_string(&mut body)
        .unwrap();
    assert_eq!(body, "plain loopback body");

    let redirected = HttpFetcher.open(&format!("http://127.0.0.1:{port}/redirect"), timeout);
    assert!(matches!(redirected, Err(FetchError::Http(error)) if error.is_redirect()));
}

fn strings(args: &[&str]) -> Vec<String> {
    args.iter().map(ToString::to_string).collect()
}

fn config_trusting(key_id: &str, public_key: &str) -> Config {
    let mut config = Config::default();
    config.update.pinned_keys.push(config::PinnedKeyConfig {
        key_id: key_id.to_string(),
        public_key: public_key.to_string(),
    });
    config
}

fn generate_key(dir: &std::path::Path, name: &str) -> (String, String) {
    let path = dir.join(name);
    let output = run_keygen(&strings(&["--out", path.to_str().unwrap()])).unwrap();
    let public_key = output
        .lines()
        .find_map(|line| line.strip_prefix("public_key: "))
        .unwrap()
        .to_string();
    (path.to_str().unwrap().to_string(), public_key)
}

#[test]
fn keygen_writes_an_owner_only_key_and_prints_only_the_public_half() {
    let dir = TempDir::new().unwrap();
    let (key_path, public_key) = generate_key(dir.path(), "update.key");

    let private = std::fs::read_to_string(&key_path).unwrap();
    let output = run_keygen(&strings(&[
        "--out",
        dir.path().join("second.key").to_str().unwrap(),
    ]))
    .unwrap();
    assert!(!output.contains(private.trim()));
    assert_eq!(STANDARD.decode(&public_key).unwrap().len(), 32);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&key_path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    assert!(run_keygen(&strings(&["--out", &key_path])).is_err());
}

#[test]
fn signed_manifest_verifies_with_the_pinned_key_and_a_co_signature_adds_a_second_signer() {
    let dir = TempDir::new().unwrap();
    let (first_key, first_public) = generate_key(dir.path(), "ci.key");
    let (second_key, second_public) = generate_key(dir.path(), "maintainer.key");
    let mut threshold_two = manifest("0.2.0", NEW_BINARY);
    threshold_two.threshold = 2;
    threshold_two.expires_at = unix_seconds() + 3_600;
    let payload_path = dir.path().join("manifest.json");
    std::fs::write(
        &payload_path,
        serde_json::to_string(&threshold_two).unwrap(),
    )
    .unwrap();
    let payload = payload_path.to_str().unwrap();

    let first = run_sign(&strings(&[
        "--role", "update", "--key", &first_key, "--key-id", "ci", payload,
    ]))
    .unwrap();
    let envelope_path = dir.path().join("envelope.json");
    std::fs::write(&envelope_path, &first).unwrap();
    let envelope = envelope_path.to_str().unwrap();

    let mut config = config_trusting("ci", &first_public);
    config.update.pinned_keys.push(config::PinnedKeyConfig {
        key_id: "maintainer".to_string(),
        public_key: second_public,
    });
    assert!(run_verify(&config, &strings(&[envelope])).is_err());

    let duplicate = run_sign(&strings(&[
        "--role",
        "update",
        "--key",
        &first_key,
        "--key-id",
        "ci",
        "--co-sign",
        envelope,
    ]));
    assert!(matches!(duplicate, Err(UpdateError::Usage(_))));

    let both = run_sign(&strings(&[
        "--role",
        "update",
        "--key",
        &second_key,
        "--key-id",
        "maintainer",
        "--co-sign",
        envelope,
    ]))
    .unwrap();
    std::fs::write(&envelope_path, both).unwrap();
    let report = run_verify(&config, &strings(&[envelope])).unwrap();
    assert!(report.contains("version: 0.2.0"));
    assert!(report.contains("channel: stable"));
    assert!(report.contains("signers: ci, maintainer"));
    assert!(report.contains("payload_sha256: "));
}

#[test]
fn signing_reads_the_key_from_the_environment_and_rejects_a_wrong_role_on_verify() {
    let dir = TempDir::new().unwrap();
    let (key_path, public_key) = generate_key(dir.path(), "update.key");
    std::env::set_var(
        "INVEIL_TEST_SIGNING_KEY",
        std::fs::read_to_string(&key_path).unwrap(),
    );
    let mut release = manifest("0.2.0", NEW_BINARY);
    release.expires_at = unix_seconds() + 3_600;
    let payload_path = dir.path().join("manifest.json");
    std::fs::write(&payload_path, serde_json::to_string(&release).unwrap()).unwrap();

    let envelope = run_sign(&strings(&[
        "--role",
        "update",
        "--key",
        "env:INVEIL_TEST_SIGNING_KEY",
        "--key-id",
        "ci",
        payload_path.to_str().unwrap(),
    ]))
    .unwrap();
    let envelope_path = dir.path().join("envelope.json");
    std::fs::write(&envelope_path, envelope).unwrap();

    let mut config = config_trusting("ci", &public_key);
    assert!(run_verify(&config, &strings(&[envelope_path.to_str().unwrap()])).is_ok());

    config.backend.pinned_keys = config.update.pinned_keys.clone();
    let as_policy = run_verify(
        &config,
        &strings(&["--role", "policy", envelope_path.to_str().unwrap()]),
    );
    assert!(as_policy.is_err());
}

#[test]
fn signing_refuses_a_payload_that_is_not_a_valid_manifest() {
    let dir = TempDir::new().unwrap();
    let (key_path, _) = generate_key(dir.path(), "update.key");
    let payload_path = dir.path().join("bad.json");
    std::fs::write(&payload_path, "{\"schema\":1}").unwrap();

    let result = run_sign(&strings(&[
        "--role",
        "update",
        "--key",
        &key_path,
        "--key-id",
        "ci",
        payload_path.to_str().unwrap(),
    ]));

    assert!(matches!(result, Err(UpdateError::Payload(_))));
}

#[test]
fn verify_accepts_command_line_keys_and_checks_the_binary_against_the_manifest() {
    let dir = TempDir::new().unwrap();
    let (key_path, public_key) = generate_key(dir.path(), "update.key");
    let mut release = manifest("0.2.0", NEW_BINARY);
    release.expires_at = unix_seconds() + 3_600;
    let payload_path = dir.path().join("manifest.json");
    std::fs::write(&payload_path, serde_json::to_string(&release).unwrap()).unwrap();
    let envelope = run_sign(&strings(&[
        "--role",
        "update",
        "--key",
        &key_path,
        "--key-id",
        "ci",
        payload_path.to_str().unwrap(),
    ]))
    .unwrap();
    let envelope_path = dir.path().join("manifest.sig");
    std::fs::write(&envelope_path, envelope).unwrap();
    let binary_path = dir.path().join("inveil-linux-x86_64");
    std::fs::write(&binary_path, NEW_BINARY).unwrap();

    let pinned = format!("ci={public_key}");
    let verify = |binary: &std::path::Path| {
        run_verify(
            &Config::default(),
            &strings(&[
                "--role",
                "update",
                "--pinned-key",
                &pinned,
                "--artifact",
                binary.to_str().unwrap(),
                envelope_path.to_str().unwrap(),
            ]),
        )
    };

    let report = verify(&binary_path).unwrap();
    assert!(report.contains("signers: ci"));
    assert!(report.contains("artifact: linux-x86_64 matches the manifest"));

    let mut tampered = NEW_BINARY.to_vec();
    tampered[0] ^= 0xff;
    std::fs::write(&binary_path, &tampered).unwrap();
    assert!(matches!(
        verify(&binary_path),
        Err(UpdateError::ArtifactMismatch(_))
    ));

    std::fs::write(&binary_path, &NEW_BINARY[..5]).unwrap();
    assert!(matches!(
        verify(&binary_path),
        Err(UpdateError::ArtifactMismatch(_))
    ));

    let unnamed = dir.path().join("some-binary");
    std::fs::write(&unnamed, NEW_BINARY).unwrap();
    assert!(matches!(verify(&unnamed), Err(UpdateError::Usage(_))));

    let other_target = dir.path().join("inveil-windows-aarch64.exe");
    std::fs::write(&other_target, NEW_BINARY).unwrap();
    assert!(matches!(
        verify(&other_target),
        Err(UpdateError::ArtifactMismatch(_))
    ));

    let wrong_key = run_verify(
        &Config::default(),
        &strings(&[
            "--pinned-key",
            &format!("ci={}", STANDARD.encode([7u8; 32])),
            envelope_path.to_str().unwrap(),
        ]),
    );
    assert!(wrong_key.is_err());
}

#[test]
fn ci_flow_signs_a_manifest_file_then_co_signs_the_resulting_envelope() {
    let dir = TempDir::new().unwrap();
    let (ci_key, ci_public) = generate_key(dir.path(), "ci.key");
    let (maintainer_key, maintainer_public) = generate_key(dir.path(), "maintainer.key");
    let mut release = manifest("0.2.0", NEW_BINARY);
    release.threshold = 2;
    release.expires_at = unix_seconds() + 3_600;
    let manifest_path = dir.path().join("update-manifest.json");
    std::fs::write(&manifest_path, serde_json::to_string(&release).unwrap()).unwrap();
    let sig_path = dir.path().join("update-manifest.json.sig");

    let first = run_sign(&strings(&[
        "--role",
        "update",
        "--key",
        &ci_key,
        "--key-id",
        "ci",
        manifest_path.to_str().unwrap(),
    ]))
    .unwrap();
    std::fs::write(&sig_path, first).unwrap();
    let second = run_sign(&strings(&[
        "--role",
        "update",
        "--co-sign",
        "--key",
        &maintainer_key,
        "--key-id",
        "maintainer",
        sig_path.to_str().unwrap(),
    ]))
    .unwrap();
    std::fs::write(&sig_path, second).unwrap();

    let both_keys = strings(&[
        "--pinned-key",
        &format!("ci={ci_public}"),
        "--pinned-key",
        &format!("maintainer={maintainer_public}"),
        sig_path.to_str().unwrap(),
    ]);
    let report = run_verify(&Config::default(), &both_keys).unwrap();
    assert!(report.contains("signers: ci, maintainer"));
}

fn fixture_with_min_signatures(min_signatures: usize, trusted: &[&Key]) -> Fixture {
    let mut fixture = Fixture::new(trusted);
    fixture.context.min_signatures = min_signatures;
    fixture
}

#[test]
fn a_manifest_cannot_lower_the_locally_pinned_minimum_number_of_signers() {
    let (first, second) = (key("ci"), key("maintainer"));
    let mut fixture = fixture_with_min_signatures(2, &[&first, &second]);
    let lenient = manifest("0.2.0", NEW_BINARY);
    assert_eq!(lenient.threshold, 1);
    fixture.serve(signed_by(&lenient, &[&first]), NEW_BINARY);

    let error = fixture.run(Action::Install).unwrap_err();

    assert!(matches!(
        error,
        UpdateError::Manifest(ManifestError::Signature(VerifyError::NotEnoughSignatures {
            valid: 1,
            required: 2
        }))
    ));
    assert_eq!(fixture.installed(), OLD_BINARY);
    fixture.serve(signed_by(&lenient, &[&first, &second]), NEW_BINARY);
    assert!(fixture.run(Action::Install).is_ok());
}

#[test]
fn a_manifest_can_ask_for_more_signers_than_the_local_minimum() {
    let (first, second) = (key("ci"), key("maintainer"));
    let mut fixture = fixture_with_min_signatures(1, &[&first, &second]);
    let mut strict = manifest("0.2.0", NEW_BINARY);
    strict.threshold = 2;
    fixture.serve(signed_by(&strict, &[&first]), NEW_BINARY);
    assert!(fixture.run(Action::Report).is_err());
}

#[test]
fn two_key_ids_pinned_to_one_public_key_count_as_one_signer() {
    let signer = key("ci");
    let alias = PinnedKey {
        key_id: "ci-alias".to_string(),
        public_key: signer.pinned.public_key,
    };
    let mut fixture = fixture_with_min_signatures(2, &[&signer]);
    fixture.context.trust.keys.push(alias.clone());
    let envelope = {
        let payload = serde_json::to_string(&manifest("0.2.0", NEW_BINARY)).unwrap();
        let signatures = ["ci", "ci-alias"]
            .iter()
            .map(|id| sign_payload(Role::Update, id, &signer.pkcs8, &payload).unwrap())
            .collect();
        serde_json::to_string(&SignedEnvelope {
            payload,
            signatures,
            delegation: None,
        })
        .unwrap()
    };
    fixture.serve(envelope, NEW_BINARY);

    let error = fixture.run(Action::Report).unwrap_err();

    assert!(matches!(
        error,
        UpdateError::Manifest(ManifestError::Signature(VerifyError::NotEnoughSignatures {
            valid: 1,
            required: 2
        }))
    ));
}

#[test]
fn a_manifest_that_offers_nothing_does_not_persist_its_revocations() {
    let (old, current) = (key("old"), key("current"));
    let mut fixture = Fixture::new(&[&old, &current]);
    let mut same_version = manifest("0.1.0", OLD_BINARY);
    same_version.revoked_key_ids = vec!["old".to_string()];
    fixture.serve(signed_by(&same_version, &[&current]), OLD_BINARY);
    assert!(matches!(
        fixture.run(Action::Report).unwrap(),
        Outcome::UpToDate
    ));

    fixture.serve(
        signed_by(&manifest("0.2.0", NEW_BINARY), &[&old]),
        NEW_BINARY,
    );
    assert!(fixture.run(Action::Report).is_ok());
}

#[test]
fn a_manifest_that_is_refused_does_not_persist_its_revocations() {
    let (old, current) = (key("old"), key("current"));
    let mut fixture = Fixture::new(&[&old, &current]);
    let mut wrong_channel = manifest("0.2.0", NEW_BINARY);
    wrong_channel.channel = "beta".to_string();
    wrong_channel.revoked_key_ids = vec!["old".to_string()];
    fixture.serve(signed_by(&wrong_channel, &[&current]), NEW_BINARY);
    assert!(fixture.run(Action::Report).is_err());

    fixture.serve(
        signed_by(&manifest("0.2.0", NEW_BINARY), &[&old]),
        NEW_BINARY,
    );
    assert!(fixture.run(Action::Report).is_ok());
}

#[test]
fn a_manifest_cannot_revoke_the_only_key_that_signed_it() {
    let (only, spare) = (key("only"), key("spare"));
    let mut fixture = Fixture::new(&[&only, &spare]);
    let mut suicidal = manifest("0.2.0", NEW_BINARY);
    suicidal.revoked_key_ids = vec!["only".to_string()];
    fixture.serve(signed_by(&suicidal, &[&only]), NEW_BINARY);

    let error = fixture.run(Action::Report).unwrap_err();

    assert!(matches!(
        error,
        UpdateError::Manifest(ManifestError::Revocation(_))
    ));
    fixture.serve(
        signed_by(&manifest("0.2.0", NEW_BINARY), &[&only]),
        NEW_BINARY,
    );
    assert!(fixture.run(Action::Report).is_ok());
}

fn verify_release(release: &UpdateManifest, extra: &[&str]) -> Result<String, UpdateError> {
    let dir = TempDir::new().unwrap();
    let (key_path, public_key) = generate_key(dir.path(), "update.key");
    let payload_path = dir.path().join("manifest.json");
    std::fs::write(&payload_path, serde_json::to_string(release).unwrap()).unwrap();
    let envelope = run_sign(&strings(&[
        "--role",
        "update",
        "--key",
        &key_path,
        "--key-id",
        "ci",
        payload_path.to_str().unwrap(),
    ]))
    .unwrap();
    let envelope_path = dir.path().join("manifest.sig");
    std::fs::write(&envelope_path, envelope).unwrap();
    let mut args = strings(extra);
    args.extend(strings(&[
        "--pinned-key",
        &format!("ci={public_key}"),
        envelope_path.to_str().unwrap(),
    ]));
    run_verify(&Config::default(), &args)
}

fn fresh_release(version: &str) -> UpdateManifest {
    let mut release = manifest(version, NEW_BINARY);
    release.expires_at = unix_seconds() + 3_600;
    release
}

#[test]
fn verify_enforces_expiry_channel_and_the_minimum_version() {
    let report = verify_release(&fresh_release("99.0.0"), &[]).unwrap();
    assert!(
        report.contains("version: 99.0.0 (newer than this binary)"),
        "{report}"
    );

    let mut expired = fresh_release("99.0.0");
    expired.expires_at = unix_seconds() - 1;
    assert!(matches!(
        verify_release(&expired, &[]),
        Err(UpdateError::Manifest(ManifestError::Expired { .. }))
    ));

    let mut beta = fresh_release("99.0.0");
    beta.channel = "beta".to_string();
    assert!(matches!(
        verify_release(&beta, &[]),
        Err(UpdateError::Manifest(ManifestError::WrongChannel { .. }))
    ));
    assert!(verify_release(&beta, &["--channel", "beta"]).is_ok());

    assert!(matches!(
        verify_release(&fresh_release("0.0.1"), &[]),
        Err(UpdateError::Manifest(ManifestError::Downgrade { .. }))
    ));

    let mut impossible = fresh_release("99.0.0");
    impossible.min_supported = Some("100.0.0".to_string());
    assert!(matches!(
        verify_release(&impossible, &[]),
        Err(UpdateError::Manifest(
            ManifestError::MinSupportedAboveVersion { .. }
        ))
    ));

    let mut required = fresh_release("100.0.0");
    required.min_supported = Some("99.0.0".to_string());
    let report = verify_release(&required, &[]).unwrap();
    assert!(report.contains("(required)"), "{report}");
}

#[test]
fn verify_takes_the_minimum_number_of_signers_from_the_flag_or_the_configuration() {
    let release = fresh_release("0.2.0");
    assert!(verify_release(&release, &["--min-signatures", "1"]).is_ok());
    assert!(matches!(
        verify_release(&release, &["--min-signatures", "2"]),
        Err(UpdateError::Manifest(ManifestError::Signature(
            VerifyError::NotEnoughSignatures { required: 2, .. }
        )))
    ));
    assert!(matches!(
        verify_release(&release, &["--min-signatures", "none"]),
        Err(UpdateError::Usage(_))
    ));
}

fn marker(fixture: &Fixture) -> Option<PendingUpdate> {
    PendingUpdate::load(&fixture.context.layout).unwrap()
}

fn installed_by_the_service(version: &str) -> Fixture {
    let (mut fixture, _) = fixture_with_release(version);
    fixture.context.running_as_service = true;
    let outcome = fixture.run(Action::Install).unwrap();
    assert!(matches!(outcome, Outcome::InstalledAwaitingRestart(_)));
    fixture
}

#[test]
fn the_service_swaps_the_binary_and_leaves_the_restart_to_its_supervisor() {
    let fixture = installed_by_the_service("0.2.0");

    assert_eq!(fixture.installed(), NEW_BINARY);
    assert_eq!(fixture.health.restarts.get(), 0);
    let pending = marker(&fixture).unwrap();
    assert_eq!(pending.version, "0.2.0");
    assert_eq!(pending.sha256, sha256_hex(NEW_BINARY));
    assert_eq!(pending.starts, 0);
}

#[test]
fn a_binary_that_cannot_run_is_never_installed() {
    let (mut fixture, _) = fixture_with_release("0.2.0");
    fixture.health.wont_run = true;

    let error = fixture.run(Action::Install).unwrap_err();

    assert!(matches!(
        error,
        UpdateError::Apply(apply::ApplyError::SmokeTest(_))
    ));
    assert_eq!(fixture.installed(), OLD_BINARY);
    assert_eq!(fixture.install_dir_entries(), ["inveil"]);
}

#[test]
fn a_healthy_new_version_clears_the_marker_once_it_is_listening() {
    let fixture = installed_by_the_service("0.2.0");
    let layout = &fixture.context.layout;
    let running = Version::new(0, 2, 0);

    pending::recover_on_start(layout, &running).unwrap();
    assert_eq!(marker(&fixture).unwrap().starts, 1);
    pending::confirm_started(layout, &running).unwrap();

    assert!(marker(&fixture).is_none());
    assert_eq!(fixture.installed(), NEW_BINARY);
}

#[test]
fn a_new_version_that_never_becomes_healthy_is_rolled_back_even_though_the_updater_exited() {
    let fixture = installed_by_the_service("0.2.0");
    let layout = &fixture.context.layout;
    let running = Version::new(0, 2, 0);

    for _ in 0..pending::MAX_START_ATTEMPTS {
        pending::recover_on_start(layout, &running).unwrap();
    }
    let error = pending::recover_on_start(layout, &running).unwrap_err();

    assert!(
        matches!(error, UpdateError::RolledBackAtStart { .. }),
        "{error}"
    );
    assert_eq!(fixture.installed(), OLD_BINARY);
    assert!(marker(&fixture).is_none());
    pending::recover_on_start(layout, &Version::new(0, 1, 0)).unwrap();
}

#[test]
fn a_new_binary_that_reports_another_version_is_rolled_back_at_its_first_start() {
    let fixture = installed_by_the_service("0.2.0");

    let error =
        pending::recover_on_start(&fixture.context.layout, &Version::new(0, 1, 9)).unwrap_err();

    assert!(matches!(error, UpdateError::RolledBackAtStart { .. }));
    assert_eq!(fixture.installed(), OLD_BINARY);
}

#[test]
fn a_crash_before_the_swap_finished_is_cleaned_up_at_the_next_start() {
    let (fixture, _) = fixture_with_release("0.2.0");
    let layout = &fixture.context.layout;
    PendingUpdate::new(&Version::new(0, 2, 0), &sha256_hex(NEW_BINARY))
        .write(layout)
        .unwrap();

    pending::recover_on_start(layout, &Version::new(0, 1, 0)).unwrap();

    assert!(marker(&fixture).is_none());
    assert_eq!(fixture.installed(), OLD_BINARY);
}

#[test]
fn an_unreadable_marker_is_discarded_instead_of_blocking_the_start() {
    let (fixture, _) = fixture_with_release("0.2.0");
    let layout = &fixture.context.layout;
    std::fs::write(layout.pending(), "{ torn write").unwrap();

    pending::recover_on_start(layout, &Version::new(0, 1, 0)).unwrap();

    assert!(!layout.pending().exists());
}

#[test]
fn a_start_with_nothing_pending_does_nothing() {
    let (fixture, _) = fixture_with_release("0.2.0");
    pending::recover_on_start(&fixture.context.layout, &Version::new(0, 1, 0)).unwrap();
    pending::confirm_started(&fixture.context.layout, &Version::new(0, 1, 0)).unwrap();
    assert_eq!(fixture.install_dir_entries(), ["inveil"]);
}

#[test]
fn the_updater_state_is_refused_when_an_older_copy_is_restored() {
    use crate::trust_state::tests::MemoryVault;
    let signer = key("release");
    let mut fixture = Fixture::new(&[&signer]);
    let state_path = fixture.context.layout.install_dir.join("update-state.json");
    fixture.context.state = StateStore::new(
        state_path.clone(),
        Some(std::sync::Arc::new(MemoryVault::default())),
    );
    fixture.serve(
        signed_by(&manifest("0.2.0", NEW_BINARY), &[&signer]),
        NEW_BINARY,
    );
    fixture.run(Action::Report).unwrap();
    let old_state = std::fs::read(&state_path).unwrap();
    fixture.serve(
        signed_by(&manifest("0.3.0", NEW_BINARY), &[&signer]),
        NEW_BINARY,
    );
    fixture.run(Action::Report).unwrap();

    std::fs::write(&state_path, old_state).unwrap();

    assert!(matches!(
        fixture.run(Action::Report).unwrap_err(),
        UpdateError::Manifest(ManifestError::State(_))
    ));
}

fn crashed_between_the_windows_renames(version: &str) -> Fixture {
    let fixture = installed_by_the_service(version);
    let layout = &fixture.context.layout;
    std::fs::rename(&layout.install_path, layout.replaced()).unwrap();
    fixture
}

#[test]
fn a_swap_that_crashed_between_the_renames_is_rebuilt_from_the_previous_version() {
    let fixture = crashed_between_the_windows_renames("0.2.0");
    let layout = &fixture.context.layout;
    assert!(!layout.install_path.exists());
    assert!(marker(&fixture).is_some());

    let restored = apply::restore_missing_install(layout).unwrap();

    assert_eq!(restored, apply::Restored::From(layout.previous()));
    assert_eq!(fixture.installed(), OLD_BINARY);
    assert!(marker(&fixture).is_none());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&layout.install_path)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o111, 0o111);
    }
}

#[test]
fn recovery_prefers_the_previous_version_over_a_moved_aside_binary_of_unknown_quality() {
    let fixture = crashed_between_the_windows_renames("0.2.0");
    let layout = &fixture.context.layout;
    std::fs::write(layout.replaced(), b"the bad binary a rollback moved aside").unwrap();

    apply::restore_missing_install(layout).unwrap();

    assert_eq!(fixture.installed(), OLD_BINARY);
}

#[test]
fn recovery_falls_back_to_the_moved_aside_binary_when_there_is_no_previous_version() {
    let fixture = crashed_between_the_windows_renames("0.2.0");
    let layout = &fixture.context.layout;
    std::fs::remove_file(layout.previous()).unwrap();

    let restored = apply::restore_missing_install(layout).unwrap();

    assert_eq!(restored, apply::Restored::From(layout.replaced()));
    assert_eq!(fixture.installed(), NEW_BINARY);
}

#[test]
fn recovery_leaves_a_present_executable_alone() {
    let fixture = installed_by_the_service("0.2.0");

    let restored = apply::restore_missing_install(&fixture.context.layout).unwrap();

    assert_eq!(restored, apply::Restored::NotNeeded);
    assert_eq!(fixture.installed(), NEW_BINARY);
    assert!(marker(&fixture).is_some());
}

#[test]
fn recovery_without_anything_to_restore_from_is_an_error() {
    let (fixture, _) = fixture_with_release("0.2.0");
    std::fs::remove_file(&fixture.context.layout.install_path).unwrap();

    let error = apply::restore_missing_install(&fixture.context.layout).unwrap_err();

    assert!(matches!(error, apply::ApplyError::NothingToRestore { .. }));
}
