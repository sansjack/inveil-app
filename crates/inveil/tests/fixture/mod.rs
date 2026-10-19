//! Shared pieces of the end-to-end tests: a signing key, a fixture backend that serves signed snapshots and records
//! what the client sends, a fake upstream, and a harness that runs the real `inveil` binary against them.
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use contract::{SignedEnvelope, Snapshot, UsageBatch, SNAPSHOT_SCHEMA};
use engine::signing::{public_key_of, sha256_hex, sign_payload, Role};
use ring::rand::SystemRandom;
use ring::signature::Ed25519KeyPair;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;

pub const KEY_ID: &str = "policy-1";
pub const UNREADABLE_BODY: &str = "this is not json";
pub const SSN_TEXT: &str = "my ssn is 123-45-6789";
const BUILTIN_RULES: &str = include_str!("../../src/builtin_rules.json");
const ONE_HOUR: u64 = 3600;
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_STEP: Duration = Duration::from_millis(50);

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub struct SigningKey {
    pkcs8: Vec<u8>,
}

impl SigningKey {
    pub fn generate() -> Self {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .unwrap()
            .as_ref()
            .to_vec();
        Self { pkcs8 }
    }

    pub fn public_base64(&self) -> String {
        STANDARD.encode(public_key_of(&self.pkcs8).unwrap())
    }

    pub fn sign(&self, snapshot: &Snapshot) -> String {
        let payload = serde_json::to_string(snapshot).unwrap();
        let signature = sign_payload(Role::Policy, KEY_ID, &self.pkcs8, &payload).unwrap();
        serde_json::to_string(&SignedEnvelope {
            payload,
            signatures: vec![signature],
            delegation: None,
        })
        .unwrap()
    }
}

/// The built-in rules as a signable snapshot, with changes applied by `change`.
pub fn snapshot(version: u64, change: impl FnOnce(&mut Snapshot)) -> Snapshot {
    let mut snapshot: Snapshot = serde_json::from_str(BUILTIN_RULES).unwrap();
    snapshot.schema = SNAPSHOT_SCHEMA;
    snapshot.version = version;
    snapshot.issued_at = now() - 10;
    snapshot.expires_at = now() + ONE_HOUR;
    change(&mut snapshot);
    snapshot
}

pub fn expired(version: u64) -> Snapshot {
    snapshot(version, |snapshot| {
        snapshot.issued_at = now() - 2 * ONE_HOUR;
        snapshot.expires_at = now() - ONE_HOUR;
    })
}

/// Rules that let everything through, so a client that wrongly applied them would stop blocking.
pub fn permissive(version: u64) -> Snapshot {
    snapshot(version, |snapshot| {
        for rule in &mut snapshot.pii {
            rule.action = contract::Action::Log;
        }
    })
}

pub fn redacting(version: u64) -> Snapshot {
    snapshot(version, |snapshot| {
        for rule in snapshot.pii.iter_mut().filter(|rule| rule.id == "ssn") {
            rule.action = contract::Action::Redact;
        }
    })
}

#[derive(Default)]
pub struct BackendState {
    envelope: Mutex<Option<String>>,
    pub rules_requests: AtomicUsize,
    pub usage_batches: Mutex<Vec<UsageBatch>>,
    pub requests: AtomicUsize,
}

pub struct Backend {
    pub address: SocketAddr,
    pub state: Arc<BackendState>,
}

impl Backend {
    pub async fn start() -> Self {
        let state = Arc::new(BackendState::default());
        let router = Router::new()
            .route("/v1/rules", get(rules))
            .route("/v1/usage", post(usage))
            .with_state(state.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, router).await });
        Self { address, state }
    }

    pub fn url(&self) -> String {
        format!("http://{}", self.address)
    }

    pub fn serve(&self, envelope: String) {
        *self.state.envelope.lock().unwrap() = Some(envelope);
    }

    pub fn rules_requests(&self) -> usize {
        self.state.rules_requests.load(Ordering::SeqCst)
    }

    pub async fn wait_for_usage(&self, timeout: Duration) -> Vec<UsageBatch> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let batches = self.state.usage_batches.lock().unwrap().clone();
            if !batches.is_empty() || std::time::Instant::now() > deadline {
                return batches;
            }
            tokio::time::sleep(POLL_STEP).await;
        }
    }
}

async fn rules(State(state): State<Arc<BackendState>>, headers: HeaderMap) -> Response {
    state.requests.fetch_add(1, Ordering::SeqCst);
    state.rules_requests.fetch_add(1, Ordering::SeqCst);
    let Some(envelope) = state.envelope.lock().unwrap().clone() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let parsed: SignedEnvelope = serde_json::from_str(&envelope).unwrap();
    let etag = format!("\"{}\"", sha256_hex(parsed.payload.as_bytes()));
    if headers
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        == Some(&etag)
    {
        return StatusCode::NOT_MODIFIED.into_response();
    }
    ([(header::ETAG, etag)], envelope).into_response()
}

async fn usage(
    State(state): State<Arc<BackendState>>,
    Json(batch): Json<UsageBatch>,
) -> StatusCode {
    state.requests.fetch_add(1, Ordering::SeqCst);
    state.usage_batches.lock().unwrap().push(batch);
    StatusCode::OK
}

/// A fake AI provider that echoes the body it received.
pub struct Upstream {
    pub address: SocketAddr,
}

impl Upstream {
    pub async fn start() -> Self {
        let router = Router::new().fallback(|body: Bytes| async move {
            Json(json!({ "body": String::from_utf8_lossy(&body) }))
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, router).await });
        Self { address }
    }

    pub fn url(&self) -> String {
        format!("http://{}", self.address)
    }
}

/// A listener that counts connections and never answers: any client that touches the network shows up.
pub struct Tripwire {
    pub address: SocketAddr,
    connections: Arc<AtomicUsize>,
}

impl Tripwire {
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let counter = connections.clone();
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                drop(socket);
            }
        });
        Self {
            address,
            connections,
        }
    }

    pub fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }
}

pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// How to configure one run of the binary.
pub struct Setup {
    upstream: String,
    backend: Option<(String, String)>,
    top_level: String,
    tables: String,
}

impl Setup {
    pub fn new(upstream: &Upstream) -> Self {
        Self {
            upstream: upstream.url(),
            backend: None,
            top_level: String::new(),
            tables: String::new(),
        }
    }

    pub fn with_backend(mut self, backend_url: String, key: &SigningKey) -> Self {
        self.backend = Some((backend_url, key.public_base64()));
        self
    }

    /// Extra top-level keys such as `dry_run = true`.
    pub fn top_level(mut self, toml: &str) -> Self {
        self.top_level.push_str(toml);
        self.top_level.push('\n');
        self
    }

    /// Extra tables such as `[usage]`.
    pub fn table(mut self, toml: &str) -> Self {
        self.tables.push_str(toml);
        self.tables.push('\n');
        self
    }

    fn render(&self, directory: &Path, port: u16) -> String {
        let mut config = format!(
            "{}upstream = \"{}\"\nnotify = false\nstate_keychain = false\ndata_dir = '{}'\n[listen]\nport = {port}\nbrowser_port = {}\n[update]\nmode = \"off\"\n[logging]\naudit_file = '{}'\n",
            self.top_level,
            self.upstream,
            directory.join("data").display(),
            free_port(),
            directory.join("audit.jsonl").display(),
        );
        if let Some((url, key)) = &self.backend {
            config.push_str(&format!(
                "[backend]\nurl = \"{url}\"\npinned_keys = [{{ key_id = \"{KEY_ID}\", public_key = \"{key}\" }}]\n"
            ));
        }
        config.push_str(&self.tables);
        config
    }
}

pub struct RunningProxy {
    child: Child,
    pub address: String,
    directory: PathBuf,
}

impl RunningProxy {
    pub fn log(&self) -> String {
        std::fs::read_to_string(self.directory.join("stderr.log")).unwrap_or_default()
    }

    pub fn audit_text(&self) -> String {
        std::fs::read_to_string(self.directory.join("audit.jsonl")).unwrap_or_default()
    }

    /// Runs the binary against `directory` (which keeps its saved state between runs) and waits until it listens;
    /// panics with its log if it exits first.
    pub fn start(directory: &Path, setup: &Setup) -> Self {
        match Self::spawn(directory, setup) {
            Ok(proxy) => proxy,
            Err((status, log)) => panic!("inveil exited early with {status}:\n{log}"),
        }
    }

    /// Runs the binary and returns its exit status and log if it stops by itself.
    pub fn start_expecting_exit(
        directory: &Path,
        setup: &Setup,
    ) -> (std::process::ExitStatus, String) {
        match Self::spawn(directory, setup) {
            Ok(_) => panic!("inveil kept running but was expected to refuse to start"),
            Err(exit) => exit,
        }
    }

    fn spawn(directory: &Path, setup: &Setup) -> Result<Self, (std::process::ExitStatus, String)> {
        let port = free_port();
        let config_path = directory.join("inveil.toml");
        std::fs::write(&config_path, setup.render(directory, port)).unwrap();
        std::fs::create_dir_all(directory.join("data")).unwrap();

        let log_path = directory.join("stderr.log");
        let mut child = Command::new(env!("CARGO_BIN_EXE_inveil"))
            .arg("--config")
            .arg(&config_path)
            .arg("run")
            .env("INVEIL_PLATFORM_SANDBOX", directory)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(&log_path).unwrap())
            .spawn()
            .unwrap();

        let deadline = std::time::Instant::now() + STARTUP_TIMEOUT;
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                return Err((
                    status,
                    std::fs::read_to_string(&log_path).unwrap_or_default(),
                ));
            }
            let listening = std::net::TcpStream::connect_timeout(
                &SocketAddr::from(([127, 0, 0, 1], port)),
                Duration::from_millis(100),
            )
            .is_ok();
            if listening {
                return Ok(Self {
                    child,
                    address: format!("http://127.0.0.1:{port}"),
                    directory: directory.to_path_buf(),
                });
            }
            assert!(
                std::time::Instant::now() < deadline,
                "inveil did not start listening"
            );
            std::thread::sleep(POLL_STEP);
        }
    }

    pub async fn post_chat(&self, body: &Value) -> reqwest::Response {
        client()
            .post(format!("{}/v1/messages", self.address))
            .json(body)
            .send()
            .await
            .unwrap()
    }
}

impl RunningProxy {
    /// A chat request whose body is not JSON, so the scanner cannot read it.
    pub async fn post_unreadable_chat(&self) -> reqwest::Response {
        client()
            .post(format!("{}/v1/messages", self.address))
            .body(UNREADABLE_BODY)
            .send()
            .await
            .unwrap()
    }
}

impl Drop for RunningProxy {
    fn drop(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
    }
}

pub fn chat(text: &str) -> Value {
    json!({"model": "m1", "input": text})
}

pub async fn echoed_body(response: reqwest::Response) -> String {
    response.json::<Value>().await.unwrap()["body"]
        .as_str()
        .unwrap()
        .to_string()
}

/// A backend serving `snapshot` signed by `key`, and a setup that trusts `key`.
pub async fn backend_serving(
    key: &SigningKey,
    snapshot: &contract::Snapshot,
) -> (Backend, Upstream, Setup) {
    let backend = Backend::start().await;
    backend.serve(key.sign(snapshot));
    let upstream = Upstream::start().await;
    let setup = Setup::new(&upstream).with_backend(backend.url(), key);
    (backend, upstream, setup)
}

pub fn client() -> reqwest::Client {
    reqwest::Client::builder().no_proxy().build().unwrap()
}
