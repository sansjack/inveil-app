//! Shared fixtures for the proxy tests: a live policy built from the built-in rules with per-test changes, a
//! usage sink that records events, and a log writer that captures what `tracing` prints.
use super::audit::AuditLog;
use super::AppState;
use crate::backend::{spawn_uploader, BackendError, UsageSink};
use crate::config::Config;
use crate::logging;
use crate::policy::{builtin_snapshot, ActivePolicy, PolicyBuilder, PolicyOrigin};
use crate::proxy::browser_ca;
use contract::{Action, ClientInfo, Snapshot, UsageEvent};
use std::io::Write;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tempfile::TempDir;
use tokio::sync::watch;
use tracing_subscriber::layer::SubscriberExt;

pub const CHAT_DOMAINS: [&str; 5] = [
    "chatgpt.com",
    "claude.ai",
    "cursor.sh",
    "gemini.google.com",
    "grok.com",
];
const UPLOAD_INTERVAL: Duration = Duration::from_millis(20);
const WAIT_ATTEMPTS: u32 = 100;
const WAIT_STEP: Duration = Duration::from_millis(20);

#[derive(Clone, Default)]
pub struct RecordingSink(pub Arc<Mutex<Vec<UsageEvent>>>);

impl UsageSink for RecordingSink {
    async fn send(&self, _client: &ClientInfo, events: &[UsageEvent]) -> Result<(), BackendError> {
        self.0.lock().unwrap().extend_from_slice(events);
        Ok(())
    }
}

/// Collects log output so a test can look for things that must never appear in it.
#[derive(Clone, Default)]
pub struct CapturedLog(pub Arc<Mutex<Vec<u8>>>);

impl Write for CapturedLog {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl CapturedLog {
    /// Installs a process-wide subscriber that records everything at trace level, once. A scoped subscriber would
    /// race with other tests registering the same call sites on their own threads and lose events.
    pub fn install_globally() -> Self {
        static LOG: OnceLock<CapturedLog> = OnceLock::new();
        LOG.get_or_init(|| {
            let log = CapturedLog::default();
            let captured = log.clone();
            let subscriber = tracing_subscriber::registry()
                .with(logging::layer(tracing::Level::TRACE, move || {
                    captured.clone()
                }));
            tracing::subscriber::set_global_default(subscriber).unwrap();
            log
        })
        .clone()
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

pub struct TestProxy {
    pub state: Arc<AppState>,
    pub sender: Arc<watch::Sender<Arc<ActivePolicy>>>,
    pub builder: PolicyBuilder,
    pub ca_directory: std::path::PathBuf,
    pub usage: RecordingSink,
    directory: TempDir,
}

pub fn builtin_with(change: impl FnOnce(&mut Snapshot)) -> Snapshot {
    let mut snapshot = builtin_snapshot().unwrap();
    change(&mut snapshot);
    snapshot
}

pub fn redact_rules(snapshot: &mut Snapshot, rule_ids: &[&str]) {
    for rule in snapshot
        .pii
        .iter_mut()
        .filter(|rule| rule_ids.contains(&rule.id.as_str()))
    {
        rule.action = Action::Redact;
    }
}

impl TestProxy {
    /// A CA for the chat domains exists on disk, so the browser routes of the snapshot are usable.
    pub fn new(config: Config, snapshot: Snapshot) -> Self {
        Self::with_expiry(config, snapshot, None)
    }

    pub fn with_expiry(config: Config, snapshot: Snapshot, expires_at: Option<u64>) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let ca_directory = browser_ca::ca_directory(directory.path());
        let domains = CHAT_DOMAINS.map(String::from).to_vec();
        browser_ca::create(&ca_directory, &domains).unwrap();

        let config = Arc::new(config);
        let builder = PolicyBuilder::new(config.clone(), ca_directory.clone());
        let active = builder
            .compile(&snapshot, PolicyOrigin::Backend, None, expires_at)
            .unwrap();
        let (sender, receiver) = watch::channel(Arc::new(active));
        let usage = RecordingSink::default();
        let reporter = spawn_uploader(usage.clone(), receiver.clone(), UPLOAD_INTERVAL);
        let mut audit_config = config.as_ref().clone();
        audit_config.logging.audit_file = Some(directory.path().join("audit.jsonl"));
        let audit = AuditLog::open(audit_config.logging.audit_file.as_deref()).unwrap();
        let state = Arc::new(AppState::new(config, receiver, Arc::new(reporter), audit).unwrap());
        Self {
            state,
            sender: Arc::new(sender),
            builder,
            ca_directory,
            usage,
            directory,
        }
    }

    pub fn replace_policy(&self, snapshot: &Snapshot) {
        let active = self
            .builder
            .compile(snapshot, PolicyOrigin::Backend, None, None)
            .unwrap();
        self.sender.send_replace(Arc::new(active));
    }

    pub fn audit_text(&self) -> String {
        let path = self.directory.path().join("audit.jsonl");
        std::fs::read_to_string(path).unwrap_or_default()
    }

    /// Usage events reported so far, waiting briefly for the background uploader.
    pub async fn usage_events(&self, at_least: usize) -> Vec<UsageEvent> {
        for _ in 0..WAIT_ATTEMPTS {
            let events = self.usage.0.lock().unwrap().clone();
            if events.len() >= at_least {
                return events;
            }
            tokio::time::sleep(WAIT_STEP).await;
        }
        self.usage.0.lock().unwrap().clone()
    }
}
