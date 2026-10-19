//! Usage reporting: one event per proxied chat, batched and handed to the configured sink in the background so a
//! proxied request never waits on it. Events carry metadata only, never prompt content.
use super::UsageSink;
use crate::policy::ActivePolicy;
use crate::util::unix_millis;
use contract::{ClientInfo, UsageEvent, MAX_USAGE_BATCH};
use engine::UsagePolicy;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};

const CHANNEL_CAPACITY: usize = 1000;
const MAX_PROVIDER_CHARS: usize = 64;
const MAX_MODEL_CHARS: usize = 128;
const UNKNOWN_MODEL: &str = "unknown";

pub fn new_event(
    provider: &str,
    model: &str,
    status: u16,
    blocked: bool,
    findings: usize,
) -> UsageEvent {
    UsageEvent {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: unix_millis(),
        provider: provider.chars().take(MAX_PROVIDER_CHARS).collect(),
        model: if model.is_empty() {
            UNKNOWN_MODEL.into()
        } else {
            model.chars().take(MAX_MODEL_CHARS).collect()
        },
        input_tokens: 0,
        output_tokens: 0,
        latency_ms: 0,
        status,
        blocked,
        findings,
    }
}

/// Fire and forget: reporting never blocks a request, and a full queue drops the event.
pub struct UsageReporter {
    sender: Option<mpsc::Sender<UsageEvent>>,
    warned_full: AtomicBool,
    fail_open_count: Arc<AtomicU64>,
}

impl UsageReporter {
    pub fn disabled() -> Self {
        Self {
            sender: None,
            warned_full: AtomicBool::new(false),
            fail_open_count: Arc::default(),
        }
    }

    /// Counts a request passed through because a failure mode is `open`; the heartbeat reports the total.
    pub fn count_fail_open(&self) {
        self.fail_open_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn report(&self, event: UsageEvent) {
        let Some(sender) = &self.sender else {
            return;
        };
        if sender.try_send(event).is_err() && !self.warned_full.swap(true, Ordering::Relaxed) {
            tracing::warn!("usage queue full; dropping events until the sink catches up");
        }
    }
}

/// Starts the background batcher. The plan is read from the live policy every tick, so a snapshot that switches
/// reporting on, off or to `required` takes effect without a restart.
pub fn spawn_uploader<S: UsageSink + 'static>(
    sink: S,
    active: watch::Receiver<Arc<ActivePolicy>>,
    flush_interval: Duration,
) -> UsageReporter {
    let (sender, mut receiver) = mpsc::channel(CHANNEL_CAPACITY);
    let fail_open_count = Arc::new(AtomicU64::new(0));
    let reported_fail_opens = fail_open_count.clone();
    tokio::spawn(async move {
        let mut batch: Vec<UsageEvent> = Vec::with_capacity(MAX_USAGE_BATCH);
        let mut ticker = tokio::time::interval(flush_interval);
        let mut last_sent = Instant::now();
        let mut last_error: Option<String> = None;
        loop {
            let flush = tokio::select! {
                event = receiver.recv() => match event {
                    Some(event) => {
                        batch.push(event);
                        batch.len() >= MAX_USAGE_BATCH
                    }
                    None => return,
                },
                _ = ticker.tick() => true,
            };
            if !flush {
                continue;
            }
            let policy = active.borrow().clone();
            let heartbeat_seconds = match policy.effective.usage {
                UsagePolicy::Off => {
                    batch.clear();
                    continue;
                }
                UsagePolicy::On { heartbeat_seconds } => heartbeat_seconds,
                UsagePolicy::HeartbeatOnly { heartbeat_seconds } => {
                    batch.clear();
                    Some(heartbeat_seconds)
                }
            };
            let heartbeat_due = heartbeat_seconds
                .is_some_and(|seconds| last_sent.elapsed() >= Duration::from_secs(seconds));
            if batch.is_empty() && !heartbeat_due {
                continue;
            }
            let client = ClientInfo {
                version: env!("CARGO_PKG_VERSION").to_string(),
                policy_version: policy.version,
                config_hash: policy.config_hash.clone(),
                failure_modes: Some(policy.effective.failure_modes.into()),
                fail_open_count: reported_fail_opens.load(Ordering::Relaxed),
            };
            let result = sink.send(&client, &batch).await;
            batch.clear();
            last_sent = Instant::now();
            match result {
                Ok(()) => last_error = None,
                Err(error) => {
                    let reason = error.to_string();
                    if last_error.as_deref() != Some(reason.as_str()) {
                        tracing::warn!("usage not sent: {reason}");
                        last_error = Some(reason);
                    }
                }
            }
        }
    });
    UsageReporter {
        sender: Some(sender),
        warned_full: AtomicBool::new(false),
        fail_open_count,
    }
}
