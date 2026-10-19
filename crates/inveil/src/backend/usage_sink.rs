use super::http::{client, endpoint, unreachable};
use super::{BackendError, CredentialProvider, Credentials, UsageSink};
use crate::config::Config;
use crate::util::open_private_append;
use contract::{ClientInfo, UsageBatch, UsageEvent, MAX_USAGE_BATCH};
use reqwest::StatusCode;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

const MAX_ATTEMPTS: u32 = 3;
const RETRY_BASE: Duration = Duration::from_secs(1);
const RETRY_BACKOFF_FACTOR: u32 = 4;

pub struct HttpUsageSink {
    client: reqwest::Client,
    url: reqwest::Url,
    credentials: Arc<Credentials>,
    retry_base: Duration,
}

impl HttpUsageSink {
    pub fn new(config: &Config, credentials: Arc<Credentials>) -> Result<Self, BackendError> {
        let base_url = config
            .backend
            .url
            .as_deref()
            .ok_or_else(|| BackendError::BadUrl("backend.url is not set".into()))?;
        Ok(Self {
            client: client()?,
            url: endpoint(base_url, &config.usage.path)?,
            credentials,
            retry_base: RETRY_BASE,
        })
    }

    #[cfg(test)]
    pub fn with_retry_base(mut self, retry_base: Duration) -> Self {
        self.retry_base = retry_base;
        self
    }

    async fn post_with_retries(&self, batch: &UsageBatch) -> Result<(), BackendError> {
        let mut last_error = BackendError::Unreachable("no attempt was made".into());
        for attempt in 0..MAX_ATTEMPTS {
            if attempt > 0 {
                tokio::time::sleep(self.retry_base * RETRY_BACKOFF_FACTOR.pow(attempt - 1)).await;
            }
            match self.post_once(batch).await {
                Ok(()) => return Ok(()),
                Err(error) if is_retryable(&error) => last_error = error,
                Err(error) => return Err(error),
            }
        }
        Err(last_error)
    }

    async fn post_once(&self, batch: &UsageBatch) -> Result<(), BackendError> {
        let mut request = self.client.post(self.url.clone()).json(batch);
        if let Some(token) = self.credentials.credential().await? {
            request = request.bearer_auth(token);
        }
        let response = request.send().await.map_err(unreachable)?;
        match response.status() {
            status if status.is_success() => Ok(()),
            StatusCode::UNAUTHORIZED => {
                self.credentials.invalidate();
                Err(BackendError::Unauthorized)
            }
            status => Err(BackendError::Status(status.as_u16())),
        }
    }
}

fn is_retryable(error: &BackendError) -> bool {
    match error {
        BackendError::Unreachable(_) | BackendError::Unauthorized => true,
        BackendError::Status(status) => *status == 429 || *status >= 500,
        _ => false,
    }
}

impl UsageSink for HttpUsageSink {
    async fn send(&self, client: &ClientInfo, events: &[UsageEvent]) -> Result<(), BackendError> {
        if events.is_empty() {
            return self
                .post_with_retries(&UsageBatch {
                    client: client.clone(),
                    events: vec![],
                })
                .await;
        }
        for chunk in events.chunks(MAX_USAGE_BATCH) {
            self.post_with_retries(&UsageBatch {
                client: client.clone(),
                events: chunk.to_vec(),
            })
            .await?;
        }
        Ok(())
    }
}

/// One JSON line per batch, appended to a local file: "bring your own metrics" without a backend.
pub struct FileUsageSink {
    path: PathBuf,
}

impl FileUsageSink {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl UsageSink for FileUsageSink {
    async fn send(&self, client: &ClientInfo, events: &[UsageEvent]) -> Result<(), BackendError> {
        if events.is_empty() {
            return Ok(());
        }
        let file_error = |source| BackendError::File {
            path: self.path.clone(),
            source,
        };
        let batch = UsageBatch {
            client: client.clone(),
            events: events.to_vec(),
        };
        let mut line = serde_json::to_vec(&batch)
            .map_err(|error| BackendError::BadResponse(error.to_string()))?;
        line.push(b'\n');
        let file = open_private_append(&self.path).map_err(file_error)?;
        let mut file = tokio::fs::File::from_std(file);
        file.write_all(&line).await.map_err(file_error)?;
        file.flush().await.map_err(file_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::State;
    use axum::routing::post;
    use axum::{Json, Router};
    use contract::Billing;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn client_info() -> ClientInfo {
        ClientInfo {
            version: "0.1.0".into(),
            policy_version: 3,
            config_hash: "abc".into(),
            failure_modes: None,
            fail_open_count: 0,
        }
    }

    fn event(id: usize) -> UsageEvent {
        UsageEvent {
            id: id.to_string(),
            timestamp: 1,
            provider: "api.example.com".into(),
            model: "m".into(),
            input_tokens: 1,
            output_tokens: 2,
            cache_read_tokens: 0,
            cache_write_tokens: 0,
            billing: Billing::Unknown,
            served_by: None,
            billing_signal: None,
            model_signal: None,
            latency_ms: 3,
            status: 200,
            blocked: false,
            findings: 0,
        }
    }

    async fn backend(failures_first: usize) -> (String, Arc<std::sync::Mutex<Vec<UsageBatch>>>) {
        #[derive(Clone)]
        struct Shared {
            calls: Arc<AtomicUsize>,
            failures_first: usize,
            received: Arc<std::sync::Mutex<Vec<UsageBatch>>>,
        }
        let shared = Shared {
            calls: Arc::default(),
            failures_first,
            received: Arc::default(),
        };
        let received = shared.received.clone();
        let router = Router::new()
            .route(
                "/v1/usage",
                post(
                    |State(shared): State<Shared>, Json(batch): Json<UsageBatch>| async move {
                        if shared.calls.fetch_add(1, Ordering::SeqCst) < shared.failures_first {
                            return axum::http::StatusCode::SERVICE_UNAVAILABLE;
                        }
                        shared.received.lock().unwrap().push(batch);
                        axum::http::StatusCode::OK
                    },
                ),
            )
            .with_state(shared);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, router).await });
        (format!("http://{address}"), received)
    }

    fn sink_for(url: &str) -> HttpUsageSink {
        let mut config = Config::default();
        config.backend.url = Some(url.into());
        HttpUsageSink::new(&config, Arc::new(Credentials::None))
            .unwrap()
            .with_retry_base(Duration::from_millis(5))
    }

    #[tokio::test]
    async fn batches_are_capped_and_carry_the_client_info() {
        let (url, received) = backend(0).await;
        let events: Vec<UsageEvent> = (0..MAX_USAGE_BATCH + 5).map(event).collect();
        sink_for(&url).send(&client_info(), &events).await.unwrap();
        let received = received.lock().unwrap();
        assert_eq!(received.len(), 2);
        assert_eq!(received[0].events.len(), MAX_USAGE_BATCH);
        assert_eq!(received[1].events.len(), 5);
        assert_eq!(received[0].client, client_info());
    }

    #[tokio::test]
    async fn transient_failures_are_retried_and_an_empty_batch_is_a_heartbeat() {
        let (url, received) = backend(2).await;
        sink_for(&url).send(&client_info(), &[]).await.unwrap();
        let received = received.lock().unwrap();
        assert_eq!(received.len(), 1);
        assert!(received[0].events.is_empty());
    }

    #[tokio::test]
    async fn a_backend_that_keeps_failing_gives_up() {
        let (url, _) = backend(usize::MAX).await;
        let result = sink_for(&url).send(&client_info(), &[event(1)]).await;
        assert!(matches!(result, Err(BackendError::Status(503))));
    }

    #[tokio::test]
    async fn the_file_sink_appends_one_json_line_per_batch() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("usage.jsonl");
        let sink = FileUsageSink::new(path.clone());
        sink.send(&client_info(), &[event(1), event(2)])
            .await
            .unwrap();
        sink.send(&client_info(), &[event(3)]).await.unwrap();
        sink.send(&client_info(), &[]).await.unwrap();
        let text = std::fs::read_to_string(path).unwrap();
        let batches: Vec<UsageBatch> = text
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].events.len(), 2);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_file_sink_creates_its_file_for_the_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("usage.jsonl");
        FileUsageSink::new(path.clone())
            .send(&client_info(), &[event(1)])
            .await
            .unwrap();
        let mode = std::fs::metadata(path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
