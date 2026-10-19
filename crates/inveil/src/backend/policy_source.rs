use super::http::{check_status, client, endpoint, read_text, unreachable};
use super::{BackendError, CredentialProvider, Credentials, Fetched, PolicySource};
use crate::config::Config;
use reqwest::header::IF_NONE_MATCH;
use reqwest::StatusCode;
use std::path::PathBuf;
use std::sync::Arc;

pub struct HttpPolicySource {
    client: reqwest::Client,
    url: reqwest::Url,
    credentials: Arc<Credentials>,
}

impl HttpPolicySource {
    pub fn new(config: &Config, credentials: Arc<Credentials>) -> Result<Self, BackendError> {
        let base_url = config
            .backend
            .url
            .as_deref()
            .ok_or_else(|| BackendError::BadUrl("backend.url is not set".into()))?;
        Ok(Self {
            client: client()?,
            url: endpoint(base_url, &config.backend.rules_path)?,
            credentials,
        })
    }
}

impl PolicySource for HttpPolicySource {
    async fn fetch(&self, etag: Option<&str>) -> Result<Fetched, BackendError> {
        let mut request = self.client.get(self.url.clone());
        if let Some(token) = self.credentials.credential().await? {
            request = request.bearer_auth(token);
        }
        if let Some(etag) = etag {
            request = request.header(IF_NONE_MATCH, format!("\"{etag}\""));
        }
        let response = request.send().await.map_err(unreachable)?;
        if response.status() == StatusCode::NOT_MODIFIED {
            if etag.is_none() {
                return Err(BackendError::BadResponse(
                    "the backend answered 304 to a request that held nothing to compare with"
                        .into(),
                ));
            }
            return Ok(Fetched::NotModified);
        }
        if let Err(error) = check_status(&response) {
            if matches!(error, BackendError::Unauthorized) {
                self.credentials.invalidate();
            }
            return Err(error);
        }
        read_text(response).await.map(Fetched::Envelope)
    }
}

/// A signed snapshot supplied as a file: air-gapped installs and standalone setups with no backend.
pub struct FilePolicySource {
    path: PathBuf,
}

impl FilePolicySource {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl PolicySource for FilePolicySource {
    async fn fetch(&self, _etag: Option<&str>) -> Result<Fetched, BackendError> {
        tokio::fs::read_to_string(&self.path)
            .await
            .map(Fetched::Envelope)
            .map_err(|source| BackendError::File {
                path: self.path.clone(),
                source,
            })
    }
}
