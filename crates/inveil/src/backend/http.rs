use super::BackendError;
use std::time::Duration;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Largest signed envelope or auth answer we read; a backend cannot make us buffer more.
pub const MAX_RESPONSE_BYTES: usize = 4 << 20;

/// Native roots and the proxy environment variables are honoured. Redirects are refused so a response cannot send
/// the bearer credential to another host.
pub fn client() -> Result<reqwest::Client, BackendError> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(REQUEST_TIMEOUT)
        .user_agent(format!("inveil/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|error| BackendError::Unreachable(error.to_string()))
}

pub fn endpoint(base_url: &str, path: &str) -> Result<reqwest::Url, BackendError> {
    let joined = format!("{}{path}", base_url.trim_end_matches('/'));
    reqwest::Url::parse(&joined).map_err(|error| BackendError::BadUrl(error.to_string()))
}

pub fn unreachable(error: reqwest::Error) -> BackendError {
    BackendError::Unreachable(error.without_url().to_string())
}

pub async fn read_text(mut response: reqwest::Response) -> Result<String, BackendError> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(unreachable)? {
        if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err(BackendError::ResponseTooLarge(MAX_RESPONSE_BYTES));
        }
        body.extend_from_slice(&chunk);
    }
    String::from_utf8(body).map_err(|_| BackendError::BadResponse("not valid UTF-8".into()))
}

pub async fn read_json<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
) -> Result<T, BackendError> {
    let text = read_text(response).await?;
    serde_json::from_str(&text).map_err(|error| BackendError::BadResponse(error.to_string()))
}

/// Maps a non-success status to the error the callers handle.
pub fn check_status(response: &reqwest::Response) -> Result<(), BackendError> {
    let status = response.status();
    if status.is_success() {
        return Ok(());
    }
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(BackendError::Unauthorized);
    }
    Err(BackendError::Status(status.as_u16()))
}
