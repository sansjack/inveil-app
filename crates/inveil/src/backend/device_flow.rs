//! OAuth device flow: the person approves a code in the browser, the long-lived session token is kept in the OS
//! keychain, and it is traded for short-lived JWTs that authenticate requests to the backend.
use super::credentials::{KeychainSlot, SESSION_TOKEN_USER};
use super::http::{check_status, client, endpoint, read_json, unreachable};
use super::BackendError;
use crate::config::{Config, DeviceFlowConfig};
use crate::util::lock;
use serde::Deserialize;
use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
/// The server issues 15 minute JWTs; refresh a little early instead of decoding `exp`.
const JWT_LIFETIME: Duration = Duration::from_secs(10 * 60);
const SLOW_DOWN_STEP: Duration = Duration::from_secs(5);

#[derive(Deserialize)]
struct DeviceCode {
    device_code: String,
    user_code: String,
    verification_uri_complete: String,
    expires_in: u64,
    interval: u64,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

#[derive(Deserialize)]
struct JwtResponse {
    token: String,
}

#[derive(Deserialize)]
struct SessionResponse {
    user: SessionUser,
}

#[derive(Deserialize)]
struct SessionUser {
    email: String,
}

#[derive(Debug, PartialEq)]
enum Poll {
    Pending,
    SlowDown,
    Failed(String),
}

fn classify_poll_error(error: &str, description: Option<&str>) -> Poll {
    match error {
        "authorization_pending" => Poll::Pending,
        "slow_down" => Poll::SlowDown,
        "access_denied" => Poll::Failed("the request was denied in the browser".into()),
        "expired_token" => Poll::Failed("the code expired; run `inveil login` again".into()),
        other => Poll::Failed(description.unwrap_or(other).to_string()),
    }
}

/// Hands out short-lived JWTs, refreshing from the keychain session when they run low.
pub struct DeviceFlowSession {
    http: reqwest::Client,
    base_url: String,
    paths: DeviceFlowConfig,
    session_slot: KeychainSlot,
    cached_jwt: Mutex<Option<(String, Instant)>>,
}

impl DeviceFlowSession {
    pub fn new(config: &Config) -> Result<Self, BackendError> {
        Ok(Self {
            http: client()?,
            base_url: config.backend.url.clone().unwrap_or_default(),
            paths: config.auth.device_flow.clone(),
            session_slot: KeychainSlot::for_backend(config, SESSION_TOKEN_USER)?,
            cached_jwt: Mutex::new(None),
        })
    }

    pub fn forget_jwt(&self) {
        *lock(&self.cached_jwt) = None;
    }

    pub async fn jwt(&self) -> Result<String, BackendError> {
        if let Some((jwt, fetched_at)) = &*lock(&self.cached_jwt) {
            if fetched_at.elapsed() < JWT_LIFETIME {
                return Ok(jwt.clone());
            }
        }
        let session_token = self.session_slot.get()?.ok_or(BackendError::NotSignedIn)?;
        let response = self
            .http
            .get(endpoint(&self.base_url, &self.paths.jwt_path)?)
            .bearer_auth(session_token)
            .send()
            .await
            .map_err(unreachable)?;
        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            self.session_slot.delete()?;
            return Err(BackendError::NotSignedIn);
        }
        check_status(&response)?;
        let jwt = read_json::<JwtResponse>(response).await?.token;
        *lock(&self.cached_jwt) = Some((jwt.clone(), Instant::now()));
        Ok(jwt)
    }

    async fn account_email(&self) -> Result<String, BackendError> {
        let session_token = self.session_slot.get()?.ok_or(BackendError::NotSignedIn)?;
        let response = self
            .http
            .get(endpoint(&self.base_url, &self.paths.session_path)?)
            .bearer_auth(session_token)
            .send()
            .await
            .map_err(unreachable)?;
        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            return Err(BackendError::NotSignedIn);
        }
        check_status(&response)?;
        Ok(read_json::<SessionResponse>(response).await?.user.email)
    }
}

/// Opens the approval page. The address is passed as one argument and never through a shell.
fn open_browser(address: &str) -> bool {
    if !(address.starts_with("https://") || address.starts_with("http://")) {
        return false;
    }
    let status = if cfg!(target_os = "macos") {
        Command::new("open").arg(address).status()
    } else if cfg!(windows) {
        Command::new("rundll32")
            .args(["url.dll,FileProtocolHandler", address])
            .status()
    } else {
        Command::new("xdg-open").arg(address).status()
    };
    status.is_ok_and(|status| status.success())
}

pub async fn login(config: &Config) -> Result<String, BackendError> {
    let base_url = config.backend.url.clone().unwrap_or_default();
    let paths = &config.auth.device_flow;
    let http = client()?;

    let response = http
        .post(endpoint(&base_url, &paths.code_path)?)
        .json(&serde_json::json!({ "client_id": paths.client_id }))
        .send()
        .await
        .map_err(unreachable)?;
    check_status(&response)?;
    let code: DeviceCode = read_json(response).await?;

    println!(
        "Approve this device in your browser:\n\n  {}\n\nCode: {}\n",
        code.verification_uri_complete, code.user_code
    );
    if !open_browser(&code.verification_uri_complete) {
        println!("Could not open a browser automatically.");
    }
    println!("Waiting for approval...");

    let slot = KeychainSlot::for_backend(config, SESSION_TOKEN_USER)?;
    let deadline = Instant::now() + Duration::from_secs(code.expires_in);
    let mut interval = Duration::from_secs(code.interval.max(1));
    while Instant::now() < deadline {
        tokio::time::sleep(interval).await;
        let response = http
            .post(endpoint(&base_url, &paths.token_path)?)
            .json(&serde_json::json!({
                "grant_type": DEVICE_GRANT,
                "device_code": code.device_code,
                "client_id": paths.client_id,
            }))
            .send()
            .await
            .map_err(unreachable)?;
        let reply: TokenResponse = read_json(response).await?;
        if let Some(token) = reply.access_token {
            slot.set(&token)?;
            return Ok("Signed in. Run `inveil whoami` to check.".to_string());
        }
        let error = reply.error.unwrap_or_else(|| "unknown_error".into());
        match classify_poll_error(&error, reply.error_description.as_deref()) {
            Poll::Pending => {}
            Poll::SlowDown => interval += SLOW_DOWN_STEP,
            Poll::Failed(reason) => return Err(BackendError::SignInFailed(reason)),
        }
    }
    Err(BackendError::SignInFailed(
        "timed out; run `inveil login` again".into(),
    ))
}

pub async fn whoami(config: &Config) -> Result<String, BackendError> {
    let session = DeviceFlowSession::new(config)?;
    let email = session.account_email().await?;
    session.jwt().await?;
    Ok(format!("Signed in as {email} (token refresh works)."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_polling_only_while_approval_is_pending() {
        assert_eq!(
            classify_poll_error("authorization_pending", None),
            Poll::Pending
        );
        assert_eq!(classify_poll_error("slow_down", None), Poll::SlowDown);
        assert!(matches!(
            classify_poll_error("access_denied", None),
            Poll::Failed(_)
        ));
        assert!(matches!(
            classify_poll_error("expired_token", None),
            Poll::Failed(_)
        ));
        assert_eq!(
            classify_poll_error("invalid_request", Some("bad code")),
            Poll::Failed("bad code".into())
        );
    }

    #[test]
    fn only_web_addresses_are_opened() {
        assert!(!open_browser("file:///etc/passwd"));
        assert!(!open_browser("calc.exe"));
    }
}
