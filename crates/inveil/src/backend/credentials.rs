use super::device_flow::DeviceFlowSession;
use super::{BackendError, CredentialProvider};
use crate::brand;
use crate::config::{AuthMode, Config};
use crate::util::lock;
use std::sync::Mutex;

const STATIC_TOKEN_USER: &str = "static-token";
const DEVICE_CREDENTIAL_USER: &str = "device-credential";
const ORG_ID_USER: &str = "org-id";
pub const SESSION_TOKEN_USER: &str = "session-token";

/// One secret in the OS keychain. The service name is derived from the backend host, so two backends never share
/// a credential.
pub struct KeychainSlot {
    service: String,
    user: &'static str,
}

impl KeychainSlot {
    pub fn for_backend(config: &Config, user: &'static str) -> Result<Self, BackendError> {
        let url = config
            .backend
            .url
            .as_deref()
            .ok_or_else(|| BackendError::BadUrl("backend.url is not set".into()))?;
        let parsed =
            reqwest::Url::parse(url).map_err(|error| BackendError::BadUrl(error.to_string()))?;
        let host = parsed
            .host_str()
            .ok_or_else(|| BackendError::BadUrl("backend.url has no host".into()))?;
        Ok(Self {
            service: brand::keychain_service(host),
            user,
        })
    }

    fn entry(&self) -> Result<keyring::Entry, BackendError> {
        Ok(keyring::Entry::new(&self.service, self.user)?)
    }

    pub fn get(&self) -> Result<Option<String>, BackendError> {
        match self.entry()?.get_password() {
            Ok(secret) => Ok(Some(secret)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    pub fn set(&self, secret: &str) -> Result<(), BackendError> {
        Ok(self.entry()?.set_password(secret)?)
    }

    /// True when something was removed.
    pub fn delete(&self) -> Result<bool, BackendError> {
        match self.entry()?.delete_credential() {
            Ok(()) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }
}

/// A keychain secret read once and kept until the backend rejects it.
pub struct StoredSecret {
    slot: KeychainSlot,
    cached: Mutex<Option<String>>,
}

impl StoredSecret {
    fn new(slot: KeychainSlot) -> Self {
        Self {
            slot,
            cached: Mutex::new(None),
        }
    }

    fn get(&self) -> Result<Option<String>, BackendError> {
        let mut cached = lock(&self.cached);
        if cached.is_none() {
            *cached = self.slot.get()?;
        }
        Ok(cached.clone())
    }

    fn forget(&self) {
        *lock(&self.cached) = None;
    }
}

/// The credential a configured `auth.mode` provides.
pub enum Credentials {
    None,
    StaticToken {
        environment_variable: Option<String>,
        stored: StoredSecret,
    },
    Enrolled(StoredSecret),
    DeviceFlow(DeviceFlowSession),
}

impl Credentials {
    pub fn from_config(config: &Config) -> Result<Self, BackendError> {
        match config.auth.mode {
            AuthMode::None => Ok(Self::None),
            AuthMode::StaticToken => Ok(Self::StaticToken {
                environment_variable: config.auth.token_env.clone(),
                stored: StoredSecret::new(KeychainSlot::for_backend(config, STATIC_TOKEN_USER)?),
            }),
            AuthMode::Enrolled => Ok(Self::Enrolled(StoredSecret::new(
                KeychainSlot::for_backend(config, DEVICE_CREDENTIAL_USER)?,
            ))),
            AuthMode::DeviceFlow => Ok(Self::DeviceFlow(DeviceFlowSession::new(config)?)),
        }
    }
}

impl CredentialProvider for Credentials {
    async fn credential(&self) -> Result<Option<String>, BackendError> {
        match self {
            Self::None => Ok(None),
            Self::StaticToken {
                environment_variable,
                stored,
            } => {
                let from_environment = environment_variable
                    .as_deref()
                    .and_then(|name| std::env::var(name).ok())
                    .filter(|token| !token.is_empty());
                match from_environment {
                    Some(token) => Ok(Some(token)),
                    None => stored.get()?.map(Some).ok_or(BackendError::NotSignedIn),
                }
            }
            Self::Enrolled(stored) => stored.get()?.map(Some).ok_or(BackendError::NotSignedIn),
            Self::DeviceFlow(session) => session.jwt().await.map(Some),
        }
    }

    fn invalidate(&self) {
        match self {
            Self::None => {}
            Self::StaticToken { stored, .. } | Self::Enrolled(stored) => stored.forget(),
            Self::DeviceFlow(session) => session.forget_jwt(),
        }
    }
}

pub fn save_static_token(config: &Config, token: &str) -> Result<(), BackendError> {
    KeychainSlot::for_backend(config, STATIC_TOKEN_USER)?.set(token)
}

pub fn save_device_credential(config: &Config, credential: &str) -> Result<(), BackendError> {
    KeychainSlot::for_backend(config, DEVICE_CREDENTIAL_USER)?.set(credential)
}

/// Records the organisation the enrollment token belongs to, or forgets an earlier one when the backend names none.
pub fn save_org_id(config: &Config, org_id: Option<&str>) -> Result<(), BackendError> {
    let slot = KeychainSlot::for_backend(config, ORG_ID_USER)?;
    match org_id {
        Some(org_id) => slot.set(org_id),
        None => slot.delete().map(drop),
    }
}

/// The organisation recorded at enrollment, if the backend named one.
pub fn stored_org_id(config: &Config) -> Result<Option<String>, BackendError> {
    KeychainSlot::for_backend(config, ORG_ID_USER)?.get()
}

/// Removes every credential this client stored for the backend. True when anything was removed.
pub fn forget_all(config: &Config) -> Result<bool, BackendError> {
    let mut removed = false;
    for user in [
        STATIC_TOKEN_USER,
        DEVICE_CREDENTIAL_USER,
        SESSION_TOKEN_USER,
        ORG_ID_USER,
    ] {
        removed |= KeychainSlot::for_backend(config, user)?.delete()?;
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn no_auth_means_no_credential() {
        assert_eq!(Credentials::None.credential().await.unwrap(), None);
    }

    #[tokio::test]
    async fn a_static_token_in_the_environment_is_used_without_touching_the_keychain() {
        let mut config = Config::default();
        config.backend.url = Some("https://policy.example.com".into());
        config.auth.mode = AuthMode::StaticToken;
        config.auth.token_env = Some("INVEIL_TEST_STATIC_TOKEN_PRESENT".into());
        std::env::set_var("INVEIL_TEST_STATIC_TOKEN_PRESENT", "secret-token");
        let credentials = Credentials::from_config(&config).unwrap();
        assert_eq!(
            credentials.credential().await.unwrap().as_deref(),
            Some("secret-token")
        );
    }

    #[test]
    fn the_keychain_service_is_derived_from_the_backend_host() {
        let mut config = Config::default();
        config.backend.url = Some("https://policy.example.com:8443/base".into());
        let slot = KeychainSlot::for_backend(&config, STATIC_TOKEN_USER).unwrap();
        assert_eq!(slot.service, "inveil.policy.example.com");
        config.backend.url = None;
        assert!(KeychainSlot::for_backend(&config, STATIC_TOKEN_USER).is_err());
    }
}
