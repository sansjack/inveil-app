//! Local bootstrap configuration. Layering (highest first): flags, `INVEIL_*` environment, `inveil.toml`, the
//! system-wide file, defaults. In managed mode the system-wide file wins for the keys the administrator locked.
//! The trust root (backend URL, pinned keys) can only come from here, never from the backend itself.
mod load;

pub use load::{load, Override, Sources};

use contract::{FailMode, FailureModes};
use engine::signing::{PinnedKey, Trust, VerifyError};
use engine::LocalSettings;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::PathBuf;

const SECONDS_PER_MINUTE: u64 = 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    pub mode: Mode,
    /// No network at all: no backend, no usage, no update checks. Rules come from `rules_file` or the built-in set.
    /// In `managed` mode this is honoured only when the signed settings set `allow_offline`.
    pub offline: bool,
    /// A locally supplied signed snapshot, used instead of the backend (air-gapped and `standalone` setups).
    pub rules_file: Option<PathBuf>,
    pub backend: BackendConfig,
    pub auth: AuthConfig,
    pub listen: ListenConfig,
    /// Default upstream for the localhost API proxy. Must be in the server's `allowed_upstreams` when that is set.
    pub upstream: String,
    pub dry_run: bool,
    /// What to do per failure condition. In `standalone` mode either value is allowed; in `managed` mode only
    /// `"closed"`, because `"open"` has to come from the signed policy and is refused at startup.
    pub failure_modes: FailureModes,
    /// Alias for `failure_modes.unscannable`: `true` is `"closed"`, `false` is `"open"` (standalone mode only).
    pub block_unscannable: Option<bool>,
    /// Extra regexes blocked on top of the server's rules.
    pub deny: Vec<String>,
    pub max_tokens: usize,
    /// Alias for `failure_modes.service_down`: `true` is `"closed"`, `false` is `"open"` (standalone mode only).
    pub browser_fail_closed: Option<bool>,
    pub notify: bool,
    pub usage: UsageConfig,
    pub logging: LoggingConfig,
    pub update: UpdateConfig,
    pub limits: LimitsConfig,
    pub data_dir: Option<PathBuf>,
    /// Anchor the anti-rollback state (high-water marks, revoked key ids) in the OS keychain, so restoring or deleting
    /// files in the data directory is detected. Turn off only where no keychain exists, such as test sandboxes.
    pub state_keychain: bool,
}

/// Who owns the policy.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// One person is both administrator and user: every setting, including usage reporting, is local.
    #[default]
    Standalone,
    /// An administrator owns the policy: the signed snapshot decides usage reporting and the other enforced
    /// settings, and this file should live in the system-wide location that standard users cannot edit.
    Managed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct BackendConfig {
    /// `None` runs offline with the built-in rules.
    pub url: Option<String>,
    pub rules_path: String,
    pub enroll_path: String,
    pub poll_minutes: u64,
    /// Public keys that may sign rules snapshots.
    pub pinned_keys: Vec<PinnedKeyConfig>,
    /// Offline keys that may certify short-lived policy signing keys (hosted mode).
    pub root_keys: Vec<PinnedKeyConfig>,
    /// Plain `http://` is refused unless this is set (loopback is always allowed).
    pub allow_insecure_http: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedKeyConfig {
    pub key_id: String,
    /// Base64 Ed25519 public key.
    pub public_key: String,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthMode {
    #[default]
    None,
    StaticToken,
    Enrolled,
    DeviceFlow,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AuthConfig {
    pub mode: AuthMode,
    /// Environment variable holding the token for `static_token`; the OS keychain is used when unset.
    pub token_env: Option<String>,
    pub device_flow: DeviceFlowConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DeviceFlowConfig {
    pub client_id: String,
    pub code_path: String,
    pub token_path: String,
    pub session_path: String,
    pub jwt_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ListenConfig {
    pub port: u16,
    pub browser_port: u16,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UsageSink {
    Http,
    File,
    #[default]
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct UsageConfig {
    pub sink: UsageSink,
    pub path: String,
    pub file: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LoggingConfig {
    pub level: Option<String>,
    /// Metadata-only debug lines. Never request content.
    pub debug: bool,
    pub trace: bool,
    pub file: Option<PathBuf>,
    pub audit_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UpdateMode {
    Off,
    #[default]
    Notify,
    Download,
    Install,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct UpdateConfig {
    pub mode: UpdateMode,
    pub feed_url: Option<String>,
    pub channel: String,
    pub check_hours: u64,
    pub pinned_keys: Vec<PinnedKeyConfig>,
    /// Distinct update keys that must sign a manifest, whatever threshold the manifest asks for. When unset it is 2
    /// as soon as two or more distinct update keys are pinned and 1 for a single key, so pinning a second key cannot
    /// leave a one-key compromise sufficient. A manifest can raise this but never lower it.
    pub min_signatures: Option<usize>,
}

impl UpdateConfig {
    /// The floor for distinct signers: the explicit `min_signatures`, else 2 with two or more distinct pinned keys.
    pub fn required_signatures(&self) -> usize {
        self.min_signatures
            .unwrap_or_else(|| {
                self.distinct_pinned_keys()
                    .min(DEFAULT_MIN_SIGNATURES_WITH_ROTATION)
            })
            .max(1)
    }

    fn distinct_pinned_keys(&self) -> usize {
        self.pinned_keys
            .iter()
            .map(|key| key.public_key.as_str())
            .collect::<BTreeSet<_>>()
            .len()
    }
}

/// Largest request body read for scanning, and the largest it may expand to after decompression. Anything bigger
/// is blocked as unreadable rather than let through unscanned.
/// Signers required by default once update keys are pinned in pairs (CI key plus maintainer key).
const DEFAULT_MIN_SIGNATURES_WITH_ROTATION: usize = 2;
const DEFAULT_MAX_BODY_BYTES: usize = 32 << 20;
const DEFAULT_MAX_DECODED_BYTES: usize = 64 << 20;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LimitsConfig {
    pub max_body_bytes: usize,
    pub max_decoded_bytes: usize,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            max_decoded_bytes: DEFAULT_MAX_DECODED_BYTES,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mode: Mode::default(),
            offline: false,
            rules_file: None,
            backend: BackendConfig::default(),
            auth: AuthConfig::default(),
            listen: ListenConfig::default(),
            upstream: "https://api.anthropic.com".into(),
            dry_run: false,
            failure_modes: FailureModes::default(),
            block_unscannable: None,
            deny: vec![],
            max_tokens: 0,
            browser_fail_closed: None,
            notify: true,
            usage: UsageConfig::default(),
            logging: LoggingConfig::default(),
            update: UpdateConfig::default(),
            limits: LimitsConfig::default(),
            data_dir: None,
            state_keychain: true,
        }
    }
}

impl Default for BackendConfig {
    fn default() -> Self {
        Self {
            url: None,
            rules_path: "/v1/rules".into(),
            enroll_path: "/v1/enroll".into(),
            poll_minutes: 30,
            pinned_keys: vec![],
            root_keys: vec![],
            allow_insecure_http: false,
        }
    }
}

impl Default for UsageConfig {
    fn default() -> Self {
        Self {
            sink: UsageSink::default(),
            path: "/v1/usage".into(),
            file: None,
        }
    }
}

impl Default for ListenConfig {
    fn default() -> Self {
        Self {
            port: 8787,
            browser_port: 8788,
        }
    }
}

impl Default for DeviceFlowConfig {
    fn default() -> Self {
        Self {
            client_id: "inveil-client".into(),
            code_path: "/api/auth/device/code".into(),
            token_path: "/api/auth/device/token".into(),
            session_path: "/api/auth/get-session".into(),
            jwt_path: "/api/auth/token".into(),
        }
    }
}

impl Default for UpdateConfig {
    fn default() -> Self {
        Self {
            mode: UpdateMode::default(),
            feed_url: None,
            channel: "stable".into(),
            check_hours: 24,
            pinned_keys: vec![],
            min_signatures: None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid configuration: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("cannot represent the default configuration: {0}")]
    Defaults(#[from] toml::ser::Error),
    #[error("{variable}: {reason}")]
    Environment {
        variable: String,
        reason: &'static str,
    },
    #[error("{key}: {reason}")]
    Invalid { key: &'static str, reason: String },
}

impl Config {
    pub fn validate(&self) -> Result<(), ConfigError> {
        let invalid = |key: &'static str, reason: &str| ConfigError::Invalid {
            key,
            reason: reason.to_string(),
        };
        if let Some(url) = &self.backend.url {
            self.validate_backend_url(url)?;
            if self.backend.pinned_keys.is_empty() && self.backend.root_keys.is_empty() {
                return Err(invalid(
                    "backend.pinned_keys",
                    "a backend needs at least one pinned key (or root key) to verify its rules",
                ));
            }
        }
        if self.rules_file.is_some() && self.backend.pinned_keys.is_empty() {
            return Err(invalid(
                "backend.pinned_keys",
                "rules_file is verified against pinned keys, but none are configured",
            ));
        }
        self.trust()?;
        let local_modes = &self.failure_modes;
        let loosens = [
            local_modes.default,
            local_modes.unscannable,
            local_modes.scan_error,
            local_modes.policy_expired,
            local_modes.service_down,
        ]
        .contains(&Some(FailMode::Open));
        if loosens && self.mode == Mode::Managed {
            return Err(invalid(
                "failure_modes",
                "in managed mode local configuration can only choose \"closed\"; \"open\" must come from the signed policy",
            ));
        }
        for (key, path) in [
            ("backend.rules_path", &self.backend.rules_path),
            ("backend.enroll_path", &self.backend.enroll_path),
            ("usage.path", &self.usage.path),
        ] {
            if !path.starts_with('/') {
                return Err(invalid(key, "must start with '/'"));
            }
        }
        if self.backend.poll_minutes == 0 {
            return Err(invalid("backend.poll_minutes", "must be at least 1"));
        }
        if self.listen.port == 0 || self.listen.browser_port == 0 {
            return Err(invalid("listen", "ports must be between 1 and 65535"));
        }
        if self.listen.port == self.listen.browser_port {
            return Err(invalid("listen", "port and browser_port must be different"));
        }
        if self.limits.max_body_bytes == 0 || self.limits.max_decoded_bytes == 0 {
            return Err(invalid("limits", "sizes must be at least 1 byte"));
        }
        crate::logging::verbosity(&self.logging)
            .map_err(|error| invalid("logging.level", &error.to_string()))?;
        if !is_https_or_loopback(&self.upstream) {
            return Err(invalid(
                "upstream",
                "must be https:// (plain http is accepted only for loopback)",
            ));
        }
        match self.usage.sink {
            UsageSink::File if self.usage.file.is_none() => {
                return Err(invalid(
                    "usage.file",
                    "required when usage.sink is \"file\"",
                ))
            }
            UsageSink::Http if self.backend.url.is_none() => {
                return Err(invalid(
                    "backend.url",
                    "required when usage.sink is \"http\"",
                ))
            }
            _ => {}
        }
        if self.auth.mode != AuthMode::None && self.backend.url.is_none() {
            return Err(invalid("backend.url", "required when auth.mode is set"));
        }
        if self.update.check_hours == 0 {
            return Err(invalid("update.check_hours", "must be at least 1"));
        }
        if self.update.min_signatures == Some(0) {
            return Err(invalid("update.min_signatures", "must be at least 1"));
        }
        let pinned_update_keys = self.update.distinct_pinned_keys();
        if pinned_update_keys > 0 && self.update.required_signatures() > pinned_update_keys {
            return Err(invalid(
                "update.min_signatures",
                "is larger than the number of update.pinned_keys, so no update could ever verify",
            ));
        }
        if let Some(feed) = &self.update.feed_url {
            if !feed.starts_with("https://") {
                return Err(invalid("update.feed_url", "must be https://"));
            }
        }
        for key in &self.update.pinned_keys {
            PinnedKey::from_base64(&key.key_id, &key.public_key)
                .map_err(|error| invalid("update.pinned_keys", &error.to_string()))?;
        }
        Ok(())
    }

    fn validate_backend_url(&self, url: &str) -> Result<(), ConfigError> {
        let invalid = |reason: String| ConfigError::Invalid {
            key: "backend.url",
            reason,
        };
        let parsed = reqwest::Url::parse(url).map_err(|error| invalid(error.to_string()))?;
        if parsed.host_str().is_none() {
            return Err(invalid("has no host".into()));
        }
        match parsed.scheme() {
            "https" => Ok(()),
            "http" if self.backend.allow_insecure_http || host_is_loopback(&parsed) => Ok(()),
            "http" => Err(invalid(
                "plain http would send credentials in the clear; use https:// or set allow_insecure_http".into(),
            )),
            other => Err(invalid(format!("unsupported scheme {other}"))),
        }
    }

    pub fn local_settings(&self) -> LocalSettings {
        let mut failure_modes = self.failure_modes.clone();
        failure_modes.unscannable = alias_mode(self.block_unscannable, failure_modes.unscannable);
        failure_modes.service_down =
            alias_mode(self.browser_fail_closed, failure_modes.service_down);
        LocalSettings {
            managed: self.mode == Mode::Managed,
            offline: self.offline,
            dry_run: self.dry_run,
            failure_modes,
            max_tokens: self.max_tokens,
            deny: self.deny.clone(),
            upstream: self.upstream.clone(),
            usage_enabled: self.usage.sink != UsageSink::None,
            debug: self.logging.debug,
            poll_seconds: self.backend.poll_minutes * SECONDS_PER_MINUTE,
            client_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    /// The keys that may sign rules snapshots, decoded.
    pub fn trust(&self) -> Result<Trust, ConfigError> {
        let decode = |keys: &[PinnedKeyConfig], key: &'static str| {
            keys.iter()
                .map(|entry| {
                    PinnedKey::from_base64(&entry.key_id, &entry.public_key).map_err(
                        |error: VerifyError| ConfigError::Invalid {
                            key,
                            reason: error.to_string(),
                        },
                    )
                })
                .collect::<Result<Vec<_>, _>>()
        };
        Ok(Trust {
            keys: decode(&self.backend.pinned_keys, "backend.pinned_keys")?,
            roots: decode(&self.backend.root_keys, "backend.root_keys")?,
            ..Trust::default()
        })
    }
}

/// A legacy switch: `true` tightens to `closed` whatever else is configured, `false` means `open` unless the
/// `failure_modes` table already chose.
fn alias_mode(switch: Option<bool>, configured: Option<FailMode>) -> Option<FailMode> {
    match switch {
        Some(true) => Some(FailMode::Closed),
        Some(false) => configured.or(Some(FailMode::Open)),
        None => configured,
    }
}

pub fn host_is_loopback(url: &reqwest::Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    if host == "localhost" {
        return true;
    }
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
        .is_ok_and(|address| address.is_loopback())
}

pub fn is_https_or_loopback(value: &str) -> bool {
    let Ok(parsed) = reqwest::Url::parse(value) else {
        return false;
    };
    match parsed.scheme() {
        "https" => parsed.host_str().is_some(),
        "http" => host_is_loopback(&parsed),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    fn with_backend(url: &str) -> Config {
        let mut config = Config::default();
        config.backend.url = Some(url.into());
        config.backend.pinned_keys = vec![PinnedKeyConfig {
            key_id: "k1".into(),
            public_key: KEY.into(),
        }];
        config
    }

    const SECOND_KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

    fn pinned_update_keys(count: usize) -> UpdateConfig {
        let keys = [KEY, SECOND_KEY]
            .iter()
            .take(count)
            .enumerate()
            .map(|(index, key)| PinnedKeyConfig {
                key_id: format!("u{index}"),
                public_key: (*key).into(),
            })
            .collect();
        UpdateConfig {
            pinned_keys: keys,
            ..UpdateConfig::default()
        }
    }

    #[test]
    fn two_pinned_update_keys_require_two_signatures_unless_set() {
        assert_eq!(pinned_update_keys(0).required_signatures(), 1);
        assert_eq!(pinned_update_keys(1).required_signatures(), 1);
        assert_eq!(pinned_update_keys(2).required_signatures(), 2);

        let explicit = UpdateConfig {
            min_signatures: Some(1),
            ..pinned_update_keys(2)
        };
        assert_eq!(explicit.required_signatures(), 1);
    }

    #[test]
    fn the_same_update_key_pinned_twice_counts_once() {
        let mut update = pinned_update_keys(1);
        update.pinned_keys.push(PinnedKeyConfig {
            key_id: "again".into(),
            public_key: KEY.into(),
        });
        assert_eq!(update.required_signatures(), 1);
    }

    #[test]
    fn a_signature_floor_of_zero_or_above_the_pinned_keys_is_refused() {
        for floor in [0, 3] {
            let config = Config {
                update: UpdateConfig {
                    min_signatures: Some(floor),
                    ..pinned_update_keys(2)
                },
                ..Config::default()
            };
            assert!(config.validate().is_err(), "{floor}");
        }
        let config = Config {
            update: pinned_update_keys(2),
            ..Config::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn defaults_are_valid() {
        assert!(Config::default().validate().is_ok());
    }

    #[test]
    fn plain_http_backend_needs_loopback_or_an_explicit_flag() {
        assert!(with_backend("https://policy.example.com")
            .validate()
            .is_ok());
        assert!(with_backend("http://127.0.0.1:9000").validate().is_ok());
        assert!(with_backend("http://[::1]:9000").validate().is_ok());
        assert!(with_backend("http://policy.example.com")
            .validate()
            .is_err());
        let mut config = with_backend("http://policy.example.com");
        config.backend.allow_insecure_http = true;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn a_backend_without_pinned_keys_is_refused() {
        let mut config = with_backend("https://policy.example.com");
        config.backend.pinned_keys.clear();
        assert!(config.validate().is_err());
    }

    #[test]
    fn undecodable_pinned_keys_are_refused() {
        let mut config = with_backend("https://policy.example.com");
        config.backend.pinned_keys[0].public_key = "not base64!".into();
        assert!(config.validate().is_err());
    }

    #[test]
    fn the_legacy_switches_are_aliases_for_closed_failure_modes() {
        let defaults = Config::default().local_settings().failure_modes;
        assert_eq!(defaults, FailureModes::default());

        let config = Config {
            block_unscannable: Some(true),
            browser_fail_closed: Some(true),
            ..Config::default()
        };
        let modes = config.local_settings().failure_modes;
        assert_eq!(modes.unscannable, Some(FailMode::Closed));
        assert_eq!(modes.service_down, Some(FailMode::Closed));
        assert_eq!(modes.scan_error, None);

        let opened = Config {
            block_unscannable: Some(false),
            browser_fail_closed: Some(false),
            ..Config::default()
        };
        let modes = opened.local_settings().failure_modes;
        assert_eq!(modes.unscannable, Some(FailMode::Open));
        assert_eq!(modes.service_down, Some(FailMode::Open));
    }

    #[test]
    fn managed_mode_refuses_a_local_open_failure_mode_and_standalone_allows_it() {
        let mut config = Config::default();
        config.failure_modes.scan_error = Some(FailMode::Closed);
        assert!(config.validate().is_ok());
        config.failure_modes.default = Some(FailMode::Open);
        assert!(config.validate().is_ok());
        config.mode = Mode::Managed;
        assert!(matches!(
            config.validate(),
            Err(ConfigError::Invalid {
                key: "failure_modes",
                ..
            })
        ));
    }

    #[test]
    fn ports_must_be_set_and_distinct() {
        let mut config = Config::default();
        config.listen.port = 0;
        assert!(config.validate().is_err());
        config.listen.port = config.listen.browser_port;
        assert!(config.validate().is_err());
    }

    #[test]
    fn upstream_must_be_https_unless_loopback() {
        let remote = Config {
            upstream: "http://api.example.com".into(),
            ..Config::default()
        };
        assert!(remote.validate().is_err());
        let loopback = Config {
            upstream: "http://127.0.0.1:9999".into(),
            ..Config::default()
        };
        assert!(loopback.validate().is_ok());
    }
}
