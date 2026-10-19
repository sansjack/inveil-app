use serde::{Deserialize, Serialize};

pub const SNAPSHOT_SCHEMA: u8 = 1;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum Validator {
    Luhn,
    Ssn,
    Iban,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Block,
    Log,
    Redact,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct PiiRule {
    pub id: String,
    pub label: String,
    pub pattern: String,
    pub validator: Option<Validator>,
    pub action: Action,
    pub enabled: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum Format {
    Json,
    Protobuf,
    ProtobufFramed,
    /// `application/x-www-form-urlencoded`; the chat text sits in the values.
    Form,
    /// A WebSocket handshake route: the JSON text frames the browser sends are read.
    WebsocketJson,
    /// A streaming Connect / gRPC-web request, read frame by frame.
    ConnectStream,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum Match {
    Exact,
    Prefix,
}

/// A route that carries chat messages: the only requests the client reads.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub path: String,
    #[serde(rename = "match")]
    pub matching: Match,
    pub format: Format,
}

/// A host the browser proxy decrypts, and the paths on it that carry chat.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct Host {
    pub host: String,
    pub endpoints: Vec<Endpoint>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum Via {
    /// The tool is pointed at the client's localhost proxy, which forwards to `upstream`.
    Local,
    /// The browser or system proxy catches the traffic and the client decrypts `hosts`.
    Browser,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct Tool {
    pub id: String,
    pub name: String,
    pub via: Via,
    pub enabled: bool,
    pub upstream: Option<String>,
    /// Local tools: path the tool uses on the client's localhost port; `None` is the default route.
    pub prefix: Option<String>,
    /// Local tools: environment variable (e.g. `ANTHROPIC_BASE_URL`) the installer points at the proxy.
    #[serde(default)]
    pub env_var: Option<String>,
    /// Local tools: routes, as the upstream sees them, that carry chat.
    pub endpoints: Vec<Endpoint>,
    pub hosts: Vec<Host>,
}

/// Whether the client must report usage to the backend. Decided by the administrator in the signed snapshot.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum UsageReporting {
    /// Events and heartbeats are sent; local configuration cannot turn them off.
    Required,
    /// Local configuration decides.
    Optional,
    /// Nothing is sent and the backend needs no ingest endpoint.
    Disabled,
}

/// What to do when the client cannot make a normal decision.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum FailMode {
    /// Let the traffic through and record that it was passed because of a failure.
    Open,
    /// Block the traffic.
    Closed,
}

/// A situation in which the client cannot make a normal decision.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum FailureCondition {
    /// The request body cannot be read or scanned (unknown encoding, not JSON, over the decoded-size limit).
    Unscannable,
    /// The scanner failed internally.
    ScanError,
    /// The snapshot has expired and no fresh one can be fetched.
    PolicyExpired,
    /// The local service is down. Applied when routing is written, not at runtime.
    ServiceDown,
}

impl FailureCondition {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unscannable => "unscannable",
            Self::ScanError => "scan_error",
            Self::PolicyExpired => "policy_expired",
            Self::ServiceDown => "service_down",
        }
    }
}

/// Behaviour per failure condition. Each override falls back to `default`; local config may only choose `Closed`.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields, default)]
pub struct FailureModes {
    pub default: Option<FailMode>,
    /// The request body cannot be read or scanned (unknown encoding, base64 media).
    pub unscannable: Option<FailMode>,
    /// The scanner timed out or failed internally.
    pub scan_error: Option<FailMode>,
    /// The snapshot has expired and no fresh one can be fetched.
    pub policy_expired: Option<FailMode>,
    /// The local service is down. Applied when routing is written (PAC fallback, managed settings), not at runtime.
    pub service_down: Option<FailMode>,
}

impl FailureModes {
    /// The override for one condition, without falling back to `default`.
    pub const fn specific(&self, condition: FailureCondition) -> Option<FailMode> {
        match condition {
            FailureCondition::Unscannable => self.unscannable,
            FailureCondition::ScanError => self.scan_error,
            FailureCondition::PolicyExpired => self.policy_expired,
            FailureCondition::ServiceDown => self.service_down,
        }
    }
}

/// Policy knobs the backend enforces. Local configuration may only make them stricter.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields, default)]
pub struct Settings {
    /// `Some(false)` forces enforcement; `None` leaves the choice to local config.
    pub dry_run: Option<bool>,
    pub block_unscannable: Option<bool>,
    /// Maximum estimated tokens per request; `0` or `None` means no server limit.
    pub max_tokens: Option<usize>,
    /// Regexes blocked in addition to the rules.
    pub deny: Vec<String>,
    pub browser_fail_closed: Option<bool>,
    /// Hosts, `https://host`, the local `upstream` setting must be one of. Empty means unrestricted.
    pub allowed_upstreams: Vec<String>,
    pub min_poll_seconds: Option<u64>,
    pub min_client_version: Option<String>,
    pub allow_debug: Option<bool>,
    /// `None` means `Optional`.
    pub usage_reporting: Option<UsageReporting>,
    /// With `Required`, a heartbeat is sent at this interval even when there are no events, so the backend can
    /// tell a silent client from an idle one.
    pub heartbeat_seconds: Option<u64>,
    /// Whether local configuration may run the client fully offline. Managed deployments normally say no.
    pub allow_offline: Option<bool>,
    /// Block all chat traffic when the last good snapshot has expired and no fresh one can be fetched.
    pub fail_closed_on_expiry: bool,
    pub failure_modes: FailureModes,
}

/// The payload of a signed rules response.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub schema: u8,
    /// Strictly increasing per audience. A client never accepts a lower version, nor the same version with other content.
    pub version: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    /// Organisation this snapshot is for; the client rejects it when it differs from its enrolled organisation.
    #[serde(default)]
    pub audience: Option<String>,
    pub pii: Vec<PiiRule>,
    #[serde(default)]
    pub tools: Vec<Tool>,
    /// The only domains the browser CA may cover.
    #[serde(default)]
    pub ca_domains: Vec<String>,
    #[serde(default)]
    pub settings: Settings,
    #[serde(default)]
    pub revoked_key_ids: Vec<String>,
}
