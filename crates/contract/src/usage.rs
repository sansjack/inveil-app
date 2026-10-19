use crate::FailureModes;
use serde::{Deserialize, Serialize};

pub const MAX_USAGE_BATCH: usize = 100;

/// How a request is paid for, judged from the host and the credential scheme only.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum Billing {
    /// A pay-per-token API key.
    Api,
    /// A consumer or plan subscription: a browser chat app, or a coding tool signed in with an account.
    Subscription,
    /// The client could not tell.
    #[default]
    Unknown,
}

/// Metadata about one proxied request. Never carries prompt content.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct UsageEvent {
    pub id: String,
    pub timestamp: u64,
    pub provider: String,
    pub model: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    /// Prompt tokens served from the provider's cache. A subset of `input_tokens`.
    #[serde(default)]
    pub cache_read_tokens: u64,
    /// Prompt tokens written to the provider's cache. A subset of `input_tokens`.
    #[serde(default)]
    pub cache_write_tokens: u64,
    #[serde(default)]
    pub billing: Billing,
    /// The real upstream provider when `provider` (the host) is a gateway or reseller, e.g. `anthropic` on Bedrock.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub served_by: Option<String>,
    /// Id of the request signal that decided `billing`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub billing_signal: Option<String>,
    /// Id of the request signal that produced `model`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_signal: Option<String>,
    pub latency_ms: u64,
    pub status: u16,
    pub blocked: bool,
    pub findings: usize,
}

/// Lets the backend detect clients running with a different policy or configuration than it published.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct ClientInfo {
    pub version: String,
    pub policy_version: u64,
    /// Hex SHA-256 of the effective (merged) configuration.
    pub config_hash: String,
    /// The failure modes the client is running with, every condition resolved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_modes: Option<FailureModes>,
    /// Requests passed through because a failure mode was `open`, counted since the client started.
    #[serde(default)]
    pub fail_open_count: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct UsageBatch {
    pub client: ClientInfo,
    pub events: Vec<UsageEvent>,
}
