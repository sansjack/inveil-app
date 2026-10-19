use crate::FailureModes;
use serde::{Deserialize, Serialize};

pub const MAX_USAGE_BATCH: usize = 100;

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
