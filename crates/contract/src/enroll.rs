use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct EnrollRequest {
    pub token: String,
    pub client_version: String,
    #[serde(default)]
    pub device_label: Option<String>,
}

/// The backend derives the organisation from the enrollment token; the client never states it.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct EnrollResponse {
    pub device_credential: String,
    #[serde(default)]
    pub expires_at: Option<u64>,
    /// The organisation the token belongs to. The client stores it and rejects snapshots whose `audience` differs.
    #[serde(default)]
    pub org_id: Option<String>,
}
