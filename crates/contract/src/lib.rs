//! Wire types shared by the client and any backend. Pure data: no I/O, no verification.
//!
//! Every payload that changes client behaviour travels inside a [`SignedEnvelope`]; the client verifies the
//! signature over the exact payload string before parsing it into one of these types.

mod enroll;
mod envelope;
mod manifest;
mod snapshot;
mod usage;

#[cfg(test)]
mod schema;

pub use enroll::{EnrollRequest, EnrollResponse};
pub use envelope::{Delegation, SignatureEntry, SignedEnvelope};
pub use manifest::{Artifact, UpdateManifest, MANIFEST_SCHEMA};
pub use snapshot::{
    Action, Endpoint, FailMode, FailureCondition, FailureModes, Format, Host, Match, PiiRule,
    Settings, Snapshot, Tool, UsageReporting, Validator, Via, SNAPSHOT_SCHEMA,
};
pub use usage::{Billing, ClientInfo, UsageBatch, UsageEvent, MAX_USAGE_BATCH};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshots_reject_unknown_fields() {
        let json = r#"{"schema":1,"version":1,"issued_at":0,"expires_at":1,"pii":[],"extra":true}"#;
        assert!(serde_json::from_str::<Snapshot>(json).is_err());
    }

    #[test]
    fn minimal_snapshot_gets_default_settings() {
        let json = r#"{"schema":1,"version":1,"issued_at":0,"expires_at":1,"pii":[]}"#;
        let snapshot: Snapshot = serde_json::from_str(json).unwrap();
        assert_eq!(snapshot.settings, Settings::default());
        assert!(snapshot.tools.is_empty());
    }

    #[test]
    fn enroll_response_names_the_organisation_only_when_the_backend_does() {
        let without: EnrollResponse = serde_json::from_str(r#"{"device_credential":"c"}"#).unwrap();
        assert_eq!(without.org_id, None);
        let with: EnrollResponse =
            serde_json::from_str(r#"{"device_credential":"c","org_id":"acme"}"#).unwrap();
        assert_eq!(with.org_id.as_deref(), Some("acme"));
    }
}
