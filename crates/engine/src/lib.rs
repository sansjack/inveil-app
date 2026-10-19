//! The decision engine: no network, no disk, no OS calls, so every stage can be tested without a server.
//!
//! The request pipeline is a chain of plain functions: [`decode()`] the body, [`inspect()`] it into a
//! [`scan::Report`], [`decide`] against the [`Effective`] settings, then redact, block or allow.
//! Policy files arrive through [`verify_snapshot`] and [`freshness::check`].

pub mod connect;
pub mod decision;
pub mod decode;
pub mod detector;
pub mod form;
pub mod freshness;
pub mod inspect;
pub mod policy;
pub mod protobuf;
pub mod scan;
pub mod settings;
pub mod signing;
pub mod validate;

mod validators;

#[cfg(test)]
mod test_support;

pub use decision::{decide, estimate_tokens, unreadable_message, Decision};
pub use decode::{decode, DecodeError, DEFAULT_MAX_DECODED_BYTES};
pub use detector::{salted_hash, Detector, Finding};
pub use freshness::{Candidate, HighWaterMark, LocalAnchors, Rejection, Verdict};
pub use inspect::{
    inspect, inspect_connect_frame, inspect_websocket_frame, InspectError, Inspection,
};
pub use policy::{is_covered, normalize_host, LocalRoute, LocalToolWiring, Policy};
pub use scan::{DenyDetector, PatternError, Report, RuleDetector, Scanner};
pub use settings::{
    effective_config_hash, merge_settings, Effective, LocalSettings, MergeError,
    ResolvedFailureModes, UsagePolicy,
};
pub use signing::{
    sha256_hex, sign_payload, verify_envelope, PinnedKey, Role, SignError, Trust, Verified,
    VerifyError,
};
pub use validate::{
    valid_host, validate, verify_snapshot, verify_snapshot_as_issued, SnapshotError,
    ValidationError,
};
