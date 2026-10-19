//! Ports to whatever backend the operator runs. Each has at least two implementations (see the plan), so each is a trait.
mod credentials;
mod device_flow;
mod enroll;
mod http;
mod policy_source;
mod policy_updater;
mod snapshot;
mod usage;
mod usage_sink;

pub use credentials::{forget_all, save_static_token, stored_org_id, Credentials};
pub use device_flow::{login, whoami};
pub use enroll::{enroll, EnrollmentBundle};
pub use policy_source::{FilePolicySource, HttpPolicySource};
pub use policy_updater::PolicyUpdater;
pub use snapshot::{Expiry, SnapshotError, SnapshotStore, VerifiedSnapshot};
pub use usage::{new_event, spawn_uploader, UsageReporter};
pub use usage_sink::{FileUsageSink, HttpUsageSink};

use contract::{ClientInfo, UsageEvent};
use std::future::Future;
use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error("cannot reach the backend: {0}")]
    Unreachable(String),
    #[error("the backend rejected our credentials")]
    Unauthorized,
    #[error("the backend answered {0}")]
    Status(u16),
    #[error("the backend's answer is larger than {0} bytes")]
    ResponseTooLarge(usize),
    #[error("unexpected answer from the backend: {0}")]
    BadResponse(String),
    #[error("not signed in; run `inveil login`")]
    NotSignedIn,
    #[error("sign-in failed: {0}")]
    SignInFailed(String),
    #[error("cannot use the OS keychain: {0}")]
    Keychain(#[from] keyring::Error),
    #[error("cannot read {path}: {source}")]
    File {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("the backend URL is not usable: {0}")]
    BadUrl(String),
}

/// What a conditional fetch of the signed rules returned.
pub enum Fetched {
    /// The backend says the held snapshot is current.
    NotModified,
    /// The raw signed envelope, exactly as received, so it can be cached byte for byte.
    Envelope(String),
}

pub trait PolicySource: Send + Sync {
    /// `etag` is the SHA-256 of the payload we already hold, if any.
    fn fetch(
        &self,
        etag: Option<&str>,
    ) -> impl Future<Output = Result<Fetched, BackendError>> + Send;
}

pub trait UsageSink: Send + Sync {
    fn send(
        &self,
        client: &ClientInfo,
        events: &[UsageEvent],
    ) -> impl Future<Output = Result<(), BackendError>> + Send;
}

pub trait CredentialProvider: Send + Sync {
    /// A bearer credential for the backend, or `None` when the backend needs none.
    fn credential(&self) -> impl Future<Output = Result<Option<String>, BackendError>> + Send;
    /// Called after a 401 so a cached credential is not reused.
    fn invalidate(&self);
}
