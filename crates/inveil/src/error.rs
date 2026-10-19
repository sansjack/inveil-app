use crate::backend::{BackendError, SnapshotError};
use crate::config::ConfigError;
use crate::logging::LoggingError;
use crate::platform::PlatformError;
use crate::policy::PolicyBuildError;
use crate::proxy::browser_ca::CaError;
use crate::proxy::ProxyError;
use crate::update::UpdateError;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Logging(#[from] LoggingError),
    #[error(transparent)]
    Platform(#[from] PlatformError),
    #[error(transparent)]
    Backend(#[from] BackendError),
    #[error(transparent)]
    Snapshot(#[from] SnapshotError),
    #[error(transparent)]
    Policy(#[from] PolicyBuildError),
    #[error(transparent)]
    Proxy(#[from] ProxyError),
    #[error(transparent)]
    Ca(#[from] CaError),
    #[error(transparent)]
    Update(#[from] UpdateError),
    #[error("cannot read {path}: {source}")]
    ReadFile {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("cannot write {path}: {source}")]
    WriteFile {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("cannot start the async runtime: {0}")]
    Runtime(std::io::Error),
    #[error("cannot listen for shutdown signals: {0}")]
    Signal(std::io::Error),
    #[error("{0}")]
    Usage(String),
    #[error("{0}")]
    Refused(String),
}

pub const EXIT_FAILURE: u8 = 1;
pub const EXIT_USAGE: u8 = 2;
/// The signed policy forbids this configuration (or this client version), so the proxy does not run.
pub const EXIT_POLICY_REFUSED: u8 = 3;

impl AppError {
    pub fn exit_code(&self) -> ExitCode {
        match self {
            Self::Config(_) | Self::Usage(_) | Self::Logging(_) => ExitCode::from(EXIT_USAGE),
            Self::Refused(_) => ExitCode::from(EXIT_POLICY_REFUSED),
            _ => ExitCode::from(EXIT_FAILURE),
        }
    }
}
