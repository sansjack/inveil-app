//! The marker an update leaves behind until its new binary has proved itself. The process that swaps the binary in
//! may be the service itself and is replaced by the restart, so it cannot judge the outcome. The new process does:
//! every start of an unconfirmed binary is counted, one that reports the wrong version or keeps failing to become
//! healthy is replaced by `inveil.prev`, and one that binds its port clears the marker.
use super::apply::restore_previous;
use super::download::hash_file;
use super::files::{failed, FileError};
use super::layout::InstallLayout;
use super::UpdateError;
use crate::util::write_atomically;
use semver::Version;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::ErrorKind;

/// Starts an unconfirmed binary gets before it is rolled back.
pub const MAX_START_ATTEMPTS: u32 = 3;

#[derive(Debug, thiserror::Error)]
pub enum PendingError {
    #[error(transparent)]
    File(#[from] FileError),
    #[error("the update marker {path} is unreadable: {source}")]
    Corrupt {
        path: String,
        source: serde_json::Error,
    },
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PendingUpdate {
    pub version: String,
    pub sha256: String,
    /// How many times the new binary has been started without confirming.
    pub starts: u32,
}

impl PendingUpdate {
    pub fn new(version: &Version, sha256: &str) -> Self {
        Self {
            version: version.to_string(),
            sha256: sha256.to_string(),
            starts: 0,
        }
    }

    pub fn load(layout: &InstallLayout) -> Result<Option<Self>, PendingError> {
        let path = layout.pending();
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(failed("read", &path)(error).into()),
        };
        serde_json::from_str(&text)
            .map(Some)
            .map_err(|source| PendingError::Corrupt {
                path: path.display().to_string(),
                source,
            })
    }

    pub fn write(&self, layout: &InstallLayout) -> Result<(), PendingError> {
        let path = layout.pending();
        let text = serde_json::to_vec(self).map_err(|source| PendingError::Corrupt {
            path: path.display().to_string(),
            source,
        })?;
        write_atomically(&path, &text).map_err(failed("write", &path))?;
        Ok(())
    }

    pub fn clear(layout: &InstallLayout) -> Result<(), PendingError> {
        let path = layout.pending();
        match fs::remove_file(&path) {
            Err(error) if error.kind() != ErrorKind::NotFound => {
                Err(failed("remove", &path)(error).into())
            }
            _ => Ok(()),
        }
    }
}

fn roll_back(layout: &InstallLayout, version: &str, reason: String) -> UpdateError {
    tracing::error!("update to {version} failed ({reason}); restoring the previous version");
    if let Err(error) = restore_previous(layout) {
        return UpdateError::Apply(error);
    }
    if let Err(error) = PendingUpdate::clear(layout) {
        return error.into();
    }
    UpdateError::RolledBackAtStart {
        version: version.to_string(),
        reason,
    }
}

/// Called at the very start of the service. Returns an error, after restoring `inveil.prev`, when the binary that is
/// starting is an update that has not proved itself: the caller must exit so the supervisor starts the old one.
pub fn recover_on_start(layout: &InstallLayout, running: &Version) -> Result<(), UpdateError> {
    let mut pending = match PendingUpdate::load(layout) {
        Ok(Some(pending)) => pending,
        Ok(None) => return Ok(()),
        Err(error) => {
            tracing::warn!("discarding the update marker: {error}");
            PendingUpdate::clear(layout)?;
            return Ok(());
        }
    };
    let installed =
        hash_file(&layout.install_path).map_err(failed("read", &layout.install_path))?;
    if installed != pending.sha256 {
        tracing::info!(
            "the update to {} did not complete or was already undone; clearing its marker",
            pending.version
        );
        PendingUpdate::clear(layout)?;
        return Ok(());
    }
    if running.to_string() != pending.version {
        let reason = format!("the new binary reports version {running}");
        return Err(roll_back(layout, &pending.version, reason));
    }
    pending.starts += 1;
    if pending.starts > MAX_START_ATTEMPTS {
        let reason = format!("it started {MAX_START_ATTEMPTS} times without becoming healthy");
        return Err(roll_back(layout, &pending.version, reason));
    }
    pending.write(layout)?;
    Ok(())
}

/// Called once the service has bound its port: the update is good, so its marker goes.
pub fn confirm_started(layout: &InstallLayout, running: &Version) -> Result<(), PendingError> {
    let Some(pending) = PendingUpdate::load(layout)? else {
        return Ok(());
    };
    if pending.version != running.to_string() {
        return Ok(());
    }
    tracing::info!("update to {running} confirmed");
    PendingUpdate::clear(layout)
}
