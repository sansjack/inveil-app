//! Moves a verified binary into place. Order matters: re-hash the staged file, run it once to see that it starts,
//! keep `inveil.prev`, record the pending update, atomically swap, re-hash what is now installed, then restart. Any
//! failure restores `inveil.prev`; once the swap is done, a new binary that proves unhealthy is rolled back either
//! here (a separate updater process watches the restart) or at its own next start (see `pending`).
use super::download::hash_file;
use super::files::{failed, make_executable, FileError};
use super::health::{HealthCheck, HealthError};
use super::layout::InstallLayout;
use super::pending::{PendingError, PendingUpdate};
use contract::Artifact;
use semver::Version;
use std::fs;
use std::io::ErrorKind;

#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    #[error(transparent)]
    File(#[from] FileError),
    #[error(transparent)]
    Pending(#[from] PendingError),
    #[error("the downloaded binary failed its smoke test and was not installed: {0}")]
    SmokeTest(HealthError),
    #[error("staged binary hash {actual} does not match the signed hash {expected}")]
    StagedHashMismatch { expected: String, actual: String },
    #[error("{} is missing and there is no previous version to restore it from", path.display())]
    NothingToRestore { path: std::path::PathBuf },
    #[error("the installed binary did not match the signed hash after the move; previous version restored")]
    InstalledHashMismatch,
    #[error(
        "the new version failed its health check ({reason}); rolled back to the previous version"
    )]
    RolledBack { reason: HealthError },
    #[error(
        "the update failed ({reason}) and restoring the previous version also failed: {rollback}"
    )]
    RollbackFailed {
        reason: String,
        rollback: Box<ApplyError>,
    },
}

/// Unix replaces the file with one atomic rename. Windows cannot overwrite a running executable but can rename it, so
/// the old one moves aside to `.old` (deleted on the next start) and the new one takes its name. A crash between the two
/// renames leaves no executable at all; the pending-update marker, written before this runs, and `inveil.prev` are what
/// `restore_missing_install` uses to put one back.
fn swap_in(layout: &InstallLayout, source: &std::path::Path) -> Result<(), ApplyError> {
    let target = &layout.install_path;
    if !cfg!(windows) {
        return fs::rename(source, target).map_err(|error| failed("replace", target)(error).into());
    }
    let replaced = layout.replaced();
    match fs::remove_file(&replaced) {
        Err(error) if error.kind() != ErrorKind::NotFound => {
            return Err(failed("remove", &replaced)(error).into())
        }
        _ => {}
    }
    fs::rename(target, &replaced).map_err(failed("move aside", target))?;
    if let Err(error) = fs::rename(source, target) {
        fs::rename(&replaced, target).map_err(failed("restore", target))?;
        return Err(failed("replace", target)(error).into());
    }
    Ok(())
}

fn save_previous(layout: &InstallLayout) -> Result<(), ApplyError> {
    let previous = layout.previous();
    let copy = layout.rollback_copy();
    fs::copy(&layout.install_path, &copy).map_err(failed("copy", &layout.install_path))?;
    fs::rename(&copy, &previous).map_err(failed("write", &previous))?;
    Ok(())
}

pub fn restore_previous(layout: &InstallLayout) -> Result<(), ApplyError> {
    let previous = layout.previous();
    let copy = layout.rollback_copy();
    fs::copy(&previous, &copy).map_err(failed("read", &previous))?;
    swap_in(layout, &copy)
}

fn rollback(layout: &InstallLayout, reason: &str) -> Result<(), ApplyError> {
    restore_previous(layout).map_err(|rollback| ApplyError::RollbackFailed {
        reason: reason.to_string(),
        rollback: Box::new(rollback),
    })
}

/// How an installation ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Installed {
    /// The updater restarted the service itself and saw the new version answer.
    Confirmed,
    /// The new binary is in place; the running process, which is the service, must exit so it gets restarted.
    RestartRequired,
}

/// `running_as_service`: the process calling this is the installed service, so restarting it from here would kill
/// the caller. It returns `RestartRequired` instead, and the new binary judges itself at start.
pub fn install(
    layout: &InstallLayout,
    artifact: &Artifact,
    version: &Version,
    health: &dyn HealthCheck,
    running_as_service: bool,
) -> Result<Installed, ApplyError> {
    let result = replace_binary(layout, artifact, version, health, running_as_service);
    let staging = layout.staging_dir();
    if let Err(error) = fs::remove_dir_all(&staging) {
        if error.kind() != ErrorKind::NotFound {
            tracing::warn!(path = %staging.display(), %error, "cannot remove update staging directory");
        }
    }
    result
}

fn replace_binary(
    layout: &InstallLayout,
    artifact: &Artifact,
    version: &Version,
    health: &dyn HealthCheck,
    running_as_service: bool,
) -> Result<Installed, ApplyError> {
    let staged = layout.staged();
    let staged_hash = hash_file(&staged).map_err(failed("read", &staged))?;
    if staged_hash != artifact.sha256 {
        return Err(ApplyError::StagedHashMismatch {
            expected: artifact.sha256.clone(),
            actual: staged_hash,
        });
    }

    make_executable(&staged).map_err(failed("make executable", &staged))?;
    health
        .smoke_test(&staged, version)
        .map_err(ApplyError::SmokeTest)?;
    save_previous(layout)?;
    PendingUpdate::new(version, &artifact.sha256).write(layout)?;
    swap_in(layout, &staged)?;

    let installed_hash =
        hash_file(&layout.install_path).map_err(failed("read", &layout.install_path))?;
    if installed_hash != artifact.sha256 {
        rollback(layout, "installed hash mismatch")?;
        PendingUpdate::clear(layout)?;
        return Err(ApplyError::InstalledHashMismatch);
    }
    if running_as_service {
        return Ok(Installed::RestartRequired);
    }

    let healthy = health.restart().and_then(|()| health.confirm(version));
    let Err(reason) = healthy else {
        return Ok(Installed::Confirmed);
    };
    tracing::error!(%reason, "new version unhealthy, rolling back");
    rollback(layout, &reason.to_string())?;
    PendingUpdate::clear(layout)?;
    if let Err(restart_error) = health.restart() {
        tracing::error!(%restart_error, "cannot restart the restored version");
    }
    Err(ApplyError::RolledBack { reason })
}

/// Deletes the executable that a Windows update moved aside. Safe to call on every start on any platform.
pub fn remove_replaced(layout: &InstallLayout) {
    let replaced = layout.replaced();
    match fs::remove_file(&replaced) {
        Err(error) if error.kind() != ErrorKind::NotFound => {
            tracing::warn!(path = %replaced.display(), %error, "cannot remove replaced executable");
        }
        _ => {}
    }
}

/// What `restore_missing_install` did.
#[derive(Debug, PartialEq, Eq)]
pub enum Restored {
    /// The executable is there; nothing was changed.
    NotNeeded,
    /// The executable was missing (a crash in the middle of the Windows swap) and was rebuilt from this file.
    From(std::path::PathBuf),
}

/// Puts the previous version back when the installed executable is gone. It cannot run from the missing executable, so
/// it is for another `inveil` binary (such as `inveil.prev` itself) invoked as `inveil update --recover`. `inveil.prev`
/// comes first because it is always the last good version; `.old` can be the bad binary of a rollback in progress.
pub fn restore_missing_install(layout: &InstallLayout) -> Result<Restored, ApplyError> {
    let target = &layout.install_path;
    match fs::metadata(target) {
        Ok(_) => return Ok(Restored::NotNeeded),
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(failed("inspect", target)(error).into()),
    }
    let source = [layout.previous(), layout.replaced()]
        .into_iter()
        .find(|candidate| candidate.is_file())
        .ok_or_else(|| ApplyError::NothingToRestore {
            path: target.clone(),
        })?;
    let copy = layout.rollback_copy();
    fs::copy(&source, &copy).map_err(failed("read", &source))?;
    make_executable(&copy).map_err(failed("make executable", &copy))?;
    fs::rename(&copy, target).map_err(failed("restore", target))?;
    PendingUpdate::clear(layout)?;
    tracing::warn!(from = %source.display(), "restored the missing executable");
    Ok(Restored::From(source))
}
