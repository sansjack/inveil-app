//! Verified self-update plus the `inveil keygen` / `sign` / `verify` tooling.
//!
//! Flow: fetch the manifest over https, verify its signatures before parsing, check version/expiry/replay/target,
//! stream the raw binary into a private staging directory under a hard size limit and SHA-256, run it once, then move
//! it into place and re-hash it. The service restarts into the new binary, which clears the pending-update marker
//! once it is healthy; one that is not is replaced by `inveil.prev` (see `pending`).
mod apply;
mod args;
mod download;
mod fetch;
mod files;
pub(crate) mod health;
mod layout;
mod manifest;
mod pending;
mod sign;
mod state;

#[cfg(test)]
mod tests;

use crate::config::{Config, UpdateMode};
use crate::platform::{self, PlatformError};
use crate::trust_state::StateStore;
use crate::util::unix_seconds;
use apply::{Installed, Restored};
use args::Arguments;
use engine::signing::{Trust, VerifyError};
use fetch::{FetchError, Fetcher, HttpFetcher};
use files::FileError;
use health::{HealthCheck, ServiceHealth, HEALTH_TIMEOUT};
use layout::InstallLayout;
use manifest::{Candidate, ManifestError};
use semver::Version;
use std::fmt;
use std::time::{Duration, SystemTime};

pub use apply::remove_replaced;
pub use sign::{run_keygen, run_sign, run_verify};

const SECONDS_PER_HOUR: u64 = 3600;
pub const STATE_FILE_NAME: &str = "update-state.json";
/// Exit status of a service that replaced its own binary and needs the supervisor to start it again. Non-zero, so
/// `Restart=on-failure` and the Task Scheduler's restart-on-failure both treat it as a reason to restart.
pub const EXIT_RESTART_FOR_UPDATE: u8 = 75;

#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    #[error("{0}")]
    Usage(String),
    #[error("{0}")]
    Config(String),
    #[error("{0}")]
    Key(String),
    #[error("artifact does not match the manifest: {0}")]
    ArtifactMismatch(String),
    #[error("invalid payload: {0}")]
    Payload(String),
    #[error(transparent)]
    File(#[from] FileError),
    #[error(transparent)]
    Verify(#[from] VerifyError),
    #[error(transparent)]
    Snapshot(#[from] engine::SnapshotError),
    #[error(transparent)]
    Sign(#[from] engine::signing::SignError),
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    #[error(transparent)]
    Download(#[from] download::DownloadError),
    #[error(transparent)]
    Apply(#[from] apply::ApplyError),
    #[error(transparent)]
    Pending(#[from] pending::PendingError),
    #[error("the update to {version} did not come up healthy ({reason}); the previous version is restored and will be started")]
    RolledBackAtStart { version: String, reason: String },
    #[error(transparent)]
    Platform(#[from] PlatformError),
}

impl From<FetchError> for UpdateError {
    fn from(error: FetchError) -> Self {
        Self::Manifest(error.into())
    }
}

/// How far to take a newer release.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Action {
    Report,
    Stage,
    Install,
}

pub struct UpdateContext {
    pub trust: Trust,
    /// Floor for the number of distinct signers, whatever the manifest itself asks for (`update.min_signatures`).
    pub min_signatures: usize,
    pub channel: String,
    pub current: Version,
    pub target: String,
    pub layout: InstallLayout,
    pub state: StateStore,
    pub now: u64,
    /// The calling process is the installed service: it cannot restart itself and watch, so it exits after installing.
    pub running_as_service: bool,
}

#[derive(Debug)]
enum Outcome {
    Skipped(&'static str),
    UpToDate,
    Available(Candidate),
    Staged(Candidate),
    Installed(Candidate),
    /// The executable had gone missing and was rebuilt from the previous version.
    Recovered(Restored),
    /// Installed by the service itself, which must now exit so that the supervisor starts the new binary.
    InstalledAwaitingRestart(Candidate),
}

impl fmt::Display for Outcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (headline, candidate) = match self {
            Outcome::Skipped(reason) => return write!(formatter, "{reason}"),
            Outcome::UpToDate => return write!(formatter, "inveil is up to date"),
            Outcome::Recovered(Restored::NotNeeded) => {
                return write!(
                    formatter,
                    "the installed executable is present; nothing to recover"
                )
            }
            Outcome::Recovered(Restored::From(source)) => {
                return write!(
                    formatter,
                    "the installed executable was missing and has been restored from {}",
                    source.display()
                )
            }
            Outcome::Available(candidate) => ("update available", candidate),
            Outcome::Staged(candidate) => (
                "update downloaded and verified; run `inveil update --apply` to install",
                candidate,
            ),
            Outcome::Installed(candidate) => ("update installed", candidate),
            Outcome::InstalledAwaitingRestart(candidate) => {
                ("update installed; restarting to run it", candidate)
            }
        };
        write!(formatter, "{headline}: {}", candidate.version)?;
        if candidate.mandatory {
            write!(
                formatter,
                " (required: the running version is no longer supported)"
            )?;
        }
        if let Some(notes) = &candidate.notes_url {
            write!(formatter, "\nrelease notes: {notes}")?;
        }
        Ok(())
    }
}

/// True when a check should run. The caller owns the clock and the loop: this starts no thread of its own.
pub fn check_due(last_checked: Option<SystemTime>, check_hours: u64) -> bool {
    let Some(last_checked) = last_checked else {
        return true;
    };
    let interval = Duration::from_secs(check_hours.saturating_mul(SECONDS_PER_HOUR));
    match last_checked.elapsed() {
        Ok(elapsed) => elapsed >= interval,
        Err(_) => true,
    }
}

fn perform(
    context: &UpdateContext,
    fetcher: &dyn Fetcher,
    health: &dyn HealthCheck,
    feed_url: &str,
    action: Action,
) -> Result<Outcome, UpdateError> {
    let Some(candidate) = manifest::fetch_candidate(context, fetcher, feed_url)? else {
        return Ok(Outcome::UpToDate);
    };
    if action == Action::Report {
        return Ok(Outcome::Available(candidate));
    }
    download::stage(fetcher, &candidate.artifact, &context.layout)?;
    if action == Action::Stage {
        return Ok(Outcome::Staged(candidate));
    }
    let installed = apply::install(
        &context.layout,
        &candidate.artifact,
        &candidate.version,
        health,
        context.running_as_service,
    )?;
    tracing::info!(version = %candidate.version, "update installed");
    Ok(match installed {
        Installed::Confirmed => Outcome::Installed(candidate),
        Installed::RestartRequired => Outcome::InstalledAwaitingRestart(candidate),
    })
}

fn requested_action(
    mode: UpdateMode,
    check_only: bool,
    apply: bool,
) -> Result<Option<Action>, UpdateError> {
    if apply && !matches!(mode, UpdateMode::Download | UpdateMode::Install) {
        return Err(UpdateError::Usage(
            "--apply needs update.mode = download or install".to_string(),
        ));
    }
    if apply && check_only {
        return Err(UpdateError::Usage(
            "--apply and --check cannot be combined".to_string(),
        ));
    }
    if check_only {
        return Ok(Some(Action::Report));
    }
    Ok(match mode {
        UpdateMode::Off => None,
        UpdateMode::Notify => Some(Action::Report),
        UpdateMode::Download if apply => Some(Action::Install),
        UpdateMode::Download => Some(Action::Stage),
        UpdateMode::Install => Some(Action::Install),
    })
}

fn running_layout() -> Result<InstallLayout, UpdateError> {
    let executable = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .map_err(|error| UpdateError::Config(format!("cannot locate the executable: {error}")))?;
    InstallLayout::new(&executable)
        .ok_or_else(|| UpdateError::Config("the executable has no parent directory".to_string()))
}

/// Deletes the `<exe>.old` that a Windows update moved aside, for the running executable. Returns whether a file
/// was removed; a missing file is not an error, so this is safe to call on every start on any platform.
pub fn remove_replaced_executable() -> Result<bool, UpdateError> {
    remove_replaced_file(&running_layout()?)
}

fn remove_replaced_file(layout: &InstallLayout) -> Result<bool, UpdateError> {
    let replaced = layout.replaced();
    match std::fs::remove_file(&replaced) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(files::failed("remove", &replaced)(error).into()),
    }
}

fn running_version() -> Result<Version, UpdateError> {
    Version::parse(env!("CARGO_PKG_VERSION"))
        .map_err(|error| UpdateError::Config(format!("own version is not semver: {error}")))
}

/// `<os>-<arch>`, the key of this build's binary in a manifest.
fn host_target() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

fn build_context(config: &Config, running_as_service: bool) -> Result<UpdateContext, UpdateError> {
    let trust = sign::update_trust(config)?;
    if trust.keys.is_empty() {
        return Err(UpdateError::Config(
            "update.pinned_keys is empty: no key is trusted to sign updates".to_string(),
        ));
    }
    let data_dir = match &config.data_dir {
        Some(path) => path.clone(),
        None => platform::data_dir()?,
    };
    let use_keychain = config.state_keychain;
    Ok(UpdateContext {
        trust,
        min_signatures: config.update.required_signatures(),
        channel: config.update.channel.clone(),
        current: running_version()?,
        target: host_target(),
        layout: running_layout()?,
        state: StateStore::open(&data_dir, STATE_FILE_NAME, use_keychain),
        now: unix_seconds(),
        running_as_service,
    })
}

/// Called first thing when the service starts. When this binary is an update that has not proved itself, the previous
/// version is put back and an error comes back: the caller must exit so the supervisor starts the old one.
pub fn recover_on_start() -> Result<(), UpdateError> {
    pending::recover_on_start(&running_layout()?, &running_version()?)
}

/// Called once the service is listening: an update that got this far is healthy, so its marker is cleared.
pub fn confirm_started() {
    let confirmed = running_layout()
        .and_then(|layout| Ok(pending::confirm_started(&layout, &running_version()?)?));
    if let Err(error) = confirmed {
        tracing::warn!("cannot confirm the update: {error}");
    }
}

/// `inveil update --recover`: rebuilds the installed executable if an interrupted Windows update left none. Judged by
/// the installation path, not by the running binary, which is typically `inveil.prev` or a fresh download.
fn recover_install() -> Result<Outcome, UpdateError> {
    let install_path = platform::install_exe_path()?;
    let layout = InstallLayout::new(&install_path).ok_or_else(|| {
        UpdateError::Config("the install path has no parent directory".to_string())
    })?;
    Ok(Outcome::Recovered(apply::restore_missing_install(&layout)?))
}

fn execute(config: &Config, args: &[String], in_service: bool) -> Result<Outcome, UpdateError> {
    let arguments = Arguments::parse(args, &[], &["--check", "--apply", "--recover"])?;
    if !arguments.positional.is_empty() {
        return Err(UpdateError::Usage("update takes no arguments".to_string()));
    }
    if arguments.has("--recover") {
        return recover_install();
    }
    if config.offline {
        return Ok(Outcome::Skipped("offline mode: update checks are disabled"));
    }
    let Some(action) = requested_action(
        config.update.mode,
        arguments.has("--check"),
        arguments.has("--apply"),
    )?
    else {
        return Ok(Outcome::Skipped("updates are disabled (update.mode = off)"));
    };
    let feed_url = config
        .update
        .feed_url
        .as_deref()
        .ok_or_else(|| UpdateError::Config("update.feed_url is not set".to_string()))?;

    let service_managed = platform::service_installed().unwrap_or_else(|error| {
        tracing::warn!(%error, "cannot tell whether the service is installed");
        false
    });
    let context = build_context(config, in_service && service_managed)?;
    remove_replaced(&context.layout);
    let health = ServiceHealth {
        service_managed,
        port: config.listen.port,
        timeout: HEALTH_TIMEOUT,
    };
    perform(&context, &HttpFetcher, &health, feed_url, action)
}

/// `inveil update [--check]`: with no flag, applies an available update; `--check` only reports. Needs
/// `update.mode` of download or install to apply. As a
/// separate process from the service it restarts the service itself and rolls back if the new version does not
/// answer.
///
/// Blocks on the network, so call it from `spawn_blocking` when inside the async runtime.
pub fn run_update(config: &Config, args: &[String]) -> Result<String, UpdateError> {
    let mut args = args.to_vec();
    // A person typing `inveil update` wants the update; only the service's scheduled check follows `update.mode`.
    if !args
        .iter()
        .any(|arg| matches!(arg.as_str(), "--check" | "--apply" | "--recover"))
    {
        args.push("--apply".to_string());
    }
    execute(config, &args, false).map(|outcome| outcome.to_string())
}

/// What the service should do after a scheduled check.
pub enum ScheduledUpdate {
    Nothing(String),
    /// A new binary is in place. The service must exit with [`EXIT_RESTART_FOR_UPDATE`] so it is restarted into it.
    RestartRequired(String),
}

/// The periodic check run inside the service: like `run_update` with the default arguments, except that it cannot
/// restart itself, so after installing it asks the caller to exit.
pub fn run_scheduled_update(config: &Config) -> Result<ScheduledUpdate, UpdateError> {
    let outcome = execute(config, &[], true)?;
    let summary = outcome.to_string();
    match outcome {
        Outcome::InstalledAwaitingRestart(_) => Ok(ScheduledUpdate::RestartRequired(summary)),
        _ => Ok(ScheduledUpdate::Nothing(summary)),
    }
}
