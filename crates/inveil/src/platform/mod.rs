//! Everything that touches the operating system: service registration, trust store, system proxy, notifications and
//! per-user directories. One implementation per OS behind `cfg`, one set of signatures for the rest of the program.
//!
//! In test builds only, setting `INVEIL_PLATFORM_SANDBOX` to a directory moves every per-user path under it and turns
//! external commands (launchctl, systemctl, security, certutil, networksetup, gsettings, ...) and registry writes into
//! no-ops, so tests can exercise install and uninstall without touching the real system. The switch is compiled out of
//! every other build, so no environment can make an installed binary skip its system changes.
//!
//! This module must not use `crate::` paths: the platform integration tests include it by file path.
use std::path::{Path, PathBuf};
use std::{env, fs, io};

mod command;
mod definitions;
mod escape;
mod proxy;
mod runtime_trust;
mod trust_store;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos as system;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as system;

#[cfg(not(any(target_os = "macos", windows)))]
mod linux;
#[cfg(not(any(target_os = "macos", windows)))]
use linux as system;

pub use proxy::{pac_script, proxy_environment};
pub use runtime_trust::{bundle_path, tool_environment, write_ca_bundle, RuntimeKind};
pub use system::{
    clear_pac, data_dir, default_log_path, install_service, notify, restart_service,
    service_installed, set_pac, stop_service, trust_ca, uninstall_service, untrust_ca,
};
#[cfg(windows)]
pub use windows::program_data_dir;

/// Common name of the browser CA; the trust stores identify the certificate by it when removing.
pub const CA_NAME: &str = "Inveil Browser CA";
/// Name of the service in launchd, systemd and the Windows task scheduler.
#[cfg_attr(windows, allow(dead_code))]
pub const SERVICE_LABEL: &str = "com.inveil.proxy";
#[cfg(test)]
pub const SANDBOX_VARIABLE: &str = "INVEIL_PLATFORM_SANDBOX";

const APP_DIR_NAME: &str = "inveil";
const PID_FILE_NAME: &str = "inveil.pid";
const SERVICE_SUBCOMMAND: &str = "run";
const LOG_FILE_FLAG: &str = "--log-file";

#[derive(Debug, thiserror::Error)]
pub enum PlatformError {
    #[error("{path}: {source}")]
    Io { path: String, source: io::Error },
    #[error("cannot run {program}: {source}")]
    Spawn { program: String, source: io::Error },
    #[error("{program} failed: {detail}")]
    CommandFailed { program: String, detail: String },
    #[cfg(target_os = "linux")]
    #[error("{tool} is not installed. {instructions}")]
    MissingTool {
        tool: String,
        instructions: &'static str,
    },
    #[error("environment variable {0} is not set")]
    MissingEnvironment(&'static str),
    #[error("{0}")]
    InvalidArgument(String),
    #[error("no system root certificates were found to build the CA bundle")]
    NoSystemRoots,
}

/// True when this process runs with administrator rights (root, or an elevated Windows token).
pub fn is_elevated() -> bool {
    #[cfg(unix)]
    {
        rustix::process::geteuid().is_root()
    }
    #[cfg(windows)]
    {
        windows::is_elevated()
    }
}

/// The Windows ProgramData folder from the registry's `%SystemDrive%\ProgramData` value, given the `SystemRoot` value
/// whose drive replaces `%SystemDrive%`. Both values live under HKLM, which only administrators can write.
#[cfg_attr(not(windows), allow(dead_code))]
fn expand_system_drive(value: &str, system_root: &str) -> Option<PathBuf> {
    let mut root = system_root.chars();
    let letter = root.next().filter(char::is_ascii_alphabetic)?;
    if root.next()? != ':' {
        return None;
    }
    let expanded = value.replace("%SystemDrive%", &format!("{letter}:"));
    if expanded.contains('%') {
        return None;
    }
    Some(PathBuf::from(expanded))
}

fn io_error(path: &Path) -> impl FnOnce(io::Error) -> PlatformError + '_ {
    move |source| PlatformError::Io {
        path: path.display().to_string(),
        source,
    }
}

#[cfg(test)]
fn sandbox_root() -> Option<PathBuf> {
    env::var_os(SANDBOX_VARIABLE).map(PathBuf::from)
}

#[cfg(not(test))]
fn sandbox_root() -> Option<PathBuf> {
    None
}

fn home_dir() -> Result<PathBuf, PlatformError> {
    if let Some(root) = sandbox_root() {
        return Ok(root);
    }
    let variable = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    env::var_os(variable)
        .map(PathBuf::from)
        .ok_or(PlatformError::MissingEnvironment(variable))
}

fn path_str(path: &Path) -> Result<&str, PlatformError> {
    path.to_str().ok_or_else(|| {
        PlatformError::InvalidArgument(format!("path is not valid UTF-8: {}", path.display()))
    })
}

fn remove_file_if_present(path: &Path) -> Result<(), PlatformError> {
    match fs::remove_file(path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(io_error(path)(error)),
        _ => Ok(()),
    }
}

/// The program and arguments the service manager runs.
fn service_command(exe: &Path, log: &Path) -> Result<Vec<String>, PlatformError> {
    Ok(vec![
        path_str(exe)?.to_string(),
        SERVICE_SUBCOMMAND.to_string(),
        LOG_FILE_FLAG.to_string(),
        path_str(log)?.to_string(),
    ])
}

/// Whether the browser CA is in the store the browsers read. Read-only; always true in the sandbox.
pub fn ca_trusted() -> Result<bool, PlatformError> {
    if sandbox_root().is_some() {
        return Ok(true);
    }
    system::ca_trusted()
}

/// Whether the system proxy settings name exactly `pac_url`. Read-only; always true in the sandbox.
pub fn pac_applied(pac_url: &str) -> Result<bool, PlatformError> {
    if sandbox_root().is_some() {
        return Ok(true);
    }
    system::pac_applied(pac_url)
}

/// Where the installed copy of the executable lives.
pub fn install_exe_path() -> Result<PathBuf, PlatformError> {
    let file_name = if cfg!(windows) {
        "inveil.exe"
    } else {
        "inveil"
    };
    Ok(data_dir()?.join(file_name))
}

/// Records this process id so the service can be stopped by PID rather than by image name.
pub fn write_pid_file() -> Result<(), PlatformError> {
    let directory = data_dir()?;
    fs::create_dir_all(&directory).map_err(io_error(&directory))?;
    let path = directory.join(PID_FILE_NAME);
    fs::write(&path, std::process::id().to_string()).map_err(io_error(&path))
}

/// Writes a file only the current user can read (mode 0600 on Unix, a current-user-only ACL on Windows).
pub fn write_private_file(path: &Path, contents: &str) -> Result<(), PlatformError> {
    create_private_file(path)?;
    fs::write(path, contents).map_err(io_error(path))
}

#[cfg(unix)]
fn create_private_file(path: &Path) -> Result<(), PlatformError> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    const OWNER_READ_WRITE: u32 = 0o600;
    let file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(OWNER_READ_WRITE)
        .open(path)
        .map_err(io_error(path))?;
    file.set_permissions(fs::Permissions::from_mode(OWNER_READ_WRITE))
        .map_err(io_error(path))
}

#[cfg(windows)]
fn create_private_file(path: &Path) -> Result<(), PlatformError> {
    fs::File::create(path).map_err(io_error(path))?;
    windows::restrict_to_current_user(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn program_data_comes_from_registry_values_with_the_system_drive_filled_in() {
        assert_eq!(
            expand_system_drive(r"%SystemDrive%\ProgramData", r"D:\Windows"),
            Some(PathBuf::from(r"D:\ProgramData"))
        );
        assert_eq!(
            expand_system_drive(r"E:\Data", r"C:\Windows"),
            Some(PathBuf::from(r"E:\Data"))
        );
    }

    #[test]
    fn a_program_data_value_that_cannot_be_resolved_is_refused() {
        assert_eq!(expand_system_drive(r"%SystemDrive%\ProgramData", ""), None);
        assert_eq!(
            expand_system_drive(r"%SystemDrive%\ProgramData", r"\\server\share"),
            None
        );
        assert_eq!(
            expand_system_drive(r"%ProgramData%\x", r"C:\Windows"),
            None,
            "an unexpanded variable would be read from the environment later"
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_test_process_is_not_elevated() {
        assert!(!is_elevated());
    }

    #[test]
    fn service_command_runs_the_executable_with_the_log_path_as_one_argument() {
        let command = service_command(
            Path::new("/opt/my app/inveil"),
            Path::new("/var/log/in veil.log"),
        )
        .unwrap();
        assert_eq!(
            command,
            [
                "/opt/my app/inveil",
                "run",
                "--log-file",
                "/var/log/in veil.log"
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn private_files_are_readable_by_the_owner_only_even_when_they_already_existed() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("ca.key");
        fs::write(&path, "old").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        write_private_file(&path, "secret").unwrap();

        assert_eq!(fs::read_to_string(&path).unwrap(), "secret");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
