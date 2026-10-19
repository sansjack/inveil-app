//! Windows: Scheduled Task with restart on failure, per-user certificate store, registry PAC, balloon notification.
use super::command::{run, run_with_environment};
use super::definitions::scheduled_task_xml;
use super::escape::{powershell_encoded_command, utf16_le_with_byte_order_mark};
use super::trust_store::remove_while_present;
use super::{
    expand_system_drive, home_dir, io_error, path_str, remove_file_if_present, sandbox_root,
    service_command, PlatformError, APP_DIR_NAME, CA_NAME, PID_FILE_NAME,
};
use std::path::{Path, PathBuf};
use std::{env, fs};
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE};
use winreg::RegKey;

const TASK_NAME: &str = "Inveil";
const TASK_FILE_NAME: &str = "inveil-task.xml";
const LOG_FILE_NAME: &str = "inveil.log";
const IMAGE_NAME: &str = "inveil.exe";
const INTERNET_SETTINGS_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
const AUTO_CONFIG_URL_VALUE: &str = "AutoConfigURL";
const NOTIFICATION_TITLE_VARIABLE: &str = "INVEIL_NOTIFY_TITLE";
const NOTIFICATION_MESSAGE_VARIABLE: &str = "INVEIL_NOTIFY_MESSAGE";
const BALLOON_DISPLAY_MILLISECONDS: u32 = 6000;
const BALLOON_WAIT_SECONDS: u32 = 7;
const WHOAMI_SID_FIELD: usize = 1;
const WINDOWS_VERSION_KEY: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
const PROFILE_LIST_KEY: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";
const SYSTEM_ROOT_VALUE: &str = "SystemRoot";
const PROGRAM_DATA_VALUE: &str = "ProgramData";
const MACHINE_SOFTWARE_KEY: &str = "SOFTWARE";

/// The ProgramData folder as the machine registry records it. The `ProgramData` environment variable is never used:
/// a standard user can set it for their own processes, which would make the administrator-only system-wide
/// configuration user-controlled. `None` when the registry does not give a usable value.
pub fn program_data_dir() -> Option<PathBuf> {
    let machine = RegKey::predef(HKEY_LOCAL_MACHINE);
    let system_root: String = machine
        .open_subkey(WINDOWS_VERSION_KEY)
        .ok()?
        .get_value(SYSTEM_ROOT_VALUE)
        .ok()?;
    let program_data: String = machine
        .open_subkey(PROFILE_LIST_KEY)
        .ok()?
        .get_value(PROGRAM_DATA_VALUE)
        .ok()?;
    expand_system_drive(&program_data, &system_root)
}

/// Only an administrator can open HKLM\SOFTWARE for writing.
pub fn is_elevated() -> bool {
    RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(MACHINE_SOFTWARE_KEY, KEY_WRITE)
        .is_ok()
}

pub fn data_dir() -> Result<PathBuf, PlatformError> {
    if sandbox_root().is_some() {
        return Ok(home_dir()?.join("AppData/Local").join(APP_DIR_NAME));
    }
    let local_app_data =
        env::var_os("LOCALAPPDATA").ok_or(PlatformError::MissingEnvironment("LOCALAPPDATA"))?;
    Ok(PathBuf::from(local_app_data).join(APP_DIR_NAME))
}

pub fn default_log_path() -> Result<PathBuf, PlatformError> {
    Ok(data_dir()?.join(LOG_FILE_NAME))
}

fn task_file_path() -> Result<PathBuf, PlatformError> {
    Ok(data_dir()?.join(TASK_FILE_NAME))
}

fn current_user() -> Result<String, PlatformError> {
    let domain =
        env::var("USERDOMAIN").map_err(|_| PlatformError::MissingEnvironment("USERDOMAIN"))?;
    let name = env::var("USERNAME").map_err(|_| PlatformError::MissingEnvironment("USERNAME"))?;
    Ok(format!("{domain}\\{name}"))
}

pub fn install_service(exe: &Path, log: &Path) -> Result<(), PlatformError> {
    let task_xml = scheduled_task_xml(&current_user()?, &service_command(exe, log)?)?;
    let task_file = task_file_path()?;
    let directory = data_dir()?;
    fs::create_dir_all(&directory).map_err(io_error(&directory))?;
    stop_service()?;
    fs::write(&task_file, utf16_le_with_byte_order_mark(&task_xml))
        .map_err(io_error(&task_file))?;
    run(
        "schtasks",
        &[
            "/Create",
            "/TN",
            TASK_NAME,
            "/XML",
            path_str(&task_file)?,
            "/F",
        ],
    )?;
    run("schtasks", &["/Run", "/TN", TASK_NAME]).map(drop)
}

/// Ends the task, then any process recorded in the PID file. Never matches by image name alone.
pub fn stop_service() -> Result<(), PlatformError> {
    if let Err(error) = run("schtasks", &["/End", "/TN", TASK_NAME]) {
        tracing::debug!("scheduled task was not running: {error}");
    }
    stop_by_pid()
}

fn stop_by_pid() -> Result<(), PlatformError> {
    let pid_path = data_dir()?.join(PID_FILE_NAME);
    let contents = match fs::read_to_string(&pid_path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(io_error(&pid_path)(error)),
    };
    let pid: u32 = contents.trim().parse().map_err(|_| {
        PlatformError::InvalidArgument(format!(
            "{} does not contain a process id",
            pid_path.display()
        ))
    })?;
    if pid != std::process::id() {
        let image_filter = format!("IMAGENAME eq {IMAGE_NAME}");
        if let Err(error) = run(
            "taskkill",
            &["/PID", &pid.to_string(), "/FI", &image_filter, "/F"],
        ) {
            tracing::debug!("process {pid} from the PID file was not running: {error}");
        }
    }
    remove_file_if_present(&pid_path)
}

pub fn uninstall_service() -> Result<(), PlatformError> {
    stop_service()?;
    let task_file = task_file_path()?;
    if task_file.exists() {
        run("schtasks", &["/Delete", "/TN", TASK_NAME, "/F"])?;
    }
    remove_file_if_present(&task_file)
}

pub fn service_installed() -> Result<bool, PlatformError> {
    Ok(task_file_path()?.exists())
}

pub fn restart_service() -> Result<bool, PlatformError> {
    if !service_installed()? {
        return Ok(false);
    }
    stop_service()?;
    run("schtasks", &["/Run", "/TN", TASK_NAME])?;
    Ok(true)
}

pub fn trust_ca(certificate: &Path) -> Result<(), PlatformError> {
    run(
        "certutil",
        &["-user", "-addstore", "Root", path_str(certificate)?],
    )
    .map(drop)
}

/// Removes every certificate named [`CA_NAME`], including the ones earlier renewals left behind.
pub fn untrust_ca(_certificate: &Path) -> Result<(), PlatformError> {
    if sandbox_root().is_some() {
        return Ok(());
    }
    remove_while_present(
        || Ok(run("certutil", &["-user", "-verifystore", "Root", CA_NAME]).is_ok()),
        || run("certutil", &["-user", "-delstore", "Root", CA_NAME]).map(drop),
    )
}

pub fn ca_trusted() -> Result<bool, PlatformError> {
    Ok(run("certutil", &["-user", "-verifystore", "Root", CA_NAME]).is_ok())
}

pub fn pac_applied(pac_url: &str) -> Result<bool, PlatformError> {
    match internet_settings(KEY_READ)?.get_value::<String, _>(AUTO_CONFIG_URL_VALUE) {
        Ok(current) => Ok(current == pac_url),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(registry_error(error)),
    }
}

fn internet_settings(access: u32) -> Result<RegKey, PlatformError> {
    RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(INTERNET_SETTINGS_KEY, access)
        .map_err(|source| PlatformError::Io {
            path: format!("HKCU\\{INTERNET_SETTINGS_KEY}"),
            source,
        })
}

fn registry_error(source: std::io::Error) -> PlatformError {
    PlatformError::Io {
        path: format!("HKCU\\{INTERNET_SETTINGS_KEY}\\{AUTO_CONFIG_URL_VALUE}"),
        source,
    }
}

pub fn set_pac(pac_url: &str) -> Result<(), PlatformError> {
    if sandbox_root().is_some() {
        return Ok(());
    }
    internet_settings(KEY_WRITE)?
        .set_value(AUTO_CONFIG_URL_VALUE, &pac_url)
        .map_err(registry_error)
}

pub fn clear_pac(pac_url: &str) -> Result<(), PlatformError> {
    if sandbox_root().is_some() {
        return Ok(());
    }
    let settings = internet_settings(KEY_READ | KEY_WRITE)?;
    let current: String = match settings.get_value(AUTO_CONFIG_URL_VALUE) {
        Ok(current) => current,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(registry_error(error)),
    };
    if current != pac_url {
        return Ok(());
    }
    settings
        .delete_value(AUTO_CONFIG_URL_VALUE)
        .map_err(registry_error)
}

fn notification_script() -> String {
    format!(
        "Add-Type -AssemblyName System.Windows.Forms; \
        Add-Type -AssemblyName System.Drawing; \
        $icon = New-Object System.Windows.Forms.NotifyIcon; \
        $icon.Icon = [System.Drawing.SystemIcons]::Information; \
        $icon.Visible = $true; \
        $icon.ShowBalloonTip({BALLOON_DISPLAY_MILLISECONDS}, $env:{NOTIFICATION_TITLE_VARIABLE}, $env:{NOTIFICATION_MESSAGE_VARIABLE}, [System.Windows.Forms.ToolTipIcon]::Info); \
        Start-Sleep -Seconds {BALLOON_WAIT_SECONDS}; \
        $icon.Dispose()"
    )
}

/// Blocks for the few seconds the balloon is shown. The text reaches PowerShell as environment variables, never as
/// part of the script.
pub fn notify(title: &str, message: &str) -> Result<(), PlatformError> {
    let encoded_script = powershell_encoded_command(&notification_script());
    run_with_environment(
        "powershell",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-WindowStyle",
            "Hidden",
            "-EncodedCommand",
            &encoded_script,
        ],
        &[
            (NOTIFICATION_TITLE_VARIABLE, title),
            (NOTIFICATION_MESSAGE_VARIABLE, message),
        ],
    )
    .map(drop)
}

/// The SID is the one identity icacls resolves the same way whatever the machine's domain or locale.
fn current_user_sid() -> Result<String, PlatformError> {
    let output = run("whoami", &["/user", "/fo", "csv", "/nh"])?;
    parse_whoami_sid(&output)
        .map(String::from)
        .ok_or_else(|| PlatformError::CommandFailed {
            program: "whoami".to_string(),
            detail: format!("no SID in {output:?}"),
        })
}

fn parse_whoami_sid(output: &str) -> Option<&str> {
    let sid = output
        .trim()
        .split(',')
        .nth(WHOAMI_SID_FIELD)?
        .trim_matches('"');
    sid.starts_with("S-1-").then_some(sid)
}

/// Replaces the inherited ACL with one that grants only the current user access. Callers create the empty file first
/// so the secret is never written under the inherited ACL.
pub(super) fn restrict_to_current_user(path: &Path) -> Result<(), PlatformError> {
    if sandbox_root().is_some() {
        return Ok(());
    }
    let grant = format!("*{}:(F)", current_user_sid()?);
    run(
        "icacls",
        &[path_str(path)?, "/inheritance:r", "/grant:r", &grant],
    )
    .map(drop)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_sid_from_whoami_csv_output() {
        let output = "\"DESKTOP\\jack\",\"S-1-5-21-1-2-3-1001\"\r\n";
        assert_eq!(parse_whoami_sid(output), Some("S-1-5-21-1-2-3-1001"));
    }

    #[test]
    fn rejects_output_without_a_sid() {
        assert_eq!(parse_whoami_sid(""), None);
        assert_eq!(parse_whoami_sid("\"DESKTOP\\jack\",\"nope\""), None);
    }

    #[test]
    fn the_notification_script_uses_the_named_timings() {
        let script = notification_script();
        assert!(script.contains("ShowBalloonTip(6000,"));
        assert!(script.contains("Start-Sleep -Seconds 7;"));
    }
}
