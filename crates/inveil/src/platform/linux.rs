//! Linux: XDG directories, `systemd --user` unit with restart on failure, PAC through gsettings (GNOME) or
//! kwriteconfig (KDE), CA trust in the NSS databases Chrome/Chromium and Firefox read. Nothing here needs root.
//!
//! Desktops without either settings tool get an error that says to configure the PAC URL by hand. System-wide trust
//! (curl, Python, Go) is deliberately not touched because it requires root; point those tools at the CA file with
//! `proxy_environment` instead.
use super::command::run;
use super::definitions::systemd_user_unit;
use super::proxy::gsettings_string;
use super::trust_store::remove_while_present;
use super::{
    home_dir, io_error, path_str, remove_file_if_present, sandbox_root, service_command,
    PlatformError, APP_DIR_NAME, CA_NAME, SERVICE_LABEL,
};
use std::env;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

const UNIT_NAME: &str = "inveil.service";
const UNIT_DESCRIPTION: &str = "Inveil local data-loss-prevention proxy";
const LOG_FILE_NAME: &str = "inveil.log";
const NSS_TRUST_FLAGS: &str = "C,,";
const FIREFOX_PROFILE_ROOTS: [&str; 3] = [
    ".mozilla/firefox",
    "snap/firefox/common/.mozilla/firefox",
    ".var/app/org.mozilla.firefox/.mozilla/firefox",
];
const CHROMIUM_NSS_DIR: &str = ".pki/nssdb";
const NSS_DATABASE_FILE: &str = "cert9.db";
const KDE_CONFIG_FILE: &str = "kioslaverc";
const KDE_GROUP: &str = "Proxy Settings";
const KDE_SCRIPT_KEY: &str = "Proxy Config Script";
const KDE_PROXY_TYPE_KEY: &str = "ProxyType";
const KDE_PROXY_TYPE_PAC: &str = "2";
const KDE_PROXY_TYPE_NONE: &str = "0";
const KDE_TOOL_VERSIONS: [&str; 2] = ["6", "5"];
const GNOME_PROXY_SCHEMA: &str = "org.gnome.system.proxy";

const SYSTEMCTL_HELP: &str =
    "inveil needs systemd with user services to run in the background. Start it manually with `inveil run` instead.";
const CERTUTIL_HELP: &str = "It is needed to trust the browser CA without root. Install it with \
    `sudo apt install libnss3-tools` (Debian/Ubuntu), `sudo dnf install nss-tools` (Fedora) or \
    `sudo pacman -S nss` (Arch), then run the command again.";
const NOTIFY_SEND_HELP: &str =
    "Install it with `sudo apt install libnotify-bin` (Debian/Ubuntu) or \
    `sudo dnf install libnotify` (Fedora) to see notifications.";
const GSETTINGS_HELP: &str =
    "It ships with GNOME (package libglib2.0-bin on Debian/Ubuntu). On other desktops, set the \
proxy auto-config URL in the network settings by hand.";
const KDE_TOOL_HELP: &str = "It ships with KDE Plasma (package kde-cli-tools or kf6-kconfig).";

fn is_missing_program(result: &Result<String, PlatformError>) -> bool {
    matches!(result, Err(PlatformError::Spawn { source, .. }) if source.kind() == ErrorKind::NotFound)
}

fn run_required(
    program: &str,
    args: &[&str],
    instructions: &'static str,
) -> Result<String, PlatformError> {
    let result = run(program, args);
    if is_missing_program(&result) {
        return Err(PlatformError::MissingTool {
            tool: program.to_string(),
            instructions,
        });
    }
    result
}

/// `$variable` when it is an absolute path, otherwise `~/fallback`; always under the sandbox when one is set.
fn xdg_dir(variable: &str, fallback: &str) -> Result<PathBuf, PlatformError> {
    let home = home_dir()?;
    if sandbox_root().is_some() {
        return Ok(home.join(fallback));
    }
    match env::var_os(variable).map(PathBuf::from) {
        Some(directory) if directory.is_absolute() => Ok(directory),
        _ => Ok(home.join(fallback)),
    }
}

pub fn data_dir() -> Result<PathBuf, PlatformError> {
    Ok(xdg_dir("XDG_DATA_HOME", ".local/share")?.join(APP_DIR_NAME))
}

pub fn default_log_path() -> Result<PathBuf, PlatformError> {
    Ok(xdg_dir("XDG_STATE_HOME", ".local/state")?
        .join(APP_DIR_NAME)
        .join(LOG_FILE_NAME))
}

fn unit_path() -> Result<PathBuf, PlatformError> {
    Ok(xdg_dir("XDG_CONFIG_HOME", ".config")?
        .join("systemd/user")
        .join(UNIT_NAME))
}

fn systemctl(arguments: &[&str]) -> Result<String, PlatformError> {
    let mut full_arguments = vec!["--user"];
    full_arguments.extend(arguments);
    run_required("systemctl", &full_arguments, SYSTEMCTL_HELP)
}

pub fn install_service(exe: &Path, log: &Path) -> Result<(), PlatformError> {
    let unit = systemd_user_unit(UNIT_DESCRIPTION, &service_command(exe, log)?)?;
    let path = unit_path()?;
    let directory = path.parent().unwrap_or(&path);
    fs::create_dir_all(directory).map_err(io_error(directory))?;
    if let Some(log_directory) = log.parent() {
        fs::create_dir_all(log_directory).map_err(io_error(log_directory))?;
    }
    stop_service()?;
    fs::write(&path, unit).map_err(io_error(&path))?;
    systemctl(&["daemon-reload"])?;
    systemctl(&["enable", "--now", UNIT_NAME]).map(drop)
}

pub fn stop_service() -> Result<(), PlatformError> {
    if !service_installed()? {
        return Ok(());
    }
    systemctl(&["stop", UNIT_NAME]).map(drop)
}

pub fn uninstall_service() -> Result<(), PlatformError> {
    let path = unit_path()?;
    if !path.exists() {
        return Ok(());
    }
    systemctl(&["disable", "--now", UNIT_NAME])?;
    remove_file_if_present(&path)?;
    systemctl(&["daemon-reload"]).map(drop)
}

pub fn service_installed() -> Result<bool, PlatformError> {
    Ok(unit_path()?.exists())
}

pub fn restart_service() -> Result<bool, PlatformError> {
    if !service_installed()? {
        return Ok(false);
    }
    systemctl(&["restart", UNIT_NAME])?;
    Ok(true)
}

/// Firefox profile directories that already have a certificate database.
fn firefox_profiles(home: &Path) -> Result<Vec<PathBuf>, PlatformError> {
    let mut profiles = Vec::new();
    for root in FIREFOX_PROFILE_ROOTS {
        let root = home.join(root);
        let entries = match fs::read_dir(&root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(error) => return Err(io_error(&root)(error)),
        };
        for entry in entries {
            let profile = entry.map_err(io_error(&root))?.path();
            if profile.join(NSS_DATABASE_FILE).exists() {
                profiles.push(profile);
            }
        }
    }
    Ok(profiles)
}

fn nss_database(directory: &Path) -> Result<String, PlatformError> {
    Ok(format!("sql:{}", path_str(directory)?))
}

pub fn trust_ca(certificate: &Path) -> Result<(), PlatformError> {
    let home = home_dir()?;
    let chromium_directory = home.join(CHROMIUM_NSS_DIR);
    if !chromium_directory.join(NSS_DATABASE_FILE).exists() {
        fs::create_dir_all(&chromium_directory).map_err(io_error(&chromium_directory))?;
        run_required(
            "certutil",
            &[
                "-d",
                &nss_database(&chromium_directory)?,
                "-N",
                "--empty-password",
            ],
            CERTUTIL_HELP,
        )?;
    }
    let mut databases = vec![chromium_directory];
    databases.extend(firefox_profiles(&home)?);
    for directory in databases {
        run_required(
            "certutil",
            &[
                "-d",
                &nss_database(&directory)?,
                "-A",
                "-t",
                NSS_TRUST_FLAGS,
                "-n",
                CA_NAME,
                "-i",
                path_str(certificate)?,
            ],
            CERTUTIL_HELP,
        )?;
    }
    Ok(())
}

/// Removes every certificate named [`CA_NAME`] from each database, including the ones earlier renewals left behind.
pub fn untrust_ca(_certificate: &Path) -> Result<(), PlatformError> {
    if sandbox_root().is_some() {
        return Ok(());
    }
    let home = home_dir()?;
    let mut databases = firefox_profiles(&home)?;
    let chromium_directory = home.join(CHROMIUM_NSS_DIR);
    if chromium_directory.join(NSS_DATABASE_FILE).exists() {
        databases.push(chromium_directory);
    }
    for directory in databases {
        let database = nss_database(&directory)?;
        remove_while_present(
            || nss_has_certificate(&database),
            || {
                run_required(
                    "certutil",
                    &["-d", &database, "-D", "-n", CA_NAME],
                    CERTUTIL_HELP,
                )
                .map(drop)
            },
        )?;
    }
    Ok(())
}

fn nss_has_certificate(database: &str) -> Result<bool, PlatformError> {
    match run_required(
        "certutil",
        &["-d", database, "-L", "-n", CA_NAME],
        CERTUTIL_HELP,
    ) {
        Err(error @ PlatformError::MissingTool { .. }) => Err(error),
        other => Ok(other.is_ok()),
    }
}

pub fn ca_trusted() -> Result<bool, PlatformError> {
    let directory = home_dir()?.join(CHROMIUM_NSS_DIR);
    if !directory.join(NSS_DATABASE_FILE).exists() {
        return Ok(false);
    }
    nss_has_certificate(&nss_database(&directory)?)
}

pub fn pac_applied(pac_url: &str) -> Result<bool, PlatformError> {
    if is_kde() {
        let current = run_kde(
            "kreadconfig",
            &[
                "--file",
                KDE_CONFIG_FILE,
                "--group",
                KDE_GROUP,
                "--key",
                KDE_SCRIPT_KEY,
            ],
        )?;
        return Ok(current.trim() == pac_url);
    }
    let current = run_required(
        "gsettings",
        &["get", GNOME_PROXY_SCHEMA, "autoconfig-url"],
        GSETTINGS_HELP,
    )?;
    Ok(gsettings_string(&current) == pac_url)
}

fn is_kde() -> bool {
    env::var("XDG_CURRENT_DESKTOP").is_ok_and(|desktop| {
        desktop
            .split(':')
            .any(|part| part.eq_ignore_ascii_case("KDE"))
    })
}

/// Runs `kwriteconfig6`/`kreadconfig6`, falling back to the Plasma 5 name.
fn run_kde(tool: &str, arguments: &[&str]) -> Result<String, PlatformError> {
    for version in KDE_TOOL_VERSIONS {
        let result = run(&format!("{tool}{version}"), arguments);
        if !is_missing_program(&result) {
            return result;
        }
    }
    Err(PlatformError::MissingTool {
        tool: tool.to_string(),
        instructions: KDE_TOOL_HELP,
    })
}

fn kde_write(arguments: &[&str]) -> Result<(), PlatformError> {
    let mut full_arguments = vec!["--file", KDE_CONFIG_FILE, "--group", KDE_GROUP];
    full_arguments.extend(arguments);
    run_kde("kwriteconfig", &full_arguments).map(drop)
}

pub fn set_pac(pac_url: &str) -> Result<(), PlatformError> {
    if is_kde() {
        kde_write(&["--key", KDE_SCRIPT_KEY, pac_url])?;
        return kde_write(&["--key", KDE_PROXY_TYPE_KEY, KDE_PROXY_TYPE_PAC]);
    }
    run_required(
        "gsettings",
        &["set", GNOME_PROXY_SCHEMA, "autoconfig-url", pac_url],
        GSETTINGS_HELP,
    )?;
    run_required(
        "gsettings",
        &["set", GNOME_PROXY_SCHEMA, "mode", "auto"],
        GSETTINGS_HELP,
    )
    .map(drop)
}

pub fn clear_pac(pac_url: &str) -> Result<(), PlatformError> {
    if is_kde() {
        let current = run_kde(
            "kreadconfig",
            &[
                "--file",
                KDE_CONFIG_FILE,
                "--group",
                KDE_GROUP,
                "--key",
                KDE_SCRIPT_KEY,
            ],
        )?;
        if current.trim() != pac_url {
            return Ok(());
        }
        kde_write(&["--key", KDE_PROXY_TYPE_KEY, KDE_PROXY_TYPE_NONE])?;
        return kde_write(&["--key", KDE_SCRIPT_KEY, "--delete"]);
    }
    let current = run_required(
        "gsettings",
        &["get", GNOME_PROXY_SCHEMA, "autoconfig-url"],
        GSETTINGS_HELP,
    )?;
    if gsettings_string(&current) != pac_url {
        return Ok(());
    }
    run_required(
        "gsettings",
        &["set", GNOME_PROXY_SCHEMA, "mode", "none"],
        GSETTINGS_HELP,
    )?;
    run_required(
        "gsettings",
        &["reset", GNOME_PROXY_SCHEMA, "autoconfig-url"],
        GSETTINGS_HELP,
    )
    .map(drop)
}

pub fn notify(title: &str, message: &str) -> Result<(), PlatformError> {
    run_required(
        "notify-send",
        &["--app-name", SERVICE_LABEL, "--", title, message],
        NOTIFY_SEND_HELP,
    )
    .map(drop)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_firefox_profiles_that_have_a_certificate_database() {
        let home = tempfile::tempdir().unwrap();
        let with_database = home.path().join(".mozilla/firefox/abc.default");
        let without_database = home.path().join(".mozilla/firefox/Crash Reports");
        let snap_profile = home
            .path()
            .join("snap/firefox/common/.mozilla/firefox/xyz.default-release");
        for directory in [&with_database, &without_database, &snap_profile] {
            fs::create_dir_all(directory).unwrap();
        }
        fs::write(with_database.join(NSS_DATABASE_FILE), "").unwrap();
        fs::write(snap_profile.join(NSS_DATABASE_FILE), "").unwrap();

        let mut profiles = firefox_profiles(home.path()).unwrap();
        profiles.sort();

        let mut expected = vec![with_database, snap_profile];
        expected.sort();
        assert_eq!(profiles, expected);
    }

    #[test]
    fn no_firefox_profiles_when_firefox_was_never_run() {
        let home = tempfile::tempdir().unwrap();
        assert!(firefox_profiles(home.path()).unwrap().is_empty());
    }
}
