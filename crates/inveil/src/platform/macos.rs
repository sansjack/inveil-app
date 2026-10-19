//! macOS: LaunchAgent with KeepAlive, user login keychain trust, `networksetup` PAC.
use super::command::{run, run_interactive};
use super::definitions::launch_agent_plist;
use super::escape::shell_join;
use super::proxy::networksetup_reports_pac;
use super::trust_store::{macos_add_trusted_args, macos_delete_args, security_certificate_hashes};
use super::{
    home_dir, io_error, path_str, remove_file_if_present, service_command, PlatformError,
    APP_DIR_NAME, CA_NAME, SERVICE_LABEL,
};
use std::fs;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

const LOG_FILE_NAME: &str = "inveil.log";
const NOTIFICATION_SCRIPT: [&str; 6] = [
    "-e",
    "on run argv",
    "-e",
    "display notification (item 2 of argv) with title (item 1 of argv)",
    "-e",
    "end run",
];
const ADMIN_SCRIPT: [&str; 6] = [
    "-e",
    "on run argv",
    "-e",
    "do shell script (item 1 of argv) with administrator privileges",
    "-e",
    "end run",
];

pub fn data_dir() -> Result<PathBuf, PlatformError> {
    Ok(home_dir()?
        .join("Library/Application Support")
        .join(APP_DIR_NAME))
}

pub fn default_log_path() -> Result<PathBuf, PlatformError> {
    Ok(data_dir()?.join(LOG_FILE_NAME))
}

fn plist_path() -> Result<PathBuf, PlatformError> {
    Ok(home_dir()?
        .join("Library/LaunchAgents")
        .join(format!("{SERVICE_LABEL}.plist")))
}

fn login_keychain() -> Result<PathBuf, PlatformError> {
    Ok(home_dir()?.join("Library/Keychains/login.keychain-db"))
}

fn user_domain() -> Result<String, PlatformError> {
    Ok(format!("gui/{}", run("id", &["-u"])?.trim()))
}

fn is_loaded(domain: &str) -> bool {
    run(
        "launchctl",
        &["print", &format!("{domain}/{SERVICE_LABEL}")],
    )
    .is_ok()
}

pub fn install_service(exe: &Path, log: &Path) -> Result<(), PlatformError> {
    let plist = launch_agent_plist(SERVICE_LABEL, &service_command(exe, log)?)?;
    let path = plist_path()?;
    let directory = path.parent().unwrap_or(&path);
    fs::create_dir_all(directory).map_err(io_error(directory))?;
    stop_service()?;
    fs::write(&path, plist).map_err(io_error(&path))?;
    run(
        "launchctl",
        &["bootstrap", &user_domain()?, path_str(&path)?],
    )
    .map(drop)
}

pub fn stop_service() -> Result<(), PlatformError> {
    let domain = user_domain()?;
    if !is_loaded(&domain) {
        return Ok(());
    }
    run(
        "launchctl",
        &["bootout", &format!("{domain}/{SERVICE_LABEL}")],
    )
    .map(drop)
}

pub fn uninstall_service() -> Result<(), PlatformError> {
    stop_service()?;
    remove_file_if_present(&plist_path()?)
}

pub fn service_installed() -> Result<bool, PlatformError> {
    Ok(plist_path()?.exists())
}

pub fn restart_service() -> Result<bool, PlatformError> {
    if !service_installed()? {
        return Ok(false);
    }
    run(
        "launchctl",
        &[
            "kickstart",
            "-k",
            &format!("{}/{SERVICE_LABEL}", user_domain()?),
        ],
    )?;
    Ok(true)
}

pub fn trust_ca(certificate: &Path) -> Result<(), PlatformError> {
    let keychain = login_keychain()?;
    run(
        "security",
        &macos_add_trusted_args(path_str(&keychain)?, path_str(certificate)?),
    )
    .map(drop)
}

/// Removes every certificate named [`CA_NAME`], including the ones earlier renewals left behind.
pub fn untrust_ca(certificate: &Path) -> Result<(), PlatformError> {
    let keychain = login_keychain()?;
    let keychain = path_str(&keychain)?;
    let listing = run(
        "security",
        &["find-certificate", "-a", "-Z", "-c", CA_NAME, keychain],
    );
    let Ok(listing) = listing else {
        return Ok(());
    };
    if certificate.exists() {
        run("security", &["remove-trusted-cert", path_str(certificate)?])?;
    }
    for hash in security_certificate_hashes(&listing) {
        run("security", &macos_delete_args(hash, keychain))?;
    }
    Ok(())
}

pub fn ca_trusted() -> Result<bool, PlatformError> {
    let keychain = login_keychain()?;
    Ok(run(
        "security",
        &["find-certificate", "-c", CA_NAME, path_str(&keychain)?],
    )
    .is_ok())
}

pub fn pac_applied(pac_url: &str) -> Result<bool, PlatformError> {
    for service in network_services()? {
        let current = run("networksetup", &["-getautoproxyurl", &service])?;
        if networksetup_reports_pac(&current, pac_url) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Network services that are switched on, e.g. "Wi-Fi".
fn network_services() -> Result<Vec<String>, PlatformError> {
    let listing = run("networksetup", &["-listallnetworkservices"])?;
    Ok(listing
        .lines()
        .skip(1)
        .filter(|line| !line.is_empty() && !line.starts_with('*'))
        .map(String::from)
        .collect())
}

fn networksetup(arguments: &[&str]) -> Vec<String> {
    std::iter::once("networksetup")
        .chain(arguments.iter().copied())
        .map(String::from)
        .collect()
}

/// Changing the system proxy needs an administrator. In a terminal that is sudo's password prompt; otherwise macOS
/// shows its own dialog. Every command is quoted as argv, and the AppleScript receives the script as data.
fn run_as_administrator(commands: &[Vec<String>]) -> Result<(), PlatformError> {
    let script = commands
        .iter()
        .map(|command| shell_join(command))
        .collect::<Vec<_>>()
        .join(" && ");
    if std::io::stdin().is_terminal() {
        return run_interactive("sudo", &["sh", "-c", &script]);
    }
    let mut arguments = ADMIN_SCRIPT.to_vec();
    arguments.extend(["--", &script]);
    run("osascript", &arguments).map(drop)
}

pub fn set_pac(pac_url: &str) -> Result<(), PlatformError> {
    let commands: Vec<Vec<String>> = network_services()?
        .iter()
        .map(|service| networksetup(&["-setautoproxyurl", service, pac_url]))
        .collect();
    if commands.is_empty() {
        return Ok(());
    }
    run_as_administrator(&commands)
}

pub fn clear_pac(pac_url: &str) -> Result<(), PlatformError> {
    let mut commands = Vec::new();
    for service in network_services()? {
        let current = run("networksetup", &["-getautoproxyurl", &service])?;
        if networksetup_reports_pac(&current, pac_url) {
            commands.push(networksetup(&["-setautoproxystate", &service, "off"]));
        }
    }
    if commands.is_empty() {
        return Ok(());
    }
    run_as_administrator(&commands)
}

pub fn notify(title: &str, message: &str) -> Result<(), PlatformError> {
    let mut arguments = NOTIFICATION_SCRIPT.to_vec();
    arguments.extend(["--", title, message]);
    run("osascript", &arguments).map(drop)
}
