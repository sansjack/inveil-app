//! `inveil install | uninstall | status`: the per-user background service, and pointing local tools at the proxy.
use super::tool_settings::{check_entry, SettingsFile};
use super::{browser, claude_settings};
use crate::backend::{BackendError, CredentialProvider};
use crate::config::{AuthMode, Config};
use crate::error::AppError;
use crate::platform;
use crate::runtime::Runtime;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

const START_CHECKS: u32 = 10;
const START_CHECK_INTERVAL: Duration = Duration::from_millis(500);
const LISTEN_CHECK_TIMEOUT: Duration = Duration::from_millis(500);
const HEALTH_RESPONSE_LIMIT: u64 = 4096;

/// Whether anything accepts connections on the port.
pub fn is_listening(port: u16) -> bool {
    TcpStream::connect_timeout(&crate::util::loopback(port), LISTEN_CHECK_TIMEOUT).is_ok()
}

/// Whether the API proxy of this version answers on the port: a bare connection would also succeed for any other
/// program that happens to hold it, or for an older inveil that was never restarted.
pub fn is_running(port: u16) -> bool {
    let Ok(mut stream) =
        TcpStream::connect_timeout(&crate::util::loopback(port), LISTEN_CHECK_TIMEOUT)
    else {
        return false;
    };
    if stream.set_read_timeout(Some(LISTEN_CHECK_TIMEOUT)).is_err()
        || stream
            .set_write_timeout(Some(LISTEN_CHECK_TIMEOUT))
            .is_err()
    {
        return false;
    }
    let request =
        format!("GET /health HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    if stream.write_all(request.as_bytes()).is_err() {
        return false;
    }
    let mut response = Vec::new();
    if stream
        .take(HEALTH_RESPONSE_LIMIT)
        .read_to_end(&mut response)
        .is_err()
    {
        return false;
    }
    answers_with_this_version(&String::from_utf8_lossy(&response))
}

/// True for a `200` response whose JSON body is `{"version": <this program's version>}`.
fn answers_with_this_version(response: &str) -> bool {
    let Some((head, body)) = response.split_once("\r\n\r\n") else {
        return false;
    };
    if !head.starts_with("HTTP/1.1 200") {
        return false;
    }
    serde_json::from_str::<HealthBody>(body.trim())
        .is_ok_and(|health| health.version == env!("CARGO_PKG_VERSION"))
}

#[derive(serde::Deserialize)]
struct HealthBody {
    version: String,
}

/// The background service cannot prompt, so sign in now if device-flow sign-in is configured and there is no
/// working session.
async fn ensure_signed_in(runtime: &Runtime) -> Result<(), AppError> {
    if runtime.config.auth.mode != AuthMode::DeviceFlow || runtime.config.offline {
        return Ok(());
    }
    match runtime.credentials()?.credential().await {
        Ok(_) => Ok(()),
        Err(BackendError::NotSignedIn | BackendError::Unauthorized) => {
            println!("You are not signed in yet, so signing in first.");
            println!("{}", crate::backend::login(&runtime.config).await?);
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

const ELEVATED_USER_INSTALL: &str = "inveil install sets up a per-user service and writes settings in your home folder, which an elevated shell cannot use safely (the home folder may be yours or root's). Run it as your own user without sudo or administrator rights. For Claude Code's machine-wide managed settings, run `inveil install --managed` elevated; it writes only that file.";
const ELEVATED_MANAGED_WITHOUT_DATA_DIR: &str = "inveil install --managed reads the rules held in the data directory, which by default is under the home folder, and an elevated shell cannot trust that. Set data_dir in the system-wide configuration file (administrators only), or run it without elevation to see the permission error first.";

/// Elevated processes must not do per-user work, and must not read state from a location the user controls.
fn refuse_unsafe_elevation(elevated: bool, managed: bool, config: &Config) -> Result<(), AppError> {
    if !elevated {
        return Ok(());
    }
    if !managed {
        return Err(AppError::Usage(ELEVATED_USER_INSTALL.into()));
    }
    if config.data_dir.is_none() {
        return Err(AppError::Usage(ELEVATED_MANAGED_WITHOUT_DATA_DIR.into()));
    }
    Ok(())
}

/// Without `managed`: the per-user service, the data directory and the settings files in the home folder, all as the
/// current user. With `managed`: only Claude Code's machine-wide managed settings, which needs administrator rights
/// and uses the rules already held (no network, no sign-in, nothing in the home folder). The two are separate
/// invocations so that privileged work never touches a home folder; an elevated shell is refused the per-user steps.
pub async fn install(config: Config, managed: bool) -> Result<String, AppError> {
    refuse_unsafe_elevation(platform::is_elevated(), managed, &config)?;
    if managed {
        return install_managed(config);
    }
    let runtime = Runtime::new(Arc::new(config))?;
    ensure_signed_in(&runtime).await?;
    let policy = runtime.latest_policy().await?;
    let port = runtime.config.listen.port;

    std::fs::create_dir_all(&runtime.data_dir).map_err(|source| AppError::WriteFile {
        path: runtime.data_dir.clone(),
        source,
    })?;
    let source = std::env::current_exe().map_err(|source| AppError::ReadFile {
        path: PathBuf::from("the running executable"),
        source,
    })?;
    let executable = platform::install_exe_path()?;
    if platform::service_installed()? {
        platform::stop_service()?;
    }
    if source != executable {
        std::fs::copy(&source, &executable).map_err(|error| AppError::WriteFile {
            path: executable.clone(),
            source: error,
        })?;
    }
    let log = platform::default_log_path()?;
    platform::install_service(&executable, &log)?;

    let mut manual_steps = vec![];
    for tool in policy.policy.local_tool_wiring() {
        let url = claude_settings::proxy_url(port, tool.prefix);
        check_entry(tool.tool_id, tool.env_var, &url)?;
        match SettingsFile::for_tool(tool.tool_id) {
            Some(file) => file.set(tool.env_var, &url)?,
            None => manual_steps.push(format!("export {}={url}", tool.env_var)),
        }
    }

    for _ in 0..START_CHECKS {
        if is_running(port) {
            let mut message = format!(
                "inveil is active on 127.0.0.1:{port}. Restart any open Claude Code session. Log: {}",
                log.display()
            );
            if !manual_steps.is_empty() {
                message.push_str(&format!(
                    "\nThese tools have no settings file inveil can write; set the variable yourself:\n  {}",
                    manual_steps.join("\n  ")
                ));
            }
            return Ok(message);
        }
        tokio::time::sleep(START_CHECK_INTERVAL).await;
    }
    Err(AppError::Usage(format!(
        "installed, but the proxy is not responding on port {port}; see {}",
        log.display()
    )))
}

fn install_managed(config: Config) -> Result<String, AppError> {
    let runtime = Runtime::new(Arc::new(config))?;
    let policy = runtime.initial_policy()?;
    let port = runtime.config.listen.port;
    let mut entries = vec![];
    for tool in policy.policy.local_tool_wiring() {
        if SettingsFile::for_tool(tool.tool_id) != Some(SettingsFile::ClaudeUser) {
            continue;
        }
        let url = claude_settings::proxy_url(port, tool.prefix);
        check_entry(tool.tool_id, tool.env_var, &url)?;
        entries.push((tool.env_var.to_string(), url));
    }
    let path = claude_settings::managed_path();
    claude_settings::set_managed(&path, &entries)?;
    Ok(format!(
        "Wrote Claude Code's machine-wide managed settings to {}. Nothing else was changed. Now, as your normal user without elevation, run `inveil install` to set up the background service and per-user settings.",
        path.display()
    ))
}

/// Elevated, only the machine-wide managed settings are removed, for the same reason `install --managed` writes
/// nothing else: the per-user steps belong to the user's own invocation.
fn uninstall_managed() -> Result<String, AppError> {
    let path = claude_settings::managed_path();
    if !claude_settings::remove_managed(&path)? {
        return Err(AppError::Usage(format!(
            "cannot delete {} even with elevated rights",
            path.display()
        )));
    }
    Ok(format!(
        "Removed {}. Run `inveil uninstall` again as your normal user to remove the per-user parts.",
        path.display()
    ))
}

pub fn uninstall(config: Config) -> Result<String, AppError> {
    if platform::is_elevated() {
        return uninstall_managed();
    }
    let runtime = Runtime::new(Arc::new(config))?;
    // Browser protection first: it trusts a CA, which must not outlive the client.
    let browser_notes = if runtime.ca_directory().exists() {
        Some(browser::remove(runtime.config.as_ref().clone())?)
    } else {
        None
    };
    platform::uninstall_service()?;
    let policy = runtime.initial_policy()?;
    for tool in policy.policy.local_tool_wiring() {
        if let Some(file) = SettingsFile::for_tool(tool.tool_id) {
            file.remove(tool.env_var)?;
        }
    }
    let managed_note = if claude_settings::remove_managed(&claude_settings::managed_path())? {
        None
    } else {
        Some(format!(
            "Could not delete {}: run `inveil uninstall` again from an elevated shell; it then removes only that file.",
            claude_settings::managed_path().display()
        ))
    };
    let removed = "inveil removed. Local tools talk to their APIs directly again.".to_string();
    let notes: Vec<String> = [browser_notes, managed_note, Some(removed)]
        .into_iter()
        .flatten()
        .collect();
    Ok(notes.join("\n"))
}

pub fn status(config: &Config) -> Result<String, AppError> {
    let port = config.listen.port;
    if is_running(port) {
        return Ok(format!("inveil is running on 127.0.0.1:{port}"));
    }
    Ok("inveil is NOT running".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn health_body() -> String {
        format!(r#"{{"version":"{}"}}"#, env!("CARGO_PKG_VERSION"))
    }

    fn answer_once(reply: String) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut request = [0u8; 512];
            if stream.read(&mut request).is_ok() {
                stream.write_all(reply.as_bytes()).ok();
            }
        });
        port
    }

    fn json_reply(status: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    #[test]
    fn a_listener_that_answers_health_with_this_version_is_running() {
        let port = answer_once(json_reply("200 OK", &health_body()));
        assert!(is_running(port));
    }

    #[test]
    fn other_listeners_are_listening_but_not_running() {
        let wrong_version = answer_once(json_reply("200 OK", r#"{"version":"0.0.0-other"}"#));
        let not_json = answer_once(json_reply("200 OK", "hello"));
        let refused = answer_once(json_reply("403 Forbidden", &health_body()));
        let not_http = answer_once("SSH-2.0-OpenSSH\r\n".to_string());
        for port in [wrong_version, not_json, refused, not_http] {
            assert!(!is_running(port), "port {port}");
        }
        let idle = TcpListener::bind("127.0.0.1:0").unwrap();
        let idle_port = idle.local_addr().unwrap().port();
        assert!(is_listening(idle_port));
        assert!(!is_running(idle_port), "nothing answers");
    }

    #[test]
    fn a_closed_port_is_neither() {
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        assert!(!is_listening(port) && !is_running(port));
    }

    #[test]
    fn elevated_shells_are_refused_the_per_user_install_and_must_name_a_trusted_data_dir_for_managed(
    ) {
        let config = Config::default();
        assert!(refuse_unsafe_elevation(false, false, &config).is_ok());
        assert!(refuse_unsafe_elevation(false, true, &config).is_ok());
        let per_user = refuse_unsafe_elevation(true, false, &config).unwrap_err();
        assert!(per_user.to_string().contains("--managed"), "{per_user}");
        assert!(refuse_unsafe_elevation(true, true, &config).is_err());
        let with_data_dir = Config {
            data_dir: Some("/etc/inveil/data".into()),
            ..Config::default()
        };
        assert!(refuse_unsafe_elevation(true, true, &with_data_dir).is_ok());
    }
}
