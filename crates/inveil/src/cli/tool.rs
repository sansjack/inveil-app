//! `inveil run <command...>`: runs a tool with the browser proxy for that one process, so tools that ignore the
//! system proxy (Codex does) are covered without changing any of their settings. Exits with the tool's own code.
//! The CA variables are chosen by the program's runtime (`platform::RuntimeKind`); a program the table does not
//! know gets the proxy plus the Node and Codex CA variables.
//! If the client is not running the tool starts normally, so a stopped client never breaks it.
use crate::config::Config;
use crate::error::AppError;
use crate::platform;
use crate::proxy::browser_ca::{ca_directory, certificate_path};
use platform::RuntimeKind;
use std::net::TcpStream;
use std::process::{Command, ExitCode};
use std::time::Duration;

const LISTEN_CHECK_TIMEOUT: Duration = Duration::from_millis(300);
const PROXY_VARIABLES: [&str; 2] = ["HTTPS_PROXY", "https_proxy"];

pub fn run(config: &Config, arguments: &[String]) -> Result<ExitCode, AppError> {
    let Some((program, program_args)) = arguments.split_first() else {
        return Err(AppError::Usage(
            "usage: inveil run <command> [args...]".into(),
        ));
    };
    if PROXY_VARIABLES
        .iter()
        .any(|name| std::env::var_os(name).is_some())
    {
        return Err(AppError::Usage(
            "this shell already uses a proxy (HTTPS_PROXY is set); inveil cannot be chained behind another proxy"
                .into(),
        ));
    }
    let port = config.listen.browser_port;
    let data_dir = match &config.data_dir {
        Some(directory) => directory.clone(),
        None => platform::data_dir()?,
    };
    let ca_directory = ca_directory(&data_dir);
    let certificate = certificate_path(&ca_directory);
    let listening =
        TcpStream::connect_timeout(&crate::util::loopback(port), LISTEN_CHECK_TIMEOUT).is_ok();

    let mut command = Command::new(program);
    command.args(program_args);
    if !certificate.exists() {
        eprintln!("inveil: no browser CA yet (run `inveil browser-setup`); starting {program} without protection");
    } else if !listening {
        eprintln!("inveil: the client is not running on port {port}; starting {program} without protection");
    } else {
        let existing = std::env::var("NO_PROXY").unwrap_or_default();
        command.envs(match RuntimeKind::for_program(program) {
            Some(runtime) => platform::tool_environment(
                runtime,
                port,
                &certificate,
                &platform::bundle_path(&ca_directory),
                &existing,
            ),
            None => platform::proxy_environment(port, &certificate, &existing),
        });
    }
    let status = command
        .status()
        .map_err(|error| AppError::Usage(format!("cannot start {program}: {error}")))?;
    Ok(status
        .code()
        .and_then(|code| u8::try_from(code).ok())
        .map_or(ExitCode::FAILURE, ExitCode::from))
}
