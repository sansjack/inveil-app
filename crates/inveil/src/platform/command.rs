//! The single place external programs are started, so the sandbox switch covers all of them.
use super::{sandbox_root, PlatformError};
use std::process::{Command, Output, Stdio};

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

fn command(program: &str, args: &[&str]) -> Command {
    let mut command = Command::new(program);
    command.args(args);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    command
}

fn spawn_error(program: &str) -> impl FnOnce(std::io::Error) -> PlatformError + '_ {
    move |source| PlatformError::Spawn {
        program: program.to_string(),
        source,
    }
}

fn failure(program: &str, output: &Output) -> PlatformError {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let detail = if stderr.trim().is_empty() {
        stdout.trim()
    } else {
        stderr.trim()
    };
    PlatformError::CommandFailed {
        program: program.to_string(),
        detail: format!("{} ({})", detail, output.status),
    }
}

/// Runs a program and returns its stdout. Does nothing when sandboxed.
pub(super) fn run(program: &str, args: &[&str]) -> Result<String, PlatformError> {
    run_with_environment(program, args, &[])
}

#[cfg_attr(not(windows), allow(dead_code))]
pub(super) fn run_with_environment(
    program: &str,
    args: &[&str],
    environment: &[(&str, &str)],
) -> Result<String, PlatformError> {
    if sandbox_root().is_some() {
        return Ok(String::new());
    }
    let output = command(program, args)
        .envs(environment.iter().copied())
        .output()
        .map_err(spawn_error(program))?;
    if !output.status.success() {
        return Err(failure(program, &output));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Runs a program attached to the terminal, for password prompts. Does nothing when sandboxed.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(super) fn run_interactive(program: &str, args: &[&str]) -> Result<(), PlatformError> {
    if sandbox_root().is_some() {
        return Ok(());
    }
    let status = command(program, args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(spawn_error(program))?;
    if !status.success() {
        return Err(PlatformError::CommandFailed {
            program: program.to_string(),
            detail: status.to_string(),
        });
    }
    Ok(())
}
