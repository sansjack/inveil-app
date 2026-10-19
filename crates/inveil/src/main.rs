#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod backend;
mod brand;
mod cli;
mod config;
mod console;
mod error;
mod logging;
mod platform;
mod policy;
mod proxy;
mod runtime;
mod serve;
mod trust_state;
mod update;
mod util;

use cli::{Cli, Command};
use error::AppError;
use std::process::ExitCode;

fn main() -> ExitCode {
    let has_console = console::attach();
    match run(has_console) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("inveil: {error}");
            error.exit_code()
        }
    }
}

fn run(has_console: bool) -> Result<ExitCode, AppError> {
    let cli = Cli::parse(std::env::args().skip(1).collect())?;
    if matches!(cli.command, Command::Help | Command::Version) {
        return block_on(cli::dispatch(cli, config::Config::default()));
    }
    if matches!(cli.command, Command::Run) {
        update::recover_on_start()?;
    }
    let config = cli.load_config()?;
    let detached_log = match has_console {
        true => None,
        false => platform::default_log_path().ok(),
    };
    logging::init(&config.logging, detached_log.as_deref())?;
    block_on(cli::dispatch(cli, config))
}

fn block_on<T>(
    future: impl std::future::Future<Output = Result<T, AppError>>,
) -> Result<T, AppError> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(AppError::Runtime)?
        .block_on(future)
}
