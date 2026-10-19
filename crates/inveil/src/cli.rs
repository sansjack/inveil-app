//! Command-line parsing and dispatch. Each subcommand lives in its own file under `cli/`; this file only parses
//! arguments and routes to them.
mod auth;
mod browser;
mod claude_settings;
mod discover;
mod doctor;
mod init;
mod install;
mod refetch;
mod tool;
mod tool_settings;

use crate::config::{self, Config, Override, Sources};
use crate::error::AppError;
use crate::platform;
use crate::runtime::Runtime;
use crate::update;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use toml::Value;

pub const USAGE: &str = "\
Usage: inveil [flags] <command>

Commands:
  run                 Start the proxy (the default)
  run <command...>    Run a command with its HTTPS traffic routed through the browser proxy
  install [--managed] Install the background service and point local tools at the proxy
                      (--managed also writes Claude Code's machine-wide managed settings; needs admin rights)
  uninstall           Remove everything: the service, browser protection, tool settings, keychain
                      credentials, enrollment, cached rules, logs and the installed binary
  status              Say whether the proxy is running
  refetch             Fetch your organisation's latest rules now
  doctor [--json]     Say, per enabled tool, whether it is covered (exit 1 if one is not)
  discover T --record Record the hosts, paths and content types a tool sends (developers; off without --record)
  login | logout | whoami
  enroll --bundle F   Redeem an enrollment bundle (enrollment.json; F can be - for stdin)
  init [--force]      Write inveil.toml and an example rules file here (use them with --config, or move
                      inveil.toml to the per-user data directory; the current directory is never read)
  browser-setup       Let the browser proxy read AI chat sites (creates and trusts a local CA)
  browser-remove      Undo browser-setup
  keygen | sign | verify  Generate a signing key; sign or check a policy or update file
  update [--check|--apply|--recover]  Check for, apply, or recover an update
  version

Flags:
  --config FILE       Use this configuration file (without it only the per-user file is read)
  --dry-run           Log findings but never block
  --offline           Make no network calls
  --debug | --trace   Metadata-only diagnostic logging
  --log-file FILE     Also write logs to this file";

#[derive(Debug, PartialEq)]
pub enum Command {
    Run,
    RunTool(Vec<String>),
    Install { managed: bool },
    Uninstall,
    Status,
    Refetch,
    Doctor { json: bool },
    Discover { target: String, record: bool },
    Login,
    Logout,
    Whoami,
    Enroll { bundle: PathBuf },
    Init { force: bool },
    BrowserSetup,
    BrowserRemove,
    Keygen(Vec<String>),
    Sign(Vec<String>),
    Verify(Vec<String>),
    Update(Vec<String>),
    Version,
    Help,
}

pub struct Cli {
    pub config_path: Option<PathBuf>,
    pub overrides: Vec<Override>,
    pub command: Command,
}

fn is_help(argument: &str) -> bool {
    matches!(argument, "-h" | "--help")
}

fn usage_error(message: impl Into<String>) -> AppError {
    AppError::Usage(message.into())
}

/// Flags that mean the same thing for every command.
struct GlobalFlags {
    config_path: Option<PathBuf>,
    overrides: Vec<Override>,
}

impl GlobalFlags {
    /// Takes `flag` (and its value, from `arguments`) if it is a global one. `Ok(false)` means it is not.
    fn take(
        &mut self,
        arguments: &mut std::vec::IntoIter<String>,
        flag: &str,
    ) -> Result<bool, AppError> {
        let (name, inline_value) = match flag.split_once('=') {
            Some((name, value)) => (name, Some(value.to_string())),
            None => (flag, None),
        };
        let mut value = |what: &str| {
            inline_value
                .clone()
                .or_else(|| arguments.next())
                .ok_or_else(|| usage_error(format!("{name} needs {what}")))
        };
        match name {
            "--config" => self.config_path = Some(PathBuf::from(value("a file")?)),
            "--log-file" => self.set("logging.file", Value::String(value("a file")?)),
            "--dry-run" => self.set("dry_run", Value::Boolean(true)),
            "--offline" => self.set("offline", Value::Boolean(true)),
            "--debug" => self.set("logging.debug", Value::Boolean(true)),
            "--trace" => {
                self.set("logging.debug", Value::Boolean(true));
                self.set("logging.trace", Value::Boolean(true));
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn set(&mut self, key: &'static str, value: Value) {
        self.overrides.push(Override { key, value });
    }
}

impl Cli {
    pub fn parse(arguments: Vec<String>) -> Result<Self, AppError> {
        let mut flags = GlobalFlags {
            config_path: None,
            overrides: vec![],
        };
        let mut arguments = arguments.into_iter();
        let mut word = None;
        while let Some(argument) = arguments.next() {
            if argument == "--" || !argument.starts_with('-') {
                word = Some(argument);
                break;
            }
            match argument.as_str() {
                help if is_help(help) => return Ok(Self::finish(flags, Command::Help)),
                "-V" | "--version" => return Ok(Self::finish(flags, Command::Version)),
                _ if flags.take(&mut arguments, &argument)? => {}
                _ => return Err(usage_error(format!("unknown flag {argument}"))),
            }
        }
        let command = match word.as_deref() {
            None => Command::Run,
            Some("--") => Command::RunTool(arguments.collect()),
            Some("keygen") => Command::Keygen(arguments.collect()),
            Some("sign") => Command::Sign(arguments.collect()),
            Some("verify") => Command::Verify(arguments.collect()),
            Some("update") => Command::Update(arguments.collect()),
            Some(name) => Self::simple_command(name, &mut flags, &mut arguments)?,
        };
        let command = match command {
            Command::Keygen(rest)
            | Command::Sign(rest)
            | Command::Verify(rest)
            | Command::Update(rest)
                if rest.iter().any(|argument| is_help(argument)) =>
            {
                Command::Help
            }
            other => other,
        };
        Ok(Self::finish(flags, command))
    }

    fn finish(flags: GlobalFlags, command: Command) -> Self {
        Self {
            config_path: flags.config_path,
            overrides: flags.overrides,
            command,
        }
    }

    /// Commands that take only flags (and, for `run`, a command to wrap).
    fn simple_command(
        name: &str,
        flags: &mut GlobalFlags,
        arguments: &mut std::vec::IntoIter<String>,
    ) -> Result<Command, AppError> {
        let mut bundle = None;
        let mut force = false;
        let mut managed = false;
        let mut json = false;
        let mut record = false;
        let mut discover_target = None;
        let mut tool: Vec<String> = vec![];
        while let Some(argument) = arguments.next() {
            if name == "run" && (!argument.starts_with('-') || argument == "--") {
                if argument != "--" {
                    tool.push(argument);
                }
                tool.extend(arguments.by_ref());
                break;
            }
            match argument.as_str() {
                help if is_help(help) => return Ok(Command::Help),
                "--bundle" if name == "enroll" => {
                    bundle = Some(PathBuf::from(
                        arguments
                            .next()
                            .ok_or_else(|| usage_error("--bundle needs a file"))?,
                    ));
                }
                "--force" if name == "init" => force = true,
                "--managed" if name == "install" => managed = true,
                "--json" if name == "doctor" => json = true,
                "--record" if name == "discover" => record = true,
                _ if name == "discover"
                    && !argument.starts_with('-')
                    && discover_target.is_none() =>
                {
                    discover_target = Some(argument);
                }
                _ if flags.take(arguments, &argument)? => {}
                _ => return Err(usage_error(format!("unexpected argument {argument}"))),
            }
        }
        match name {
            "run" if tool.is_empty() => Ok(Command::Run),
            "run" => Ok(Command::RunTool(tool)),
            "install" => Ok(Command::Install { managed }),
            "doctor" => Ok(Command::Doctor { json }),
            "discover" => Ok(Command::Discover {
                target: discover_target
                    .ok_or_else(|| usage_error("discover needs a host or tool id"))?,
                record,
            }),
            "uninstall" => Ok(Command::Uninstall),
            "status" => Ok(Command::Status),
            "refetch" => Ok(Command::Refetch),
            "login" => Ok(Command::Login),
            "logout" => Ok(Command::Logout),
            "whoami" => Ok(Command::Whoami),
            "enroll" => Ok(Command::Enroll {
                bundle: bundle.ok_or_else(|| usage_error("enroll needs --bundle FILE"))?,
            }),
            "init" => Ok(Command::Init { force }),
            "browser-setup" => Ok(Command::BrowserSetup),
            "browser-remove" => Ok(Command::BrowserRemove),
            "version" => Ok(Command::Version),
            "help" => Ok(Command::Help),
            other => Err(usage_error(format!("unknown command {other}\n\n{USAGE}"))),
        }
    }

    /// Layers the configuration for this invocation.
    pub fn load_config(&self) -> Result<Config, AppError> {
        let user_file = match &self.config_path {
            Some(path) if !path.exists() => {
                return Err(usage_error(format!("{} does not exist", path.display())))
            }
            Some(path) => Some(path.clone()),
            None => default_user_config(),
        };
        Ok(config::load(&Sources::from_process(
            user_file,
            self.overrides.clone(),
        ))?)
    }
}

/// The per-user configuration file. The current directory is never searched: a cloned repository that ships an
/// `inveil.toml` must not be able to set the trust roots, the update feed or the rules file of whoever runs inveil
/// there. A file elsewhere is used only when named with `--config`.
fn default_user_config() -> Option<PathBuf> {
    platform::data_dir()
        .ok()
        .map(|directory| directory.join(crate::brand::CONFIG_FILE_NAME))
}

pub async fn dispatch(cli: Cli, config: Config) -> Result<ExitCode, AppError> {
    let message = match cli.command {
        Command::Run => {
            crate::serve::run(config).await?;
            return Ok(ExitCode::SUCCESS);
        }
        Command::RunTool(arguments) => return tool::run(&config, &arguments),
        Command::Install { managed } => install::install(config, managed).await?,
        Command::Uninstall => install::uninstall(config)?,
        Command::Status => install::status(&config)?,
        Command::Refetch => refetch::refetch(&config).await?,
        Command::Doctor { json } => return doctor::run(&config, json),
        Command::Discover { target, record } => discover::run(config, &target, record).await?,
        Command::Login => auth::login(&config).await?,
        Command::Logout => auth::logout(&config)?,
        Command::Whoami => auth::whoami(&config).await?,
        Command::Enroll { bundle } => auth::enroll(&config, cli.config_path, &bundle).await?,
        Command::Init { force } => init::run(cli.config_path, force)?,
        Command::BrowserSetup => browser::setup(config).await?,
        Command::BrowserRemove => browser::remove(config)?,
        Command::Keygen(arguments) => update::run_keygen(&arguments)?,
        Command::Sign(arguments) => update::run_sign(&arguments)?,
        Command::Verify(arguments) => update::run_verify(&config, &arguments)?,
        Command::Update(arguments) => {
            refuse_when_offline(&config)?;
            update::run_update(&config, &arguments)?
        }
        Command::Version => format!("inveil {}", env!("CARGO_PKG_VERSION")),
        Command::Help => USAGE.to_string(),
    };
    println!("{message}");
    Ok(ExitCode::SUCCESS)
}

fn refuse_when_offline(config: &Config) -> Result<(), AppError> {
    let runtime = Runtime::new(Arc::new(config.clone()))?;
    if runtime.initial_policy()?.effective.offline {
        return Err(AppError::Usage(
            "offline mode makes no network calls, so there is nothing to check".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(line: &str) -> Result<Cli, AppError> {
        Cli::parse(line.split_whitespace().map(String::from).collect())
    }

    #[test]
    fn the_current_directory_is_never_searched_for_a_configuration_file() {
        let path = default_user_config().unwrap();
        assert!(path.is_absolute(), "{}", path.display());
        assert!(path.ends_with(crate::brand::CONFIG_FILE_NAME));
    }

    #[test]
    fn refetch_takes_no_arguments() {
        assert_eq!(parse("refetch").unwrap().command, Command::Refetch);
        assert!(matches!(parse("refetch --bogus"), Err(AppError::Usage(_))));
    }

    #[test]
    fn no_command_runs_the_proxy_and_flags_become_overrides() {
        let cli = parse("--dry-run --log-file /tmp/x.log").unwrap();
        assert_eq!(cli.command, Command::Run);
        let keys: Vec<&str> = cli.overrides.iter().map(|flag| flag.key).collect();
        assert_eq!(keys, ["dry_run", "logging.file"]);
    }

    #[test]
    fn run_with_a_command_wraps_it_and_keeps_its_flags() {
        assert_eq!(parse("run").unwrap().command, Command::Run);
        let cli = parse("run --offline claude --dry-run -p hi").unwrap();
        assert_eq!(
            cli.command,
            Command::RunTool(vec![
                "claude".into(),
                "--dry-run".into(),
                "-p".into(),
                "hi".into()
            ])
        );
        assert_eq!(
            cli.overrides.len(),
            1,
            "only flags before the wrapped command are ours"
        );
    }

    #[test]
    fn subcommands_parse_with_their_own_flags() {
        assert_eq!(
            parse("enroll --bundle enrollment.json").unwrap().command,
            Command::Enroll {
                bundle: "enrollment.json".into()
            }
        );
        assert_eq!(
            parse("init --force").unwrap().command,
            Command::Init { force: true }
        );
        assert_eq!(
            parse("sign --role policy --key k.pk8 rules.json")
                .unwrap()
                .command,
            Command::Sign(
                ["--role", "policy", "--key", "k.pk8", "rules.json"]
                    .map(String::from)
                    .to_vec()
            )
        );
        assert_eq!(parse("--version").unwrap().command, Command::Version);
    }

    #[test]
    fn install_doctor_and_discover_take_their_own_flags() {
        assert_eq!(
            parse("install").unwrap().command,
            Command::Install { managed: false }
        );
        assert_eq!(
            parse("install --managed").unwrap().command,
            Command::Install { managed: true }
        );
        assert_eq!(
            parse("doctor --json").unwrap().command,
            Command::Doctor { json: true }
        );
        assert_eq!(
            parse("discover claude.ai --record").unwrap().command,
            Command::Discover {
                target: "claude.ai".into(),
                record: true
            }
        );
        assert_eq!(
            parse("discover claude.ai").unwrap().command,
            Command::Discover {
                target: "claude.ai".into(),
                record: false
            }
        );
    }

    #[test]
    fn help_after_any_subcommand_prints_usage() {
        for line in [
            "run --help",
            "install --help",
            "uninstall -h",
            "status --help",
            "refetch --help",
            "doctor --help",
            "discover --help",
            "login --help",
            "enroll --help",
            "init --help",
            "browser-setup --help",
            "browser-remove --help",
            "keygen --help",
            "sign --role policy --help",
            "verify --help",
            "update --help",
            "version --help",
        ] {
            assert_eq!(parse(line).unwrap().command, Command::Help, "{line}");
        }
        assert_eq!(
            parse("run claude --help").unwrap().command,
            Command::RunTool(vec!["claude".into(), "--help".into()]),
            "help after the wrapped command belongs to that command"
        );
    }

    #[test]
    fn mistakes_are_usage_errors_not_panics() {
        for line in [
            "enroll",
            "--nonsense",
            "install extra",
            "doctor --managed",
            "discover",
            "frobnicate",
            "--config",
        ] {
            assert!(matches!(parse(line), Err(AppError::Usage(_))), "{line}");
        }
    }
}
