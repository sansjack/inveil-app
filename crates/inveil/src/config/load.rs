use super::{Config, ConfigError};
use crate::brand;
use std::path::{Path, PathBuf};
use toml::{Table, Value};

/// Keys an administrator locks by setting `mode = "managed"` in the system-wide file, as dotted paths. A user file,
/// the environment and flags cannot change them; a locked table is locked with everything inside it. Every
/// configuration key must be here or in `USER_ADJUSTABLE_KEYS`, which a test enforces so a new key cannot be left
/// unlocked by accident.
const MANAGED_LOCKED_KEYS: [&str; 19] = [
    "mode",
    "offline",
    "rules_file",
    "backend",
    "auth",
    "usage",
    "update",
    "data_dir",
    "state_keychain",
    "listen",
    "upstream",
    "dry_run",
    "failure_modes",
    "block_unscannable",
    "browser_fail_closed",
    "deny",
    "limits",
    "notify",
    "logging.audit_file",
];

/// Environment variable -> configuration key. The value is parsed as the type of the key's default.
const ENVIRONMENT_KEYS: [(&str, &str); 19] = [
    ("INVEIL_MODE", "mode"),
    ("INVEIL_OFFLINE", "offline"),
    ("INVEIL_RULES_FILE", "rules_file"),
    ("INVEIL_BACKEND_URL", "backend.url"),
    ("INVEIL_BACKEND_RULES_PATH", "backend.rules_path"),
    ("INVEIL_AUTH_MODE", "auth.mode"),
    ("INVEIL_UPSTREAM", "upstream"),
    ("INVEIL_DRY_RUN", "dry_run"),
    ("INVEIL_BLOCK_UNSCANNABLE", "block_unscannable"),
    ("INVEIL_MAX_TOKENS", "max_tokens"),
    ("INVEIL_BROWSER_FAIL_CLOSED", "browser_fail_closed"),
    ("INVEIL_NOTIFY", "notify"),
    ("INVEIL_LISTEN_PORT", "listen.port"),
    ("INVEIL_BROWSER_PORT", "listen.browser_port"),
    ("INVEIL_USAGE_SINK", "usage.sink"),
    ("INVEIL_LOG_LEVEL", "logging.level"),
    ("INVEIL_LOG_FILE", "logging.file"),
    ("INVEIL_AUDIT_FILE", "logging.audit_file"),
    ("INVEIL_DATA_DIR", "data_dir"),
];

/// Optional booleans have no default to take their type from, so the environment is told it is a boolean.
const OPTIONAL_BOOLEAN_KEYS: [&str; 2] = ["block_unscannable", "browser_fail_closed"];

/// `INVEIL_DEBUG=1` turns on debug lines and `INVEIL_DEBUG=trace` also turns on trace lines.
const DEBUG_VARIABLE: &str = "INVEIL_DEBUG";

/// One value set from a command-line flag; flags beat everything else.
#[derive(Debug, Clone)]
pub struct Override {
    pub key: &'static str,
    pub value: Value,
}

#[derive(Debug, Default)]
pub struct Sources {
    pub system_file: Option<PathBuf>,
    pub user_file: Option<PathBuf>,
    pub environment: Vec<(String, String)>,
    pub overrides: Vec<Override>,
}

impl Sources {
    pub fn from_process(user_file: Option<PathBuf>, overrides: Vec<Override>) -> Self {
        let environment = std::env::vars()
            .filter(|(name, _)| name.starts_with(brand::ENV_PREFIX))
            .collect();
        Self {
            system_file: system_config_path(),
            user_file,
            environment,
            overrides,
        }
    }
}

/// Where an administrator puts the managed configuration; writable by administrators only. No environment variable
/// takes part in finding it: a user could point one at a directory they control.
pub fn system_config_path() -> Option<PathBuf> {
    Some(system_config_directory()?.join(brand::CONFIG_FILE_NAME))
}

#[cfg(target_os = "macos")]
fn system_config_directory() -> Option<PathBuf> {
    Some(PathBuf::from("/Library/Application Support").join(brand::PRODUCT))
}

#[cfg(windows)]
fn system_config_directory() -> Option<PathBuf> {
    Some(crate::platform::program_data_dir()?.join(brand::PRODUCT))
}

#[cfg(not(any(target_os = "macos", windows)))]
fn system_config_directory() -> Option<PathBuf> {
    Some(PathBuf::from("/etc").join(brand::PRODUCT))
}

pub fn load(sources: &Sources) -> Result<Config, ConfigError> {
    let defaults = match Value::try_from(Config::default())? {
        Value::Table(table) => table,
        _ => Table::new(),
    };
    let system = read_table(sources.system_file.as_deref())?;
    let user = read_table(sources.user_file.as_deref())?;

    let mut table = defaults.clone();
    merge(&mut table, system.clone().unwrap_or_default());
    merge(&mut table, user.unwrap_or_default());
    apply_environment(&mut table, &defaults, &sources.environment)?;
    for flag in &sources.overrides {
        set_path(&mut table, flag.key, flag.value.clone());
    }

    let system_managed = system.as_ref().is_some_and(declares_managed);
    if system_managed {
        let mut locked = defaults;
        merge(&mut locked, system.unwrap_or_default());
        for key in MANAGED_LOCKED_KEYS {
            match lookup(&locked, key) {
                Some(value) => set_path(&mut table, key, value.clone()),
                None => remove_path(&mut table, key),
            }
        }
    }

    let mut config: Config = Value::Table(table).try_into()?;
    config.system_managed = system_managed;
    config.validate()?;
    Ok(config)
}

fn declares_managed(system: &Table) -> bool {
    system.get("mode").and_then(Value::as_str) == Some("managed")
}

fn read_table(path: Option<&Path>) -> Result<Option<Table>, ConfigError> {
    let Some(path) = path else {
        return Ok(None);
    };
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(ConfigError::Read {
                path: path.to_path_buf(),
                source,
            })
        }
    };
    Ok(Some(text.parse::<Table>()?))
}

/// Tables merge key by key; every other value, arrays included, is replaced.
fn merge(base: &mut Table, over: Table) {
    for (key, value) in over {
        match (base.get_mut(&key), value) {
            (Some(Value::Table(base_table)), Value::Table(over_table)) => {
                merge(base_table, over_table)
            }
            (_, value) => {
                base.insert(key, value);
            }
        }
    }
}

fn set_path(table: &mut Table, path: &str, value: Value) {
    let Some((head, rest)) = path.split_once('.') else {
        table.insert(path.to_string(), value);
        return;
    };
    let child = table
        .entry(head.to_string())
        .or_insert_with(|| Value::Table(Table::new()));
    if let Value::Table(child) = child {
        set_path(child, rest, value);
    }
}

fn remove_path(table: &mut Table, path: &str) {
    let Some((head, rest)) = path.split_once('.') else {
        table.remove(path);
        return;
    };
    if let Some(Value::Table(child)) = table.get_mut(head) {
        remove_path(child, rest);
    }
}

fn lookup<'a>(table: &'a Table, path: &str) -> Option<&'a Value> {
    let mut parts = path.split('.');
    let mut current = table.get(parts.next()?)?;
    for part in parts {
        current = current.as_table()?.get(part)?;
    }
    Some(current)
}

fn apply_environment(
    table: &mut Table,
    defaults: &Table,
    environment: &[(String, String)],
) -> Result<(), ConfigError> {
    for (variable, raw) in environment {
        if variable == DEBUG_VARIABLE {
            apply_debug(table, raw);
            continue;
        }
        let Some((_, key)) = ENVIRONMENT_KEYS.iter().find(|(name, _)| name == variable) else {
            continue;
        };
        let default = if OPTIONAL_BOOLEAN_KEYS.contains(key) {
            Some(&Value::Boolean(false))
        } else {
            lookup(defaults, key)
        };
        let value = parse_like(default, raw).map_err(|reason| ConfigError::Environment {
            variable: variable.clone(),
            reason,
        })?;
        set_path(table, key, value);
    }
    Ok(())
}

fn apply_debug(table: &mut Table, raw: &str) {
    match raw {
        "trace" => {
            set_path(table, "logging.debug", Value::Boolean(true));
            set_path(table, "logging.trace", Value::Boolean(true));
        }
        "1" | "true" => set_path(table, "logging.debug", Value::Boolean(true)),
        _ => {}
    }
}

fn parse_like(default: Option<&Value>, raw: &str) -> Result<Value, &'static str> {
    match default {
        Some(Value::Boolean(_)) => match raw {
            "1" | "true" => Ok(Value::Boolean(true)),
            "0" | "false" => Ok(Value::Boolean(false)),
            _ => Err("expected true or false"),
        },
        Some(Value::Integer(_)) => raw
            .parse::<i64>()
            .map(Value::Integer)
            .map_err(|_| "expected a whole number"),
        _ => Ok(Value::String(raw.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Keys a user may still change in managed mode. Each can only make the client stricter or is a local diagnostic:
    /// `max_tokens` is merged with the signed limit by taking the smaller, and `debug` needs the signed `allow_debug`.
    pub const USER_ADJUSTABLE_KEYS: [&str; 5] = [
        "max_tokens",
        "logging.level",
        "logging.debug",
        "logging.trace",
        "logging.file",
    ];

    fn write(directory: &Path, name: &str, text: &str) -> PathBuf {
        let path = directory.join(name);
        std::fs::write(&path, text).unwrap();
        path
    }

    fn environment(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect()
    }

    #[test]
    fn empty_sources_give_the_defaults() {
        let config = load(&Sources::default()).unwrap();
        assert_eq!(config.listen.port, 8787);
        assert!(config.backend.url.is_none());
        assert_eq!(config.backend.rules_path, "/v1/rules");
    }

    #[test]
    fn flags_beat_environment_beat_user_file_beat_system_file() {
        let directory = tempfile::tempdir().unwrap();
        let system = write(directory.path(), "system.toml", "[listen]\nport = 9001\n");
        let user = write(directory.path(), "user.toml", "[listen]\nport = 9002\n");

        let mut sources = Sources {
            system_file: Some(system),
            user_file: Some(user),
            ..Sources::default()
        };
        assert_eq!(load(&sources).unwrap().listen.port, 9002);

        sources.environment = environment(&[("INVEIL_LISTEN_PORT", "9003")]);
        assert_eq!(load(&sources).unwrap().listen.port, 9003);

        sources.overrides = vec![Override {
            key: "listen.port",
            value: Value::Integer(9004),
        }];
        assert_eq!(load(&sources).unwrap().listen.port, 9004);
    }

    #[test]
    fn a_managed_system_file_locks_its_keys_against_every_other_layer() {
        let directory = tempfile::tempdir().unwrap();
        let system = write(
            directory.path(),
            "system.toml",
            "mode = \"managed\"\noffline = false\n[usage]\nsink = \"file\"\nfile = \"/var/log/usage.jsonl\"\n",
        );
        let user = write(
            directory.path(),
            "user.toml",
            "offline = true\nmax_tokens = 500\n[usage]\nsink = \"none\"\n",
        );
        let sources = Sources {
            system_file: Some(system),
            user_file: Some(user),
            environment: environment(&[("INVEIL_OFFLINE", "true"), ("INVEIL_USAGE_SINK", "none")]),
            overrides: vec![Override {
                key: "offline",
                value: Value::Boolean(true),
            }],
        };
        let config = load(&sources).unwrap();
        assert!(!config.offline, "a managed system file locks offline");
        assert_eq!(config.usage.sink, crate::config::UsageSink::File);
        assert_eq!(
            config.max_tokens, 500,
            "keys that are not locked stay user-controlled"
        );
    }

    const BACKEND_TOML: &str = "[backend]\nurl = \"https://inveil.example.com\"\npinned_keys = [{ key_id = \"k1\", public_key = \"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\" }]\n";

    #[test]
    fn a_managed_system_file_keeps_its_own_dry_run_and_refuses_a_local_open_failure_mode() {
        let directory = tempfile::tempdir().unwrap();
        let system_text = format!("mode = \"managed\"\ndry_run = true\n{BACKEND_TOML}");
        let system = write(directory.path(), "system.toml", &system_text);
        let config = load(&Sources {
            system_file: Some(system.clone()),
            ..Sources::default()
        })
        .unwrap();
        assert!(config.system_managed);
        assert!(config.local_settings().dry_run);
        assert!(config.ignored_overrides().is_empty());

        let refusing = format!("{system_text}[failure_modes]\ndefault = \"open\"\n");
        let system = write(directory.path(), "refusing.toml", &refusing);
        let error = load(&Sources {
            system_file: Some(system),
            ..Sources::default()
        })
        .unwrap_err();
        assert!(matches!(
            error,
            ConfigError::Invalid {
                key: "failure_modes",
                ..
            }
        ));
    }

    #[test]
    fn a_user_file_declaring_managed_does_not_make_the_device_system_managed() {
        let directory = tempfile::tempdir().unwrap();
        let user_text = format!(
            "mode = \"managed\"\ndry_run = true\n[auth]\nmode = \"enrolled\"\n{BACKEND_TOML}"
        );
        let user = write(directory.path(), "user.toml", &user_text);
        let config = load(&Sources {
            user_file: Some(user),
            ..Sources::default()
        })
        .unwrap();
        assert!(!config.system_managed);
        assert!(!config.local_settings().dry_run);
    }

    #[test]
    fn a_managed_system_file_keeps_enforcement_settings_out_of_the_users_hands() {
        let directory = tempfile::tempdir().unwrap();
        let system = write(directory.path(), "system.toml", "mode = \"managed\"\n");
        let user = write(
            directory.path(),
            "user.toml",
            r#"
dry_run = true
upstream = "https://evil.example"
deny = ["x"]
notify = false
block_unscannable = false
browser_fail_closed = false
[failure_modes]
default = "open"
[limits]
max_body_bytes = 999999999
[listen]
port = 9999
[logging]
audit_file = "/tmp/elsewhere.jsonl"
level = "debug"
"#,
        );
        let sources = Sources {
            system_file: Some(system),
            user_file: Some(user),
            environment: environment(&[
                ("INVEIL_DRY_RUN", "true"),
                ("INVEIL_UPSTREAM", "https://evil.example"),
                ("INVEIL_NOTIFY", "false"),
                ("INVEIL_BLOCK_UNSCANNABLE", "false"),
                ("INVEIL_BROWSER_FAIL_CLOSED", "false"),
                ("INVEIL_BROWSER_PORT", "9998"),
                ("INVEIL_AUDIT_FILE", "/tmp/elsewhere.jsonl"),
            ]),
            overrides: vec![
                Override {
                    key: "dry_run",
                    value: Value::Boolean(true),
                },
                Override {
                    key: "listen.port",
                    value: Value::Integer(9997),
                },
            ],
        };
        let config = load(&sources).unwrap();
        let defaults = Config::default();
        assert!(
            !config.dry_run,
            "managed mode enforces unless the signed settings say otherwise"
        );
        assert_eq!(config.upstream, defaults.upstream);
        assert!(config.deny.is_empty());
        assert!(config.notify);
        assert_eq!(config.block_unscannable, None);
        assert_eq!(config.browser_fail_closed, None);
        assert_eq!(config.failure_modes, defaults.failure_modes);
        assert_eq!(config.limits.max_body_bytes, defaults.limits.max_body_bytes);
        assert_eq!(config.listen.port, defaults.listen.port);
        assert_eq!(config.listen.browser_port, defaults.listen.browser_port);
        assert_eq!(config.logging.audit_file, None);
        assert_eq!(config.logging.level.as_deref(), Some("debug"));
    }

    #[test]
    fn every_configuration_key_is_either_locked_in_managed_mode_or_listed_as_user_adjustable() {
        let full = Config {
            rules_file: Some("rules.json".into()),
            block_unscannable: Some(true),
            browser_fail_closed: Some(true),
            data_dir: Some("data".into()),
            logging: crate::config::LoggingConfig {
                level: Some("info".into()),
                file: Some("log".into()),
                audit_file: Some("audit".into()),
                ..Default::default()
            },
            usage: crate::config::UsageConfig {
                file: Some("usage".into()),
                ..Default::default()
            },
            auth: crate::config::AuthConfig {
                token_env: Some("TOKEN".into()),
                ..Default::default()
            },
            update: crate::config::UpdateConfig {
                feed_url: Some("https://feed.example".into()),
                ..Default::default()
            },
            backend: crate::config::BackendConfig {
                url: Some("https://backend.example".into()),
                ..Default::default()
            },
            ..Config::default()
        };
        let Value::Table(table) = Value::try_from(full).unwrap() else {
            panic!("the configuration is a table");
        };

        let mut uncovered = vec![];
        collect_unclassified(&table, "", &mut uncovered);
        assert!(
            uncovered.is_empty(),
            "add these to MANAGED_LOCKED_KEYS or USER_ADJUSTABLE_KEYS: {uncovered:?}"
        );
        for key in MANAGED_LOCKED_KEYS.iter().chain(&USER_ADJUSTABLE_KEYS) {
            assert!(
                lookup(&table, key).is_some(),
                "{key} is not a configuration key"
            );
        }
        for key in USER_ADJUSTABLE_KEYS {
            assert!(!MANAGED_LOCKED_KEYS.contains(&key), "{key} is both");
        }
    }

    fn collect_unclassified(table: &Table, prefix: &str, found: &mut Vec<String>) {
        for (name, value) in table {
            let path = format!("{prefix}{name}");
            if MANAGED_LOCKED_KEYS.contains(&path.as_str())
                || USER_ADJUSTABLE_KEYS.contains(&path.as_str())
            {
                continue;
            }
            match value {
                Value::Table(inner) => collect_unclassified(inner, &format!("{path}."), found),
                _ => found.push(path),
            }
        }
    }

    #[test]
    fn without_a_managed_declaration_the_user_file_wins() {
        let directory = tempfile::tempdir().unwrap();
        let system = write(directory.path(), "system.toml", "offline = false\n");
        let user = write(directory.path(), "user.toml", "offline = true\n");
        let sources = Sources {
            system_file: Some(system),
            user_file: Some(user),
            ..Sources::default()
        };
        assert!(load(&sources).unwrap().offline);
    }

    #[test]
    fn bad_input_is_a_typed_error_not_a_panic() {
        let directory = tempfile::tempdir().unwrap();
        let typo = write(directory.path(), "typo.toml", "typo = true\n");
        let sources = Sources {
            user_file: Some(typo),
            ..Sources::default()
        };
        assert!(matches!(load(&sources), Err(ConfigError::Parse(_))));

        let sources = Sources {
            environment: environment(&[("INVEIL_LISTEN_PORT", "eighty")]),
            ..Sources::default()
        };
        assert!(matches!(
            load(&sources),
            Err(ConfigError::Environment { .. })
        ));

        let sources = Sources {
            environment: environment(&[("INVEIL_BACKEND_URL", "http://policy.example.com")]),
            ..Sources::default()
        };
        assert!(matches!(load(&sources), Err(ConfigError::Invalid { .. })));
    }

    #[test]
    fn debug_variable_enables_debug_and_trace() {
        let sources = Sources {
            environment: environment(&[("INVEIL_DEBUG", "trace")]),
            ..Sources::default()
        };
        let config = load(&sources).unwrap();
        assert!(config.logging.debug && config.logging.trace);
    }
}
