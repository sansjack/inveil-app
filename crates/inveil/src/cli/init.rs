//! `inveil init`: writes a starter `inveil.toml` and an example (unsigned) rules file to edit and sign.
use crate::brand;
use crate::error::AppError;
use std::path::{Path, PathBuf};

const EXAMPLE_RULES_FILE: &str = "rules.example.json";
const EXAMPLE_RULES: &str = include_str!("../builtin_rules.json");
const EXAMPLE_CONFIG: &str = r#"# inveil configuration. Every key is optional; these are the defaults you are most likely to change.
# Layering, highest first: command-line flags, INVEIL_* environment variables, this file, the system-wide file.
# inveil only reads this file when it is named with --config or placed in the per-user data directory,
# never because it sits in the current directory.

# "standalone": you are both administrator and user. "managed": an administrator's signed policy decides
# usage reporting and the other enforced settings (put this in the system-wide file so users cannot edit it).
mode = "standalone"

# Log findings but never block.
dry_run = false
# What to do when inveil cannot decide normally. By default requests that cannot be scanned (and scanner errors and an
# expired policy) are blocked, and browsers go direct while inveil is down. In standalone mode you choose per
# condition, "open" (let it through, audited as fail_open) or "closed" (block). In managed mode only "closed" is
# accepted here; "open" has to come from the signed policy.
# [failure_modes]
# default = "closed"
# unscannable = "open"
# service_down = "closed"   # browsers stop loading chat sites while inveil is down
# Extra regexes to block, on top of the rules.
deny = []
# Show an OS notification when something is redacted or blocked.
notify = true

# Default upstream of the localhost API proxy (https, or http on loopback).
upstream = "https://api.anthropic.com"

# Without a backend, inveil runs on its built-in rules. To use your own, sign a rules file
# (`inveil sign`) and point at it, or at a backend that serves signed snapshots:
# rules_file = "rules.signed.json"
#
# [backend]
# url = "https://policy.example.com"
# pinned_keys = [{ key_id = "policy-1", public_key = "BASE64_ED25519_PUBLIC_KEY" }]
#
# [auth]
# mode = "none"   # none | static_token | enrolled | device_flow

[listen]
port = 8787
browser_port = 8788

[usage]
# none | file | http. File writes one JSON line per batch to `file`.
sink = "none"
"#;

pub fn run(config_path: Option<PathBuf>, force: bool) -> Result<String, AppError> {
    let config_file = config_path.unwrap_or_else(|| PathBuf::from(brand::CONFIG_FILE_NAME));
    let rules_file = config_file.with_file_name(EXAMPLE_RULES_FILE);
    for path in [&config_file, &rules_file] {
        if path.exists() && !force {
            return Err(AppError::Usage(format!(
                "{} already exists; use --force to overwrite it",
                path.display()
            )));
        }
    }
    write(&config_file, EXAMPLE_CONFIG)?;
    write(&rules_file, EXAMPLE_RULES)?;
    Ok(format!(
        "Wrote {} and {}.\ninveil does not read configuration files from the current directory. Use this one with \
         `inveil --config {} run`, or move it to the per-user location (see docs/CONFIGURATION.md) to make it the default.\n\
         Review it first: it decides which rules are trusted and where updates come from.",
        config_file.display(),
        rules_file.display(),
        config_file.display()
    ))
}

fn write(path: &Path, contents: &str) -> Result<(), AppError> {
    std::fs::write(path, contents).map_err(|source| AppError::WriteFile {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use contract::Snapshot;

    #[test]
    fn the_example_configuration_is_valid() {
        let config: Config = toml::from_str(EXAMPLE_CONFIG).unwrap();
        config.validate().unwrap();
    }

    #[test]
    fn the_example_rules_are_a_snapshot_ready_to_sign() {
        let snapshot: Snapshot = serde_json::from_str(EXAMPLE_RULES).unwrap();
        engine::validate(&snapshot).unwrap();
    }

    #[test]
    fn existing_files_are_not_overwritten_without_force() {
        let directory = tempfile::tempdir().unwrap();
        let config = directory.path().join("inveil.toml");
        run(Some(config.clone()), false).unwrap();
        assert!(directory.path().join(EXAMPLE_RULES_FILE).exists());
        assert!(matches!(
            run(Some(config.clone()), false),
            Err(AppError::Usage(_))
        ));
        run(Some(config), true).unwrap();
    }
}
