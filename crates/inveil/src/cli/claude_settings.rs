//! Points Claude Code at the localhost proxy through the `env` map of its user settings file, keeping everything
//! else in that file as it was. Which variable to set comes from the signed snapshot (`tools[].env_var`).
//!
//! With `--managed` the variables go to a drop-in file in Claude Code's machine-wide managed settings directory
//! instead, which outranks every user and project file. Paths and the `env` key are as documented at
//! <https://code.claude.com/docs/en/managed-settings> (file-based delivery, `managed-settings.d/`) and
//! <https://code.claude.com/docs/en/settings-reference#env>. Writing there needs administrator rights. That is the
//! only thing an elevated `inveil install --managed` does: it never touches the home folder, whose location an
//! elevated process cannot trust (`HOME` may be the user's or root's). The file is written atomically with mode 0644
//! in directories of mode 0755, and a symlink at any of those paths is refused rather than followed.
//!
//! The per-user settings file is written atomically with mode 0600, and a symlink there is refused too.
use crate::error::AppError;
use crate::util::{
    create_directory, refuse_symlink, write_atomically, write_atomically_with_mode,
    PRIVATE_DIRECTORY_MODE, PUBLIC_DIRECTORY_MODE, PUBLIC_FILE_MODE,
};
use serde_json::{json, Map, Value};
use std::path::{Path, PathBuf};

const LOOPBACK_PREFIX: &str = "http://127.0.0.1:";
const SETTINGS_DIR: &str = ".claude";
const SETTINGS_FILE: &str = "settings.json";
const ENV_KEY: &str = "env";
const MANAGED_DROP_IN_DIR: &str = "managed-settings.d";
/// Sorts before most administrators' own files, and is wholly ours, so it is rewritten and deleted as a unit.
const MANAGED_FILE: &str = "50-inveil.json";

/// The current user's home folder.
pub fn home_directory() -> Result<PathBuf, AppError> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .ok_or_else(|| AppError::Usage("cannot find the home folder".into()))
}

fn settings_path() -> Result<PathBuf, AppError> {
    Ok(home_directory()?.join(SETTINGS_DIR).join(SETTINGS_FILE))
}

/// Claude Code's system directory for managed settings on this OS.
fn managed_directory() -> PathBuf {
    if cfg!(windows) {
        return PathBuf::from(r"C:\Program Files\ClaudeCode");
    }
    if cfg!(target_os = "macos") {
        return PathBuf::from("/Library/Application Support/ClaudeCode");
    }
    PathBuf::from("/etc/claude-code")
}

pub fn managed_path() -> PathBuf {
    managed_directory()
        .join(MANAGED_DROP_IN_DIR)
        .join(MANAGED_FILE)
}

fn unexpected_shape(path: &Path) -> AppError {
    AppError::Usage(format!(
        "{} has an unexpected shape; fix or remove it, then retry",
        path.display()
    ))
}

fn read(path: &Path) -> Result<Option<Value>, AppError> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(AppError::ReadFile {
                path: path.to_path_buf(),
                source,
            })
        }
    };
    serde_json::from_str(&text)
        .map(Some)
        .map_err(|_| unexpected_shape(path))
}

fn write(path: &Path, value: &Value) -> Result<(), AppError> {
    let failed = |source| AppError::WriteFile {
        path: path.to_path_buf(),
        source,
    };
    if let Some(parent) = path.parent() {
        create_directory(parent, PRIVATE_DIRECTORY_MODE).map_err(failed)?;
    }
    let text =
        serde_json::to_string_pretty(value).map_err(|error| AppError::Usage(error.to_string()))?;
    write_atomically(path, text.as_bytes()).map_err(failed)
}

/// Writes the managed drop-in file holding `entries` as its `env` map. Fails before changing anything when this
/// process cannot write to the system directory.
pub fn set_managed(path: &Path, entries: &[(String, String)]) -> Result<(), AppError> {
    let environment: Map<String, Value> = entries
        .iter()
        .map(|(variable, url)| (variable.clone(), Value::String(url.clone())))
        .collect();
    let denied = |error: std::io::Error| {
        if error.kind() == std::io::ErrorKind::PermissionDenied {
            return AppError::Usage(format!(
                "--managed writes {}, which needs administrator rights; run it again from an elevated shell",
                path.display()
            ));
        }
        AppError::WriteFile {
            path: path.to_path_buf(),
            source: error,
        }
    };
    if let Some(parent) = path.parent() {
        create_directory(parent, PUBLIC_DIRECTORY_MODE).map_err(denied)?;
        refuse_symlink(parent).map_err(denied)?;
        if let Some(grandparent) = parent.parent() {
            refuse_symlink(grandparent).map_err(denied)?;
        }
    }
    let text = serde_json::to_string_pretty(&json!({ ENV_KEY: environment }))
        .map_err(|error| AppError::Usage(error.to_string()))?;
    write_atomically_with_mode(path, text.as_bytes(), PUBLIC_FILE_MODE).map_err(denied)
}

/// Deletes the managed drop-in file if there is one. Returns false when it exists but cannot be deleted.
pub fn remove_managed(path: &Path) -> Result<bool, AppError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => Ok(false),
        Err(source) => Err(AppError::WriteFile {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// The value `variable` has in the user settings or, failing that, the managed drop-in file.
pub fn read_variable(variable: &str) -> Result<Option<String>, AppError> {
    for path in [managed_path(), settings_path()?] {
        let Some(settings) = read(&path)? else {
            continue;
        };
        let value = settings
            .get(ENV_KEY)
            .and_then(|environment| environment.get(variable))
            .and_then(Value::as_str);
        if let Some(value) = value {
            return Ok(Some(value.to_string()));
        }
    }
    Ok(None)
}

/// Sets each `(variable, url)` pair in the settings' `env` map.
pub fn set(entries: &[(String, String)]) -> Result<(), AppError> {
    let path = settings_path()?;
    let mut settings = read(&path)?.unwrap_or_else(|| json!({}));
    let environment = environment_map(&mut settings, &path)?;
    for (variable, url) in entries {
        environment.insert(variable.clone(), Value::String(url.clone()));
    }
    write(&path, &settings)
}

/// Removes each variable, but only when it still points at the loopback proxy; a value the person set is theirs.
pub fn remove(variables: &[String]) -> Result<(), AppError> {
    let path = settings_path()?;
    let Some(mut settings) = read(&path)? else {
        return Ok(());
    };
    remove_from(&mut settings, variables, &path)?;
    write(&path, &settings)
}

fn remove_from(settings: &mut Value, variables: &[String], path: &Path) -> Result<(), AppError> {
    let environment = environment_map(settings, path)?;
    for variable in variables {
        let ours = environment
            .get(variable)
            .and_then(Value::as_str)
            .is_some_and(|value| value.starts_with(LOOPBACK_PREFIX));
        if ours {
            environment.shift_remove(variable);
        }
    }
    Ok(())
}

fn environment_map<'a>(
    settings: &'a mut Value,
    path: &Path,
) -> Result<&'a mut Map<String, Value>, AppError> {
    settings
        .as_object_mut()
        .ok_or_else(|| unexpected_shape(path))?
        .entry(ENV_KEY)
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(|| unexpected_shape(path))
}

pub fn proxy_url(port: u16, prefix: Option<&str>) -> String {
    format!("{LOOPBACK_PREFIX}{port}{}", prefix.unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_url_carries_the_tools_prefix() {
        assert_eq!(proxy_url(8787, None), "http://127.0.0.1:8787");
        assert_eq!(
            proxy_url(8787, Some("/openai")),
            "http://127.0.0.1:8787/openai"
        );
    }

    #[test]
    fn only_our_own_entries_are_removed_and_the_rest_is_kept() {
        let path = Path::new("settings.json");
        let mut settings = json!({"theme": "dark", "env": {"A": "http://127.0.0.1:8787", "B": "https://mine.example"}});
        remove_from(&mut settings, &["A".to_string(), "B".to_string()], path).unwrap();
        assert_eq!(
            settings,
            json!({"theme": "dark", "env": {"B": "https://mine.example"}})
        );
    }

    #[test]
    fn a_settings_file_with_an_unexpected_shape_is_an_error() {
        let path = Path::new("settings.json");
        assert!(remove_from(&mut json!({"env": 3}), &["A".to_string()], path).is_err());
        assert!(remove_from(&mut json!([]), &["A".to_string()], path).is_err());
    }

    #[test]
    fn the_managed_file_is_a_drop_in_that_holds_only_our_env_entries() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory
            .path()
            .join(MANAGED_DROP_IN_DIR)
            .join(MANAGED_FILE);

        set_managed(
            &path,
            &[("ANTHROPIC_BASE_URL".into(), "http://127.0.0.1:8787".into())],
        )
        .unwrap();

        let written: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            written,
            json!({"env": {"ANTHROPIC_BASE_URL": "http://127.0.0.1:8787"}})
        );
        assert!(remove_managed(&path).unwrap());
        assert!(!path.exists());
        assert!(remove_managed(&path).unwrap());
    }

    #[test]
    fn a_hostile_value_stays_inside_its_json_string() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(MANAGED_FILE);
        let hostile = "http://127.0.0.1:1\"}, \"hooks\": {\"x\": \"y";

        set_managed(&path, &[("ANTHROPIC_BASE_URL".into(), hostile.into())]).unwrap();

        let written: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(written["env"]["ANTHROPIC_BASE_URL"], hostile);
        assert_eq!(written.as_object().unwrap().len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn writing_to_a_directory_without_rights_says_to_use_an_elevated_shell() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
        let path = directory
            .path()
            .join(MANAGED_DROP_IN_DIR)
            .join(MANAGED_FILE);

        let result = set_managed(&path, &[]);

        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        if let Err(error) = result {
            assert!(error.to_string().contains("administrator"), "{error}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn the_managed_file_is_world_readable_in_traversable_directories_whatever_the_umask() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory
            .path()
            .join("claude-code")
            .join(MANAGED_DROP_IN_DIR)
            .join(MANAGED_FILE);

        set_managed(&path, &[]).unwrap();

        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o644);
        assert_eq!(mode(path.parent().unwrap()), 0o755);
        assert_eq!(mode(path.parent().unwrap().parent().unwrap()), 0o755);
    }

    #[cfg(unix)]
    #[test]
    fn the_managed_file_is_never_written_through_a_symlink() {
        let directory = tempfile::tempdir().unwrap();
        let victim = directory.path().join("victim.json");
        std::fs::write(&victim, "keep").unwrap();
        let drop_in = directory.path().join(MANAGED_DROP_IN_DIR);
        std::fs::create_dir(&drop_in).unwrap();
        let path = drop_in.join(MANAGED_FILE);
        std::os::unix::fs::symlink(&victim, &path).unwrap();

        assert!(set_managed(&path, &[]).is_err());
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep");

        let elsewhere = tempfile::tempdir().unwrap();
        let linked_directory = directory.path().join("linked");
        std::os::unix::fs::symlink(elsewhere.path(), &linked_directory).unwrap();
        let through_link = linked_directory.join(MANAGED_FILE);
        assert!(set_managed(&through_link, &[]).is_err());
        assert!(!elsewhere.path().join(MANAGED_FILE).exists());
    }

    #[cfg(unix)]
    #[test]
    fn user_settings_are_owner_only_and_a_symlinked_file_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(SETTINGS_DIR).join(SETTINGS_FILE);

        write(&path, &json!({"env": {}})).unwrap();

        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);

        let victim = directory.path().join("dotfiles.json");
        std::fs::write(&victim, "keep").unwrap();
        let link = directory.path().join("linked.json");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        assert!(write(&link, &json!({})).is_err());
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep");
    }
}
