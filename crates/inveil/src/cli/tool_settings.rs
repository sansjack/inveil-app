//! Where each local tool reads its base URL from, so the installer can write the proxy address there.
//!
//! Only files whose location and format are documented by the tool are written. Gemini CLI loads variables from
//! `~/.gemini/.env` (<https://geminicli.com/docs/reference/configuration>). Codex reads `openai_base_url` from a TOML
//! file whose comments would not survive a rewrite, so it is left to the person and reported by `inveil doctor`.
use super::claude_settings;
use crate::error::AppError;
use crate::util::{create_directory, write_atomically, PRIVATE_DIRECTORY_MODE};
use std::path::{Path, PathBuf};

const CLAUDE_CODE_TOOL_ID: &str = "claude-code";
const GEMINI_CLI_TOOL_ID: &str = "gemini-cli";
const GEMINI_DIR: &str = ".gemini";
const DOTENV_FILE: &str = ".env";
const LOOPBACK_PREFIX: &str = "http://127.0.0.1:";
const EXPORT_PREFIX: &str = "export ";
/// The variables inveil may write, whatever a catalog says: the base-URL variables of the tools it wires.
const KNOWN_BASE_URL_VARIABLES: [&str; 3] = [
    "ANTHROPIC_BASE_URL",
    "OPENAI_BASE_URL",
    "GOOGLE_GEMINI_BASE_URL",
];
/// Catalog tools whose base-URL variable may be a name the catalog chose, when it has the strict shape of one.
const KNOWN_TOOL_IDS: [&str; 3] = [CLAUDE_CODE_TOOL_ID, "codex-api", GEMINI_CLI_TOOL_ID];
const BASE_URL_SUFFIX: &str = "_BASE_URL";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettingsFile {
    ClaudeUser,
    GeminiDotenv,
}

impl SettingsFile {
    pub fn for_tool(tool_id: &str) -> Option<Self> {
        match tool_id {
            CLAUDE_CODE_TOOL_ID => Some(Self::ClaudeUser),
            GEMINI_CLI_TOOL_ID => Some(Self::GeminiDotenv),
            _ => None,
        }
    }

    fn tool_id(self) -> &'static str {
        match self {
            Self::ClaudeUser => CLAUDE_CODE_TOOL_ID,
            Self::GeminiDotenv => GEMINI_CLI_TOOL_ID,
        }
    }

    pub fn set(self, variable: &str, url: &str) -> Result<(), AppError> {
        check_entry(self.tool_id(), variable, url)?;
        match self {
            Self::ClaudeUser => claude_settings::set(&[(variable.to_string(), url.to_string())]),
            Self::GeminiDotenv => set_dotenv(&dotenv_path()?, variable, url),
        }
    }

    pub fn remove(self, variable: &str) -> Result<(), AppError> {
        match self {
            Self::ClaudeUser => claude_settings::remove(&[variable.to_string()]),
            Self::GeminiDotenv => remove_dotenv(&dotenv_path()?, variable),
        }
    }

    pub fn read(self, variable: &str) -> Result<Option<String>, AppError> {
        match self {
            Self::ClaudeUser => claude_settings::read_variable(variable),
            Self::GeminiDotenv => read_dotenv(&dotenv_path()?, variable),
        }
    }
}

fn dotenv_path() -> Result<PathBuf, AppError> {
    Ok(claude_settings::home_directory()?
        .join(GEMINI_DIR)
        .join(DOTENV_FILE))
}

/// True for `A-Z`, `0-9` and `_` names that start with a letter and end in `_BASE_URL` after a non-empty prefix.
fn has_base_url_shape(variable: &str) -> bool {
    let Some(prefix) = variable.strip_suffix(BASE_URL_SUFFIX) else {
        return false;
    };
    prefix.starts_with(|character: char| character.is_ascii_uppercase())
        && !prefix.contains("__")
        && !prefix.ends_with('_')
        && prefix.chars().all(|character| {
            character.is_ascii_uppercase() || character.is_ascii_digit() || character == '_'
        })
}

/// A variable name and a URL that are safe to put on one line of a settings file. The name must be one of the known
/// base-URL variables, or, for a known tool only, a catalog-chosen name of the strict `NAME_BASE_URL` shape: the
/// catalog is signed but its names still end up in files other programs read, so nothing else is accepted. The value
/// must be a loopback URL whose path has no whitespace, quotes or control characters.
pub fn check_entry(tool_id: &str, variable: &str, url: &str) -> Result<(), AppError> {
    let known = KNOWN_BASE_URL_VARIABLES.contains(&variable)
        || (KNOWN_TOOL_IDS.contains(&tool_id) && has_base_url_shape(variable));
    if !known {
        return Err(AppError::Usage(format!(
            "refusing to write the variable {variable:?} for {tool_id}: only ANTHROPIC_BASE_URL, OPENAI_BASE_URL and GOOGLE_GEMINI_BASE_URL, or a NAME_BASE_URL variable of a known tool, are set"
        )));
    }
    let plain_url = url.starts_with(LOOPBACK_PREFIX)
        && url
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || ":/._-".contains(character));
    if !plain_url {
        return Err(AppError::Usage(format!(
            "refusing to write {variable}: the proxy address {url:?} has unexpected characters"
        )));
    }
    Ok(())
}

fn read_lines(path: &Path) -> Result<Vec<String>, AppError> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(text.lines().map(String::from).collect()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(source) => Err(AppError::ReadFile {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn write_lines(path: &Path, lines: &[String]) -> Result<(), AppError> {
    let failed = |source| AppError::WriteFile {
        path: path.to_path_buf(),
        source,
    };
    if let Some(parent) = path.parent() {
        create_directory(parent, PRIVATE_DIRECTORY_MODE).map_err(failed)?;
    }
    write_atomically(path, format!("{}\n", lines.join("\n")).as_bytes()).map_err(failed)
}

/// The value assigned on `line` when it assigns `variable`, without quotes.
fn assigned_value<'a>(line: &'a str, variable: &str) -> Option<&'a str> {
    let line = line.trim();
    let line = line
        .strip_prefix(EXPORT_PREFIX)
        .unwrap_or(line)
        .trim_start();
    let (name, value) = line.split_once('=')?;
    if name.trim() != variable {
        return None;
    }
    Some(value.trim().trim_matches(['"', '\'']))
}

fn set_dotenv(path: &Path, variable: &str, url: &str) -> Result<(), AppError> {
    let mut lines = read_lines(path)?;
    let line = format!("{variable}={url}");
    match lines
        .iter()
        .position(|existing| assigned_value(existing, variable).is_some())
    {
        Some(index) => lines[index] = line,
        None => lines.push(line),
    }
    write_lines(path, &lines)
}

/// Removes the assignment only when it still points at the loopback proxy; a value the person set is theirs.
fn remove_dotenv(path: &Path, variable: &str) -> Result<(), AppError> {
    let lines = read_lines(path)?;
    let kept: Vec<String> = lines
        .iter()
        .filter(|line| {
            !assigned_value(line, variable).is_some_and(|value| value.starts_with(LOOPBACK_PREFIX))
        })
        .cloned()
        .collect();
    if kept.len() == lines.len() {
        return Ok(());
    }
    write_lines(path, &kept)
}

fn read_dotenv(path: &Path, variable: &str) -> Result<Option<String>, AppError> {
    Ok(read_lines(path)?
        .iter()
        .find_map(|line| assigned_value(line, variable))
        .map(String::from))
}

#[cfg(test)]
mod tests {
    use super::*;

    const URL: &str = "http://127.0.0.1:8787/google";

    #[test]
    fn tools_with_a_documented_settings_file_are_known_and_others_are_not() {
        assert_eq!(
            SettingsFile::for_tool("claude-code"),
            Some(SettingsFile::ClaudeUser)
        );
        assert_eq!(
            SettingsFile::for_tool("gemini-cli"),
            Some(SettingsFile::GeminiDotenv)
        );
        assert_eq!(SettingsFile::for_tool("codex-api"), None);
    }

    #[test]
    fn setting_replaces_our_line_and_keeps_every_other_line() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(".gemini/.env");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            "# mine\nGEMINI_API_KEY=abc\nexport GOOGLE_GEMINI_BASE_URL=\"https://old.example\"\n",
        )
        .unwrap();

        set_dotenv(&path, "GOOGLE_GEMINI_BASE_URL", URL).unwrap();

        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            format!("# mine\nGEMINI_API_KEY=abc\nGOOGLE_GEMINI_BASE_URL={URL}\n")
        );
        assert_eq!(
            read_dotenv(&path, "GOOGLE_GEMINI_BASE_URL")
                .unwrap()
                .as_deref(),
            Some(URL)
        );
    }

    #[test]
    fn removing_deletes_only_a_line_that_points_at_the_proxy() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(".env");
        std::fs::write(&path, format!("A={URL}\nB=https://mine.example\n")).unwrap();

        remove_dotenv(&path, "A").unwrap();
        remove_dotenv(&path, "B").unwrap();

        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "B=https://mine.example\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_dotenv_file_is_owner_only_and_never_written_through_a_symlink() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(".gemini").join(".env");

        set_dotenv(&path, "GOOGLE_GEMINI_BASE_URL", URL).unwrap();

        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);

        let victim = directory.path().join("victim");
        std::fs::write(&victim, "keep").unwrap();
        let link = directory.path().join("linked.env");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        assert!(set_dotenv(&link, "GOOGLE_GEMINI_BASE_URL", URL).is_err());
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep");
    }

    #[test]
    fn a_missing_file_reads_as_unset_and_is_not_created_by_removal() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(".env");
        assert_eq!(read_dotenv(&path, "A").unwrap(), None);
        remove_dotenv(&path, "A").unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn only_known_base_url_variables_and_strictly_shaped_names_of_known_tools_are_written() {
        for variable in [
            "NODE_OPTIONS",
            "LD_PRELOAD",
            "DYLD_INSERT_LIBRARIES",
            "PATH",
            "HOME",
            "PYTHONSTARTUP",
            "RUBYOPT",
            "OPENAI_API_KEY",
            "SOME_API_BASE",
            "SOME_ENDPOINT",
            "SOME_URL",
            "HTTPS_PROXY",
            "BASH_ENV",
            "_BASE_URL",
            "A__BASE_URL",
            "lower_BASE_URL",
            "1ABC_BASE_URL",
            "ABC_BASE_URL;touch",
            "ABC_BASE_URL_EXTRA",
            "EVIL_PATH_BASE_URL ",
        ] {
            assert!(
                check_entry("claude-code", variable, URL).is_err(),
                "{variable}"
            );
        }
        for variable in [
            "ANTHROPIC_BASE_URL",
            "OPENAI_BASE_URL",
            "GOOGLE_GEMINI_BASE_URL",
        ] {
            for tool_id in ["claude-code", "codex-api", "gemini-cli", "anything-else"] {
                assert!(check_entry(tool_id, variable, URL).is_ok(), "{variable}");
            }
        }
    }

    #[test]
    fn a_catalog_chosen_name_is_accepted_for_known_tools_only() {
        assert!(check_entry("claude-code", "CLAUDE_PROXY_BASE_URL", URL).is_ok());
        assert!(check_entry("gemini-cli", "GEMINI_V2_BASE_URL", URL).is_ok());
        assert!(check_entry("xai-api", "XAI_BASE_URL", URL).is_err());
        assert!(check_entry("made-up-tool", "ANYTHING_BASE_URL", URL).is_err());
    }

    #[test]
    fn values_that_could_add_a_second_line_or_variable_are_refused() {
        for url in [
            "http://127.0.0.1:8787/x\nEVIL=1",
            "http://127.0.0.1:8787/x EVIL=1",
            "http://127.0.0.1:8787/\"x",
            "http://127.0.0.1:8787/$(id)",
            "https://example.com",
        ] {
            assert!(
                check_entry("gemini-cli", "GOOGLE_GEMINI_BASE_URL", url).is_err(),
                "{url:?}"
            );
        }
        for variable in ["A=B", "a b", "A\nB", "", "lower"] {
            assert!(
                check_entry("gemini-cli", variable, URL).is_err(),
                "{variable:?}"
            );
        }
        assert!(check_entry("gemini-cli", "GOOGLE_GEMINI_BASE_URL", URL).is_ok());
    }
}
