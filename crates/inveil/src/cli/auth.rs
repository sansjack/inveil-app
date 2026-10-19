//! `inveil login | logout | whoami | enroll`: how this device proves itself to the backend.
use crate::backend::{self, BackendError, CredentialProvider, EnrollmentBundle};
use crate::brand;
use crate::config::{AuthMode, Config};
use crate::error::AppError;
use crate::platform;
use crate::runtime::Runtime;
use crate::util::{create_directory, write_atomically, PRIVATE_DIRECTORY_MODE};
use std::io::{BufRead, IsTerminal, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;

fn require_backend(config: &Config) -> Result<(), AppError> {
    if config.offline {
        return Err(AppError::Usage(
            "offline mode makes no network calls".into(),
        ));
    }
    if config.backend.url.is_none() {
        return Err(AppError::Usage(
            "no backend is configured (backend.url)".into(),
        ));
    }
    Ok(())
}

pub async fn login(config: &Config) -> Result<String, AppError> {
    require_backend(config)?;
    match config.auth.mode {
        AuthMode::DeviceFlow => Ok(backend::login(config).await?),
        AuthMode::StaticToken => {
            let token = read_token()?;
            backend::save_static_token(config, &token)?;
            Ok("Token saved to the OS keychain.".into())
        }
        AuthMode::Enrolled => Err(AppError::Usage(
            "this device authenticates with an enrolled credential; run `inveil enroll --bundle FILE`".into(),
        )),
        AuthMode::None => Err(AppError::Usage("auth.mode is \"none\", so there is nothing to sign in to".into())),
    }
}

fn read_token() -> Result<String, AppError> {
    let mut input = std::io::stdin().lock();
    if input.is_terminal() {
        eprint!("Token: ");
    }
    let mut line = String::new();
    input
        .read_line(&mut line)
        .map_err(|source| AppError::ReadFile {
            path: PathBuf::from("standard input"),
            source,
        })?;
    let token = line.trim();
    if token.is_empty() {
        return Err(AppError::Usage("no token was given".into()));
    }
    Ok(token.to_string())
}

pub fn logout(config: &Config) -> Result<String, AppError> {
    require_backend(config)?;
    let message = if backend::forget_all(config)? {
        "Signed out."
    } else {
        "Already signed out."
    };
    Ok(message.into())
}

pub async fn whoami(config: &Config) -> Result<String, AppError> {
    require_backend(config)?;
    match config.auth.mode {
        AuthMode::DeviceFlow => Ok(backend::whoami(config).await?),
        AuthMode::None => Ok("No authentication is configured (auth.mode = \"none\").".into()),
        AuthMode::StaticToken | AuthMode::Enrolled => {
            let credentials = Runtime::new(Arc::new(config.clone()))?.credentials()?;
            match credentials.credential().await {
                Ok(_) => Ok("A credential is stored for this backend.".into()),
                Err(BackendError::NotSignedIn) => Err(AppError::Usage(
                    "no credential is stored; run `inveil login`".into(),
                )),
                Err(error) => Err(error.into()),
            }
        }
    }
}

/// Redeems the bundle's token and records the backend, pinned keys and update feed in the user configuration. The
/// file is written only after the backend accepted the token, so a failed enrollment leaves the configuration alone.
pub async fn enroll(
    config: &Config,
    config_path: Option<PathBuf>,
    bundle_path: &Path,
) -> Result<String, AppError> {
    if config.offline {
        return Err(AppError::Usage(
            "offline mode makes no network calls".into(),
        ));
    }
    let text = read_bundle(bundle_path, std::io::stdin().lock())?;
    let bundle = EnrollmentBundle::parse(&text)?;
    let target = match config_path {
        Some(path) => path,
        None => platform::data_dir()?.join(brand::CONFIG_FILE_NAME),
    };

    let mut table = match std::fs::read_to_string(&target) {
        Ok(existing) => existing
            .parse::<toml::Table>()
            .map_err(crate::config::ConfigError::from)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => toml::Table::new(),
        Err(source) => {
            return Err(AppError::ReadFile {
                path: target,
                source,
            })
        }
    };
    record_bundle(&mut table, &bundle)?;
    let updated: Config = toml::Value::Table(table.clone())
        .try_into()
        .map_err(crate::config::ConfigError::from)?;
    updated.validate()?;

    if updated.auth.mode == AuthMode::Enrolled {
        backend::enroll(&updated, &bundle.enrollment_token).await?;
    }
    if let Some(parent) = target.parent() {
        create_directory(parent, PRIVATE_DIRECTORY_MODE).map_err(|source| AppError::WriteFile {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    let rendered = toml::to_string_pretty(&table).map_err(crate::config::ConfigError::from)?;
    write_atomically(&target, rendered.as_bytes()).map_err(|source| AppError::WriteFile {
        path: target.clone(),
        source,
    })?;
    Ok(format!(
        "Enrolled with {}. Configuration saved to {}. Run `inveil install` to start the background service.",
        bundle.backend_url,
        target.display()
    ))
}

/// `-` reads the bundle from `stdin`, so the install scripts never put the enrollment token in a file or argument.
fn read_bundle(path: &Path, mut stdin: impl Read) -> Result<String, AppError> {
    if path != Path::new("-") {
        return std::fs::read_to_string(path).map_err(|source| AppError::ReadFile {
            path: path.to_path_buf(),
            source,
        });
    }
    let mut text = String::new();
    stdin
        .read_to_string(&mut text)
        .map_err(|source| AppError::ReadFile {
            path: PathBuf::from("<stdin>"),
            source,
        })?;
    Ok(text)
}

fn record_bundle(table: &mut toml::Table, bundle: &EnrollmentBundle) -> Result<(), AppError> {
    let to_config_error = |error: toml::ser::Error| AppError::Config(error.into());
    let backend = table
        .entry("backend")
        .or_insert_with(|| toml::Value::Table(toml::Table::new()));
    if let toml::Value::Table(backend) = backend {
        backend.insert(
            "url".into(),
            toml::Value::String(bundle.backend_url.clone()),
        );
        backend.insert(
            "pinned_keys".into(),
            toml::Value::try_from(&bundle.pinned_keys).map_err(to_config_error)?,
        );
    }
    let auth = match &bundle.auth {
        Some(auth) => toml::Value::try_from(auth).map_err(to_config_error)?,
        None => toml::Value::try_from(crate::config::AuthConfig {
            mode: AuthMode::Enrolled,
            ..crate::config::AuthConfig::default()
        })
        .map_err(to_config_error)?,
    };
    table.insert("auth".into(), auth);
    bundle.record_update(table).map_err(to_config_error)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_dash_reads_the_bundle_from_stdin() {
        let bundle = r#"{"backend_url":"https://b.example"}"#;
        let text = read_bundle(Path::new("-"), bundle.as_bytes()).unwrap();
        assert_eq!(text, bundle);
    }

    #[test]
    fn a_path_reads_the_file_and_ignores_stdin() {
        let directory = std::env::temp_dir().join(format!("inveil-bundle-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let file = directory.join("enrollment.json");
        std::fs::write(&file, "from file").unwrap();
        let text = read_bundle(&file, "from stdin".as_bytes()).unwrap();
        std::fs::remove_dir_all(&directory).unwrap();
        assert_eq!(text, "from file");
    }
}
