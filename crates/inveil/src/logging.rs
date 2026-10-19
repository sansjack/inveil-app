//! Logging through `tracing`. Debug and trace lines carry metadata only (sizes, timings, hosts, rule ids): request
//! content never reaches a `tracing` call, and a test in `proxy` proves it by scanning the captured output.
use crate::brand;
use crate::config::LoggingConfig;
use crate::util::open_private_append;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::{Level, Metadata, Subscriber};
use tracing_subscriber::filter::dynamic_filter_fn;
use tracing_subscriber::fmt::writer::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, Layer};

const DEFAULT_LEVEL: Level = Level::INFO;

/// Set when the signed settings forbid debug output (`allow_debug = false`) although the person asked for it.
static DEBUG_FORBIDDEN: AtomicBool = AtomicBool::new(false);

#[derive(Debug, thiserror::Error)]
pub enum LoggingError {
    #[error("logging.level {0:?} is not one of error, warn, info, debug, trace")]
    BadLevel(String),
    #[error("cannot open log file {path}: {source}")]
    OpenFile {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("logging was already initialised")]
    AlreadyInitialised,
}

pub fn forbid_debug(forbidden: bool) {
    DEBUG_FORBIDDEN.store(forbidden, Ordering::Relaxed);
}

/// The most verbose level asked for by `logging.level`, `debug` or `trace`.
pub fn verbosity(config: &LoggingConfig) -> Result<Level, LoggingError> {
    let configured = match &config.level {
        Some(level) => Level::from_str(level).map_err(|_| LoggingError::BadLevel(level.clone()))?,
        None => DEFAULT_LEVEL,
    };
    let requested = if config.trace {
        Level::TRACE
    } else if config.debug {
        Level::DEBUG
    } else {
        configured
    };
    Ok(requested.max(configured))
}

fn enabled(metadata: &Metadata<'_>, verbosity: Level) -> bool {
    let level = *metadata.level();
    if level > verbosity {
        return false;
    }
    if !metadata.target().starts_with(brand::PRODUCT) {
        return level <= Level::WARN;
    }
    level <= Level::INFO || !DEBUG_FORBIDDEN.load(Ordering::Relaxed)
}

pub fn layer<S, W>(verbosity: Level, writer: W) -> impl Layer<S>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    W: for<'a> MakeWriter<'a> + 'static,
{
    fmt::layer()
        .with_writer(writer)
        .with_ansi(false)
        .with_filter(dynamic_filter_fn(move |metadata, _context| {
            enabled(metadata, verbosity)
        }))
}

/// Console plus the log file, when there is one. `fallback_file` is used when the configuration names none, for a
/// process that has no console to print to.
pub fn init(config: &LoggingConfig, fallback_file: Option<&Path>) -> Result<(), LoggingError> {
    let verbosity = verbosity(config)?;
    let file_layer = match config.file.as_deref().or(fallback_file) {
        Some(path) => {
            let file = open_private_append(path).map_err(|source| LoggingError::OpenFile {
                path: path.to_path_buf(),
                source,
            })?;
            Some(layer(verbosity, Arc::new(file)))
        }
        None => None,
    };
    tracing_subscriber::registry()
        .with(layer(verbosity, std::io::stderr))
        .with(file_layer)
        .try_init()
        .map_err(|_| LoggingError::AlreadyInitialised)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_and_trace_raise_the_level_and_a_bad_level_is_an_error() {
        let mut config = LoggingConfig::default();
        assert_eq!(verbosity(&config).unwrap(), Level::INFO);
        config.debug = true;
        assert_eq!(verbosity(&config).unwrap(), Level::DEBUG);
        config.trace = true;
        assert_eq!(verbosity(&config).unwrap(), Level::TRACE);
        config.level = Some("loud".into());
        assert!(matches!(verbosity(&config), Err(LoggingError::BadLevel(_))));
    }
}
