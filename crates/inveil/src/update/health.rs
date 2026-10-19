//! Checks a new binary before it is installed (it must run and report the signed version) and, when the updater is
//! a separate process from the service, confirms afterwards that the restarted service really is the new version.
use crate::platform::{self, PlatformError};
use semver::Version;
use serde::Deserialize;
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

const POLL_INTERVAL: Duration = Duration::from_millis(500);
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
pub const HEALTH_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, thiserror::Error)]
pub enum HealthError {
    #[error("cannot restart the service: {0}")]
    Restart(#[from] PlatformError),
    #[error("the new version did not answer on its port within {0:?}")]
    NotListening(Duration),
    #[error("the running proxy reports version {reported}, expected {expected}")]
    WrongVersion { expected: Version, reported: String },
    #[error("the downloaded binary cannot run: {0}")]
    CannotRun(String),
}

pub trait HealthCheck {
    /// Runs the staged binary far enough to see that it starts and says which version it is.
    fn smoke_test(&self, binary: &Path, expected: &Version) -> Result<(), HealthError>;
    fn restart(&self) -> Result<(), HealthError>;
    fn confirm(&self, expected: &Version) -> Result<(), HealthError>;
}

#[derive(Deserialize)]
pub struct HealthReport {
    pub version: String,
    /// Absent when the running proxy predates this field.
    #[serde(default)]
    pub policy_version: u64,
}

/// Restarts through the platform service manager and asks the local proxy which version it is.
pub struct ServiceHealth {
    pub service_managed: bool,
    pub port: u16,
    pub timeout: Duration,
}

impl ServiceHealth {
    fn probe(&self) -> Option<HealthReport> {
        let client = reqwest::blocking::Client::builder()
            .timeout(PROBE_TIMEOUT)
            .build()
            .ok()?;
        let url = format!("http://127.0.0.1:{}/health", self.port);
        client.get(url).send().ok()?.json().ok()
    }

    /// Waits until the local proxy answers `/health` and returns what it said.
    pub fn wait_for_report(&self) -> Result<HealthReport, HealthError> {
        let deadline = Instant::now() + self.timeout;
        loop {
            if let Some(report) = self.probe() {
                return Ok(report);
            }
            if Instant::now() >= deadline {
                return Err(HealthError::NotListening(self.timeout));
            }
            thread::sleep(POLL_INTERVAL);
        }
    }
}

impl HealthCheck for ServiceHealth {
    fn smoke_test(&self, binary: &Path, expected: &Version) -> Result<(), HealthError> {
        let output = Command::new(binary)
            .arg("--version")
            .output()
            .map_err(|error| HealthError::CannotRun(error.to_string()))?;
        if !output.status.success() {
            return Err(HealthError::CannotRun(format!(
                "`--version` exited with {}",
                output.status
            )));
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let reported = stdout.split_whitespace().last().unwrap_or_default();
        if reported != expected.to_string() {
            return Err(HealthError::WrongVersion {
                expected: expected.clone(),
                reported: reported.to_string(),
            });
        }
        Ok(())
    }

    fn restart(&self) -> Result<(), HealthError> {
        if !self.service_managed {
            return Ok(());
        }
        platform::restart_service()?;
        Ok(())
    }

    fn confirm(&self, expected: &Version) -> Result<(), HealthError> {
        if !self.service_managed {
            return Ok(());
        }
        let reported = self.wait_for_report()?.version;
        if reported == expected.to_string() {
            return Ok(());
        }
        Err(HealthError::WrongVersion {
            expected: expected.clone(),
            reported,
        })
    }
}
