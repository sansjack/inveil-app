//! `inveil refetch`: restarts the background service so it fetches the organisation's rules again. The service
//! fetches them at startup, so a restart is a refetch.
use crate::config::Config;
use crate::error::AppError;
use crate::platform;
use crate::update::health::{HealthCheck, ServiceHealth, HEALTH_TIMEOUT};

pub async fn refetch(config: &Config) -> Result<String, AppError> {
    if config.backend.url.is_none() {
        return Err(AppError::Usage(
            "this device has no backend to fetch rules from".into(),
        ));
    }
    if !platform::service_installed()? {
        return Err(AppError::Usage(
            "inveil is not running as a background service; run `inveil install` first".into(),
        ));
    }
    let health = ServiceHealth {
        service_managed: true,
        port: config.listen.port,
        timeout: HEALTH_TIMEOUT,
    };
    // Both steps block (service manager, then polling `/health`).
    let report = tokio::task::spawn_blocking(move || {
        health.restart()?;
        health.wait_for_report()
    })
    .await
    .map_err(|error| AppError::Runtime(std::io::Error::other(error)))??;
    Ok(format!(
        "Service restarted; running policy version {}",
        report.policy_version
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn refuses_when_the_device_has_no_backend() {
        let error = refetch(&Config::default()).await.unwrap_err();
        assert!(
            matches!(&error, AppError::Usage(message) if message.contains("no backend")),
            "{error}"
        );
    }
}
