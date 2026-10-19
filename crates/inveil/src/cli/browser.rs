//! `inveil browser-setup | browser-remove`: lets the browser proxy read AI chat sites.
//!
//! Setup creates a CA on this device whose certificate is constrained to the signed domain list, trusts it for the
//! current user only, and points the system's proxy auto-config at this client. Removal undoes every step.
use crate::config::Config;
use crate::error::AppError;
use crate::platform;
use crate::proxy::browser_ca::{self, CaStatus};
use crate::runtime::Runtime;
use contract::FailMode;
use std::sync::Arc;

pub async fn setup(config: Config) -> Result<String, AppError> {
    let runtime = Runtime::new(Arc::new(config))?;
    let policy = runtime.latest_policy().await?;
    let domains = policy.policy.ca_domains.clone();
    if domains.is_empty() {
        return Err(AppError::Usage(
            "the policy lists no domains for the browser CA".into(),
        ));
    }
    let ca_directory = runtime.ca_directory();
    let certificate = browser_ca::certificate_path(&ca_directory);
    let mut notes = vec![];

    match browser_ca::status(&ca_directory, &domains) {
        CaStatus::Current => {}
        status @ (CaStatus::Outdated | CaStatus::Expiring) => {
            notes.push(
                match status {
                    CaStatus::Outdated => "Renewed the browser CA: the signed domain list changed.",
                    _ => "Renewed the browser CA: the old one was close to expiring.",
                }
                .to_string(),
            );
            platform::untrust_ca(&certificate)?;
            browser_ca::create(&ca_directory, &domains)?;
        }
        CaStatus::Missing => {
            browser_ca::create(&ca_directory, &domains)?;
        }
    }
    notes.push(format!("Browser CA covers only: {}.", domains.join(", ")));

    platform::trust_ca(&certificate)?;
    if let Err(error) =
        platform::write_ca_bundle(&certificate, &platform::bundle_path(&ca_directory))
    {
        notes.push(format!(
            "Could not build the CA bundle that Python, Go, Rust, curl and git tools need: {error}"
        ));
    }
    platform::set_pac(&browser_ca::pac_url(runtime.config.listen.port))?;

    if !platform::restart_service()? {
        notes.push(
            "The client is not installed as a service, so restart it yourself to load the new CA."
                .into(),
        );
    }
    notes.push(
        match policy.effective.failure_modes.service_down {
            FailMode::Open => "If inveil stops, browsers fall back to a direct connection (failure mode service_down = open).",
            FailMode::Closed => "If inveil stops, the chat sites stop loading (failure mode service_down = closed).",
        }
        .into(),
    );
    notes.push(
        "Browser protection is on for chat sites in the rules. Restart your browser. Firefox is not covered yet.\n\
         Undo with `inveil browser-remove`."
            .into(),
    );
    Ok(notes.join("\n"))
}

pub fn remove(config: Config) -> Result<String, AppError> {
    let runtime = Runtime::new(Arc::new(config))?;
    let ca_directory = runtime.ca_directory();
    let mut notes = vec![];

    if let Err(error) = platform::clear_pac(&browser_ca::pac_url(runtime.config.listen.port)) {
        notes.push(format!("Could not clear the proxy setting: {error}"));
    }
    let certificate = browser_ca::certificate_path(&ca_directory);
    if certificate.exists() {
        if let Err(error) = platform::untrust_ca(&certificate) {
            notes.push(format!(
                "Could not remove the CA from the trust store: {error}"
            ));
        }
    }
    browser_ca::remove(&ca_directory)?;
    // The service only matters if it is installed.
    if let Err(error) = platform::restart_service() {
        notes.push(format!("Could not restart the service: {error}"));
    }
    notes
        .push("Browser protection removed: the CA, its key and the proxy setting are gone.".into());
    Ok(notes.join("\n"))
}
