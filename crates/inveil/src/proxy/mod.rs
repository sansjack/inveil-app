//! The two proxies: the localhost API proxy (`api`) for tools pointed at it, and the browser proxy (`browser`) that
//! decrypts a short list of AI chat sites. Both screen requests with the same pipeline (`screen`).
pub mod api;
pub mod audit;
pub mod browser;
pub mod browser_ca;
mod guard;
pub use guard::GuardError;
mod notify;
mod screen;
mod signals;
mod usage_tap;

#[cfg(test)]
mod provider_tests;
#[cfg(test)]
mod test_support;

use crate::backend::UsageReporter;
use crate::config::Config;
use crate::policy::ActivePolicy;
use audit::{AuditAction, AuditLog};
use notify::{Kind, Notifier};
use screen::{Outcome, Screened};
use signals::{SignalError, Signals};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::watch;

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("cannot listen on {address}: {source}")]
    Bind {
        address: SocketAddr,
        source: std::io::Error,
    },
    #[error("the API proxy stopped: {0}")]
    Serve(std::io::Error),
    #[error("cannot build the HTTP client: {0}")]
    Client(reqwest::Error),
    #[error("cannot start the browser proxy: {0}")]
    Browser(String),
    #[error(transparent)]
    Signals(#[from] SignalError),
}

/// Everything a request needs, shared by both proxies.
pub struct AppState {
    pub config: Arc<Config>,
    active: watch::Receiver<Arc<ActivePolicy>>,
    pub http: reqwest::Client,
    pub usage: Arc<UsageReporter>,
    signals: Signals,
    audit: AuditLog,
    notifier: Notifier,
}

impl AppState {
    pub fn new(
        config: Arc<Config>,
        active: watch::Receiver<Arc<ActivePolicy>>,
        usage: Arc<UsageReporter>,
        audit: AuditLog,
    ) -> Result<Self, ProxyError> {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(ProxyError::Client)?;
        let notifier = Notifier::new(config.notify);
        let signals = Signals::builtin()?;
        Ok(Self {
            config,
            active,
            http,
            usage,
            signals,
            audit,
            notifier,
        })
    }

    /// The policy to use for one request: taken once, so a request is judged by one consistent snapshot.
    pub fn policy(&self) -> Arc<ActivePolicy> {
        self.active.borrow().clone()
    }

    /// Records what was decided: the audit lines, including one per pass-through caused by an `open` failure mode, and a notice for the person when something was changed or blocked.
    fn conclude(&self, screened: &Screened, destination: &str, label: &str) {
        let noteworthy =
            screened.audit_action != AuditAction::Allow || !screened.report.findings.is_empty();
        if noteworthy {
            self.audit.record(
                screened.audit_action,
                destination,
                screened.tokens,
                &screened.report.findings,
            );
        } else {
            tracing::debug!(tokens = screened.tokens, "clean request");
        }
        for condition in &screened.fail_open {
            self.audit
                .record_fail_open(*condition, destination, screened.tokens);
            self.usage.count_fail_open();
        }
        match screened.outcome {
            Outcome::Rewrite(_) => {
                self.notifier
                    .notify(Kind::Redacted, label, &screened.report.findings)
            }
            Outcome::Block { .. } => {
                self.notifier
                    .notify(Kind::Blocked, label, &screened.report.findings)
            }
            Outcome::Allow => {}
        }
    }
}

pub const POLICY_EXPIRED_REASON: &str = "the policy has expired and could not be refreshed";
