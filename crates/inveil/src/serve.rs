//! `inveil run`: wires the policy, the usage reporter and both proxies together and runs until told to stop.
use crate::backend::{
    spawn_uploader, FilePolicySource, FileUsageSink, HttpUsageSink, PolicyUpdater, UsageReporter,
};
use crate::config::{Config, UpdateMode, UsageSink};
use crate::error::AppError;
use crate::logging;
use crate::platform;
use crate::policy::{ActivePolicy, PolicyOrigin};
use crate::proxy::audit::AuditLog;
use crate::proxy::{api, browser, AppState, ProxyError};
use crate::runtime::Runtime;
use crate::update::{self, ScheduledUpdate};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::net::TcpListener;
use tokio::sync::watch;

const USAGE_FLUSH_INTERVAL: Duration = Duration::from_secs(5);
const UPDATE_TICK: Duration = Duration::from_secs(3600);

pub async fn run(config: Config) -> Result<(), AppError> {
    match update::remove_replaced_executable() {
        Ok(true) => tracing::debug!("removed the executable replaced by the last update"),
        Ok(false) => {}
        Err(error) => tracing::warn!("cannot remove the replaced executable: {error}"),
    }
    if let Err(error) = platform::write_pid_file() {
        tracing::warn!("cannot record the process id: {error}");
    }
    let runtime = Runtime::new(Arc::new(config))?;
    let config = runtime.config.clone();

    let initial = runtime.initial_policy()?;
    logging::forbid_debug(initial.debug_forbidden);
    let offline = initial.effective.offline;
    describe_start(&config, &initial);
    let (active_sender, active) = watch::channel(Arc::new(initial));
    let active_sender = Arc::new(active_sender);

    let backend_in_use = !offline && config.backend.url.is_some();
    let credentials = match backend_in_use {
        true => Some(runtime.credentials()?),
        false => None,
    };

    if let Some(path) = &config.rules_file {
        PolicyUpdater::new(
            FilePolicySource::new(path.clone()),
            runtime.store.clone(),
            runtime.policy_builder(),
            active_sender.clone(),
            PolicyOrigin::LocalFile,
        )
        .spawn();
    } else if let Some(credentials) = credentials.clone() {
        runtime
            .refresh_from_backend(&active_sender, credentials)
            .await?
            .spawn();
    }

    if !offline {
        spawn_update_checks(config.clone(), active.clone());
    }
    let usage = start_usage(&config, offline, credentials, &active)?;
    let audit = AuditLog::open(config.logging.audit_file.as_deref()).map_err(|source| {
        AppError::WriteFile {
            path: config.logging.audit_file.clone().unwrap_or_default(),
            source,
        }
    })?;
    let state = Arc::new(AppState::new(
        config.clone(),
        active,
        Arc::new(usage),
        audit,
    )?);

    let address = crate::util::loopback(config.listen.port);
    let listener = TcpListener::bind(address)
        .await
        .map_err(|source| ProxyError::Bind { address, source })?;
    browser::start(state.clone(), &runtime.ca_directory()).await?;
    update::confirm_started();

    // Not a graceful shutdown: a long streaming response must not keep the process waiting.
    tokio::select! {
        result = api::serve(listener, state) => Ok(result?),
        signal = shutdown_signal() => signal.map_err(AppError::Signal),
    }
}

/// Checks the update feed every `update.check_hours`. What happens next (report, download, install) follows
/// `update.mode`; this only keeps the clock. Mode and interval are re-read from the live policy on every tick, so an
/// administrator's signed choice applies without touching the local file or restarting.
fn spawn_update_checks(config: Arc<Config>, active: watch::Receiver<Arc<ActivePolicy>>) {
    if config.update.feed_url.is_none() {
        return;
    }
    tokio::spawn(async move {
        let mut last_checked: Option<SystemTime> = None;
        loop {
            let settings = config.update.with_policy(&active.borrow().update);
            if settings.mode != UpdateMode::Off
                && update::check_due(last_checked, settings.check_hours)
            {
                last_checked = Some(SystemTime::now());
                let checked = Config {
                    update: settings,
                    ..(*config).clone()
                };
                match tokio::task::spawn_blocking(move || update::run_scheduled_update(&checked))
                    .await
                {
                    Ok(Ok(ScheduledUpdate::Nothing(summary))) => tracing::info!("{summary}"),
                    Ok(Ok(ScheduledUpdate::RestartRequired(summary))) => {
                        tracing::info!("{summary}");
                        std::process::exit(i32::from(update::EXIT_RESTART_FOR_UPDATE));
                    }
                    Ok(Err(error)) => tracing::warn!("update check failed: {error}"),
                    Err(error) => tracing::error!("update check task failed: {error}"),
                }
            }
            tokio::time::sleep(UPDATE_TICK).await;
        }
    });
}

fn describe_start(config: &Config, policy: &ActivePolicy) {
    if policy.origin == PolicyOrigin::Builtin && config.backend.url.is_none() {
        tracing::info!("no backend configured: using the built-in rules");
    }
    if policy.effective.offline {
        tracing::info!("offline: no network calls will be made");
    }
    for key in config.ignored_overrides() {
        tracing::warn!(
            "{key} is set locally but ignored: this device is enrolled, so your organisation's settings apply"
        );
    }
    if policy.effective.dry_run {
        tracing::info!("dry run: findings are logged, nothing is blocked");
    }
    let modes = policy.effective.failure_modes;
    tracing::info!(
        "failure modes: unscannable {:?}, scan_error {:?}, policy_expired {:?}, service_down {:?}",
        modes.unscannable,
        modes.scan_error,
        modes.policy_expired,
        modes.service_down
    );
    tracing::info!(
        "policy version {} from {:?}; API proxy on 127.0.0.1:{}, upstream {}",
        policy.version,
        policy.origin,
        config.listen.port,
        policy.effective.upstream
    );
}

/// A managed or enrolled client sends usage to the backend whatever the local sink says, because the administrator's
/// signed `usage_reporting` setting decides whether and how often; the live policy is consulted on every flush.
fn start_usage(
    config: &Config,
    offline: bool,
    credentials: Option<Arc<crate::backend::Credentials>>,
    active: &watch::Receiver<Arc<ActivePolicy>>,
) -> Result<UsageReporter, AppError> {
    if offline {
        return Ok(UsageReporter::disabled());
    }
    if config.usage.sink == UsageSink::Http || config.owned_by_backend() {
        let Some(credentials) = credentials else {
            return Ok(UsageReporter::disabled());
        };
        let sink = HttpUsageSink::new(config, credentials)?;
        return Ok(spawn_uploader(sink, active.clone(), USAGE_FLUSH_INTERVAL));
    }
    match (&config.usage.sink, &config.usage.file) {
        (UsageSink::File, Some(path)) => Ok(spawn_uploader(
            FileUsageSink::new(path.clone()),
            active.clone(),
            USAGE_FLUSH_INTERVAL,
        )),
        _ => Ok(UsageReporter::disabled()),
    }
}

async fn shutdown_signal() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut terminate = signal(SignalKind::terminate())?;
        // Closing the terminal window sends SIGHUP, so stop cleanly then too.
        let mut hangup = signal(SignalKind::hangup())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result,
            _ = terminate.recv() => Ok(()),
            _ = hangup.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await
}
