//! `inveil doctor [--json]`: for every enabled tool in the signed catalog, says whether its traffic is covered.
//!
//! - Covered: every check passed.
//! - Needs setup: a step the person can take (a command, a variable) makes it covered.
//! - Not covered: nothing inveil can do for this tool as configured, or the proxy it depends on is not running.
//!
//! Exits non-zero when any enabled tool is Not covered. Nothing is changed and no secret is read or printed: the
//! report holds booleans, loopback addresses and the names of settings, never their foreign values.
use super::claude_settings;
use super::install::{is_listening, is_running};
use super::tool_settings::SettingsFile;
use super::ui;
use crate::config::Config;
use crate::error::AppError;
use crate::platform::{self, RuntimeKind};
use crate::policy::{ActivePolicy, PolicyOrigin};
use crate::proxy::browser_ca;
use crate::runtime::Runtime;
use crate::util::unix_seconds;
use contract::{Tool, Via};
use serde::Serialize;
use std::collections::HashMap;
use std::process::ExitCode;
use std::sync::Arc;

const SECONDS_PER_DAY: u64 = 86_400;
const PLAIN_HTTP_RUNTIME: &str = "none (plain HTTP to the local proxy)";
const FIREFOX_ADVICE: &str = "keeps its own certificate store and inveil cannot check it. On Linux `inveil browser-setup` imports the CA into existing profiles; elsewhere set security.enterprise_roots.enabled to true in about:config.";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
enum Status {
    Covered,
    NeedsSetup,
    NotCovered,
}

impl Status {
    fn label(self) -> &'static str {
        match self {
            Self::Covered => "Covered",
            Self::NeedsSetup => "Needs setup",
            Self::NotCovered => "Not covered",
        }
    }
}

#[derive(Serialize)]
struct ToolReport {
    id: String,
    name: String,
    route: &'static str,
    runtime: &'static str,
    status: Status,
    reasons: Vec<String>,
}

#[derive(Serialize)]
struct SnapshotReport {
    version: u64,
    origin: &'static str,
    expires_at: Option<u64>,
    expired: bool,
}

#[derive(Serialize)]
struct Report {
    snapshot: SnapshotReport,
    proxy_running: bool,
    browser_proxy_running: bool,
    /// Conditions that weaken protection for every tool, and make each one Needs setup.
    warnings: Vec<String>,
    tools: Vec<ToolReport>,
    notes: Vec<String>,
}

/// What the machine looks like, gathered once so the verdicts are a pure function of it.
struct Facts {
    api_port: u16,
    browser_port: u16,
    api_listening: bool,
    browser_listening: bool,
    ca_present: bool,
    /// Domains the CA on disk was created for and the signed list still names.
    ca_usable_domains: Vec<String>,
    ca_trusted: Result<bool, String>,
    pac_applied: Result<bool, String>,
    https_proxy_is_ours: bool,
    /// Per local tool id: the value its base URL variable has where the tool reads it.
    base_urls: HashMap<String, Result<Option<String>, String>>,
}

fn gather(config: &Config, policy: &ActivePolicy, ca_directory: &std::path::Path) -> Facts {
    let api_port = config.listen.port;
    let browser_port = config.listen.browser_port;
    let ca_present = browser_ca::certificate_path(ca_directory).exists();
    let base_urls = policy
        .policy
        .local_tool_wiring()
        .iter()
        .map(|tool| {
            let value = match SettingsFile::for_tool(tool.tool_id) {
                Some(file) => file.read(tool.env_var).map_err(|error| error.to_string()),
                None => Ok(std::env::var(tool.env_var).ok()),
            };
            (tool.tool_id.to_string(), value)
        })
        .collect();
    let report =
        |result: Result<bool, platform::PlatformError>| result.map_err(|error| error.to_string());
    Facts {
        api_port,
        browser_port,
        api_listening: is_running(api_port),
        browser_listening: is_listening(browser_port),
        ca_present,
        ca_usable_domains: policy.policy.usable_domains.clone(),
        ca_trusted: if ca_present {
            report(platform::ca_trusted())
        } else {
            Ok(false)
        },
        pac_applied: report(platform::pac_applied(&browser_ca::pac_url(api_port))),
        https_proxy_is_ours: std::env::var("HTTPS_PROXY")
            .is_ok_and(|value| value == format!("http://127.0.0.1:{browser_port}")),
        base_urls,
    }
}

struct Verdict {
    status: Status,
    reasons: Vec<String>,
}

impl Verdict {
    fn new() -> Self {
        Self {
            status: Status::Covered,
            reasons: Vec::new(),
        }
    }

    fn problem(&mut self, status: Status, reason: String) {
        self.status = self.status.max(status);
        self.reasons.push(reason);
    }
}

fn assess_local(tool: &Tool, facts: &Facts) -> Verdict {
    let mut verdict = Verdict::new();
    let Some(variable) = tool.env_var.as_deref() else {
        verdict.problem(
            Status::NotCovered,
            "the signed catalog names no base-URL variable for this tool, so it cannot be pointed at the proxy".into(),
        );
        return verdict;
    };
    if !facts.api_listening {
        verdict.problem(
            Status::NotCovered,
            format!(
                "inveil is not answering on 127.0.0.1:{} (nothing listens there, or another program or an older inveil holds the port); run `inveil install`",
                facts.api_port
            ),
        );
    }
    let expected = claude_settings::proxy_url(facts.api_port, tool.prefix.as_deref());
    let has_file = SettingsFile::for_tool(&tool.id).is_some();
    let fix = if has_file {
        "run `inveil install`".to_string()
    } else {
        format!(
            "set {variable}={expected} where the tool reads it (`export {variable}={expected}`)"
        )
    };
    match facts.base_urls.get(&tool.id) {
        Some(Ok(Some(value))) if *value == expected => {}
        Some(Ok(Some(_))) => verdict.problem(
            Status::NeedsSetup,
            format!("{variable} points somewhere other than the proxy; {fix}"),
        ),
        Some(Err(error)) => verdict.problem(
            Status::NeedsSetup,
            format!("cannot read where {variable} is set: {error}"),
        ),
        _ => verdict.problem(Status::NeedsSetup, format!("{variable} is not set; {fix}")),
    }
    verdict
}

fn assess_browser(
    tool: &Tool,
    runtime: RuntimeKind,
    ca_domains: &[String],
    facts: &Facts,
) -> Verdict {
    let mut verdict = Verdict::new();
    if !facts.ca_present {
        verdict.problem(
            Status::NeedsSetup,
            "there is no browser CA yet; run `inveil browser-setup`".into(),
        );
    }
    for entry in &tool.hosts {
        let host = &entry.host;
        if engine::is_covered(host, &facts.ca_usable_domains) {
            continue;
        }
        if engine::is_covered(host, ca_domains) {
            verdict.problem(
                Status::NeedsSetup,
                format!("the CA was made before {host} was listed; run `inveil browser-setup` to renew it"),
            );
        } else {
            verdict.problem(
                Status::NotCovered,
                format!("{host} is outside the signed ca_domains, so the CA cannot vouch for it"),
            );
        }
    }
    match &facts.ca_trusted {
        Ok(true) => {}
        Ok(false) if facts.ca_present => verdict.problem(
            Status::NeedsSetup,
            "the CA is not in the operating system's store; run `inveil browser-setup`".into(),
        ),
        Ok(false) => {}
        Err(error) => verdict.problem(
            Status::NeedsSetup,
            format!("cannot check the trust store: {error}"),
        ),
    }
    if !facts.browser_listening {
        verdict.problem(
            Status::NotCovered,
            format!(
                "the browser proxy is not listening on 127.0.0.1:{}; run `inveil install`",
                facts.browser_port
            ),
        );
    }
    if runtime.uses_proxy_environment() {
        if !facts.https_proxy_is_ours {
            verdict.problem(
                Status::NeedsSetup,
                format!(
                    "{} ignores the system proxy settings; start it with `inveil run <command>`",
                    runtime.name()
                ),
            );
        }
        return verdict;
    }
    match &facts.pac_applied {
        Ok(true) => {}
        Ok(false) => verdict.problem(
            Status::NeedsSetup,
            "the system proxy settings do not use inveil's proxy auto-config; run `inveil browser-setup`".into(),
        ),
        Err(error) => verdict.problem(
            Status::NeedsSetup,
            format!("cannot check the system proxy settings: {error}"),
        ),
    }
    verdict
}

fn weakening_conditions(policy: &ActivePolicy, now: u64) -> Vec<String> {
    let mut warnings = Vec::new();
    if policy.effective.dry_run {
        warnings.push(
            "dry_run is on: findings are logged but nothing is blocked or redacted; turn it off in the configuration or the signed settings".into(),
        );
    }
    if policy.is_expired(now) {
        warnings.push(
            "the signed rules have expired and could not be refreshed; what happens to traffic now is decided by the policy_expired failure mode, so check that the backend is reachable".into(),
        );
    }
    warnings
}

fn assess(policy: &ActivePolicy, facts: &Facts, now: u64) -> Report {
    let warnings = weakening_conditions(policy, now);
    let tools: Vec<ToolReport> = policy
        .policy
        .tools
        .iter()
        .filter(|tool| tool.enabled)
        .map(|tool| {
            let (route, runtime_name, mut verdict) = match tool.via {
                Via::Local => ("base_url", PLAIN_HTTP_RUNTIME, assess_local(tool, facts)),
                Via::Browser => {
                    let runtime = RuntimeKind::for_tool(&tool.id);
                    (
                        "browser_proxy",
                        runtime.name(),
                        assess_browser(tool, runtime, &policy.policy.ca_domains, facts),
                    )
                }
            };
            for warning in &warnings {
                verdict.problem(Status::NeedsSetup, warning.clone());
            }
            ToolReport {
                id: tool.id.clone(),
                name: tool.name.clone(),
                route,
                runtime: runtime_name,
                status: verdict.status,
                reasons: verdict.reasons,
            }
        })
        .collect();
    let uses_os_browser = policy.policy.tools.iter().any(|tool| {
        tool.enabled
            && tool.via == Via::Browser
            && !RuntimeKind::for_tool(&tool.id).uses_proxy_environment()
    });
    Report {
        snapshot: SnapshotReport {
            version: policy.version,
            origin: origin_name(policy.origin),
            expires_at: policy.expires_at,
            expired: policy.expires_at.is_some_and(|expiry| now >= expiry),
        },
        proxy_running: facts.api_listening,
        browser_proxy_running: facts.browser_listening,
        warnings,
        tools,
        notes: if uses_os_browser {
            vec![format!("{} {FIREFOX_ADVICE}", RuntimeKind::Firefox.name())]
        } else {
            Vec::new()
        },
    }
}

fn origin_name(origin: PolicyOrigin) -> &'static str {
    match origin {
        PolicyOrigin::Builtin => "builtin",
        PolicyOrigin::Cache => "cached",
        PolicyOrigin::LocalFile => "local_file",
        PolicyOrigin::Backend => "backend",
    }
}

fn expiry_text(snapshot: &SnapshotReport, now: u64) -> String {
    let Some(expires_at) = snapshot.expires_at else {
        return "does not expire".into();
    };
    if snapshot.expired {
        return format!("EXPIRED {} days ago", (now - expires_at) / SECONDS_PER_DAY);
    }
    format!("expires in {} days", (expires_at - now) / SECONDS_PER_DAY)
}

fn render_text(report: &Report, now: u64) -> String {
    let yes_no = |value| if value { "running" } else { "NOT running" };
    let mut lines = vec![
        format!(
            "Rules: version {} ({}), {}",
            report.snapshot.version,
            report.snapshot.origin,
            expiry_text(&report.snapshot, now)
        ),
        format!("Proxy: {}", yes_no(report.proxy_running)),
        format!("Browser proxy: {}", yes_no(report.browser_proxy_running)),
    ];
    lines.extend(
        report
            .warnings
            .iter()
            .map(|warning| format!("Warning: {warning}")),
    );
    lines.push(String::new());
    for tool in &report.tools {
        lines.push(format!(
            "{}: {} [{}]",
            tool.status.label(),
            tool.name,
            tool.runtime
        ));
        lines.extend(tool.reasons.iter().map(|reason| format!("    {reason}")));
    }
    lines.extend(report.notes.iter().map(|note| format!("\nNote: {note}")));
    lines.join("\n")
}

pub fn run(config: &Config, json: bool) -> Result<ExitCode, AppError> {
    let runtime = Runtime::new(Arc::new(config.clone()))?;
    let policy = runtime.initial_policy()?;
    let facts = gather(config, &policy, &runtime.ca_directory());
    let now = unix_seconds();
    let report = assess(&policy, &facts, now);
    if json {
        let text = serde_json::to_string_pretty(&report)
            .map_err(|error| AppError::Usage(error.to_string()))?;
        println!("{text}");
    } else {
        println!("{}", render_text(&report, now));
    }
    let uncovered = report
        .tools
        .iter()
        .any(|tool| tool.status == Status::NotCovered);
    Ok(if uncovered {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

/// `inveil health`: the few things that must hold for protection to be on, one line each. Exit 1 if any fails; the
/// per-tool detail is `inveil doctor`.
pub fn health(config: &Config) -> Result<ExitCode, AppError> {
    let runtime = Runtime::new(Arc::new(config.clone()))?;
    let policy = runtime.initial_policy()?;
    let facts = gather(config, &policy, &runtime.ca_directory());
    let now = unix_seconds();
    let report = assess(&policy, &facts, now);

    ui::heading(&format!("inveil {} health", env!("CARGO_PKG_VERSION")));
    let mut healthy = true;
    let mut check = |ok: bool, label: &str, detail: &str| {
        healthy &= ok;
        ui::check(ok, label, if ok { "" } else { detail });
    };
    check(
        report.proxy_running,
        "Proxy running",
        &format!(
            "not answering on 127.0.0.1:{}; run `inveil install`",
            facts.api_port
        ),
    );
    check(
        !report.snapshot.expired,
        "Rules up to date",
        "the organisation's rules have expired; check your network, then run `inveil doctor`",
    );
    let uncovered: Vec<&str> = report
        .tools
        .iter()
        .filter(|tool| tool.status != Status::Covered)
        .map(|tool| tool.name.as_str())
        .collect();
    check(
        uncovered.is_empty(),
        "AI tools covered",
        &format!(
            "{} of your AI tools need attention; run `inveil doctor`",
            uncovered.len()
        ),
    );
    println!();
    Ok(if healthy {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::policy::PolicyBuilder;
    use std::path::PathBuf;

    const API_PORT: u16 = 8787;
    const BROWSER_PORT: u16 = 8788;
    const NOW: u64 = 1_800_000_000;

    fn builtin_policy() -> ActivePolicy {
        PolicyBuilder::new(Arc::new(Config::default()), PathBuf::new())
            .builtin()
            .unwrap()
    }

    fn policy_with_ca() -> ActivePolicy {
        let snapshot: contract::Snapshot =
            serde_json::from_str(include_str!("../../../../examples/rules.json")).unwrap();
        PolicyBuilder::new(Arc::new(Config::default()), PathBuf::new())
            .compile(&snapshot, PolicyOrigin::Builtin, None, None)
            .map(|mut policy| {
                policy.policy.usable_domains = policy.policy.ca_domains.clone();
                policy
            })
            .unwrap()
    }

    fn healthy_facts(policy: &ActivePolicy) -> Facts {
        let base_urls = policy
            .policy
            .local_tool_wiring()
            .iter()
            .map(|tool| {
                (
                    tool.tool_id.to_string(),
                    Ok(Some(claude_settings::proxy_url(API_PORT, tool.prefix))),
                )
            })
            .collect();
        Facts {
            api_port: API_PORT,
            browser_port: BROWSER_PORT,
            api_listening: true,
            browser_listening: true,
            ca_present: true,
            ca_usable_domains: policy.policy.ca_domains.clone(),
            ca_trusted: Ok(true),
            pac_applied: Ok(true),
            https_proxy_is_ours: true,
            base_urls,
        }
    }

    fn tool<'a>(report: &'a Report, id: &str) -> &'a ToolReport {
        report.tools.iter().find(|tool| tool.id == id).unwrap()
    }

    #[test]
    fn a_fully_set_up_machine_has_every_tool_with_a_base_url_variable_covered() {
        let policy = policy_with_ca();
        let report = assess(&policy, &healthy_facts(&policy), NOW);

        for tool in &report.tools {
            let has_variable = policy
                .policy
                .tools
                .iter()
                .find(|candidate| candidate.id == tool.id)
                .is_some_and(|candidate| {
                    candidate.via == Via::Browser || candidate.env_var.is_some()
                });
            if has_variable {
                assert_eq!(
                    tool.status,
                    Status::Covered,
                    "{}: {:?}",
                    tool.id,
                    tool.reasons
                );
            }
        }
        assert_eq!(tool(&report, "claude-web").status, Status::Covered);
        assert!(tool(&report, "claude-web").reasons.is_empty());
    }

    #[test]
    fn a_local_tool_without_a_catalog_variable_is_not_covered() {
        let policy = policy_with_ca();
        let report = assess(&policy, &healthy_facts(&policy), NOW);
        let xai = tool(&report, "xai-api");
        assert_eq!(xai.status, Status::NotCovered);
        assert!(xai.reasons[0].contains("no base-URL variable"));
    }

    #[test]
    fn an_unset_base_url_needs_setup_and_names_the_fix() {
        let policy = policy_with_ca();
        let mut facts = healthy_facts(&policy);
        facts.base_urls.insert("claude-code".into(), Ok(None));
        facts.base_urls.insert("codex-api".into(), Ok(None));

        let report = assess(&policy, &facts, NOW);

        let claude = tool(&report, "claude-code");
        assert_eq!(claude.status, Status::NeedsSetup);
        assert!(claude.reasons[0].contains("run `inveil install`"));
        let codex = tool(&report, "codex-api");
        assert_eq!(codex.status, Status::NeedsSetup);
        assert!(codex.reasons[0].contains("run `inveil install`"));
    }

    #[test]
    fn a_foreign_base_url_is_reported_without_printing_it() {
        let policy = policy_with_ca();
        let mut facts = healthy_facts(&policy);
        facts.base_urls.insert(
            "claude-code".into(),
            Ok(Some("https://user:hunter2@corp.example".into())),
        );

        let report = assess(&policy, &facts, NOW);

        assert_eq!(tool(&report, "claude-code").status, Status::NeedsSetup);
        let text = render_text(&report, NOW);
        let json = serde_json::to_string(&report).unwrap();
        assert!(!text.contains("hunter2") && !json.contains("hunter2"));
    }

    #[test]
    fn a_stopped_proxy_leaves_every_tool_not_covered() {
        let policy = policy_with_ca();
        let mut facts = healthy_facts(&policy);
        facts.api_listening = false;
        facts.browser_listening = false;

        let report = assess(&policy, &facts, NOW);

        for id in ["claude-code", "claude-web", "chatgpt-web"] {
            assert_eq!(tool(&report, id).status, Status::NotCovered, "{id}");
        }
    }

    #[test]
    fn a_missing_ca_needs_setup_for_browser_tools() {
        let policy = builtin_policy();
        let mut facts = healthy_facts(&policy);
        facts.ca_present = false;
        facts.ca_usable_domains = Vec::new();
        facts.ca_trusted = Ok(false);

        let report = assess(&policy, &facts, NOW);

        let claude_web = tool(&report, "claude-web");
        assert_eq!(claude_web.status, Status::NeedsSetup);
        assert!(claude_web
            .reasons
            .iter()
            .any(|reason| reason.contains("browser-setup")));
    }

    #[test]
    fn an_untrusted_ca_and_a_missing_pac_each_need_setup() {
        let policy = policy_with_ca();
        let mut facts = healthy_facts(&policy);
        facts.ca_trusted = Ok(false);
        facts.pac_applied = Ok(false);

        let report = assess(&policy, &facts, NOW);

        let claude_web = tool(&report, "claude-web");
        assert_eq!(claude_web.status, Status::NeedsSetup);
        assert_eq!(claude_web.reasons.len(), 2);
    }

    #[test]
    fn a_host_outside_the_signed_ca_domains_is_not_covered() {
        let policy = policy_with_ca();
        let mut facts = healthy_facts(&policy);
        facts.ca_usable_domains = Vec::new();
        let mut narrowed = policy_with_ca();
        narrowed.policy.ca_domains = Vec::new();

        let report = assess(&narrowed, &facts, NOW);

        assert_eq!(tool(&report, "claude-web").status, Status::NotCovered);
    }

    #[test]
    fn tools_that_ignore_the_system_proxy_need_inveil_run_unless_the_proxy_variable_is_set() {
        let policy = policy_with_ca();
        let mut facts = healthy_facts(&policy);
        facts.https_proxy_is_ours = false;

        let report = assess(&policy, &facts, NOW);

        let codex = tool(&report, "codex");
        assert_eq!(codex.status, Status::NeedsSetup);
        assert!(codex.reasons[0].contains("inveil run"));
        assert_eq!(codex.runtime, "Codex");
        assert_eq!(tool(&report, "claude-web").status, Status::Covered);
    }

    #[test]
    fn the_report_names_the_snapshot_and_flags_an_expired_one() {
        let mut policy = policy_with_ca();
        policy.expires_at = Some(NOW - 3 * SECONDS_PER_DAY);

        let report = assess(&policy, &healthy_facts(&policy), NOW);

        assert!(report.snapshot.expired);
        assert!(render_text(&report, NOW).contains("EXPIRED 3 days ago"));
    }

    #[test]
    fn dry_run_and_an_expired_policy_are_warnings_and_leave_every_tool_needing_setup() {
        let mut policy = policy_with_ca();
        policy.effective.dry_run = true;
        policy.expires_at = Some(NOW - SECONDS_PER_DAY);

        let report = assess(&policy, &healthy_facts(&policy), NOW);

        assert_eq!(report.warnings.len(), 2);
        let text = render_text(&report, NOW);
        assert!(text.contains("Warning: dry_run is on"), "{text}");
        assert!(
            text.contains("Warning: the signed rules have expired"),
            "{text}"
        );
        assert_eq!(tool(&report, "claude-web").status, Status::NeedsSetup);
        assert_eq!(tool(&report, "claude-code").status, Status::NeedsSetup);
        assert_eq!(tool(&report, "claude-web").reasons.len(), 2);
    }

    #[test]
    fn a_healthy_enforcing_current_policy_has_no_warnings() {
        let policy = policy_with_ca();
        let report = assess(&policy, &healthy_facts(&policy), NOW);
        assert!(report.warnings.is_empty());
    }

    #[test]
    fn json_uses_snake_case_statuses() {
        let policy = policy_with_ca();
        let report = assess(&policy, &healthy_facts(&policy), NOW);
        let json: serde_json::Value = serde_json::to_value(&report).unwrap();
        let statuses: Vec<&str> = json["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tool| tool["status"].as_str().unwrap())
            .collect();
        assert!(statuses.contains(&"covered"));
        assert!(statuses.contains(&"not_covered"));
    }
}
