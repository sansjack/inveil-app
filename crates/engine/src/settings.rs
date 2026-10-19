//! Merging the local configuration with the settings the backend signed. The result can only be as strict as the
//! stricter of the two: a server can tighten a client, and a local file can tighten itself, but neither can loosen
//! what the other demands. Failure modes are the exception: the signed policy may choose `open` for a condition,
//! which local configuration can never do.
use crate::signing::sha256_hex;
use contract::{FailMode, FailureCondition, FailureModes, Settings};
use semver::Version;
use serde::Serialize;

/// How often a heartbeat is sent when the server requires usage reporting but does not say.
pub const DEFAULT_HEARTBEAT_SECONDS: u64 = 300;

const BUILTIN_IN_PROCESS_MODE: FailMode = FailMode::Closed;
/// A stopped client should not take AI sites offline unless somebody asks for that.
const BUILTIN_SERVICE_DOWN_MODE: FailMode = FailMode::Open;

/// What local configuration asks for. Plain values: the engine never reads files or the environment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalSettings {
    /// The policy is owned by an administrator, so local switches that dodge reporting are ignored.
    pub managed: bool,
    pub offline: bool,
    pub dry_run: bool,
    /// In standalone mode the owner chooses `open` or `closed` per condition (a specific entry beats `default`).
    /// In managed mode only `closed` counts and `open` is ignored, because only the signed policy may loosen a
    /// failure mode. The legacy `block_unscannable` and `browser_fail_closed` switches arrive here as `unscannable`
    /// and `service_down`.
    pub failure_modes: FailureModes,
    /// `0` means no limit.
    pub max_tokens: usize,
    pub deny: Vec<String>,
    /// Default upstream of the localhost API proxy.
    pub upstream: String,
    /// Whether local configuration wants usage reported (a sink other than `none`).
    pub usage_enabled: bool,
    pub debug: bool,
    pub poll_seconds: u64,
    pub client_version: String,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UsagePolicy {
    Off,
    /// Events are sent. With a heartbeat, one is sent at this interval even when there are no events.
    On {
        heartbeat_seconds: Option<u64>,
    },
    /// Events are dropped, but a heartbeat with no events is sent at this interval so the backend sees the client.
    HeartbeatOnly {
        heartbeat_seconds: u64,
    },
}

/// What each failure condition resolves to once the local and signed settings are merged.
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub struct ResolvedFailureModes {
    pub unscannable: FailMode,
    pub scan_error: FailMode,
    pub policy_expired: FailMode,
    pub service_down: FailMode,
}

impl ResolvedFailureModes {
    pub const fn mode(&self, condition: FailureCondition) -> FailMode {
        match condition {
            FailureCondition::Unscannable => self.unscannable,
            FailureCondition::ScanError => self.scan_error,
            FailureCondition::PolicyExpired => self.policy_expired,
            FailureCondition::ServiceDown => self.service_down,
        }
    }
}

impl From<ResolvedFailureModes> for FailureModes {
    fn from(resolved: ResolvedFailureModes) -> Self {
        Self {
            default: None,
            unscannable: Some(resolved.unscannable),
            scan_error: Some(resolved.scan_error),
            policy_expired: Some(resolved.policy_expired),
            service_down: Some(resolved.service_down),
        }
    }
}

/// The configuration the client actually runs with.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Effective {
    pub dry_run: bool,
    pub failure_modes: ResolvedFailureModes,
    pub max_tokens: usize,
    pub deny: Vec<String>,
    pub upstream: String,
    pub debug: bool,
    pub poll_seconds: u64,
    pub offline: bool,
    pub usage: UsagePolicy,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MergeError {
    #[error("upstream {upstream:?} is not one of the upstreams the policy allows")]
    UpstreamNotAllowed { upstream: String },
    #[error("this client is version {current}, the policy requires at least {required}")]
    ClientTooOld { current: String, required: String },
    #[error("'{0}' is not a version this client can compare")]
    BadVersion(String),
}

fn smallest_non_zero(local: usize, server: Option<usize>) -> usize {
    match (local, server.unwrap_or(0)) {
        (0, server) => server,
        (local, 0) => local,
        (local, server) => local.min(server),
    }
}

fn union_in_order(local: &[String], server: &[String]) -> Vec<String> {
    let mut merged: Vec<String> = Vec::with_capacity(local.len() + server.len());
    for pattern in server.iter().chain(local) {
        if !merged.contains(pattern) {
            merged.push(pattern.clone());
        }
    }
    merged
}

fn check_client_version(local: &LocalSettings, server: &Settings) -> Result<(), MergeError> {
    let Some(required) = server.min_client_version.as_deref() else {
        return Ok(());
    };
    let required_version =
        Version::parse(required).map_err(|_| MergeError::BadVersion(required.to_string()))?;
    let current_version = Version::parse(&local.client_version)
        .map_err(|_| MergeError::BadVersion(local.client_version.clone()))?;
    if current_version < required_version {
        return Err(MergeError::ClientTooOld {
            current: local.client_version.clone(),
            required: required.to_string(),
        });
    }
    Ok(())
}

fn check_upstream(local: &LocalSettings, server: &Settings) -> Result<(), MergeError> {
    if server.allowed_upstreams.is_empty() {
        return Ok(());
    }
    let wanted = local.upstream.trim_end_matches('/');
    let allowed = server
        .allowed_upstreams
        .iter()
        .any(|origin| origin.trim_end_matches('/').eq_ignore_ascii_case(wanted));
    if !allowed {
        return Err(MergeError::UpstreamNotAllowed {
            upstream: local.upstream.clone(),
        });
    }
    Ok(())
}

/// The contract crate does not re-export the `UsageReporting` type, so its wire name is read instead.
/// An absent or unrecognised value is `optional`, the setting that grants the server nothing.
fn server_usage_mode(server: &Settings) -> &'static str {
    let name = serde_json::to_value(server.usage_reporting).unwrap_or_default();
    match name.as_str() {
        Some("required") => "required",
        Some("disabled") => "disabled",
        _ => "optional",
    }
}

fn usage_policy(local: &LocalSettings, server: &Settings, offline: bool) -> UsagePolicy {
    if offline {
        return UsagePolicy::Off;
    }
    let heartbeat_seconds = server
        .heartbeat_seconds
        .unwrap_or(DEFAULT_HEARTBEAT_SECONDS);
    match server_usage_mode(server) {
        "disabled" => UsagePolicy::Off,
        "required" => UsagePolicy::On {
            heartbeat_seconds: Some(heartbeat_seconds),
        },
        _ if local.managed && local.usage_enabled => UsagePolicy::On {
            heartbeat_seconds: Some(heartbeat_seconds),
        },
        _ if local.managed => UsagePolicy::HeartbeatOnly { heartbeat_seconds },
        _ if local.usage_enabled => UsagePolicy::On {
            heartbeat_seconds: None,
        },
        _ => UsagePolicy::Off,
    }
}

/// The signed `block_unscannable`, `browser_fail_closed` and `fail_closed_on_expiry` flags, which can only ask for
/// `closed`. They apply to a condition only when `failure_modes` says nothing about it, not even through `default`.
fn legacy_server_closed(condition: FailureCondition, server: &Settings) -> bool {
    match condition {
        FailureCondition::Unscannable => server.block_unscannable == Some(true),
        FailureCondition::ScanError => false,
        FailureCondition::PolicyExpired => server.fail_closed_on_expiry,
        FailureCondition::ServiceDown => server.browser_fail_closed == Some(true),
    }
}

/// What local configuration asks for one condition. A standalone owner's choice, `open` included, counts; in managed
/// mode only `closed` (for the condition or in `default`) counts.
fn local_failure_mode(condition: FailureCondition, local: &LocalSettings) -> Option<FailMode> {
    let modes = &local.failure_modes;
    if !local.managed {
        return modes.specific(condition).or(modes.default);
    }
    let asks_closed = modes.specific(condition) == Some(FailMode::Closed)
        || modes.default == Some(FailMode::Closed);
    asks_closed.then_some(FailMode::Closed)
}

/// Resolution order for one condition:
/// 1. `closed` from local configuration: it can always tighten;
/// 2. the signed `failure_modes` entry for the condition, then the signed `failure_modes.default`, open or closed;
/// 3. `closed` from a legacy signed flag;
/// 4. `open` from local configuration, which exists only in standalone mode and only for conditions the signed
///    policy left alone;
/// 5. the built-in mode: `closed` for conditions the client handles in process, `open` for `service_down`.
fn resolve_failure_mode(
    condition: FailureCondition,
    local: &LocalSettings,
    server: &Settings,
) -> FailMode {
    let local_mode = local_failure_mode(condition, local);
    if local_mode == Some(FailMode::Closed) {
        return FailMode::Closed;
    }
    let signed = &server.failure_modes;
    if let Some(mode) = signed.specific(condition).or(signed.default) {
        return mode;
    }
    if legacy_server_closed(condition, server) {
        return FailMode::Closed;
    }
    if let Some(mode) = local_mode {
        return mode;
    }
    match condition {
        FailureCondition::ServiceDown => BUILTIN_SERVICE_DOWN_MODE,
        _ => BUILTIN_IN_PROCESS_MODE,
    }
}

pub fn merge_settings(local: &LocalSettings, server: &Settings) -> Result<Effective, MergeError> {
    check_client_version(local, server)?;
    check_upstream(local, server)?;
    let offline = local.offline && (!local.managed || server.allow_offline.unwrap_or(false));
    Ok(Effective {
        dry_run: local.dry_run && server.dry_run != Some(false),
        failure_modes: ResolvedFailureModes {
            unscannable: resolve_failure_mode(FailureCondition::Unscannable, local, server),
            scan_error: resolve_failure_mode(FailureCondition::ScanError, local, server),
            policy_expired: resolve_failure_mode(FailureCondition::PolicyExpired, local, server),
            service_down: resolve_failure_mode(FailureCondition::ServiceDown, local, server),
        },
        max_tokens: smallest_non_zero(local.max_tokens, server.max_tokens),
        deny: union_in_order(&local.deny, &server.deny),
        upstream: local.upstream.clone(),
        debug: local.debug && server.allow_debug != Some(false),
        poll_seconds: local.poll_seconds.max(server.min_poll_seconds.unwrap_or(0)),
        offline,
        usage: usage_policy(local, server, offline),
    })
}

/// Fingerprint of the running configuration, sent with every usage batch so the backend can notice a client whose
/// effective policy differs from the one published.
pub fn effective_config_hash(effective: &Effective) -> Result<String, serde_json::Error> {
    let mut canonical = effective.clone();
    canonical.deny.sort();
    Ok(sha256_hex(&serde_json::to_vec(&canonical)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::test_support::local_settings as local;
    use serde_json::json;

    fn server_with(json: serde_json::Value) -> Settings {
        serde_json::from_value(json).unwrap()
    }

    fn merged(local: &LocalSettings, server: &Settings) -> Effective {
        merge_settings(local, server).unwrap()
    }

    #[test]
    fn a_server_that_says_nothing_leaves_local_choices_alone() {
        let local = LocalSettings {
            dry_run: true,
            max_tokens: 500,
            debug: true,
            ..local()
        };
        let effective = merged(&local, &Settings::default());
        assert!(effective.dry_run && effective.debug);
        assert_eq!(effective.max_tokens, 500);
        assert_eq!(effective.usage, UsagePolicy::Off);
    }

    #[test]
    fn a_server_that_says_enforce_overrides_a_local_dry_run() {
        let local = LocalSettings {
            dry_run: true,
            ..local()
        };
        let server = Settings {
            dry_run: Some(false),
            ..Settings::default()
        };
        assert!(!merged(&local, &server).dry_run);
    }

    #[test]
    fn a_server_cannot_force_dry_run_on_and_local_cannot_turn_enforcement_off() {
        let server = Settings {
            dry_run: Some(true),
            ..Settings::default()
        };
        assert!(!merged(&local(), &server).dry_run);
        let server = Settings {
            dry_run: Some(false),
            ..Settings::default()
        };
        assert!(!merged(&local(), &server).dry_run);
    }

    const CONDITIONS: [FailureCondition; 4] = [
        FailureCondition::Unscannable,
        FailureCondition::ScanError,
        FailureCondition::PolicyExpired,
        FailureCondition::ServiceDown,
    ];

    fn modes(effective: &Effective) -> [FailMode; 4] {
        CONDITIONS.map(|condition| effective.failure_modes.mode(condition))
    }

    fn only(condition: FailureCondition, mode: FailMode) -> FailureModes {
        let mut modes = FailureModes::default();
        match condition {
            FailureCondition::Unscannable => modes.unscannable = Some(mode),
            FailureCondition::ScanError => modes.scan_error = Some(mode),
            FailureCondition::PolicyExpired => modes.policy_expired = Some(mode),
            FailureCondition::ServiceDown => modes.service_down = Some(mode),
        }
        modes
    }

    fn with_server_modes(failure_modes: FailureModes) -> Settings {
        Settings {
            failure_modes,
            ..Settings::default()
        }
    }

    fn with_local_modes(failure_modes: FailureModes) -> LocalSettings {
        LocalSettings {
            failure_modes,
            ..local()
        }
    }

    #[test]
    fn with_nothing_configured_in_process_conditions_are_closed_and_service_down_is_open() {
        let effective = merged(&local(), &Settings::default());
        assert_eq!(
            modes(&effective),
            [
                FailMode::Closed,
                FailMode::Closed,
                FailMode::Closed,
                FailMode::Open
            ]
        );
    }

    #[test]
    fn the_server_decides_each_condition_and_unset_ones_follow_its_default() {
        for condition in CONDITIONS {
            for mode in [FailMode::Open, FailMode::Closed] {
                let server = with_server_modes(only(condition, mode));
                let effective = merged(&local(), &server);
                assert_eq!(
                    effective.failure_modes.mode(condition),
                    mode,
                    "{condition:?}"
                );
            }
        }
        let server = with_server_modes(FailureModes {
            default: Some(FailMode::Open),
            scan_error: Some(FailMode::Closed),
            ..FailureModes::default()
        });
        assert_eq!(
            modes(&merged(&local(), &server)),
            [
                FailMode::Open,
                FailMode::Closed,
                FailMode::Open,
                FailMode::Open
            ]
        );
        let server = with_server_modes(FailureModes {
            default: Some(FailMode::Closed),
            ..FailureModes::default()
        });
        assert_eq!(modes(&merged(&local(), &server)), [FailMode::Closed; 4]);
    }

    #[test]
    fn local_configuration_can_tighten_a_condition_the_server_opened() {
        for condition in CONDITIONS {
            let server = with_server_modes(FailureModes {
                default: Some(FailMode::Open),
                ..FailureModes::default()
            });
            let local = with_local_modes(only(condition, FailMode::Closed));
            let effective = merged(&local, &server);
            for other in CONDITIONS {
                let expected = if other == condition {
                    FailMode::Closed
                } else {
                    FailMode::Open
                };
                assert_eq!(
                    effective.failure_modes.mode(other),
                    expected,
                    "{condition:?}"
                );
            }
        }
        let local = with_local_modes(FailureModes {
            default: Some(FailMode::Closed),
            ..FailureModes::default()
        });
        let server = with_server_modes(FailureModes {
            default: Some(FailMode::Open),
            ..FailureModes::default()
        });
        assert_eq!(modes(&merged(&local, &server)), [FailMode::Closed; 4]);
    }

    fn managed_with_modes(failure_modes: FailureModes) -> LocalSettings {
        LocalSettings {
            managed: true,
            ..with_local_modes(failure_modes)
        }
    }

    #[test]
    fn managed_local_configuration_cannot_loosen_a_condition() {
        for condition in CONDITIONS {
            let loosening = managed_with_modes(only(condition, FailMode::Open));
            let closed_by_server = with_server_modes(only(condition, FailMode::Closed));
            assert_eq!(
                merged(&loosening, &closed_by_server)
                    .failure_modes
                    .mode(condition),
                FailMode::Closed,
                "{condition:?}"
            );
            let baseline = merged(
                &LocalSettings {
                    managed: true,
                    ..local()
                },
                &Settings::default(),
            );
            let untouched = merged(&loosening, &Settings::default());
            assert_eq!(untouched.failure_modes, baseline.failure_modes);
        }
        let local = managed_with_modes(FailureModes {
            default: Some(FailMode::Open),
            ..FailureModes::default()
        });
        let effective = merged(&local, &Settings::default());
        assert_eq!(effective.failure_modes.unscannable, FailMode::Closed);
    }

    #[test]
    fn standalone_local_configuration_may_open_what_the_server_left_alone() {
        for condition in CONDITIONS {
            let opening = with_local_modes(only(condition, FailMode::Open));
            let effective = merged(&opening, &Settings::default());
            assert_eq!(effective.failure_modes.mode(condition), FailMode::Open);
        }
        let default_open = with_local_modes(FailureModes {
            default: Some(FailMode::Open),
            unscannable: Some(FailMode::Closed),
            ..FailureModes::default()
        });
        assert_eq!(
            modes(&merged(&default_open, &Settings::default())),
            [
                FailMode::Closed,
                FailMode::Open,
                FailMode::Open,
                FailMode::Open
            ]
        );
    }

    #[test]
    fn standalone_local_open_loses_to_a_signed_value_for_the_same_condition() {
        for condition in CONDITIONS {
            let opening = with_local_modes(FailureModes {
                default: Some(FailMode::Open),
                ..FailureModes::default()
            });
            let signed_closed = with_server_modes(only(condition, FailMode::Closed));
            let effective = merged(&opening, &signed_closed);
            assert_eq!(effective.failure_modes.mode(condition), FailMode::Closed);
        }
        let legacy = Settings {
            block_unscannable: Some(true),
            ..Settings::default()
        };
        let opening = with_local_modes(only(FailureCondition::Unscannable, FailMode::Open));
        assert_eq!(
            merged(&opening, &legacy).failure_modes.unscannable,
            FailMode::Closed
        );
    }

    #[test]
    fn legacy_signed_flags_close_their_condition_unless_failure_modes_speak() {
        let server = Settings {
            block_unscannable: Some(true),
            browser_fail_closed: Some(true),
            fail_closed_on_expiry: true,
            ..Settings::default()
        };
        assert_eq!(modes(&merged(&local(), &server)), [FailMode::Closed; 4]);

        let overruled = Settings {
            failure_modes: FailureModes {
                unscannable: Some(FailMode::Open),
                default: Some(FailMode::Open),
                ..FailureModes::default()
            },
            ..server
        };
        assert_eq!(modes(&merged(&local(), &overruled)), [FailMode::Open; 4]);

        let false_flags = Settings {
            block_unscannable: Some(false),
            browser_fail_closed: Some(false),
            ..Settings::default()
        };
        assert_eq!(
            modes(&merged(&local(), &false_flags)),
            modes(&merged(&local(), &Settings::default()))
        );
    }

    #[test]
    fn max_tokens_is_the_smallest_non_zero_limit() {
        let tokens = |local_limit, server_limit| {
            let local = LocalSettings {
                max_tokens: local_limit,
                ..local()
            };
            let server = Settings {
                max_tokens: server_limit,
                ..Settings::default()
            };
            merged(&local, &server).max_tokens
        };
        assert_eq!(tokens(0, None), 0);
        assert_eq!(tokens(0, Some(0)), 0);
        assert_eq!(tokens(100, None), 100);
        assert_eq!(tokens(0, Some(200)), 200);
        assert_eq!(tokens(100, Some(200)), 100);
        assert_eq!(tokens(300, Some(200)), 200);
        assert_eq!(tokens(300, Some(0)), 300);
    }

    #[test]
    fn deny_lists_are_a_union_without_duplicates() {
        let local = LocalSettings {
            deny: vec!["a".into(), "b".into()],
            ..local()
        };
        let server = Settings {
            deny: vec!["b".into(), "c".into()],
            ..Settings::default()
        };
        assert_eq!(merged(&local, &server).deny, ["b", "c", "a"]);
    }

    #[test]
    fn the_local_upstream_must_be_on_the_servers_list() {
        let server = Settings {
            allowed_upstreams: vec!["https://api.anthropic.com".into()],
            ..Settings::default()
        };
        assert!(merge_settings(&local(), &server).is_ok());
        let trailing_slash = LocalSettings {
            upstream: "https://API.anthropic.com/".into(),
            ..local()
        };
        assert!(merge_settings(&trailing_slash, &server).is_ok());

        let elsewhere = LocalSettings {
            upstream: "https://evil.example".into(),
            ..local()
        };
        assert_eq!(
            merge_settings(&elsewhere, &server),
            Err(MergeError::UpstreamNotAllowed {
                upstream: "https://evil.example".into()
            })
        );
        assert!(
            merge_settings(&elsewhere, &Settings::default()).is_ok(),
            "an empty list is unrestricted"
        );
    }

    fn usage_for(managed: bool, usage_enabled: bool, mode: Option<&str>) -> UsagePolicy {
        let local = LocalSettings {
            managed,
            usage_enabled,
            ..local()
        };
        let server = server_with(json!({"usage_reporting": mode, "heartbeat_seconds": 90}));
        merged(&local, &server).usage
    }

    #[test]
    fn a_backend_owned_client_heartbeats_under_optional_and_goes_silent_only_when_disabled() {
        let heartbeat_seconds = 90;
        let managed = |usage_enabled, mode| usage_for(true, usage_enabled, mode);
        assert_eq!(
            managed(false, Some("optional")),
            UsagePolicy::HeartbeatOnly { heartbeat_seconds }
        );
        assert_eq!(
            managed(true, Some("optional")),
            UsagePolicy::On {
                heartbeat_seconds: Some(heartbeat_seconds)
            }
        );
        assert_eq!(managed(false, Some("disabled")), UsagePolicy::Off);
        assert_eq!(
            managed(false, None),
            UsagePolicy::HeartbeatOnly { heartbeat_seconds }
        );
    }

    #[test]
    fn usage_reporting_follows_the_server_when_it_decides() {
        let usage = |local_wants: bool, mode: Option<&str>| usage_for(false, local_wants, mode);
        let heartbeat = UsagePolicy::On {
            heartbeat_seconds: Some(90),
        };
        assert_eq!(usage(false, Some("required")), heartbeat);
        assert_eq!(usage(true, Some("disabled")), UsagePolicy::Off);
        assert_eq!(
            usage(true, Some("optional")),
            UsagePolicy::On {
                heartbeat_seconds: None
            }
        );
        assert_eq!(usage(false, Some("optional")), UsagePolicy::Off);
        assert_eq!(
            usage(true, None),
            UsagePolicy::On {
                heartbeat_seconds: None
            }
        );
    }

    #[test]
    fn required_reporting_uses_the_default_heartbeat_when_none_is_given() {
        let server = server_with(json!({"usage_reporting": "required"}));
        assert_eq!(
            merged(&local(), &server).usage,
            UsagePolicy::On {
                heartbeat_seconds: Some(DEFAULT_HEARTBEAT_SECONDS)
            }
        );
    }

    #[test]
    fn offline_is_ignored_in_managed_mode_unless_the_server_allows_it() {
        let offline_local = |managed| LocalSettings {
            managed,
            offline: true,
            ..local()
        };
        let required = server_with(json!({"usage_reporting": "required"}));
        let allowed = Settings {
            allow_offline: Some(true),
            ..required.clone()
        };

        assert!(
            merged(&offline_local(false), &required).offline,
            "standalone owners may go offline"
        );
        let managed = merged(&offline_local(true), &required);
        assert!(!managed.offline, "an employee cannot dodge reporting");
        assert!(matches!(managed.usage, UsagePolicy::On { .. }));
        let allowed = merged(&offline_local(true), &allowed);
        assert!(allowed.offline);
        assert_eq!(allowed.usage, UsagePolicy::Off, "offline sends nothing");
    }

    #[test]
    fn poll_interval_and_debug_can_only_be_tightened() {
        let server = Settings {
            min_poll_seconds: Some(300),
            allow_debug: Some(false),
            ..Settings::default()
        };
        let local = LocalSettings {
            poll_seconds: 60,
            debug: true,
            ..local()
        };
        let effective = merged(&local, &server);
        assert_eq!(effective.poll_seconds, 300);
        assert!(!effective.debug);
        let slower = LocalSettings {
            poll_seconds: 900,
            ..local
        };
        assert_eq!(merged(&slower, &server).poll_seconds, 900);
    }

    #[test]
    fn an_old_client_is_refused() {
        let server = Settings {
            min_client_version: Some("1.3.0".into()),
            ..Settings::default()
        };
        assert_eq!(
            merge_settings(&local(), &server),
            Err(MergeError::ClientTooOld {
                current: "1.2.3".into(),
                required: "1.3.0".into()
            })
        );
        let server = Settings {
            min_client_version: Some("1.2.3".into()),
            ..Settings::default()
        };
        assert!(merge_settings(&local(), &server).is_ok());
        let server = Settings {
            min_client_version: Some("soon".into()),
            ..Settings::default()
        };
        assert_eq!(
            merge_settings(&local(), &server),
            Err(MergeError::BadVersion("soon".into()))
        );
    }

    #[test]
    fn versions_are_compared_like_semver_including_prereleases() {
        let required = |minimum: &str, current: &str| {
            let local = LocalSettings {
                client_version: current.into(),
                ..local()
            };
            let server = Settings {
                min_client_version: Some(minimum.into()),
                ..Settings::default()
            };
            merge_settings(&local, &server).is_ok()
        };
        assert!(required("0.9.9", "0.10.0"));
        assert!(!required("0.10.0", "0.9.9"));
        assert!(required("1.2.3", "1.2.4"));
        assert!(!required("2.0.0", "1.99.0"));
        assert!(!required("1.2.3", "1.2.3-rc.1"));
        assert!(required("1.2.3-rc.1", "1.2.3"));
        assert!(required("1.2.3", "1.2.3+build.5"));
    }

    #[test]
    fn malformed_minimum_versions_are_rejected() {
        for version in ["", "1", "1.2", "1.2.3.4", "a.b.c", "1.2.x", "-1.0.0"] {
            let server = Settings {
                min_client_version: Some(version.into()),
                ..Settings::default()
            };
            assert_eq!(
                merge_settings(&local(), &server),
                Err(MergeError::BadVersion(version.into())),
                "{version:?}"
            );
        }
    }

    #[test]
    fn the_config_hash_changes_with_the_policy_and_ignores_deny_order() {
        let base = merged(&local(), &Settings::default());
        let same = effective_config_hash(&base).unwrap();
        assert_eq!(same.len(), 64);
        assert_eq!(effective_config_hash(&base.clone()).unwrap(), same);

        for condition in CONDITIONS {
            let other = match base.failure_modes.mode(condition) {
                FailMode::Open => FailMode::Closed,
                FailMode::Closed => FailMode::Open,
            };
            let server = with_server_modes(only(condition, other));
            let changed = merged(&local(), &server);
            assert_ne!(
                effective_config_hash(&changed).unwrap(),
                same,
                "{condition:?}"
            );
        }

        let ab = Effective {
            deny: vec!["a".into(), "b".into()],
            ..base.clone()
        };
        let ba = Effective {
            deny: vec!["b".into(), "a".into()],
            ..base
        };
        assert_eq!(
            effective_config_hash(&ab).unwrap(),
            effective_config_hash(&ba).unwrap()
        );
    }
}
