//! The pipeline every proxy path shares: decode, inspect, decide. It returns what to do with the request, and
//! `AppState::conclude` records it (audit, notice) so both proxies treat a finding the same way.
use super::audit::AuditAction;
use super::POLICY_EXPIRED_REASON;
use crate::policy::ActivePolicy;
use crate::util::unix_seconds;
use bytes::Bytes;
use contract::{FailMode, FailureCondition, Format};
use engine::connect::Frame;
use engine::{
    decide, decode, estimate_tokens, inspect, inspect_connect_frame, inspect_websocket_frame,
    unreadable_message, Decision, Inspection, Report,
};
use serde::Deserialize;
use std::sync::Arc;

/// Scanning is CPU work. Bodies under this run right on the async worker (a thread hop would cost more than the
/// scan); bigger ones run on a blocking thread, so one huge request cannot stall every other connection.
const OFFLOAD_BYTES: usize = 64 << 10;
const INTERNAL_ERROR: &str = "internal error while scanning";

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Allow,
    /// Send this body (or, for a stream frame, this frame) instead of the original.
    Rewrite(Vec<u8>),
    Block {
        rule_ids: Vec<String>,
        message: String,
    },
}

#[derive(Debug)]
pub struct Screened {
    pub outcome: Outcome,
    pub audit_action: AuditAction,
    pub report: Report,
    pub tokens: usize,
    pub model: String,
    /// Conditions whose failure mode is `open` and that let this request through unchecked.
    pub fail_open: Vec<FailureCondition>,
}

impl Screened {
    pub fn blocked(condition: FailureCondition, why: &str, report: Report, tokens: usize) -> Self {
        Self {
            outcome: Outcome::Block {
                rule_ids: vec![condition.as_str().to_string()],
                message: unreadable_message(why),
            },
            audit_action: AuditAction::Block,
            report,
            tokens,
            model: String::new(),
            fail_open: vec![],
        }
    }
}

#[derive(Deserialize)]
struct ModelField {
    model: Option<String>,
}

fn model_of(format: Format, body: &[u8]) -> String {
    if format != Format::Json {
        return String::new();
    }
    serde_json::from_slice::<ModelField>(body)
        .ok()
        .and_then(|field| field.model)
        .unwrap_or_default()
}

/// What happens to a request when `condition` stops it from being checked normally: blocked when the failure mode
/// is `closed`, passed on and flagged for the audit log and the usage heartbeat when it is `open`.
pub fn on_failure(
    active: &ActivePolicy,
    condition: FailureCondition,
    why: &str,
    tokens: usize,
) -> Screened {
    if active.effective.failure_modes.mode(condition) == FailMode::Closed {
        return apply_expiry(
            active,
            Screened::blocked(condition, why, Report::default(), tokens),
        );
    }
    tracing::warn!(
        "passing a request unchecked because the {condition:?} failure mode is open: {why}"
    );
    apply_expiry(
        active,
        Screened {
            outcome: Outcome::Allow,
            audit_action: AuditAction::Allow,
            report: Report::default(),
            tokens,
            model: String::new(),
            fail_open: vec![condition],
        },
    )
}

/// A request that would go out is blocked, or flagged as passed, when the policy is past `expires_at` and no fresh
/// snapshot arrived, according to the `policy_expired` failure mode.
fn apply_expiry(active: &ActivePolicy, mut screened: Screened) -> Screened {
    let expired = active.is_expired(unix_seconds());
    if !expired || matches!(screened.outcome, Outcome::Block { .. }) {
        return screened;
    }
    match active
        .effective
        .failure_modes
        .mode(FailureCondition::PolicyExpired)
    {
        FailMode::Closed => Screened::blocked(
            FailureCondition::PolicyExpired,
            POLICY_EXPIRED_REASON,
            screened.report,
            screened.tokens,
        ),
        FailMode::Open => {
            screened.fail_open.push(FailureCondition::PolicyExpired);
            screened
        }
    }
}

fn conclude(
    active: &ActivePolicy,
    inspection: Inspection,
    tokens: usize,
    model: String,
) -> Screened {
    let decision = decide(&inspection.report, &active.effective, tokens);
    let (outcome, audit_action) = match decision {
        Decision::Allow => (Outcome::Allow, AuditAction::Allow),
        Decision::Redact { .. } => match inspection.redacted {
            Some(body) => (Outcome::Rewrite(body), AuditAction::Redact),
            None => (Outcome::Allow, AuditAction::Allow),
        },
        Decision::Block { rule_ids, message } => {
            (Outcome::Block { rule_ids, message }, AuditAction::Block)
        }
        Decision::DryRun { .. } => (Outcome::Allow, AuditAction::DryRun),
    };
    apply_expiry(
        active,
        Screened {
            outcome,
            audit_action,
            report: inspection.report,
            tokens,
            model,
            fail_open: vec![],
        },
    )
}

pub fn screen_body(
    active: &ActivePolicy,
    format: Format,
    content_encoding: Option<&[u8]>,
    raw: &[u8],
    max_decoded_bytes: usize,
) -> Screened {
    let tokens = estimate_tokens(raw.len());
    let body = match decode(content_encoding, raw, max_decoded_bytes) {
        Ok(body) => body,
        Err(error) => {
            return on_failure(
                active,
                FailureCondition::Unscannable,
                &error.to_string(),
                tokens,
            )
        }
    };
    let tokens = estimate_tokens(body.len());
    let model = model_of(format, &body);
    match inspect(&active.policy.scanner, format, &body) {
        Ok(inspection) => conclude(active, inspection, tokens, model),
        Err(error) => on_failure(
            active,
            FailureCondition::Unscannable,
            &error.to_string(),
            tokens,
        ),
    }
}

pub fn screen_frame(active: &ActivePolicy, frame: &Frame, max_decoded_bytes: usize) -> Screened {
    let tokens = estimate_tokens(frame.message.len());
    match inspect_connect_frame(&active.policy.scanner, frame, max_decoded_bytes) {
        Ok(inspection) => conclude(active, inspection, tokens, String::new()),
        Err(error) => on_failure(
            active,
            FailureCondition::Unscannable,
            &error.to_string(),
            tokens,
        ),
    }
}

/// `None` when the frame is not JSON, which passes untouched.
pub fn screen_websocket_text(active: &ActivePolicy, text: &str) -> Option<Screened> {
    let inspection = inspect_websocket_frame(&active.policy.scanner, text)?;
    Some(conclude(
        active,
        inspection,
        estimate_tokens(text.len()),
        String::new(),
    ))
}

/// Runs `work` inline for small inputs and on a blocking thread for big ones. A scan that panics follows the
/// `scan_error` failure mode.
pub async fn offload<F>(active: Arc<ActivePolicy>, size: usize, work: F) -> Screened
where
    F: FnOnce(&ActivePolicy) -> Screened + Send + 'static,
{
    if size < OFFLOAD_BYTES {
        return work(&active);
    }
    let for_task = active.clone();
    match tokio::task::spawn_blocking(move || work(&for_task)).await {
        Ok(screened) => screened,
        Err(error) => {
            tracing::error!("scan task failed: {error}");
            on_failure(&active, FailureCondition::ScanError, INTERNAL_ERROR, 0)
        }
    }
}

pub async fn screen_body_offloaded(
    active: Arc<ActivePolicy>,
    format: Format,
    content_encoding: Option<Vec<u8>>,
    raw: Bytes,
    max_decoded_bytes: usize,
) -> Screened {
    let size = raw.len();
    offload(active, size, move |active| {
        screen_body(
            active,
            format,
            content_encoding.as_deref(),
            &raw,
            max_decoded_bytes,
        )
    })
    .await
}

pub async fn screen_frame_offloaded(
    active: Arc<ActivePolicy>,
    frame: Frame,
    max_decoded_bytes: usize,
) -> Screened {
    let size = frame.message.len();
    offload(active, size, move |active| {
        screen_frame(active, &frame, max_decoded_bytes)
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::proxy::test_support::{builtin_with, redact_rules, TestProxy};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    const SSN_TEXT: &str = "my ssn is 123-45-6789";
    const DECODED_LIMIT: usize = 1 << 20;
    const HUGE_DECODED_LIMIT: usize = 64 << 20;

    fn active(redact: &[&str]) -> Arc<ActivePolicy> {
        TestProxy::new(
            Config::default(),
            builtin_with(|snapshot| redact_rules(snapshot, redact)),
        )
        .state
        .policy()
    }

    fn screen_json(active: &ActivePolicy, body: &str) -> Screened {
        screen_body(active, Format::Json, None, body.as_bytes(), DECODED_LIMIT)
    }

    #[tokio::test]
    async fn an_ssn_blocks_a_clean_body_is_allowed_and_a_redact_rule_rewrites() {
        let blocking = active(&[]);
        assert!(matches!(
            screen_json(&blocking, &format!(r#"{{"parts":["{SSN_TEXT}"]}}"#)).outcome,
            Outcome::Block { .. }
        ));
        assert_eq!(
            screen_json(&blocking, r#"{"parts":["hello"]}"#).outcome,
            Outcome::Allow
        );

        let redacting = active(&["ssn"]);
        let screened = screen_json(&redacting, &format!(r#"{{"parts":["{SSN_TEXT}"]}}"#));
        assert_eq!(
            screened.outcome,
            Outcome::Rewrite(br#"{"parts":["my ssn is [REDACTED:ssn]"]}"#.to_vec())
        );
    }

    fn active_with_modes(
        config: Config,
        change: impl FnOnce(&mut contract::FailureModes),
    ) -> Arc<ActivePolicy> {
        let snapshot = builtin_with(|snapshot| change(&mut snapshot.settings.failure_modes));
        TestProxy::new(config, snapshot).state.policy()
    }

    #[tokio::test]
    async fn bodies_that_cannot_be_read_are_blocked_by_default() {
        let blocking = active(&[]);
        let blocked = screen_json(&blocking, "not json");
        assert!(matches!(blocked.outcome, Outcome::Block { .. }));
        assert!(blocked.fail_open.is_empty());
        let unknown_encoding =
            screen_body(&blocking, Format::Json, Some(b"br"), b"{}", DECODED_LIMIT);
        assert!(matches!(unknown_encoding.outcome, Outcome::Block { .. }));
        let oversized = screen_body(&blocking, Format::Json, None, &[b' '; 64], 8);
        assert!(
            matches!(oversized.outcome, Outcome::Block { .. }),
            "over the decoded-size limit"
        );
    }

    #[tokio::test]
    async fn bodies_that_cannot_be_read_pass_and_are_flagged_when_the_unscannable_mode_is_open() {
        let lenient = active_with_modes(Config::default(), |modes| {
            modes.unscannable = Some(FailMode::Open)
        });
        for screened in [
            screen_json(&lenient, "not json"),
            screen_body(&lenient, Format::Json, Some(b"br"), b"{}", DECODED_LIMIT),
            screen_body(&lenient, Format::Json, None, &[b' '; 64], 8),
        ] {
            assert_eq!(screened.outcome, Outcome::Allow);
            assert_eq!(screened.fail_open, [FailureCondition::Unscannable]);
        }
    }

    #[tokio::test]
    async fn local_configuration_can_close_what_the_server_opened_but_not_the_reverse() {
        let tightened = Config {
            block_unscannable: Some(true),
            ..Config::default()
        };
        let closed = active_with_modes(tightened, |modes| modes.default = Some(FailMode::Open));
        assert!(matches!(
            screen_json(&closed, "not json").outcome,
            Outcome::Block { .. }
        ));
        assert!(matches!(
            screen_body(&closed, Format::Json, None, b"{}", DECODED_LIMIT).outcome,
            Outcome::Allow
        ));
    }

    #[tokio::test]
    async fn a_scan_failure_follows_the_scan_error_mode() {
        let closed = active(&[]);
        let screened = on_failure(&closed, FailureCondition::ScanError, INTERNAL_ERROR, 0);
        assert!(matches!(
            screened.outcome,
            Outcome::Block { ref rule_ids, .. } if rule_ids == &["scan_error"]
        ));

        let open = active_with_modes(Config::default(), |modes| {
            modes.scan_error = Some(FailMode::Open)
        });
        let screened = on_failure(&open, FailureCondition::ScanError, INTERNAL_ERROR, 0);
        assert_eq!(screened.outcome, Outcome::Allow);
        assert_eq!(screened.fail_open, [FailureCondition::ScanError]);
    }

    #[tokio::test]
    async fn an_expired_policy_follows_the_policy_expired_mode() {
        let screen_expired = |mode: Option<FailMode>| {
            let snapshot =
                builtin_with(|snapshot| snapshot.settings.failure_modes.policy_expired = mode);
            let active = TestProxy::with_expiry(Config::default(), snapshot, Some(0))
                .state
                .policy();
            screen_json(&active, r#"{"parts":["hello"]}"#)
        };
        for mode in [None, Some(FailMode::Closed)] {
            let screened = screen_expired(mode);
            assert!(matches!(
                screened.outcome,
                Outcome::Block { ref rule_ids, .. } if rule_ids == &["policy_expired"]
            ));
        }
        let open = screen_expired(Some(FailMode::Open));
        assert_eq!(open.outcome, Outcome::Allow);
        assert_eq!(open.fail_open, [FailureCondition::PolicyExpired]);
    }

    #[tokio::test]
    async fn the_model_name_is_read_from_json_bodies() {
        let screened = screen_json(&active(&[]), r#"{"model":"m1","messages":[]}"#);
        assert_eq!(screened.model, "m1");
    }

    #[tokio::test]
    async fn websocket_text_is_screened_when_json_and_ignored_otherwise() {
        let redacting = active(&["ssn"]);
        assert!(screen_websocket_text(&redacting, "ping").is_none());
        let screened =
            screen_websocket_text(&redacting, &format!(r#"{{"t":"{SSN_TEXT}"}}"#)).unwrap();
        assert!(matches!(screened.outcome, Outcome::Rewrite(_)));
        let blocking = active(&[]);
        let screened =
            screen_websocket_text(&blocking, &format!(r#"{{"t":"{SSN_TEXT}"}}"#)).unwrap();
        assert!(matches!(screened.outcome, Outcome::Block { .. }));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_huge_body_is_scanned_without_stalling_other_connections() {
        let ticks = Arc::new(AtomicUsize::new(0));
        let counter = ticks.clone();
        let ticker = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(1)).await;
                counter.fetch_add(1, Ordering::Relaxed);
            }
        });
        let messages: Vec<serde_json::Value> = (0..3000)
            .map(|index| serde_json::json!({"content": format!("message {index}: {}", "ordinary chat text ".repeat(100))}))
            .collect();
        let body = Bytes::from(serde_json::json!({ "messages": messages }).to_string());
        assert!(body.len() > OFFLOAD_BYTES * 20);

        let screened =
            screen_body_offloaded(active(&[]), Format::Json, None, body, HUGE_DECODED_LIMIT).await;
        let ticks_during_scan = ticks.load(Ordering::Relaxed);
        ticker.abort();
        assert_eq!(screened.outcome, Outcome::Allow);
        assert!(
            ticks_during_scan >= 5,
            "other tasks only got {ticks_during_scan} turns while a big body was scanned"
        );
    }

    #[tokio::test]
    async fn big_and_small_bodies_get_the_same_verdict() {
        let padding = "x ".repeat(OFFLOAD_BYTES);
        let cases = [
            (SSN_TEXT.to_string(), true),
            (format!("{padding} {SSN_TEXT}"), true),
            (padding.clone(), false),
        ];
        for (text, blocked) in cases {
            let body = Bytes::from(serde_json::json!({ "parts": [text] }).to_string());
            let size = body.len();
            let screened =
                screen_body_offloaded(active(&[]), Format::Json, None, body, DECODED_LIMIT).await;
            assert_eq!(
                matches!(screened.outcome, Outcome::Block { .. }),
                blocked,
                "{size} bytes"
            );
        }
    }
}
