//! The policy step: what to do with a scan, given the effective configuration.
use crate::scan::Report;
use crate::settings::Effective;
use contract::{Action, FailMode, FailureCondition};

pub const UNSCANNABLE_RULE_ID: &str = "unscannable";
pub const TOKEN_LIMIT_RULE_ID: &str = "token_limit";
/// Rough size estimate, good enough for a limit that only has to catch runaway requests.
const BYTES_PER_TOKEN: usize = 4;
const BLOCK_TAG: &str = "[INVEIL BLOCKED]";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    /// Nothing blocks, but `redact` rules matched: send the redacted body.
    Redact {
        rule_ids: Vec<String>,
    },
    Block {
        rule_ids: Vec<String>,
        /// Shown to the user in the tool's own error.
        message: String,
    },
    /// Dry run: this request would have been blocked, and is let through.
    DryRun {
        rule_ids: Vec<String>,
        message: String,
    },
}

pub fn estimate_tokens(body_len: usize) -> usize {
    body_len / BYTES_PER_TOKEN
}

fn push_unique(items: &mut Vec<String>, item: String) {
    if !items.contains(&item) {
        items.push(item);
    }
}

/// Anything that cannot be read safely is a reason to block unless the `unscannable` failure mode is `open`, in which
/// case the caller lets it through and records the pass-through (see `Report::unscannable`).
pub fn decide(report: &Report, effective: &Effective, estimated_tokens: usize) -> Decision {
    let mut rule_ids = Vec::new();
    let mut reasons = Vec::new();
    let mut add = |rule_id: &str, reason: String| {
        push_unique(&mut reasons, reason);
        push_unique(&mut rule_ids, rule_id.to_string());
    };
    for finding in report
        .findings
        .iter()
        .filter(|finding| finding.action == Action::Block)
    {
        add(
            &finding.rule_id,
            format!("{} in {}", finding.label, finding.location),
        );
    }
    if effective.failure_modes.mode(FailureCondition::Unscannable) == FailMode::Closed {
        for location in &report.unscannable {
            add(
                UNSCANNABLE_RULE_ID,
                format!("image/document in {location} cannot be scanned"),
            );
        }
    }
    if effective.max_tokens > 0 && estimated_tokens > effective.max_tokens {
        add(
            TOKEN_LIMIT_RULE_ID,
            format!(
                "request too large (~{estimated_tokens} tokens, limit {})",
                effective.max_tokens
            ),
        );
    }

    if !reasons.is_empty() {
        let message = format!(
            "{BLOCK_TAG} {}. Nothing was sent. Edit or rewind the flagged message and resend.",
            reasons.join(", ")
        );
        if effective.dry_run {
            return Decision::DryRun { rule_ids, message };
        }
        return Decision::Block { rule_ids, message };
    }
    if !report.wants_redaction() {
        return Decision::Allow;
    }
    let rule_ids = report
        .findings
        .iter()
        .filter(|finding| finding.action == Action::Redact)
        .fold(Vec::new(), |mut ids, finding| {
            push_unique(&mut ids, finding.rule_id.clone());
            ids
        });
    Decision::Redact { rule_ids }
}

/// The message for a request that could not be read at all (undecodable, not JSON, over the size cap).
pub fn unreadable_message(why: &str) -> String {
    format!("{BLOCK_TAG} {why}. Nothing was sent.")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detector::Finding;
    use crate::settings::merge_settings;
    use crate::test_support::local_settings;

    fn effective(adjust: impl FnOnce(&mut Effective)) -> Effective {
        let mut effective =
            merge_settings(&local_settings(), &contract::Settings::default()).unwrap();
        adjust(&mut effective);
        effective
    }

    fn finding(rule_id: &str, location: &str, action: Action) -> Finding {
        Finding {
            rule_id: rule_id.into(),
            label: format!("{rule_id} label"),
            location: location.into(),
            hash: 0,
            action,
        }
    }

    fn report(findings: Vec<Finding>, unscannable: Vec<&str>) -> Report {
        Report {
            findings,
            unscannable: unscannable.into_iter().map(String::from).collect(),
        }
    }

    #[test]
    fn a_clean_request_and_log_only_findings_are_allowed() {
        assert_eq!(
            decide(&report(vec![], vec![]), &effective(|_| {}), 10),
            Decision::Allow
        );
        let logged = report(vec![finding("email", "message 1", Action::Log)], vec![]);
        assert_eq!(decide(&logged, &effective(|_| {}), 10), Decision::Allow);
    }

    #[test]
    fn a_block_finding_blocks_with_the_rule_and_a_user_message() {
        let scan = report(
            vec![
                finding("ssn", "message 2", Action::Block),
                finding("ssn", "message 2", Action::Block),
                finding("card", "system", Action::Block),
            ],
            vec![],
        );
        let Decision::Block { rule_ids, message } = decide(&scan, &effective(|_| {}), 10) else {
            panic!("expected a block");
        };
        assert_eq!(rule_ids, ["ssn", "card"]);
        assert!(
            message.contains("ssn label in message 2, card label in system"),
            "{message}"
        );
        assert!(message.starts_with("[INVEIL BLOCKED]"));
    }

    #[test]
    fn dry_run_reports_the_block_without_enforcing_it() {
        let scan = report(vec![finding("ssn", "message 1", Action::Block)], vec![]);
        let decision = decide(&scan, &effective(|e| e.dry_run = true), 10);
        assert!(matches!(decision, Decision::DryRun { ref rule_ids, .. } if rule_ids == &["ssn"]));
    }

    #[test]
    fn redact_findings_redact_when_nothing_blocks_and_block_wins_otherwise() {
        let scan = report(vec![finding("ssn", "m", Action::Redact)], vec![]);
        assert_eq!(
            decide(&scan, &effective(|_| {}), 10),
            Decision::Redact {
                rule_ids: vec!["ssn".into()]
            }
        );
        let mixed = report(
            vec![
                finding("ssn", "m", Action::Redact),
                finding("card", "m", Action::Block),
            ],
            vec![],
        );
        assert!(matches!(
            decide(&mixed, &effective(|_| {}), 10),
            Decision::Block { .. }
        ));
    }

    #[test]
    fn unscannable_media_blocks_unless_the_failure_mode_is_open() {
        let scan = report(vec![], vec!["message 3"]);
        let Decision::Block { rule_ids, message } = decide(&scan, &effective(|_| {}), 10) else {
            panic!("expected a block");
        };
        assert_eq!(rule_ids, [UNSCANNABLE_RULE_ID]);
        assert!(message.contains("message 3"));

        let open = effective(|e| e.failure_modes.unscannable = FailMode::Open);
        assert_eq!(decide(&scan, &open, 10), Decision::Allow);
    }

    #[test]
    fn requests_over_the_token_limit_are_blocked() {
        let scan = report(vec![], vec![]);
        let limited = effective(|e| e.max_tokens = 100);
        assert_eq!(decide(&scan, &limited, 100), Decision::Allow);
        assert!(matches!(
            decide(&scan, &limited, 101),
            Decision::Block { ref rule_ids, .. } if rule_ids == &[TOKEN_LIMIT_RULE_ID]
        ));
    }

    #[test]
    fn tokens_are_estimated_from_bytes() {
        assert_eq!(estimate_tokens(4000), 1000);
    }

    #[test]
    fn unreadable_requests_have_a_user_message() {
        assert_eq!(
            unreadable_message("request body is not valid JSON"),
            "[INVEIL BLOCKED] request body is not valid JSON. Nothing was sent."
        );
    }
}
