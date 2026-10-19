//! The audit stream: one JSON line per request that had findings or was blocked. It records rule ids, locations and
//! salted hashes, never the matched text. A request let through because a failure mode is `open` has its own line
//! with `action: fail_open` and the `condition`. Without `logging.audit_file` the lines go to the normal log.
use crate::brand;
use crate::util::{lock, open_private_append, unix_seconds};
use contract::FailureCondition;
use engine::Finding;
use serde::Serialize;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    Allow,
    Redact,
    Block,
    DryRun,
    FailOpen,
    /// A request refused before it was read, because its path was ambiguous.
    Rejected,
}

#[derive(Debug, Serialize)]
struct AuditFinding<'a> {
    rule: &'a str,
    at: &'a str,
    hash: String,
}

#[derive(Debug, Serialize)]
struct AuditEntry<'a> {
    ts: u64,
    action: AuditAction,
    #[serde(skip_serializing_if = "Option::is_none")]
    condition: Option<FailureCondition>,
    destination: &'a str,
    tokens: usize,
    findings: Vec<AuditFinding<'a>>,
}

pub struct AuditLog {
    file: Option<Mutex<File>>,
}

impl AuditLog {
    pub fn open(path: Option<&Path>) -> std::io::Result<Self> {
        let file = match path {
            Some(path) => Some(Mutex::new(open_private_append(path)?)),
            None => None,
        };
        Ok(Self { file })
    }

    pub fn record(
        &self,
        action: AuditAction,
        destination: &str,
        tokens: usize,
        findings: &[Finding],
    ) {
        self.write(&AuditEntry {
            ts: unix_seconds(),
            action,
            condition: None,
            destination,
            tokens,
            findings: findings
                .iter()
                .map(|finding| AuditFinding {
                    rule: &finding.rule_id,
                    at: &finding.location,
                    hash: format!("{:016x}", finding.hash),
                })
                .collect(),
        });
    }

    pub fn record_fail_open(&self, condition: FailureCondition, destination: &str, tokens: usize) {
        self.write(&AuditEntry {
            ts: unix_seconds(),
            action: AuditAction::FailOpen,
            condition: Some(condition),
            destination,
            tokens,
            findings: vec![],
        });
    }

    fn write(&self, entry: &AuditEntry) {
        let Ok(line) = serde_json::to_string(entry) else {
            return;
        };
        let Some(file) = &self.file else {
            tracing::info!(target: brand::AUDIT_TARGET, "{line}");
            return;
        };
        if let Err(error) = writeln!(lock(file), "{line}") {
            tracing::warn!("cannot write the audit log: {error}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use contract::Action;

    #[test]
    fn entries_hold_rule_location_and_hash_but_no_content() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("audit.jsonl");
        let log = AuditLog::open(Some(&path)).unwrap();
        let finding = Finding {
            rule_id: "ssn".into(),
            label: "US Social Security number".into(),
            location: "message 1".into(),
            hash: 0xabc,
            action: Action::Block,
        };
        log.record(AuditAction::Block, "api.example.com", 12, &[finding]);
        let text = std::fs::read_to_string(path).unwrap();
        let entry: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
        assert_eq!(entry["action"], "block");
        assert_eq!(entry["findings"][0]["rule"], "ssn");
        assert_eq!(entry["findings"][0]["hash"], "0000000000000abc");
        assert!(!text.contains("US Social Security number"));
    }

    #[cfg(unix)]
    #[test]
    fn the_audit_file_is_owner_only_even_when_it_already_existed_with_wider_rights() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("audit.jsonl");
        std::fs::write(&path, "").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        AuditLog::open(Some(&path)).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let fresh = directory.path().join("fresh.jsonl");
        AuditLog::open(Some(&fresh)).unwrap();
        let mode = std::fs::metadata(&fresh).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn a_fail_open_entry_names_the_condition_and_carries_no_findings() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("audit.jsonl");
        let log = AuditLog::open(Some(&path)).unwrap();
        log.record_fail_open(FailureCondition::Unscannable, "api.example.com", 3);
        let text = std::fs::read_to_string(path).unwrap();
        let entry: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
        assert_eq!(entry["action"], "fail_open");
        assert_eq!(entry["condition"], "unscannable");
        assert_eq!(entry["destination"], "api.example.com");
        assert_eq!(entry["findings"], serde_json::json!([]));
    }
}
