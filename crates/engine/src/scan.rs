//! Detectors for the signed regex rules and the `deny` list, and the walker that applies them to a JSON request.
use crate::detector::{salted_hash, Detector, Finding};
use crate::validators::{check_for, CheckFn};
use contract::{Action, PiiRule};
use regex::{Captures, Regex, RegexBuilder, RegexSet, RegexSetBuilder};
use serde_json::{Map, Value};
use std::borrow::Cow;
use std::collections::HashSet;
use std::sync::{Mutex, PoisonError};

/// Texts shorter than this are cheaper to scan again than to look up.
const CLEAN_CACHE_MIN_LEN: usize = 128;
/// Bound on remembered clean texts; the cache is emptied when it fills up.
const CLEAN_CACHE_MAX_ENTRIES: usize = 50_000;
/// Compiled size one pattern may reach. Patterns come from a server, so an unbounded one could exhaust memory.
pub const PATTERN_SIZE_LIMIT: usize = 1 << 20;
/// Compiled size all patterns of one detector may reach together.
const PATTERN_SET_SIZE_LIMIT: usize = 16 << 20;
const DENY_RULE_ID: &str = "deny";
const DENY_LABEL: &str = "Denied term";
const BODY_LOCATION: &str = "body";
const MESSAGES_KEY: &str = "messages";

#[derive(Debug, thiserror::Error)]
pub enum PatternError {
    #[error("rule '{rule_id}' has an invalid pattern: {reason}")]
    Invalid { rule_id: String, reason: String },
    #[error("rule '{rule_id}' compiles to more than {PATTERN_SIZE_LIMIT} bytes")]
    TooLarge { rule_id: String },
    #[error("the rule patterns together compile to more than {PATTERN_SET_SIZE_LIMIT} bytes")]
    SetTooLarge,
}

#[derive(Debug, Default)]
pub struct Report {
    pub findings: Vec<Finding>,
    /// Locations holding base64 images or documents that cannot be read.
    pub unscannable: Vec<String>,
}

impl Report {
    pub fn wants_redaction(&self) -> bool {
        self.findings
            .iter()
            .any(|finding| finding.action == Action::Redact)
    }
}

fn compile(rule_id: &str, pattern: &str) -> Result<Regex, PatternError> {
    RegexBuilder::new(pattern)
        .size_limit(PATTERN_SIZE_LIMIT)
        .build()
        .map_err(|error| match error {
            regex::Error::CompiledTooBig(_) => PatternError::TooLarge {
                rule_id: rule_id.to_string(),
            },
            other => PatternError::Invalid {
                rule_id: rule_id.to_string(),
                reason: other.to_string(),
            },
        })
}

fn compile_set(patterns: &[&str]) -> Result<RegexSet, PatternError> {
    RegexSetBuilder::new(patterns)
        .size_limit(PATTERN_SET_SIZE_LIMIT)
        .build()
        .map_err(|error| match error {
            regex::Error::CompiledTooBig(_) => PatternError::SetTooLarge,
            other => PatternError::Invalid {
                rule_id: "(rule set)".to_string(),
                reason: other.to_string(),
            },
        })
}

struct CompiledRule {
    id: String,
    label: String,
    regex: Regex,
    check: CheckFn,
    action: Action,
}

/// The signed `pii` rules.
pub struct RuleDetector {
    rules: Vec<CompiledRule>,
    /// All patterns in one automaton: a text is scanned once to learn which rules, if any, can match it.
    set: RegexSet,
    /// Hashes of long texts already scanned with no findings. Chat clients resend the whole conversation every
    /// turn, so most of a request was checked last time.
    clean: Mutex<HashSet<u64>>,
}

impl RuleDetector {
    /// Disabled rules are skipped. Any pattern that does not compile, or is too large, rejects the whole set.
    pub fn new(pii: &[PiiRule]) -> Result<Self, PatternError> {
        let mut rules = Vec::with_capacity(pii.len());
        for rule in pii.iter().filter(|rule| rule.enabled) {
            rules.push(CompiledRule {
                id: rule.id.clone(),
                label: rule.label.clone(),
                regex: compile(&rule.id, &rule.pattern)?,
                check: check_for(rule.validator),
                action: rule.action,
            });
        }
        let patterns: Vec<&str> = rules.iter().map(|rule| rule.regex.as_str()).collect();
        let set = compile_set(&patterns)?;
        Ok(Self {
            rules,
            set,
            clean: Mutex::new(HashSet::new()),
        })
    }

    fn remember_clean(&self, key: u64) {
        let mut clean = self.clean.lock().unwrap_or_else(PoisonError::into_inner);
        if clean.len() >= CLEAN_CACHE_MAX_ENTRIES {
            clean.clear();
        }
        clean.insert(key);
    }

    fn is_known_clean(&self, key: u64) -> bool {
        self.clean
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(&key)
    }
}

impl Detector for RuleDetector {
    fn detect(&self, text: &str, location: &str) -> Vec<Finding> {
        let cache_key = (text.len() >= CLEAN_CACHE_MIN_LEN).then(|| salted_hash(text));
        if cache_key.is_some_and(|key| self.is_known_clean(key)) {
            return Vec::new();
        }
        let mut findings = Vec::new();
        for index in self.set.matches(text).iter() {
            let rule = &self.rules[index];
            for found in rule
                .regex
                .find_iter(text)
                .filter(|found| (rule.check)(found.as_str()))
            {
                findings.push(Finding {
                    rule_id: rule.id.clone(),
                    label: rule.label.clone(),
                    location: location.to_string(),
                    hash: salted_hash(found.as_str()),
                    action: rule.action,
                });
            }
        }
        if let (Some(key), true) = (cache_key, findings.is_empty()) {
            self.remember_clean(key);
        }
        findings
    }

    fn redact(&self, text: &str) -> Option<String> {
        let mut redacted: Option<String> = None;
        for rule in self
            .rules
            .iter()
            .filter(|rule| rule.action == Action::Redact)
        {
            let current = redacted.as_deref().unwrap_or(text);
            let replaced = rule.regex.replace_all(current, |captures: &Captures| {
                if (rule.check)(&captures[0]) {
                    format!("[REDACTED:{}]", rule.id)
                } else {
                    captures[0].to_string()
                }
            });
            let Cow::Owned(replaced) = replaced else {
                continue;
            };
            if replaced != current {
                redacted = Some(replaced);
            }
        }
        redacted
    }
}

/// Regexes that always block: the local `deny` list plus the server's.
pub struct DenyDetector {
    regexes: Vec<Regex>,
    set: RegexSet,
}

impl DenyDetector {
    pub fn new(patterns: &[String]) -> Result<Self, PatternError> {
        let regexes = patterns
            .iter()
            .map(|pattern| compile(DENY_RULE_ID, pattern))
            .collect::<Result<Vec<_>, _>>()?;
        let sources: Vec<&str> = regexes.iter().map(Regex::as_str).collect();
        let set = compile_set(&sources)?;
        Ok(Self { regexes, set })
    }
}

impl Detector for DenyDetector {
    fn detect(&self, text: &str, location: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for index in self.set.matches(text).iter() {
            for found in self.regexes[index].find_iter(text) {
                findings.push(Finding {
                    rule_id: DENY_RULE_ID.to_string(),
                    label: DENY_LABEL.to_string(),
                    location: location.to_string(),
                    hash: salted_hash(found.as_str()),
                    action: Action::Block,
                });
            }
        }
        findings
    }
}

fn is_base64_media(fields: &Map<String, Value>) -> bool {
    let kind = fields.get("type").and_then(Value::as_str);
    let source = fields
        .get("source")
        .and_then(|source| source.get("type"))
        .and_then(Value::as_str);
    matches!(kind, Some("image" | "document")) && source == Some("base64")
}

/// Applies every detector to every string of a JSON request.
pub struct Scanner {
    detectors: Vec<Box<dyn Detector>>,
}

impl Scanner {
    pub fn new(detectors: Vec<Box<dyn Detector>>) -> Self {
        Self { detectors }
    }

    /// The standard set: the snapshot's rules and the deny list.
    pub fn from_rules(pii: &[PiiRule], deny: &[String]) -> Result<Self, PatternError> {
        Ok(Self::new(vec![
            Box::new(RuleDetector::new(pii)?),
            Box::new(DenyDetector::new(deny)?),
        ]))
    }

    /// Top-level `messages` are labelled by turn number, everything else by its key.
    pub fn scan(&self, body: &Value) -> Report {
        let mut report = Report::default();
        let Some(fields) = body.as_object() else {
            self.walk(body, BODY_LOCATION, &mut report);
            return report;
        };
        for (key, value) in fields {
            match (key.as_str(), value.as_array()) {
                (MESSAGES_KEY, Some(messages)) => {
                    for (index, message) in messages.iter().enumerate() {
                        self.walk(message, &format!("message {}", index + 1), &mut report);
                    }
                }
                _ => self.walk(value, key, &mut report),
            }
        }
        report
    }

    /// Replaces matches of `redact` rules in place with `[REDACTED:<rule id>]`. True if anything changed.
    pub fn redact(&self, body: &mut Value) -> bool {
        let mut changed = false;
        self.redact_value(body, &mut changed);
        changed
    }

    fn walk(&self, value: &Value, location: &str, report: &mut Report) {
        match value {
            Value::String(text) => {
                for detector in &self.detectors {
                    report.findings.extend(detector.detect(text, location));
                }
            }
            Value::Array(items) => items
                .iter()
                .for_each(|item| self.walk(item, location, report)),
            Value::Object(fields) => {
                if is_base64_media(fields) {
                    report.unscannable.push(location.to_string());
                    return;
                }
                fields
                    .values()
                    .for_each(|field| self.walk(field, location, report));
            }
            _ => {}
        }
    }

    fn redact_value(&self, value: &mut Value, changed: &mut bool) {
        match value {
            Value::String(text) => {
                for detector in &self.detectors {
                    let Some(redacted) = detector.redact(text) else {
                        continue;
                    };
                    *text = redacted;
                    *changed = true;
                }
            }
            Value::Array(items) => items
                .iter_mut()
                .for_each(|item| self.redact_value(item, changed)),
            Value::Object(fields) => {
                if is_base64_media(fields) {
                    return;
                }
                fields
                    .values_mut()
                    .for_each(|field| self.redact_value(field, changed));
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::example_snapshot;
    use serde_json::json;

    fn scanner(deny: &[&str]) -> Scanner {
        let deny: Vec<String> = deny.iter().map(ToString::to_string).collect();
        Scanner::from_rules(&example_snapshot().pii, &deny).unwrap()
    }

    fn found(body: &Value) -> Vec<(String, String)> {
        scanner(&["Project Falcon"])
            .scan(body)
            .findings
            .into_iter()
            .map(|finding| (finding.rule_id, finding.location))
            .collect()
    }

    fn message(text: &str) -> Value {
        json!({"messages":[
            {"role":"user","content":"hi"},
            {"role":"user","content":[{"type":"text","text":text}]}
        ]})
    }

    fn hit(text: &str, rule_id: &str) -> bool {
        found(&message(text)).contains(&(rule_id.into(), "message 2".into()))
    }

    fn rule(id: &str, pattern: &str) -> PiiRule {
        PiiRule {
            id: id.into(),
            label: id.into(),
            pattern: pattern.into(),
            validator: None,
            action: Action::Block,
            enabled: true,
        }
    }

    #[test]
    fn detects_each_kind_of_sensitive_data() {
        assert!(hit("card 4111 1111 1111 1111", "card"));
        assert!(hit("ssn 123-45-6789", "ssn"));
        assert!(hit("iban GB82WEST12345698765432", "iban"));
        assert!(hit("key AKIAIOSFODNN7EXAMPLE", "aws_key"));
        assert!(hit("sk-ant-api03-abcdefghijklmnopqrstuvwxyz", "api_key"));
        assert!(hit("-----BEGIN RSA PRIVATE KEY-----", "private_key"));
        assert!(hit("mail bob@example.com", "email"));
        assert!(hit("call +44 20 7946 0958", "phone"));
        assert!(hit("about Project Falcon", "deny"));
    }

    #[test]
    fn ignores_near_misses() {
        assert!(!hit("card 4111 1111 1111 1112", "card"));
        assert!(!hit("ssn 000-12-3456", "ssn"));
        assert!(!hit("iban GB82WEST12345698765433", "iban"));
        assert!(found(&message("fn main() { println!(\"hello\"); }")).is_empty());
    }

    #[test]
    fn walks_tool_results_and_system() {
        let tool_result = json!({"system":"x","messages":[{"content":[{"type":"tool_result","content":[{"type":"text","text":"123-45-6789"}]}]}]});
        assert_eq!(
            found(&tool_result),
            vec![("ssn".to_string(), "message 1".to_string())]
        );
        let system = json!({"system":"123-45-6789","messages":[]});
        assert_eq!(
            found(&system),
            vec![("ssn".to_string(), "system".to_string())]
        );
    }

    #[test]
    fn a_body_that_is_not_an_object_is_labelled_body() {
        let report = scanner(&[]).scan(&json!(["123-45-6789"]));
        assert_eq!(report.findings[0].location, "body");
    }

    #[test]
    fn flags_base64_images_as_unscannable() {
        let body = json!({"messages":[{"content":[{"type":"image","source":{"type":"base64","data":"AAAA"}}]}]});
        let report = Scanner::from_rules(&[], &[]).unwrap().scan(&body);
        assert_eq!(report.unscannable, vec!["message 1"]);
    }

    #[test]
    fn log_rules_report_findings_with_their_action() {
        let report = scanner(&[]).scan(&message("mail bob@example.com ssn 123-45-6789"));
        let action = |id: &str| {
            report
                .findings
                .iter()
                .find(|finding| finding.rule_id == id)
                .map(|finding| finding.action)
        };
        assert_eq!(action("email"), Some(Action::Log));
        assert_eq!(action("ssn"), Some(Action::Block));
    }

    #[test]
    fn redacts_matches_and_leaves_the_rest() {
        let mut pii = example_snapshot().pii;
        for rule in pii
            .iter_mut()
            .filter(|rule| rule.id == "ssn" || rule.id == "card")
        {
            rule.action = Action::Redact;
        }
        let scanner = Scanner::from_rules(&pii, &[]).unwrap();
        let mut body = message("ssn 123-45-6789, bad card 4111 1111 1111 1112");
        assert!(scanner.redact(&mut body));
        assert_eq!(
            body["messages"][1]["content"][0]["text"],
            "ssn [REDACTED:ssn], bad card 4111 1111 1111 1112"
        );
        assert!(!scanner.redact(&mut body));
    }

    #[test]
    fn redaction_skips_base64_media() {
        let mut pii = example_snapshot().pii;
        pii.push(PiiRule {
            action: Action::Redact,
            ..rule("aaaa", "AAAA")
        });
        let scanner = Scanner::from_rules(&pii, &[]).unwrap();
        let mut body = json!({"messages":[{"content":[{"type":"image","source":{"type":"base64","data":"AAAA"}}]}]});
        assert!(!scanner.redact(&mut body));
    }

    #[test]
    fn disabled_rules_do_not_fire() {
        let mut pii = example_snapshot().pii;
        for rule in &mut pii {
            rule.enabled = false;
        }
        let report = Scanner::from_rules(&pii, &[])
            .unwrap()
            .scan(&message("ssn 123-45-6789"));
        assert!(report.findings.is_empty());
    }

    #[test]
    fn a_repeated_clean_text_is_still_clean_and_a_dirty_one_is_never_cached() {
        let detector = RuleDetector::new(&example_snapshot().pii).unwrap();
        let clean = "nothing sensitive here ".repeat(10);
        assert!(detector.detect(&clean, "a").is_empty());
        assert!(detector.detect(&clean, "b").is_empty());
        let dirty = format!("{clean} 123-45-6789");
        assert_eq!(detector.detect(&dirty, "a").len(), 1);
        assert_eq!(detector.detect(&dirty, "a").len(), 1);
    }

    #[test]
    fn the_same_secret_gets_the_same_hash_and_different_secrets_differ() {
        let detector = RuleDetector::new(&example_snapshot().pii).unwrap();
        let first = detector.detect("123-45-6789", "a");
        let again = detector.detect("see 123-45-6789", "b");
        let other = detector.detect("123-45-6788", "a");
        assert_eq!(first[0].hash, again[0].hash);
        assert_ne!(first[0].hash, other[0].hash);
    }

    #[test]
    fn an_invalid_pattern_rejects_the_whole_rule_set() {
        let error = RuleDetector::new(&[rule("good", "a"), rule("bad", "(")]).err();
        assert!(matches!(error, Some(PatternError::Invalid { rule_id, .. }) if rule_id == "bad"));
        assert!(DenyDetector::new(&["(".to_string()]).is_err());
    }

    #[test]
    fn an_oversized_pattern_is_rejected_with_a_typed_error() {
        let huge = r"\p{L}{1000}\p{L}{1000}";
        let error = RuleDetector::new(&[rule("huge", huge)]).err();
        assert!(matches!(error, Some(PatternError::TooLarge { rule_id }) if rule_id == "huge"));
        assert!(matches!(
            DenyDetector::new(&[huge.to_string()]).err(),
            Some(PatternError::TooLarge { .. })
        ));
    }
}
