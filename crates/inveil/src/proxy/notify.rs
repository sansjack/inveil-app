//! Out-of-band notices: tell the person when something was redacted or blocked without putting anything in the chat
//! or the model's response. A notice names the destination and the kinds of data (the rule labels), never the data.
//! At most one is shown every few seconds, and delivery happens off the request path.
use crate::brand;
use crate::platform;
use crate::util::lock;
use contract::Action;
use engine::Finding;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const MIN_GAP: Duration = Duration::from_secs(8);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Redacted,
    Blocked,
}

pub struct Notifier {
    enabled: bool,
    last_shown: Mutex<Option<Instant>>,
}

impl Notifier {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            last_shown: Mutex::new(None),
        }
    }

    /// Fire and forget. `destination` is a host or tool name.
    pub fn notify(&self, kind: Kind, destination: &str, findings: &[Finding]) {
        if !self.enabled {
            return;
        }
        let Some(message) = describe(kind, destination, findings) else {
            return;
        };
        if !self.allow(Instant::now()) {
            tracing::debug!("notice held back (one per {}s)", MIN_GAP.as_secs());
            return;
        }
        tokio::task::spawn_blocking(move || {
            if let Err(error) = platform::notify(brand::NOTIFICATION_TITLE, &message) {
                tracing::debug!("notification not shown: {error}");
            }
        });
    }

    fn allow(&self, now: Instant) -> bool {
        let mut last = lock(&self.last_shown);
        if last.is_some_and(|last| now.duration_since(last) < MIN_GAP) {
            return false;
        }
        *last = Some(now);
        true
    }
}

/// "Redacted 2 items before sending to chatgpt.com: Email address, US Social Security number", or `None` when the
/// findings contain nothing of that kind.
fn describe(kind: Kind, destination: &str, findings: &[Finding]) -> Option<String> {
    let wanted = match kind {
        Kind::Redacted => Action::Redact,
        Kind::Blocked => Action::Block,
    };
    let matching: Vec<&Finding> = findings
        .iter()
        .filter(|finding| finding.action == wanted)
        .collect();
    if matching.is_empty() {
        return None;
    }
    let mut labels: Vec<&str> = matching
        .iter()
        .map(|finding| finding.label.as_str())
        .collect();
    labels.sort_unstable();
    labels.dedup();
    let labels = labels.join(", ");
    let count = matching.len();
    Some(match kind {
        Kind::Redacted => {
            let plural = if count == 1 { "" } else { "s" };
            format!("Redacted {count} item{plural} before sending to {destination}: {labels}")
        }
        Kind::Blocked => format!("Blocked a message to {destination}: it contains {labels}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(label: &str, action: Action) -> Finding {
        Finding {
            rule_id: "r".into(),
            label: label.into(),
            location: "m".into(),
            hash: 1,
            action,
        }
    }

    #[test]
    fn notices_name_the_kinds_of_data_and_only_the_matching_action() {
        let findings = [
            finding("Email address", Action::Redact),
            finding("Email address", Action::Redact),
            finding("US Social Security number", Action::Block),
        ];
        assert_eq!(
            describe(Kind::Redacted, "chatgpt.com", &findings).unwrap(),
            "Redacted 2 items before sending to chatgpt.com: Email address"
        );
        assert_eq!(
            describe(Kind::Blocked, "chatgpt.com", &findings).unwrap(),
            "Blocked a message to chatgpt.com: it contains US Social Security number"
        );
        assert!(describe(Kind::Blocked, "x", &[finding("a", Action::Log)]).is_none());
    }

    #[test]
    fn at_most_one_notice_per_gap() {
        let notifier = Notifier::new(true);
        let start = Instant::now();
        assert!(notifier.allow(start));
        assert!(!notifier.allow(start + Duration::from_secs(1)));
        assert!(notifier.allow(start + MIN_GAP));
    }
}
