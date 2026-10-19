use crate::settings::LocalSettings;
use contract::{FailureModes, Snapshot};

pub const CA_DOMAINS: [&str; 5] = [
    "claude.ai",
    "chatgpt.com",
    "grok.com",
    "gemini.google.com",
    "cursor.sh",
];

pub fn example_snapshot() -> Snapshot {
    serde_json::from_str(include_str!("../../../examples/rules.json")).unwrap()
}

pub fn ca_domains() -> Vec<String> {
    CA_DOMAINS.map(String::from).to_vec()
}

pub fn local_settings() -> LocalSettings {
    LocalSettings {
        managed: false,
        offline: false,
        dry_run: false,
        failure_modes: FailureModes::default(),
        max_tokens: 0,
        deny: vec![],
        upstream: "https://api.anthropic.com".into(),
        usage_enabled: false,
        debug: false,
        poll_seconds: 60,
        client_version: "1.2.3".into(),
    }
}
