//! Strict validation of a snapshot after its signature has been checked: schema, size caps, and the shape of every
//! host, route, prefix and environment variable name, because those end up in routing, a PAC script and shell profiles.
use crate::signing::{
    verify_envelope, verify_envelope_as_issued, Role, Trust, Verified, VerifyError,
};
use contract::{Endpoint, Snapshot, Tool, Via, SNAPSHOT_SCHEMA};
use std::collections::HashSet;

const MAX_RULES: usize = 200;
const MAX_TOOLS: usize = 50;
const MAX_HOSTS: usize = 20;
const MAX_ENDPOINTS: usize = 20;
const MAX_CA_DOMAINS: usize = 50;
const MAX_DENY_PATTERNS: usize = 100;
const MAX_ALLOWED_UPSTREAMS: usize = 50;
const MAX_REVOKED_KEYS: usize = 100;
const MAX_HOST_LEN: usize = 253;
const MAX_PREFIX_LEN: usize = 33;
const MAX_ENDPOINT_PATH_LEN: usize = 200;
const MAX_PATTERN_LEN: usize = 1024;
const MAX_IDENTIFIER_LEN: usize = 64;
const MAX_LABEL_LEN: usize = 100;
const MIN_CA_DOMAIN_LABELS: usize = 2;
/// Second-level labels that country registries use as suffixes (`co.uk`, `com.au`, `ac.jp`, ...).
const REGISTRY_SECOND_LEVEL_LABELS: [&str; 9] =
    ["co", "com", "org", "net", "gov", "edu", "ac", "ne", "or"];
const COUNTRY_CODE_LABEL_LEN: usize = 2;
/// Hosting suffixes whose subdomains belong to unrelated tenants, so a CA scoped to one would cover strangers.
const SHARED_HOSTING_SUFFIXES: [&str; 14] = [
    "github.io",
    "gitlab.io",
    "herokuapp.com",
    "appspot.com",
    "vercel.app",
    "netlify.app",
    "pages.dev",
    "workers.dev",
    "web.app",
    "firebaseapp.com",
    "cloudfront.net",
    "amazonaws.com",
    "azurewebsites.net",
    "blogspot.com",
];
const SECONDS_PER_DAY: u64 = 86_400;
/// Longest a snapshot may stay valid, so a leaked old snapshot cannot be replayed for years.
pub const MAX_VALIDITY_SECONDS: u64 = 400 * SECONDS_PER_DAY;
/// Policy snapshots need one valid signature; update manifests state their own threshold.
pub const POLICY_SIGNATURE_THRESHOLD: usize = 1;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ValidationError {
    #[error("unsupported rules schema {0}")]
    UnsupportedSchema(u8),
    #[error("the snapshot version must be at least 1")]
    ZeroVersion,
    #[error("the snapshot must expire after it was issued, and within {} days", MAX_VALIDITY_SECONDS / SECONDS_PER_DAY)]
    BadValidityWindow,
    #[error("more than {max} {what}")]
    TooMany { what: &'static str, max: usize },
    #[error("invalid {what}: {value:?}")]
    Invalid { what: &'static str, value: String },
    #[error("tool {tool_id:?} does not fit its transport")]
    ToolTransport { tool_id: String },
}

#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    #[error(transparent)]
    Verify(#[from] VerifyError),
    #[error(transparent)]
    Invalid(#[from] ValidationError),
    #[error(
        "the signing key is delegated for audience {allowed:?} but the snapshot is for {found:?}"
    )]
    DelegationAudience {
        allowed: String,
        found: Option<String>,
    },
}

/// A registrable domain such as `claude.ai`. A single label (`com`) or a public suffix (`co.uk`, `github.io`) would let
/// the browser CA cover far more than one organisation. The suffix rules are deliberately short, not the full public
/// suffix list, so an unlisted suffix is still caught only by the two-label minimum.
fn valid_ca_domain(domain: &str) -> bool {
    if !valid_host(domain) {
        return false;
    }
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < MIN_CA_DOMAIN_LABELS {
        return false;
    }
    if SHARED_HOSTING_SUFFIXES.contains(&domain) {
        return false;
    }
    let is_registry_suffix = labels.len() == 2
        && REGISTRY_SECOND_LEVEL_LABELS.contains(&labels[0])
        && labels[1].len() == COUNTRY_CODE_LABEL_LEN;
    !is_registry_suffix
}

fn invalid(what: &'static str, value: &str) -> ValidationError {
    ValidationError::Invalid {
        what,
        value: value.to_string(),
    }
}

fn check_count(what: &'static str, count: usize, max: usize) -> Result<(), ValidationError> {
    if count > max {
        return Err(ValidationError::TooMany { what, max });
    }
    Ok(())
}

/// A plain lower-case DNS name: nothing that could break out of a PAC script or a URL.
pub fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= MAX_HOST_LEN
        && host
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
        && !host.starts_with(['.', '-'])
        && !host.ends_with(['.', '-'])
        && !host.contains("..")
}

/// `https://host` with nothing after the host.
pub fn valid_https_origin(origin: &str) -> bool {
    origin.strip_prefix("https://").is_some_and(valid_host)
}

fn valid_identifier(identifier: &str) -> bool {
    !identifier.is_empty()
        && identifier.len() <= MAX_IDENTIFIER_LEN
        && identifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn valid_env_var(name: &str) -> bool {
    let mut bytes = name.bytes();
    let starts_well = bytes
        .next()
        .is_some_and(|b| b.is_ascii_uppercase() || b == b'_');
    starts_well
        && name.len() <= MAX_IDENTIFIER_LEN
        && bytes.all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

fn valid_prefix(prefix: &str) -> bool {
    prefix.len() <= MAX_PREFIX_LEN
        && prefix.strip_prefix('/').is_some_and(|name| {
            !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

fn check_endpoints(endpoints: &[Endpoint]) -> Result<(), ValidationError> {
    check_count("endpoints", endpoints.len(), MAX_ENDPOINTS)?;
    let bad = endpoints.iter().find(|endpoint| {
        !endpoint.path.starts_with('/')
            || endpoint.path.len() > MAX_ENDPOINT_PATH_LEN
            || !endpoint.path.bytes().all(|b| b.is_ascii_graphic())
    });
    match bad {
        Some(endpoint) => Err(invalid("endpoint path", &endpoint.path)),
        None => Ok(()),
    }
}

fn check_tool(tool: &Tool) -> Result<(), ValidationError> {
    if !valid_identifier(&tool.id) {
        return Err(invalid("tool id", &tool.id));
    }
    let fits_transport = match tool.via {
        Via::Local => tool.upstream.is_some() && tool.hosts.is_empty(),
        Via::Browser => {
            tool.upstream.is_none()
                && tool.prefix.is_none()
                && tool.env_var.is_none()
                && tool.endpoints.is_empty()
                && !tool.hosts.is_empty()
        }
    };
    if !fits_transport || tool.hosts.len() > MAX_HOSTS {
        return Err(ValidationError::ToolTransport {
            tool_id: tool.id.clone(),
        });
    }
    if let Some(prefix) = tool
        .prefix
        .as_deref()
        .filter(|prefix| !valid_prefix(prefix))
    {
        return Err(invalid("tool prefix", prefix));
    }
    if let Some(name) = tool.env_var.as_deref().filter(|name| !valid_env_var(name)) {
        return Err(invalid("environment variable name", name));
    }
    if let Some(upstream) = tool
        .upstream
        .as_deref()
        .filter(|upstream| !valid_https_origin(upstream))
    {
        return Err(invalid("upstream", upstream));
    }
    check_endpoints(&tool.endpoints)?;
    for host in &tool.hosts {
        if !valid_host(&host.host) {
            return Err(invalid("host", &host.host));
        }
        check_endpoints(&host.endpoints)?;
    }
    Ok(())
}

fn check_tools(tools: &[Tool]) -> Result<(), ValidationError> {
    check_count("tools", tools.len(), MAX_TOOLS)?;
    let mut ids = HashSet::new();
    let mut local_prefixes = HashSet::new();
    for tool in tools {
        check_tool(tool)?;
        if !ids.insert(tool.id.as_str()) {
            return Err(invalid("duplicate tool id", &tool.id));
        }
        if tool.via == Via::Local && !local_prefixes.insert(tool.prefix.as_deref()) {
            return Err(invalid("duplicate local tool prefix", &tool.id));
        }
    }
    Ok(())
}

fn check_pii(snapshot: &Snapshot) -> Result<(), ValidationError> {
    check_count("rules", snapshot.pii.len(), MAX_RULES)?;
    let mut ids = HashSet::new();
    for rule in &snapshot.pii {
        if !valid_identifier(&rule.id) || !ids.insert(rule.id.as_str()) {
            return Err(invalid("rule id", &rule.id));
        }
        if rule.label.is_empty() || rule.label.len() > MAX_LABEL_LEN {
            return Err(invalid("rule label", &rule.label));
        }
        if rule.pattern.is_empty() || rule.pattern.len() > MAX_PATTERN_LEN {
            return Err(invalid("rule pattern length", &rule.id));
        }
    }
    Ok(())
}

fn check_settings(snapshot: &Snapshot) -> Result<(), ValidationError> {
    let settings = &snapshot.settings;
    check_count("deny patterns", settings.deny.len(), MAX_DENY_PATTERNS)?;
    if let Some(pattern) = settings
        .deny
        .iter()
        .find(|pattern| pattern.is_empty() || pattern.len() > MAX_PATTERN_LEN)
    {
        return Err(invalid("deny pattern length", pattern));
    }
    check_count(
        "allowed upstreams",
        settings.allowed_upstreams.len(),
        MAX_ALLOWED_UPSTREAMS,
    )?;
    if let Some(origin) = settings
        .allowed_upstreams
        .iter()
        .find(|origin| !valid_https_origin(origin))
    {
        return Err(invalid("allowed upstream", origin));
    }
    check_count(
        "revoked keys",
        snapshot.revoked_key_ids.len(),
        MAX_REVOKED_KEYS,
    )?;
    if let Some(key_id) = snapshot
        .revoked_key_ids
        .iter()
        .find(|key_id| !valid_identifier(key_id))
    {
        return Err(invalid("revoked key id", key_id));
    }
    if let Some(audience) = snapshot
        .audience
        .as_deref()
        .filter(|audience| !valid_identifier(audience))
    {
        return Err(invalid("audience", audience));
    }
    Ok(())
}

/// Checks everything that does not need the clock, the stored high-water mark or the key store.
pub fn validate(snapshot: &Snapshot) -> Result<(), ValidationError> {
    if snapshot.schema != SNAPSHOT_SCHEMA {
        return Err(ValidationError::UnsupportedSchema(snapshot.schema));
    }
    if snapshot.version == 0 {
        return Err(ValidationError::ZeroVersion);
    }
    let window = snapshot.expires_at.checked_sub(snapshot.issued_at);
    if !window.is_some_and(|seconds| (1..=MAX_VALIDITY_SECONDS).contains(&seconds)) {
        return Err(ValidationError::BadValidityWindow);
    }
    check_pii(snapshot)?;
    check_tools(&snapshot.tools)?;
    check_count("CA domains", snapshot.ca_domains.len(), MAX_CA_DOMAINS)?;
    if let Some(domain) = snapshot
        .ca_domains
        .iter()
        .find(|domain| !valid_ca_domain(domain))
    {
        return Err(invalid("CA domain", domain));
    }
    check_settings(snapshot)
}

/// The one entry point for a signed policy snapshot: signature first, then strict parsing, then validation.
/// Freshness (rollback, expiry, audience) is a separate step, see [`crate::freshness`].
pub fn verify_snapshot(
    trust: &Trust,
    now: u64,
    envelope: &str,
) -> Result<Verified<Snapshot>, SnapshotError> {
    let verified = verify_envelope(
        Role::Policy,
        trust,
        POLICY_SIGNATURE_THRESHOLD,
        now,
        envelope,
    )?;
    check_verified(verified)
}

/// [`verify_snapshot`] for a snapshot accepted before and read back from the cache: a delegated key's certificate is
/// judged at the snapshot's own `issued_at`, so the snapshot stays loadable after the certificate has lapsed. Its own
/// expiry is a separate decision (see [`crate::freshness`]). Use it only for a snapshot whose content was already
/// accepted, never for one that just arrived.
pub fn verify_snapshot_as_issued(
    trust: &Trust,
    envelope: &str,
) -> Result<Verified<Snapshot>, SnapshotError> {
    let verified = verify_envelope_as_issued(
        Role::Policy,
        trust,
        POLICY_SIGNATURE_THRESHOLD,
        envelope,
        |snapshot: &Snapshot| snapshot.issued_at,
    )?;
    check_verified(verified)
}

fn check_verified(verified: Verified<Snapshot>) -> Result<Verified<Snapshot>, SnapshotError> {
    validate(&verified.value)?;
    if let Some(allowed) = &verified.delegation_audience {
        if verified.value.audience.as_deref() != Some(allowed.as_str()) {
            return Err(SnapshotError::DelegationAudience {
                allowed: allowed.clone(),
                found: verified.value.audience.clone(),
            });
        }
    }
    Ok(verified)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::{public_key_of, sign_payload, PinnedKey};
    use crate::test_support::example_snapshot;
    use contract::{Host, Match, PiiRule, SignedEnvelope};
    use ring::rand::SystemRandom;
    use ring::signature::Ed25519KeyPair;

    const NOW: u64 = 1_800_000_000;

    fn signed_with_new_key(payload: &str) -> (String, Trust) {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .unwrap()
            .as_ref()
            .to_vec();
        let signature = sign_payload(Role::Policy, "policy", &pkcs8, payload).unwrap();
        let envelope = serde_json::to_string(&SignedEnvelope {
            payload: payload.into(),
            signatures: vec![signature],
            delegation: None,
        })
        .unwrap();
        let trust = Trust {
            keys: vec![PinnedKey {
                key_id: "policy".into(),
                public_key: public_key_of(&pkcs8).unwrap(),
            }],
            roots: vec![],
            ..Trust::default()
        };
        (envelope, trust)
    }

    fn browser_tool(host: &str, path: &str) -> Tool {
        Tool {
            id: "t".into(),
            name: "T".into(),
            via: Via::Browser,
            enabled: true,
            upstream: None,
            prefix: None,
            env_var: None,
            endpoints: vec![],
            hosts: vec![Host {
                host: host.into(),
                endpoints: vec![Endpoint {
                    path: path.into(),
                    matching: Match::Exact,
                    format: contract::Format::Json,
                }],
            }],
        }
    }

    fn local_tool(id: &str, upstream: Option<&str>, prefix: Option<&str>) -> Tool {
        Tool {
            id: id.into(),
            name: id.into(),
            via: Via::Local,
            enabled: true,
            upstream: upstream.map(String::from),
            prefix: prefix.map(String::from),
            env_var: None,
            endpoints: vec![],
            hosts: vec![],
        }
    }

    fn with_tools(tools: Vec<Tool>) -> Snapshot {
        Snapshot {
            tools,
            ..example_snapshot()
        }
    }

    #[test]
    fn the_example_catalog_is_valid_and_has_both_transports() {
        let snapshot = example_snapshot();
        validate(&snapshot).unwrap();
        assert!(snapshot.tools.iter().any(|tool| tool.via == Via::Local));
        assert!(snapshot.tools.iter().any(|tool| tool.via == Via::Browser));
    }

    #[test]
    fn host_names_must_be_plain() {
        assert!(valid_host("claude.ai") && valid_host("a-b.example.com"));
        for bad in [
            "",
            ".claude.ai",
            "claude.ai.",
            "a..b",
            "Claude.ai",
            "a b",
            "a\"b",
            "-a.com",
        ] {
            assert!(!valid_host(bad), "{bad:?}");
        }
    }

    #[test]
    fn schema_version_and_validity_window_are_checked() {
        let mut snapshot = example_snapshot();
        snapshot.schema = 2;
        assert_eq!(
            validate(&snapshot),
            Err(ValidationError::UnsupportedSchema(2))
        );

        let mut snapshot = example_snapshot();
        snapshot.version = 0;
        assert_eq!(validate(&snapshot), Err(ValidationError::ZeroVersion));

        let mut snapshot = example_snapshot();
        snapshot.expires_at = snapshot.issued_at;
        assert_eq!(validate(&snapshot), Err(ValidationError::BadValidityWindow));

        let mut snapshot = example_snapshot();
        snapshot.expires_at = snapshot.issued_at + MAX_VALIDITY_SECONDS + 1;
        assert_eq!(validate(&snapshot), Err(ValidationError::BadValidityWindow));
    }

    #[test]
    fn ca_domains_must_be_registrable_domains() {
        for domain in [
            "claude.ai",
            "chatgpt.com",
            "gemini.google.com",
            "example.co.uk",
        ] {
            assert!(valid_ca_domain(domain), "{domain}");
        }
        for domain in [
            "com",
            "ai",
            "co.uk",
            "com.au",
            "github.io",
            "vercel.app",
            "Claude.ai",
            "",
        ] {
            assert!(!valid_ca_domain(domain), "{domain}");
        }
        let mut snapshot = example_snapshot();
        snapshot.ca_domains = vec!["co.uk".into()];
        assert!(matches!(
            validate(&snapshot),
            Err(ValidationError::Invalid {
                what: "CA domain",
                ..
            })
        ));
    }

    #[test]
    fn size_caps_are_enforced() {
        let mut snapshot = example_snapshot();
        snapshot.ca_domains = vec!["a.example".into(); MAX_CA_DOMAINS + 1];
        assert!(matches!(
            validate(&snapshot),
            Err(ValidationError::TooMany {
                what: "CA domains",
                ..
            })
        ));

        let mut snapshot = example_snapshot();
        let rule = snapshot.pii[0].clone();
        snapshot.pii = (0..=MAX_RULES)
            .map(|index| PiiRule {
                id: format!("r{index}"),
                ..rule.clone()
            })
            .collect();
        assert!(matches!(
            validate(&snapshot),
            Err(ValidationError::TooMany { what: "rules", .. })
        ));
    }

    #[test]
    fn rejects_hosts_paths_and_upstreams_that_are_not_plain() {
        let bad_tools = [
            browser_tool("Bad.Host", "/x"),
            browser_tool("x.com", "nope"),
            browser_tool("x.com", "/has space"),
            local_tool("t", None, None),
            local_tool("t", Some("http://x.com"), None),
            local_tool("t", Some("https://x.com/path"), None),
            local_tool("t", Some("https://x.com"), Some("/Bad")),
            local_tool("t", Some("https://x.com"), Some("nope")),
        ];
        for tool in bad_tools {
            assert!(
                validate(&with_tools(vec![tool.clone()])).is_err(),
                "{tool:?}"
            );
        }
    }

    #[test]
    fn a_tool_must_fit_its_transport() {
        let mut browser = browser_tool("x.com", "/x");
        browser.upstream = Some("https://x.com".into());
        assert!(matches!(
            validate(&with_tools(vec![browser])),
            Err(ValidationError::ToolTransport { .. })
        ));
        let mut local = local_tool("t", Some("https://x.com"), None);
        local.hosts = browser_tool("x.com", "/x").hosts;
        assert!(matches!(
            validate(&with_tools(vec![local])),
            Err(ValidationError::ToolTransport { .. })
        ));
    }

    #[test]
    fn environment_variable_names_cannot_carry_shell_syntax() {
        for name in ["", "lower", "A B", "A;rm -rf", "A=B", "1A", "A$(x)"] {
            let mut tool = local_tool("t", Some("https://x.com"), None);
            tool.env_var = Some(name.into());
            assert!(validate(&with_tools(vec![tool])).is_err(), "{name:?}");
        }
        let mut tool = local_tool("t", Some("https://x.com"), None);
        tool.env_var = Some("ANTHROPIC_BASE_URL".into());
        validate(&with_tools(vec![tool])).unwrap();
    }

    #[test]
    fn tool_ids_and_local_prefixes_cannot_collide() {
        let first = local_tool("a", Some("https://x.com"), Some("/p"));
        let same_id = local_tool("a", Some("https://x.com"), Some("/q"));
        let same_prefix = local_tool("b", Some("https://x.com"), Some("/p"));
        assert!(validate(&with_tools(vec![first.clone(), same_id])).is_err());
        assert!(validate(&with_tools(vec![first, same_prefix])).is_err());
        let default_a = local_tool("a", Some("https://x.com"), None);
        let default_b = local_tool("b", Some("https://x.com"), None);
        assert!(validate(&with_tools(vec![default_a, default_b])).is_err());
    }

    #[test]
    fn rule_ids_must_be_plain_and_unique() {
        let mut snapshot = example_snapshot();
        snapshot.pii[0].id = "bad id\n".into();
        assert!(validate(&snapshot).is_err());
        let mut snapshot = example_snapshot();
        snapshot.pii[1].id = snapshot.pii[0].id.clone();
        assert!(validate(&snapshot).is_err());
    }

    #[test]
    fn settings_must_be_well_formed() {
        let mut snapshot = example_snapshot();
        snapshot.settings.allowed_upstreams = vec!["http://api.example".into()];
        assert!(validate(&snapshot).is_err());
        let mut snapshot = example_snapshot();
        snapshot.settings.deny = vec![String::new()];
        assert!(validate(&snapshot).is_err());
        let mut snapshot = example_snapshot();
        snapshot.audience = Some("not valid".into());
        assert!(validate(&snapshot).is_err());
    }

    #[test]
    fn a_signed_snapshot_that_breaks_the_strict_format_is_rejected() {
        let valid = serde_json::to_string(&example_snapshot()).unwrap();
        let unknown_field = valid.replacen('{', r#"{"extra":true,"#, 1);
        let bad_domain = valid.replace("claude.ai", "bad host");
        let wrong_schema = valid.replacen(r#""schema":1"#, r#""schema":2"#, 1);
        for payload in [unknown_field, bad_domain, wrong_schema] {
            let (envelope, trust) = signed_with_new_key(&payload);
            assert!(
                verify_snapshot(&trust, NOW, &envelope).is_err(),
                "{payload}"
            );
        }
    }

    #[test]
    fn a_correctly_signed_valid_snapshot_is_accepted() {
        let payload = serde_json::to_string(&example_snapshot()).unwrap();
        let (envelope, trust) = signed_with_new_key(&payload);
        let verified = verify_snapshot(&trust, NOW, &envelope).unwrap();
        assert_eq!(verified.value, example_snapshot());
    }

    #[test]
    fn a_snapshot_signed_by_an_unknown_key_is_rejected() {
        let payload = serde_json::to_string(&example_snapshot()).unwrap();
        let (envelope, _) = signed_with_new_key(&payload);
        let (_, other_trust) = signed_with_new_key(&payload);
        assert!(matches!(
            verify_snapshot(&other_trust, NOW, &envelope),
            Err(SnapshotError::Verify(_))
        ));
    }

    fn delegated_snapshot(
        delegation_audience: Option<&str>,
        snapshot_audience: Option<&str>,
    ) -> (String, Trust) {
        let random = SystemRandom::new();
        let generate = || {
            Ed25519KeyPair::generate_pkcs8(&random)
                .unwrap()
                .as_ref()
                .to_vec()
        };
        let (root_pkcs8, policy_pkcs8) = (generate(), generate());
        let mut delegation = contract::Delegation {
            key_id: "policy-1".into(),
            public_key: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                public_key_of(&policy_pkcs8).unwrap(),
            ),
            not_before: NOW - 10,
            not_after: NOW + 10,
            audience: delegation_audience.map(String::from),
            root_key_id: "root".into(),
            signature: String::new(),
        };
        delegation.signature = crate::signing::sign_delegation("root", &root_pkcs8, &delegation)
            .unwrap()
            .signature;
        let mut snapshot = example_snapshot();
        snapshot.audience = snapshot_audience.map(String::from);
        let payload = serde_json::to_string(&snapshot).unwrap();
        let signature = sign_payload(Role::Policy, "policy-1", &policy_pkcs8, &payload).unwrap();
        let envelope = serde_json::to_string(&SignedEnvelope {
            payload,
            signatures: vec![signature],
            delegation: Some(delegation),
        })
        .unwrap();
        let trust = Trust {
            keys: vec![],
            roots: vec![PinnedKey {
                key_id: "root".into(),
                public_key: public_key_of(&root_pkcs8).unwrap(),
            }],
            ..Trust::default()
        };
        (envelope, trust)
    }

    #[test]
    fn a_key_delegated_for_one_audience_cannot_sign_for_another() {
        let (envelope, trust) = delegated_snapshot(Some("acme"), Some("acme"));
        assert!(verify_snapshot(&trust, NOW, &envelope).is_ok());

        let (envelope, trust) = delegated_snapshot(Some("acme"), Some("globex"));
        assert!(matches!(
            verify_snapshot(&trust, NOW, &envelope),
            Err(SnapshotError::DelegationAudience { .. })
        ));

        let (envelope, trust) = delegated_snapshot(Some("acme"), None);
        assert!(matches!(
            verify_snapshot(&trust, NOW, &envelope),
            Err(SnapshotError::DelegationAudience { found: None, .. })
        ));
    }

    #[test]
    fn a_key_delegated_without_an_audience_may_sign_for_any() {
        let (envelope, trust) = delegated_snapshot(None, Some("globex"));
        assert!(verify_snapshot(&trust, NOW, &envelope).is_ok());
        let (envelope, trust) = delegated_snapshot(None, None);
        assert!(verify_snapshot(&trust, NOW, &envelope).is_ok());
    }
}
