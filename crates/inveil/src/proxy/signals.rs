//! Works out how a request is billed, which model answered and who served it, from a table of narrow signals
//! (`builtin_signals.json`). Each signal feeds one fact and carries a human-readable reason; the first signal that
//! matches a fact wins, and a fact no signal matches stays unknown. Credential headers are read here only to test
//! for presence or a short prefix and are dropped: no signal can copy a header value into an event.
use crate::backend::{MAX_MODEL_CHARS, MAX_PROVIDER_CHARS};
use axum::http::HeaderMap;
use contract::{Billing, UsageEvent};
use engine::{is_covered, normalize_host};
use regex::Regex;
use serde::Deserialize;
use serde_json::Value;
use std::cell::OnceCell;

const BUILTIN_SIGNALS: &str = include_str!("../builtin_signals.json");
const SUPPORTED_SCHEMA: u32 = 1;
const MAX_PREFIX_CHARS: usize = 16;
/// Headers that carry a credential. A response header signal may not read these.
const CREDENTIAL_HEADERS: [&str; 7] = [
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "api-key",
    "x-goog-api-key",
    "cookie",
    "set-cookie",
];

#[derive(Debug, thiserror::Error)]
pub enum SignalError {
    #[error("the signal table is unreadable: {0}")]
    Unreadable(serde_json::Error),
    #[error("the signal table has schema {0}, this client reads schema {SUPPORTED_SCHEMA}")]
    UnsupportedSchema(u32),
    #[error("signal `{id}` is invalid: {problem}")]
    Invalid { id: String, problem: String },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Table {
    schema: u32,
    signals: Vec<Signal>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Fact {
    Billing,
    Model,
    ServedBy,
}

/// When a billing signal applies. The header is only tested, never copied.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct When {
    #[serde(default)]
    always: bool,
    request_header: Option<String>,
    /// Compared against the credential after an optional `Bearer `, at most `MAX_PREFIX_CHARS` long.
    prefix: Option<String>,
}

/// Where a model or served-by value is read from: exactly one of the four locations. Request headers are not a
/// location, so a credential can never be read this way.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Extractor {
    /// One capture group, matched against the request path.
    path_regex: Option<String>,
    /// JSON pointer into the request body.
    request_body: Option<String>,
    response_header: Option<String>,
    /// JSON pointer into the response body.
    response_body: Option<String>,
    /// Keep only the host of a URL value.
    #[serde(default)]
    host_only: bool,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Signal {
    id: String,
    /// A domain (also matches its subdomains), `*` for any host, or one `*` standing in for part of a host.
    host: String,
    path_prefix: Option<String>,
    sets: Fact,
    when: Option<When>,
    /// The billing for a billing signal (`api` or `subscription`), a fixed provider for a `served_by` signal.
    value: Option<String>,
    from: Option<Extractor>,
    reason: String,
    verified: bool,
    /// A public page the evidence for this signal comes from, and a string it must still contain. Only the
    /// scheduled evidence watch reads these; the proxy never does.
    evidence_url: Option<String>,
    evidence_contains: Option<String>,
    #[serde(skip)]
    billing: Billing,
    #[serde(skip)]
    path_pattern: Option<Regex>,
}

pub struct Signals {
    signals: Vec<Signal>,
}

/// What the signals found for one request. A fact no signal found stays at its default.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Evidence {
    pub billing: Billing,
    billing_signal: Option<String>,
    model: Option<String>,
    model_signal: Option<String>,
    served_by: Option<String>,
}

/// The request as the signals see it. The body is parsed at most once, and only if a signal reads it.
struct RequestView<'a> {
    path: &'a str,
    body: &'a [u8],
    parsed: OnceCell<Option<Value>>,
}

impl RequestView<'_> {
    fn json(&self) -> Option<&Value> {
        self.parsed
            .get_or_init(|| serde_json::from_slice(self.body).ok())
            .as_ref()
    }
}

/// Reads the response signals out of a response as it streams past. Created once the response headers are in.
#[derive(Default)]
pub struct ResponseReader {
    evidence: Evidence,
    pending: Vec<Signal>,
}

impl Signals {
    pub fn builtin() -> Result<Self, SignalError> {
        Self::parse(BUILTIN_SIGNALS)
    }

    pub fn parse(json: &str) -> Result<Self, SignalError> {
        let table: Table = serde_json::from_str(json).map_err(SignalError::Unreadable)?;
        if table.schema != SUPPORTED_SCHEMA {
            return Err(SignalError::UnsupportedSchema(table.schema));
        }
        let mut signals = table.signals;
        for signal in &mut signals {
            signal.prepare()?;
        }
        Ok(Self { signals })
    }

    /// Everything a request shows before it is sent. `headers` and `body` are the request's own; the first signal
    /// that matches each fact wins, in table order.
    pub fn classify_request(
        &self,
        host: &str,
        path: &str,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Evidence {
        let view = RequestView {
            path,
            body,
            parsed: OnceCell::new(),
        };
        let mut evidence = Evidence::default();
        for signal in self.matching(host, path) {
            if evidence.has(signal.sets) {
                continue;
            }
            match signal.sets {
                Fact::Billing => {
                    if signal.condition_holds(headers) {
                        evidence.billing = signal.billing;
                        evidence.billing_signal = Some(signal.id.clone());
                        signal.log_match();
                    }
                }
                Fact::Model => {
                    if let Some(model) = signal.read_request(&view) {
                        evidence.set_model(signal, model);
                    }
                }
                Fact::ServedBy => {
                    if let Some(served_by) = signal.fixed_or_read_request(&view) {
                        evidence.set_served_by(signal, served_by);
                    }
                }
            }
        }
        evidence
    }

    /// The signals that still have something to read in the response. Header signals are settled here; body
    /// signals wait for the stream.
    pub fn response_reader(
        &self,
        host: &str,
        path: &str,
        request: &Evidence,
        response_headers: &HeaderMap,
    ) -> ResponseReader {
        let mut reader = ResponseReader {
            evidence: request.clone(),
            pending: Vec::new(),
        };
        for signal in self.matching(host, path).filter(|s| s.reads_response()) {
            if reader.evidence.has(signal.sets) {
                continue;
            }
            let Some(extractor) = &signal.from else {
                continue;
            };
            let Some(name) = &extractor.response_header else {
                reader.pending.push(signal.clone());
                continue;
            };
            let value = response_headers
                .get(name.as_str())
                .and_then(|value| value.to_str().ok())
                .and_then(|value| extractor.finish(value));
            if let Some(value) = value {
                reader.evidence.set_from_response(signal, value);
            }
        }
        reader
    }

    fn matching<'a>(&'a self, host: &'a str, path: &'a str) -> impl Iterator<Item = &'a Signal> {
        self.signals.iter().filter(move |signal| {
            host_matches(&signal.host, host)
                && signal
                    .path_prefix
                    .as_ref()
                    .is_none_or(|prefix| path.starts_with(prefix.as_str()))
        })
    }
}

fn host_matches(pattern: &str, host: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let Some((before, after)) = pattern.split_once('*') else {
        return is_covered(host, std::slice::from_ref(&pattern.to_string()));
    };
    let host = normalize_host(host);
    host.len() > before.len() + after.len() && host.starts_with(before) && host.ends_with(after)
}

impl Signal {
    /// Checks the signal and compiles its path pattern. A table that fails here never reaches a request.
    fn prepare(&mut self) -> Result<(), SignalError> {
        let id = self.id.clone();
        let invalid = |problem: &str| SignalError::Invalid {
            id: id.clone(),
            problem: problem.to_string(),
        };
        if self.id.trim().is_empty() {
            return Err(invalid("id is empty"));
        }
        if self.reason.trim().is_empty() {
            return Err(invalid("reason is empty"));
        }
        if self.host.is_empty() || self.host.matches('*').count() > 1 {
            return Err(invalid("host must be set and hold at most one `*`"));
        }
        match (&self.evidence_url, &self.evidence_contains) {
            (None, None) => {}
            (Some(url), Some(contains)) => {
                if !url.starts_with("https://") {
                    return Err(invalid("`evidence_url` must be an https URL"));
                }
                if contains.is_empty() {
                    return Err(invalid("`evidence_contains` is empty"));
                }
            }
            _ => {
                return Err(invalid(
                    "`evidence_url` and `evidence_contains` go together",
                ))
            }
        }
        match self.sets {
            Fact::Billing => {
                if self.from.is_some() {
                    return Err(invalid("a billing signal cannot read a value"));
                }
                let when = self
                    .when
                    .as_ref()
                    .ok_or_else(|| invalid("a billing signal needs `when`"))?;
                if when.always == when.request_header.is_some() {
                    return Err(invalid(
                        "`when` needs exactly one of `always` or `request_header`",
                    ));
                }
                if when.request_header.as_deref().is_some_and(str::is_empty) {
                    return Err(invalid("`request_header` is empty"));
                }
                if when.prefix.is_some() && when.request_header.is_none() {
                    return Err(invalid("`prefix` needs `request_header`"));
                }
                if when.prefix.as_ref().is_some_and(|prefix| {
                    prefix.is_empty() || prefix.chars().count() > MAX_PREFIX_CHARS
                }) {
                    return Err(invalid("`prefix` must be 1 to 16 characters"));
                }
                self.billing = match self.value.as_deref() {
                    Some("api") => Billing::Api,
                    Some("subscription") => Billing::Subscription,
                    _ => {
                        return Err(invalid(
                            "a billing signal's value is `api` or `subscription`",
                        ))
                    }
                };
            }
            Fact::Model | Fact::ServedBy => {
                if self.when.is_some() {
                    return Err(invalid("only a billing signal has `when`"));
                }
                let fixed = self.value.is_some();
                if fixed == self.from.is_some() {
                    return Err(invalid("needs exactly one of `value` or `from`"));
                }
                if fixed && self.sets == Fact::Model {
                    return Err(invalid("a model signal reads its value, it cannot fix it"));
                }
                if self
                    .value
                    .as_ref()
                    .is_some_and(|value| value.chars().count() > MAX_PROVIDER_CHARS)
                {
                    return Err(invalid("`value` is too long"));
                }
            }
        }
        if let Some(extractor) = &self.from {
            self.path_pattern = extractor.validate().map_err(|problem| invalid(&problem))?;
        }
        Ok(())
    }

    fn condition_holds(&self, headers: &HeaderMap) -> bool {
        let Some(when) = &self.when else {
            return false;
        };
        if when.always {
            return true;
        }
        let Some(name) = &when.request_header else {
            return false;
        };
        let Some(value) = headers.get(name.as_str()).and_then(|v| v.to_str().ok()) else {
            return false;
        };
        let credential = value.strip_prefix("Bearer ").unwrap_or(value);
        when.prefix
            .as_ref()
            .is_none_or(|prefix| credential.starts_with(prefix.as_str()))
    }

    fn reads_response(&self) -> bool {
        self.from.as_ref().is_some_and(|extractor| {
            extractor.response_header.is_some() || extractor.response_body.is_some()
        })
    }

    fn read_request(&self, view: &RequestView) -> Option<String> {
        let extractor = self.from.as_ref()?;
        if let Some(pattern) = &self.path_pattern {
            let captured = pattern.captures(view.path)?.get(1)?.as_str();
            return extractor.finish(&captured.replace("%3A", ":").replace("%3a", ":"));
        }
        let pointer = extractor.request_body.as_deref()?;
        extractor.finish(view.json()?.pointer(pointer)?.as_str()?)
    }

    fn fixed_or_read_request(&self, view: &RequestView) -> Option<String> {
        self.value.clone().or_else(|| self.read_request(view))
    }

    fn read_response_body(&self, body: &Value) -> Option<String> {
        let extractor = self.from.as_ref()?;
        let pointer = extractor.response_body.as_deref()?;
        extractor.finish(body.pointer(pointer)?.as_str()?)
    }

    fn log_match(&self) {
        tracing::debug!(
            signal = %self.id,
            verified = self.verified,
            reason = %self.reason,
            "signal matched"
        );
    }
}

impl Extractor {
    /// Returns the compiled path pattern, if this extractor reads the path.
    fn validate(&self) -> Result<Option<Regex>, String> {
        let locations = [
            self.path_regex.is_some(),
            self.request_body.is_some(),
            self.response_header.is_some(),
            self.response_body.is_some(),
        ];
        if locations.into_iter().filter(|set| *set).count() != 1 {
            return Err("`from` needs exactly one location".into());
        }
        for pointer in [&self.request_body, &self.response_body]
            .into_iter()
            .flatten()
        {
            if !pointer.starts_with('/') {
                return Err("a JSON pointer starts with `/`".into());
            }
        }
        if let Some(name) = &self.response_header {
            let carries_credential = CREDENTIAL_HEADERS.contains(&name.as_str())
                || name.contains("token")
                || name.contains("key");
            if carries_credential {
                return Err(format!(
                    "`{name}` may carry a credential and cannot be read"
                ));
            }
            if *name != name.to_ascii_lowercase() {
                return Err("header names are lowercase".into());
            }
        }
        let Some(source) = &self.path_regex else {
            return Ok(None);
        };
        let pattern = Regex::new(source).map_err(|error| format!("bad `path_regex`: {error}"))?;
        if pattern.captures_len() != 2 {
            return Err("`path_regex` needs exactly one capture group".into());
        }
        Ok(Some(pattern))
    }

    /// The value to report: the host only when asked, never empty.
    fn finish(&self, raw: &str) -> Option<String> {
        let value = if self.host_only {
            host_of(raw)?
        } else {
            raw.trim().to_string()
        };
        (!value.is_empty()).then_some(value)
    }
}

/// The host of a URL, without credentials, port, path or query.
fn host_of(url: &str) -> Option<String> {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit('@').next()?.split(':').next()?;
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

impl Evidence {
    fn has(&self, fact: Fact) -> bool {
        match fact {
            Fact::Billing => self.billing_signal.is_some(),
            Fact::Model => self.model_signal.is_some(),
            Fact::ServedBy => self.served_by.is_some(),
        }
    }

    fn set_model(&mut self, signal: &Signal, model: String) {
        self.model = Some(model);
        self.model_signal = Some(signal.id.clone());
        signal.log_match();
    }

    fn set_served_by(&mut self, signal: &Signal, served_by: String) {
        self.served_by = Some(served_by);
        signal.log_match();
    }

    fn set_from_response(&mut self, signal: &Signal, value: String) {
        match signal.sets {
            Fact::Model => self.set_model(signal, value),
            Fact::ServedBy => self.set_served_by(signal, value),
            Fact::Billing => {}
        }
    }

    /// Adds what the signals found to a new event. The model replaces the request body's only when a signal
    /// produced it. Everything is length-capped like the event's other strings.
    pub fn stamp(&self, event: &mut UsageEvent) {
        event.billing_signal = self.billing_signal.as_deref().map(cap_provider);
        event.served_by = self.served_by.as_deref().map(cap_provider);
        if let (Some(model), Some(signal)) = (&self.model, &self.model_signal) {
            event.model = model.chars().take(MAX_MODEL_CHARS).collect();
            event.model_signal = Some(cap_provider(signal));
        }
    }
}

fn cap_provider(value: &str) -> String {
    value.chars().take(MAX_PROVIDER_CHARS).collect()
}

impl ResponseReader {
    /// True while a response body signal could still find something.
    pub fn wants_body(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Offers one parsed JSON value of the response (a body, or one SSE event) to the waiting signals.
    pub fn observe(&mut self, body: &Value) {
        let evidence = &mut self.evidence;
        self.pending.retain(|signal| {
            if evidence.has(signal.sets) {
                return false;
            }
            let Some(value) = signal.read_response_body(body) else {
                return true;
            };
            evidence.set_from_response(signal, value);
            false
        });
    }

    pub fn stamp(&self, event: &mut UsageEvent) {
        self.evidence.stamp(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use serde_json::json;

    fn table() -> Signals {
        Signals::builtin().unwrap()
    }

    fn headers(name: &'static str, value: &str) -> HeaderMap {
        let mut map = HeaderMap::new();
        map.insert(name, HeaderValue::from_str(value).unwrap());
        map
    }

    fn request(host: &str, path: &str, headers: &HeaderMap) -> Evidence {
        table().classify_request(host, path, headers, b"")
    }

    fn billing(host: &str, headers: &HeaderMap) -> Billing {
        request(host, "/", headers).billing
    }

    fn browser(host: &str) -> Billing {
        billing(host, &HeaderMap::new())
    }

    fn invalid(json: &str) -> String {
        match Signals::parse(json) {
            Ok(_) => panic!("table was accepted"),
            Err(error) => error.to_string(),
        }
    }

    fn single(signal: &str) -> String {
        format!(r#"{{"schema":1,"signals":[{signal}]}}"#)
    }

    #[test]
    fn browser_chat_hosts_are_subscriptions() {
        assert_eq!(browser("claude.ai"), Billing::Subscription);
        assert_eq!(browser("chatgpt.com"), Billing::Subscription);
        assert_eq!(browser("gemini.google.com"), Billing::Subscription);
        assert_eq!(browser("grok.com"), Billing::Subscription);
    }

    #[test]
    fn cursor_is_a_subscription() {
        assert_eq!(
            browser("agentn.global.api5.cursor.sh"),
            Billing::Subscription
        );
    }

    #[test]
    fn an_unrecognised_browser_host_is_unknown() {
        assert_eq!(browser("chat.example.com"), Billing::Unknown);
    }

    #[test]
    fn an_anthropic_api_key_is_api() {
        let map = headers("x-api-key", "sk-ant-api03-secret");
        assert_eq!(billing("api.anthropic.com", &map), Billing::Api);
    }

    #[test]
    fn an_anthropic_oauth_bearer_is_a_subscription() {
        let map = headers("authorization", "Bearer sk-ant-oat01-secret");
        assert_eq!(billing("api.anthropic.com", &map), Billing::Subscription);
    }

    #[test]
    fn an_unrecognised_anthropic_credential_is_unknown() {
        let map = headers("authorization", "Bearer something-else");
        assert_eq!(billing("api.anthropic.com", &map), Billing::Unknown);
        assert_eq!(
            billing("api.anthropic.com", &HeaderMap::new()),
            Billing::Unknown
        );
    }

    #[test]
    fn an_openai_key_is_api() {
        let map = headers("authorization", "Bearer sk-proj-secret");
        assert_eq!(billing("api.openai.com", &map), Billing::Api);
    }

    #[test]
    fn an_openai_token_that_is_not_a_key_is_unknown() {
        let map = headers("authorization", "Bearer eyJhbGciOi.jwt.shape");
        assert_eq!(billing("api.openai.com", &map), Billing::Unknown);
    }

    #[test]
    fn a_gemini_api_key_header_is_api() {
        let map = headers("x-goog-api-key", "AIza-secret");
        assert_eq!(
            billing("generativelanguage.googleapis.com", &map),
            Billing::Api
        );
    }

    #[test]
    fn other_hosts_are_unknown_even_with_a_key() {
        let map = headers("authorization", "Bearer xai-secret");
        assert_eq!(billing("api.x.ai", &map), Billing::Unknown);
    }

    #[test]
    fn codex_signed_in_with_chatgpt_is_a_subscription_by_path() {
        let evidence = request(
            "chatgpt.com",
            "/backend-api/codex/responses",
            &HeaderMap::new(),
        );
        assert_eq!(evidence.billing, Billing::Subscription);
        assert_eq!(
            evidence.billing_signal.as_deref(),
            Some("codex-chatgpt-login")
        );
    }

    #[test]
    fn gemini_cli_signed_in_with_google_is_a_subscription_by_host() {
        let evidence = request(
            "cloudcode-pa.googleapis.com",
            "/v1internal:streamGenerateContent",
            &HeaderMap::new(),
        );
        assert_eq!(evidence.billing, Billing::Subscription);
        assert_eq!(
            evidence.billing_signal.as_deref(),
            Some("gemini-code-assist-login")
        );
    }

    #[test]
    fn gemini_code_assist_names_the_model_in_the_request_body() {
        let body = br#"{"model":"gemini-2.5-pro","project":"p","request":{"contents":[]}}"#;
        let evidence = table().classify_request(
            "cloudcode-pa.googleapis.com",
            "/v1internal:generateContent",
            &HeaderMap::new(),
            body,
        );
        assert_eq!(evidence.model.as_deref(), Some("gemini-2.5-pro"));
        assert_eq!(
            evidence.model_signal.as_deref(),
            Some("gemini-code-assist-model")
        );
    }

    #[test]
    fn azure_openai_is_api_served_by_azure_without_guessing_the_model_from_the_deployment() {
        let evidence = request(
            "contoso.openai.azure.com",
            "/openai/deployments/my-chat/chat/completions",
            &headers("api-key", "azure-secret"),
        );
        assert_eq!(evidence.billing, Billing::Api);
        assert_eq!(evidence.served_by.as_deref(), Some("azure"));
        assert_eq!(evidence.model, None);
    }

    #[test]
    fn azure_openai_with_an_entra_bearer_is_api() {
        let map = headers("authorization", "Bearer eyJ0eXAi.entra.token");
        assert_eq!(billing("contoso.openai.azure.com", &map), Billing::Api);
    }

    #[test]
    fn copilot_seats_are_subscriptions_and_the_plan_is_in_the_signal_id() {
        for (host, signal) in [
            ("api.individual.githubcopilot.com", "copilot-individual"),
            ("api.business.githubcopilot.com", "copilot-business"),
            ("api.enterprise.githubcopilot.com", "copilot-enterprise"),
        ] {
            let evidence = request(host, "/chat/completions", &HeaderMap::new());
            assert_eq!(evidence.billing, Billing::Subscription);
            assert_eq!(evidence.billing_signal.as_deref(), Some(signal));
        }
    }

    #[test]
    fn vertex_and_bedrock_hosts_are_api() {
        for host in [
            "us-central1-aiplatform.googleapis.com",
            "aiplatform.googleapis.com",
            "aiplatform.us.rep.googleapis.com",
            "bedrock-runtime.us-east-1.amazonaws.com",
        ] {
            assert_eq!(billing(host, &HeaderMap::new()), Billing::Api, "{host}");
        }
        assert_eq!(
            billing("s3.us-east-1.amazonaws.com", &HeaderMap::new()),
            Billing::Unknown
        );
    }

    #[test]
    fn openrouter_with_a_key_is_api() {
        let map = headers("authorization", "Bearer sk-or-v1-secret");
        assert_eq!(billing("openrouter.ai", &map), Billing::Api);
        assert_eq!(
            billing("openrouter.ai", &HeaderMap::new()),
            Billing::Unknown
        );
    }

    #[test]
    fn the_gemini_api_model_comes_from_the_url_path() {
        let evidence = request(
            "generativelanguage.googleapis.com",
            "/v1beta/models/gemini-2.5-flash:streamGenerateContent",
            &HeaderMap::new(),
        );
        assert_eq!(evidence.model.as_deref(), Some("gemini-2.5-flash"));
        assert_eq!(evidence.model_signal.as_deref(), Some("gemini-api-model"));
    }

    #[test]
    fn a_vertex_model_and_publisher_come_from_the_url_path() {
        let evidence = request(
            "us-east5-aiplatform.googleapis.com",
            "/v1/projects/p/locations/us-east5/publishers/anthropic/models/claude-sonnet-4@20250929:rawPredict",
            &HeaderMap::new(),
        );
        assert_eq!(evidence.model.as_deref(), Some("claude-sonnet-4@20250929"));
        assert_eq!(evidence.model_signal.as_deref(), Some("vertex-model"));
        assert_eq!(evidence.served_by.as_deref(), Some("anthropic"));
    }

    #[test]
    fn a_bedrock_model_and_author_come_from_the_url_path() {
        let host = "bedrock-runtime.us-east-1.amazonaws.com";
        let evidence = request(
            host,
            "/model/us.anthropic.claude-haiku-4-5-20251001-v1:0/invoke-with-response-stream",
            &HeaderMap::new(),
        );
        assert_eq!(
            evidence.model.as_deref(),
            Some("us.anthropic.claude-haiku-4-5-20251001-v1:0")
        );
        assert_eq!(evidence.served_by.as_deref(), Some("anthropic"));

        let encoded = request(
            host,
            "/model/meta.llama3-1-70b-instruct-v1%3A0/invoke",
            &HeaderMap::new(),
        );
        assert_eq!(
            encoded.model.as_deref(),
            Some("meta.llama3-1-70b-instruct-v1:0")
        );
        assert_eq!(encoded.served_by.as_deref(), Some("meta"));
    }

    #[test]
    fn a_bedrock_inference_profile_arn_is_never_reported() {
        let host = "bedrock-runtime.us-east-1.amazonaws.com";
        let arn = "/model/arn%3Aaws%3Abedrock%3Aus-east-1%3A123456789012%3Aapplication-inference-profile%2Fabc/invoke";
        let evidence = request(host, arn, &HeaderMap::new());
        assert_eq!(evidence.model, None);
        assert_eq!(evidence.served_by, None);
    }

    fn reader_for(host: &str, response_headers: &HeaderMap) -> ResponseReader {
        table().response_reader(host, "/", &Evidence::default(), response_headers)
    }

    #[test]
    fn openrouter_reports_the_answering_model_in_the_response_body() {
        let mut reader = reader_for("openrouter.ai", &HeaderMap::new());
        assert!(reader.wants_body());
        reader.observe(&json!({"id": "gen-1", "usage": {"is_byok": false}}));
        assert!(reader.wants_body());
        reader.observe(&json!({"model": "openai/gpt-4", "usage": {"is_byok": false}}));
        assert!(!reader.wants_body());

        let mut event = crate::backend::new_event(
            "openrouter.ai",
            "openrouter/auto",
            200,
            false,
            0,
            Billing::Api,
        );
        reader.stamp(&mut event);
        assert_eq!(event.model, "openai/gpt-4");
        assert_eq!(event.model_signal.as_deref(), Some("openrouter-model"));
    }

    #[test]
    fn litellm_names_the_upstream_by_host_only() {
        let map = headers(
            "x-litellm-model-api-base",
            "https://user:pw@api.openai.com:443/v1?key=secret",
        );
        let reader = reader_for("gateway.internal.example", &map);
        let mut event = crate::backend::new_event(
            "gateway.internal.example",
            "gpt",
            200,
            false,
            0,
            Billing::Unknown,
        );
        reader.stamp(&mut event);
        assert_eq!(event.served_by.as_deref(), Some("api.openai.com"));
        let json = serde_json::to_string(&event).unwrap();
        for leaked in ["pw", "secret", "/v1"] {
            assert!(!json.contains(leaked), "event leaked {leaked}: {json}");
        }
    }

    #[test]
    fn evidence_needs_an_https_url_and_a_string_together() {
        let with = |fields: &str| {
            single(&format!(
                r#"{{"id":"x","host":"x.example","sets":"billing","when":{{"always":true}},"value":"api","reason":"r","verified":true{fields}}}"#
            ))
        };
        let url = r#","evidence_url":"https://example.com/src""#;
        let http_url = r#","evidence_url":"http://example.com/src""#;
        let contains = r#","evidence_contains":"CONST""#;
        assert!(Signals::parse(&with(&format!("{url}{contains}"))).is_ok());
        assert!(invalid(&with(&format!("{http_url}{contains}"))).contains("https"));
        assert!(invalid(&with(url)).contains("go together"));
        assert!(invalid(&with(contains)).contains("go together"));
        let empty = r#","evidence_contains":"""#;
        assert!(invalid(&with(&format!("{url}{empty}"))).contains("empty"));
    }

    #[test]
    fn the_first_matching_signal_wins() {
        let signals = Signals::parse(&single(
            r#"{"id":"a","host":"x.example","sets":"billing","when":{"always":true},"value":"api","reason":"first","verified":true},
               {"id":"b","host":"x.example","sets":"billing","when":{"always":true},"value":"subscription","reason":"second","verified":true}"#,
        ))
        .unwrap();
        let evidence = signals.classify_request("x.example", "/", &HeaderMap::new(), b"");
        assert_eq!(evidence.billing, Billing::Api);
        assert_eq!(evidence.billing_signal.as_deref(), Some("a"));
    }

    #[test]
    fn a_request_signal_beats_a_later_response_signal_for_the_same_fact() {
        let signals = Signals::parse(&single(
            r#"{"id":"path","host":"x.example","sets":"model","from":{"path_regex":"^/m/([^/]+)"},"reason":"path","verified":true},
               {"id":"echo","host":"x.example","sets":"model","from":{"response_body":"/model"},"reason":"echo","verified":true}"#,
        ))
        .unwrap();
        let evidence =
            signals.classify_request("x.example", "/m/from-path", &HeaderMap::new(), b"");
        let mut reader =
            signals.response_reader("x.example", "/m/from-path", &evidence, &HeaderMap::new());
        assert!(!reader.wants_body());
        reader.observe(&json!({"model": "from-body"}));
        let mut event = crate::backend::new_event("x.example", "", 200, false, 0, Billing::Unknown);
        reader.stamp(&mut event);
        assert_eq!(event.model, "from-path");
    }

    #[test]
    fn a_fact_no_signal_matches_stays_unknown() {
        let evidence = request("chat.example.com", "/v1/messages", &HeaderMap::new());
        assert_eq!(evidence, Evidence::default());
        let mut event = crate::backend::new_event(
            "chat.example.com",
            "from-body",
            200,
            false,
            0,
            Billing::Unknown,
        );
        evidence.stamp(&mut event);
        assert_eq!(event.model, "from-body");
        assert_eq!(event.served_by, None);
        assert_eq!(event.billing_signal, None);
        assert_eq!(event.model_signal, None);
    }

    #[test]
    fn the_builtin_table_is_valid_and_every_signal_has_a_reason() {
        let signals = table();
        assert!(signals.signals.len() > 20);
        for signal in &signals.signals {
            assert!(!signal.reason.trim().is_empty(), "{}", signal.id);
        }
    }

    #[test]
    fn a_table_with_an_unknown_field_is_rejected() {
        let message = invalid(&single(
            r#"{"id":"a","host":"x.example","sets":"billing","when":{"always":true},"value":"api","reason":"r","verified":true,"extra":1}"#,
        ));
        assert!(message.contains("unknown field `extra`"), "{message}");
    }

    #[test]
    fn a_signal_without_a_reason_is_rejected() {
        let message = invalid(&single(
            r#"{"id":"a","host":"x.example","sets":"billing","when":{"always":true},"value":"api","verified":true}"#,
        ));
        assert!(message.contains("missing field `reason`"), "{message}");
        let blank = invalid(&single(
            r#"{"id":"a","host":"x.example","sets":"billing","when":{"always":true},"value":"api","reason":" ","verified":true}"#,
        ));
        assert!(blank.contains("reason is empty"), "{blank}");
    }

    #[test]
    fn a_prefix_over_sixteen_characters_is_rejected() {
        let long = single(
            r#"{"id":"a","host":"x.example","sets":"billing","when":{"request_header":"authorization","prefix":"12345678901234567"},"value":"api","reason":"r","verified":true}"#,
        );
        assert!(invalid(&long).contains("prefix"));
        let exact = single(
            r#"{"id":"a","host":"x.example","sets":"billing","when":{"request_header":"authorization","prefix":"1234567890123456"},"value":"api","reason":"r","verified":true}"#,
        );
        assert!(Signals::parse(&exact).is_ok());
    }

    #[test]
    fn a_response_header_signal_cannot_read_a_credential_header() {
        for name in [
            "authorization",
            "x-api-key",
            "set-cookie",
            "x-session-token",
            "x-secret-key",
        ] {
            let table = single(&format!(
                r#"{{"id":"a","host":"x.example","sets":"served_by","from":{{"response_header":"{name}"}},"reason":"r","verified":true}}"#
            ));
            assert!(invalid(&table).contains("credential"), "{name}");
        }
    }

    #[test]
    fn a_signal_cannot_read_a_request_header_as_a_value() {
        let message = invalid(&single(
            r#"{"id":"a","host":"x.example","sets":"model","from":{"request_header":"authorization"},"reason":"r","verified":true}"#,
        ));
        assert!(
            message.contains("unknown field `request_header`"),
            "{message}"
        );
    }

    #[test]
    fn a_malformed_signal_is_rejected() {
        let cases = [
            r#"{"id":"a","host":"x.example","sets":"billing","reason":"r","verified":true,"value":"api"}"#,
            r#"{"id":"a","host":"x.example","sets":"billing","when":{"always":true},"value":"unknown","reason":"r","verified":true}"#,
            r#"{"id":"a","host":"x.example","sets":"model","from":{"path_regex":"^/(a)/(b)"},"reason":"r","verified":true}"#,
            r#"{"id":"a","host":"x.example","sets":"model","from":{"path_regex":"^/a","response_body":"/m"},"reason":"r","verified":true}"#,
            r#"{"id":"a","host":"x.example","sets":"model","from":{"response_body":"model"},"reason":"r","verified":true}"#,
            r#"{"id":"a","host":"a.*.b.*","sets":"model","from":{"response_body":"/m"},"reason":"r","verified":true}"#,
            r#"{"id":"a","host":"x.example","sets":"model","value":"fixed","reason":"r","verified":true}"#,
        ];
        for case in cases {
            assert!(Signals::parse(&single(case)).is_err(), "{case}");
        }
        assert!(Signals::parse(r#"{"schema":2,"signals":[]}"#).is_err());
    }

    #[test]
    fn a_wildcard_host_matches_one_stretch_of_the_host() {
        assert!(host_matches(
            "bedrock-runtime.*.amazonaws.com",
            "bedrock-runtime.eu-west-1.amazonaws.com"
        ));
        assert!(!host_matches(
            "bedrock-runtime.*.amazonaws.com",
            "bedrock-runtime..amazonaws.com"
        ));
        assert!(!host_matches("bedrock-runtime.*.amazonaws.com", "evil.com"));
        assert!(host_matches("*", "anything.example"));
        assert!(host_matches("claude.ai", "www.claude.ai"));
        assert!(!host_matches("claude.ai", "notclaude.ai"));
    }

    #[test]
    fn the_serialised_event_never_contains_the_credential() {
        let secret = "sk-ant-oat01-TOPSECRETVALUE";
        let map = headers("authorization", &format!("Bearer {secret}"));
        let evidence = request("api.anthropic.com", "/v1/messages", &map);
        let mut event =
            crate::backend::new_event("api.anthropic.com", "m", 200, false, 0, evidence.billing);
        evidence.stamp(&mut event);
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains(r#""billing":"subscription""#));
        assert!(json.contains(r#""billing_signal":"anthropic-oauth""#));
        for leaked in ["TOPSECRET", "sk-ant-oat", "authorization", "Bearer"] {
            assert!(!json.contains(leaked), "event leaked {leaked}: {json}");
        }
    }

    #[test]
    fn no_billing_signal_puts_a_credential_in_any_event_field() {
        let secret = "TOPSECRETVALUE";
        let signals = table();
        for signal in signals.signals.iter().filter(|s| s.sets == Fact::Billing) {
            let host = signal.host.replace('*', "us-east-1");
            let credential = format!("{}{secret}", "Bearer sk-ant-oat-sk-");
            let mut map = HeaderMap::new();
            for name in ["authorization", "x-api-key", "api-key", "x-goog-api-key"] {
                map.insert(name, HeaderValue::from_str(&credential).unwrap());
            }
            let path = signal.path_prefix.as_deref().unwrap_or("/");
            let evidence = signals.classify_request(&host, path, &map, b"");
            let mut event = crate::backend::new_event(&host, "m", 200, false, 0, evidence.billing);
            evidence.stamp(&mut event);
            let json = serde_json::to_string(&event).unwrap();
            assert!(!json.contains(secret), "{} leaked: {json}", signal.id);
        }
    }

    #[test]
    fn the_new_event_fields_are_omitted_when_absent_and_truncated_when_long() {
        let mut event = crate::backend::new_event("h", "m", 200, false, 0, Billing::Unknown);
        let json = serde_json::to_string(&event).unwrap();
        for field in ["served_by", "billing_signal", "model_signal"] {
            assert!(!json.contains(field), "{json}");
        }
        let evidence = Evidence {
            billing_signal: Some("b".repeat(100)),
            model: Some("m".into()),
            model_signal: Some("s".repeat(100)),
            served_by: Some("p".repeat(100)),
            ..Evidence::default()
        };
        evidence.stamp(&mut event);
        assert_eq!(event.served_by.as_deref().map(str::len), Some(64));
        assert_eq!(event.billing_signal.as_deref().map(str::len), Some(64));
        assert_eq!(event.model_signal.as_deref().map(str::len), Some(64));
    }
}
