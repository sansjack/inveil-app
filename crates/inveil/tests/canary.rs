#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Scheduled checks that providers still behave the way our signals assume. Both tests are `#[ignore]`d because they
//! need the network (and, for the canary, API keys):
//!
//! ```sh
//! cargo test -p inveil --test canary -- --ignored canary_   # real tiny calls through the real client
//! cargo test -p inveil --test canary -- --ignored evidence_watch   # public sources our signals cite
//! ```
//!
//! Each writes a JSON array of `{provider, status, detail}` (`status` is `pass`, `fail` or `skipped`) to the path in
//! `CANARY_RESULTS`, or to stdout when it is not set. Run them one at a time, since both write that file.
#![allow(dead_code)] // shares the end-to-end harness, which has more than this file uses
#[cfg(test)]
mod fixture;

use contract::{Billing, UsageEvent};
use fixture::*;
use serde::Serialize;
use serde_json::{json, Value};
use std::time::Duration;

const ASK: &str = "Reply with the single word: ok";
const MAX_OUTPUT_TOKENS: u32 = 16;
/// Gemini models may spend part of the budget thinking, so a 16 token cap can leave no visible answer.
const GEMINI_MAX_OUTPUT_TOKENS: u32 = 64;
const CALL_TIMEOUT: Duration = Duration::from_secs(60);
const USAGE_WAIT: Duration = Duration::from_secs(30);
const POLL_STEP: Duration = Duration::from_millis(100);
const DETAIL_CHARS: usize = 300;
const EVIDENCE_ATTEMPTS: u32 = 2;
const EVIDENCE_RETRY_WAIT: Duration = Duration::from_secs(5);
const BUILTIN_SIGNALS: &str = include_str!("../src/builtin_signals.json");

#[derive(Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Status {
    Pass,
    Fail,
    Skipped,
}

#[derive(Serialize)]
struct Outcome {
    provider: String,
    status: Status,
    detail: String,
}

impl Outcome {
    fn new(provider: &str, status: Status, detail: impl Into<String>) -> Self {
        Self {
            provider: provider.to_string(),
            status,
            detail: detail.into(),
        }
    }
}

/// What one provider's request looks like, and what the client must report for it.
struct Provider {
    name: &'static str,
    key_variable: &'static str,
    model_variable: &'static str,
    /// Cheapest suitable model, checked against the provider's own docs and pricing page on 2026-10-19.
    default_model: &'static str,
    host: &'static str,
    billing_signal: &'static str,
    /// `None` when no signal reads the model and it is the request's own.
    model_signal: Option<&'static str>,
    request: fn(model: &str, key: &str, stream: bool) -> ProviderRequest,
}

struct ProviderRequest {
    /// Path on the client's local proxy, including the tool prefix.
    path: String,
    headers: Vec<(&'static str, String)>,
    body: Value,
}

const PROVIDERS: [Provider; 4] = [
    Provider {
        name: "anthropic",
        key_variable: "ANTHROPIC_API_KEY",
        model_variable: "CANARY_ANTHROPIC_MODEL",
        default_model: "claude-haiku-5-5",
        host: "api.anthropic.com",
        billing_signal: "anthropic-api-key",
        model_signal: None,
        request: anthropic_request,
    },
    Provider {
        name: "openai",
        key_variable: "OPENAI_API_KEY",
        model_variable: "CANARY_OPENAI_MODEL",
        default_model: "gpt-4.1-nano",
        host: "api.openai.com",
        billing_signal: "openai-api-key",
        model_signal: None,
        request: openai_request,
    },
    Provider {
        name: "gemini",
        key_variable: "GEMINI_API_KEY",
        model_variable: "CANARY_GEMINI_MODEL",
        default_model: "gemini-3.5-flash-lite",
        host: "generativelanguage.googleapis.com",
        billing_signal: "gemini-api-key",
        model_signal: Some("gemini-api-model"),
        request: gemini_request,
    },
    Provider {
        name: "openrouter",
        key_variable: "OPENROUTER_API_KEY",
        model_variable: "CANARY_OPENROUTER_MODEL",
        default_model: "openai/gpt-4.1-nano",
        host: "openrouter.ai",
        billing_signal: "openrouter-key",
        model_signal: Some("openrouter-model"),
        request: openrouter_request,
    },
];

fn anthropic_request(model: &str, key: &str, stream: bool) -> ProviderRequest {
    ProviderRequest {
        path: "/anthropic/v1/messages".into(),
        headers: vec![
            ("x-api-key", key.into()),
            ("anthropic-version", "2023-06-01".into()),
        ],
        body: json!({
            "model": model,
            "max_tokens": MAX_OUTPUT_TOKENS,
            "stream": stream,
            "messages": [{"role": "user", "content": ASK}],
        }),
    }
}

fn openai_request(model: &str, key: &str, stream: bool) -> ProviderRequest {
    ProviderRequest {
        path: "/openai/v1/responses".into(),
        headers: vec![("authorization", format!("Bearer {key}"))],
        body: json!({
            "model": model,
            "max_output_tokens": MAX_OUTPUT_TOKENS,
            "stream": stream,
            "input": ASK,
        }),
    }
}

fn gemini_request(model: &str, key: &str, stream: bool) -> ProviderRequest {
    let method = if stream {
        "streamGenerateContent?alt=sse"
    } else {
        "generateContent"
    };
    ProviderRequest {
        path: format!("/google/v1beta/models/{model}:{method}"),
        headers: vec![("x-goog-api-key", key.into())],
        body: json!({
            "contents": [{"role": "user", "parts": [{"text": ASK}]}],
            "generationConfig": {"maxOutputTokens": GEMINI_MAX_OUTPUT_TOKENS},
        }),
    }
}

fn openrouter_request(model: &str, key: &str, stream: bool) -> ProviderRequest {
    ProviderRequest {
        path: "/openrouter/api/v1/chat/completions".into(),
        headers: vec![("authorization", format!("Bearer {key}"))],
        body: json!({
            "model": model,
            "max_tokens": MAX_OUTPUT_TOKENS,
            "stream": stream,
            "messages": [{"role": "user", "content": ASK}],
        }),
    }
}

fn write_results(outcomes: &[Outcome]) {
    let json = serde_json::to_string_pretty(outcomes).unwrap();
    match std::env::var("CANARY_RESULTS") {
        Ok(path) if !path.is_empty() => std::fs::write(&path, json).unwrap(),
        _ => println!("{json}"),
    }
}

fn assert_no_failures(outcomes: &[Outcome]) {
    let failed: Vec<String> = outcomes
        .iter()
        .filter(|outcome| outcome.status == Status::Fail)
        .map(|outcome| format!("{}: {}", outcome.provider, outcome.detail))
        .collect();
    assert!(failed.is_empty(), "failed: {failed:#?}");
}

fn shorten(text: &str) -> String {
    let one_line = text.split_whitespace().collect::<Vec<_>>().join(" ");
    one_line.chars().take(DETAIL_CHARS).collect()
}

/// Every usage event the stub backend has received so far, in order.
fn received_events(backend: &Backend) -> Vec<UsageEvent> {
    backend
        .state
        .usage_batches
        .lock()
        .unwrap()
        .iter()
        .flat_map(|batch| batch.events.clone())
        .collect()
}

async fn next_event(backend: &Backend, already_seen: usize) -> Result<UsageEvent, String> {
    let deadline = std::time::Instant::now() + USAGE_WAIT;
    loop {
        if let Some(event) = received_events(backend).into_iter().nth(already_seen) {
            return Ok(event);
        }
        if std::time::Instant::now() > deadline {
            return Err("the client reported no usage event for the call".into());
        }
        tokio::time::sleep(POLL_STEP).await;
    }
}

/// The provider's answer must be intact: a 200 and a body a client could parse.
fn check_response(status: u16, body: &str, stream: bool) -> Result<(), String> {
    if status != 200 {
        return Err(format!(
            "HTTP {status} through the client: {}",
            shorten(body)
        ));
    }
    let parseable = if stream {
        body.lines()
            .filter_map(|line| line.strip_prefix("data:"))
            .any(|data| serde_json::from_str::<Value>(data.trim()).is_ok())
    } else {
        serde_json::from_str::<Value>(body).is_ok()
    };
    if !parseable {
        return Err(format!("the response did not parse: {}", shorten(body)));
    }
    Ok(())
}

fn check_event(provider: &Provider, model: &str, event: &UsageEvent) -> Result<(), String> {
    let mut problems = Vec::new();
    if event.billing != Billing::Api {
        problems.push(format!("billing was {:?}, not api", event.billing));
    }
    if event.billing_signal.as_deref() != Some(provider.billing_signal) {
        problems.push(format!(
            "billing_signal was {:?}, expected {}",
            event.billing_signal, provider.billing_signal
        ));
    }
    if event.provider != provider.host {
        problems.push(format!(
            "provider was {}, expected {}",
            event.provider, provider.host
        ));
    }
    if event.model != model {
        problems.push(format!("model was {}, expected {model}", event.model));
    }
    if event.model_signal.as_deref() != provider.model_signal {
        problems.push(format!(
            "model_signal was {:?}, expected {:?}",
            event.model_signal, provider.model_signal
        ));
    }
    if event.status != 200 {
        problems.push(format!("event status was {}", event.status));
    }
    if event.input_tokens == 0 || event.output_tokens == 0 {
        problems.push(format!(
            "tokens were {} in / {} out, expected both above 0",
            event.input_tokens, event.output_tokens
        ));
    }
    if problems.is_empty() {
        return Ok(());
    }
    Err(problems.join("; "))
}

/// One real call through the client. Returns what to say about it when it passes.
async fn call_provider(
    proxy: &RunningProxy,
    backend: &Backend,
    provider: &Provider,
    model: &str,
    key: &str,
    stream: bool,
) -> Result<String, String> {
    let already_seen = received_events(backend).len();
    let request = (provider.request)(model, key, stream);
    let mut builder = client()
        .post(format!("{}{}", proxy.address, request.path))
        .timeout(CALL_TIMEOUT)
        .json(&request.body);
    for (name, value) in request.headers {
        builder = builder.header(name, value);
    }
    let response = builder
        .send()
        .await
        .map_err(|error| format!("the call could not be made: {}", error.without_url()))?;
    let status = response.status().as_u16();
    let body = response.text().await.map_err(|error| {
        format!(
            "the response body could not be read: {}",
            error.without_url()
        )
    })?;
    check_response(status, &body, stream)?;

    let event = next_event(backend, already_seen).await?;
    check_event(provider, model, &event)?;
    Ok(format!(
        "{} ok ({} in / {} out)",
        if stream { "stream" } else { "non-stream" },
        event.input_tokens,
        event.output_tokens
    ))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "calls the real provider APIs and needs keys; see CONTRIBUTING.md"]
async fn canary_providers_through_the_real_client() {
    let keys: Vec<Option<String>> = PROVIDERS
        .iter()
        .map(|provider| std::env::var(provider.key_variable).ok())
        .map(|key| key.filter(|key| !key.is_empty()))
        .collect();
    let mut outcomes = Vec::new();
    if keys.iter().all(Option::is_none) {
        for provider in &PROVIDERS {
            outcomes.push(Outcome::new(
                provider.name,
                Status::Skipped,
                format!("{} is not set", provider.key_variable),
            ));
        }
        write_results(&outcomes);
        return;
    }

    // The default route goes to the configured upstream. Giving Claude Code a prefix sends it to the real
    // api.anthropic.com from the catalog instead, like the OpenAI and Gemini routes. No built-in tool routes
    // openrouter.ai, so this test catalog adds one; the shipped client does not intercept it.
    let signing_key = SigningKey::generate();
    let catalog = snapshot(1, |snapshot| {
        for tool in snapshot
            .tools
            .iter_mut()
            .filter(|tool| tool.id == "claude-code")
        {
            tool.prefix = Some("/anthropic".into());
        }
        snapshot.tools.push(
            serde_json::from_value(json!({
                "id": "openrouter-canary",
                "name": "OpenRouter (canary only)",
                "via": "local",
                "enabled": true,
                "upstream": "https://openrouter.ai",
                "prefix": "/openrouter",
                "endpoints": [
                    {"path": "/api/v1/chat/completions", "match": "exact", "format": "json"}
                ],
                "hosts": [],
            }))
            .unwrap(),
        );
    });
    let (backend, _unused_upstream, setup) = backend_serving(&signing_key, &catalog).await;
    let setup = setup.table("[usage]\nsink = \"http\"");
    let directory = tempfile::tempdir().unwrap();
    let proxy = RunningProxy::start(directory.path(), &setup);

    for (provider, key) in PROVIDERS.iter().zip(keys) {
        let Some(key) = key else {
            outcomes.push(Outcome::new(
                provider.name,
                Status::Skipped,
                format!("{} is not set", provider.key_variable),
            ));
            continue;
        };
        let model = std::env::var(provider.model_variable)
            .ok()
            .filter(|model| !model.is_empty())
            .unwrap_or_else(|| provider.default_model.to_string());
        let mut passed = Vec::new();
        let mut failed = Vec::new();
        for stream in [false, true] {
            let label = if stream { "stream" } else { "non-stream" };
            match call_provider(&proxy, &backend, provider, &model, &key, stream).await {
                Ok(detail) => passed.push(detail),
                Err(problem) => failed.push(format!("{label}: {problem}")),
            }
        }
        let outcome = if failed.is_empty() {
            Outcome::new(
                provider.name,
                Status::Pass,
                format!("model {model}: {}", passed.join(", ")),
            )
        } else {
            Outcome::new(
                provider.name,
                Status::Fail,
                failed.join(" | ").replace(&key, "***"),
            )
        };
        outcomes.push(outcome);
    }
    write_results(&outcomes);
    assert_no_failures(&outcomes);
}

async fn evidence_is_present(
    client: &reqwest::Client,
    url: &str,
    needle: &str,
) -> Result<(), String> {
    let mut last_problem = String::new();
    for attempt in 1..=EVIDENCE_ATTEMPTS {
        if attempt > 1 {
            tokio::time::sleep(EVIDENCE_RETRY_WAIT).await;
        }
        let response = match client.get(url).send().await {
            Ok(response) => response,
            Err(error) => {
                last_problem = format!("{url} could not be fetched: {}", error.without_url());
                continue;
            }
        };
        let status = response.status();
        if !status.is_success() {
            last_problem = format!("{url} answered HTTP {status}");
            continue;
        }
        match response.text().await {
            Ok(text) if text.contains(needle) => return Ok(()),
            Ok(_) => return Err(format!("{url} no longer contains `{needle}`")),
            Err(error) => {
                last_problem = format!("{url} could not be read: {}", error.without_url())
            }
        }
    }
    Err(last_problem)
}

#[tokio::test]
#[ignore = "fetches the public pages our signals cite; see CONTRIBUTING.md"]
async fn evidence_watch() {
    let table: Value = serde_json::from_str(BUILTIN_SIGNALS).unwrap();
    let client = reqwest::Client::builder()
        .user_agent("inveil-evidence-watch")
        .timeout(CALL_TIMEOUT)
        .build()
        .unwrap();
    let mut outcomes = Vec::new();
    for signal in table["signals"].as_array().unwrap() {
        let (Some(url), Some(needle)) = (
            signal["evidence_url"].as_str(),
            signal["evidence_contains"].as_str(),
        ) else {
            continue;
        };
        let provider = format!("evidence:{}", signal["id"].as_str().unwrap());
        outcomes.push(match evidence_is_present(&client, url, needle).await {
            Ok(()) => Outcome::new(
                &provider,
                Status::Pass,
                format!("{url} contains `{needle}`"),
            ),
            Err(problem) => Outcome::new(&provider, Status::Fail, problem),
        });
    }
    assert!(!outcomes.is_empty(), "no signal cites evidence");
    write_results(&outcomes);
    assert_no_failures(&outcomes);
}
