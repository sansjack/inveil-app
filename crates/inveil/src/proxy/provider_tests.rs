//! Pins what the client reports for each provider family. Every file in `tests/provider_fixtures/` is one sanitised
//! exchange (request, response, and the event we expect) and runs through the real signals table and usage tap, and
//! through the real localhost proxy in front of a fake upstream. The drift fixtures are provider changes we must
//! survive: they have to fall back to `unknown` or zero, and never alter what the client receives.
use super::api;
use super::screen::screen_body_offloaded;
use super::test_support::{builtin_with, TestProxy};
use super::usage_tap::{Encoding, Tap};
use super::AppState;
use crate::backend::new_event;
use crate::config::Config;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Router;
use contract::{Billing, Format, Snapshot, UsageReporting};
use flate2::write::{GzEncoder, ZlibEncoder};
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;

const BUILTIN_SIGNALS: &str = include_str!("../builtin_signals.json");
/// Response bytes reach the tap in pieces that split lines and JSON anywhere, like a real network read.
const CHUNK_BYTES: usize = 13;
const FIXTURE_HEADER: &str = "x-fixture";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    #[allow(dead_code)]
    note: Option<String>,
    /// The signals this exchange proves work. Drift fixtures prove none.
    covers: Vec<String>,
    request: FixtureRequest,
    response: FixtureResponse,
    expect: Expected,
    #[serde(skip)]
    name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureRequest {
    host: String,
    path: String,
    headers: BTreeMap<String, String>,
    body: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureResponse {
    status: u16,
    headers: BTreeMap<String, String>,
    /// A string is sent as written (an SSE stream, HTML, nothing); anything else as compact JSON.
    body: Value,
    /// Compress the body, as a provider that sets `content-encoding` would.
    #[serde(default)]
    compression: Option<Compression>,
    /// Newlines put in front of the body: a stream that expands far beyond the decoding budget.
    #[serde(default)]
    leading_newlines: usize,
    /// Bytes cut off the end of the compressed body: a connection that dropped mid-stream.
    #[serde(default)]
    truncate_bytes: usize,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Compression {
    Gzip,
    Deflate,
    Br,
    Zstd,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Expected {
    billing: Billing,
    billing_signal: Option<String>,
    model: String,
    model_signal: Option<String>,
    served_by: Option<String>,
    input_tokens: u64,
    output_tokens: u64,
    cache_read_tokens: u64,
    cache_write_tokens: u64,
}

impl FixtureRequest {
    fn body_bytes(&self) -> Vec<u8> {
        match &self.body {
            Value::String(text) => text.clone().into_bytes(),
            body => serde_json::to_vec(body).unwrap(),
        }
    }
}

impl FixtureResponse {
    fn body_bytes(&self) -> Vec<u8> {
        let mut plain = vec![b'\n'; self.leading_newlines];
        match &self.body {
            Value::String(text) => plain.extend_from_slice(text.as_bytes()),
            body => plain.extend_from_slice(&serde_json::to_vec(body).unwrap()),
        }
        let Some(compression) = self.compression else {
            return plain;
        };
        let mut compressed = match compression {
            Compression::Gzip => {
                let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
                encoder.write_all(&plain).unwrap();
                encoder.finish().unwrap()
            }
            Compression::Deflate => {
                let mut encoder = ZlibEncoder::new(Vec::new(), flate2::Compression::default());
                encoder.write_all(&plain).unwrap();
                encoder.finish().unwrap()
            }
            Compression::Br => {
                let mut encoder = brotli::CompressorWriter::new(Vec::new(), 4096, 5, 22);
                encoder.write_all(&plain).unwrap();
                encoder.into_inner()
            }
            Compression::Zstd => zstd::stream::encode_all(plain.as_slice(), 3).unwrap(),
        };
        compressed.truncate(compressed.len() - self.truncate_bytes);
        compressed
    }

    /// How the response says it is encoded, which is what the usage tap decodes by.
    fn encoding(&self) -> Encoding {
        Encoding::from_headers(&header_map(&self.headers))
    }

    fn is_event_stream(&self) -> bool {
        self.headers
            .get("content-type")
            .is_some_and(|value| value.contains("text/event-stream"))
    }
}

/// The built-in catalog with usage reporting switched on, so the uploader hands events to the recording sink.
fn with_usage_reporting() -> Snapshot {
    builtin_with(|snapshot| snapshot.settings.usage_reporting = Some(UsageReporting::Required))
}

fn header_map(headers: &BTreeMap<String, String>) -> HeaderMap {
    headers
        .iter()
        .map(|(name, value)| {
            (
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            )
        })
        .collect()
}

fn fixtures() -> Vec<Fixture> {
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/provider_fixtures");
    let mut paths: Vec<PathBuf> = std::fs::read_dir(&directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect();
    paths.sort();
    assert!(!paths.is_empty(), "no fixtures in {}", directory.display());
    paths
        .iter()
        .map(|path| {
            let text = std::fs::read_to_string(path).unwrap();
            let mut fixture: Fixture = serde_json::from_str(&text)
                .unwrap_or_else(|error| panic!("{} is not a fixture: {error}", path.display()));
            fixture.name = path.file_stem().unwrap().to_string_lossy().into_owned();
            fixture
        })
        .collect()
}

/// The request half of `api::handle` and the response half of `api::forward`, for one fixture, against the real
/// signals table. The host is the provider's own, which a fake upstream on 127.0.0.1 cannot be.
async fn run_pipeline(state: &AppState, fixture: &Fixture) -> String {
    let request = &fixture.request;
    let response = &fixture.response;
    let body = Bytes::from(request.body_bytes());
    let evidence = state.signals.classify_request(
        &request.host,
        &request.path,
        &header_map(&request.headers),
        &body,
    );
    let screened = screen_body_offloaded(
        state.policy(),
        Format::Json,
        None,
        body,
        state.config.limits.max_decoded_bytes,
    )
    .await;
    let event = new_event(
        &request.host,
        &screened.model,
        response.status,
        false,
        screened.report.findings.len(),
        evidence.billing,
    );
    let event_id = event.id.clone();
    let reader = state.signals.response_reader(
        &request.host,
        &request.path,
        &evidence,
        &header_map(&response.headers),
    );
    let mut tap = Tap::new(
        state.usage.clone(),
        event,
        response.is_event_stream(),
        response.encoding(),
        reader,
    );
    for chunk in response.body_bytes().chunks(CHUNK_BYTES) {
        tap.observe(chunk);
    }
    drop(tap);
    event_id
}

#[tokio::test]
async fn every_fixture_yields_the_expected_event() {
    let proxy = TestProxy::new(Config::default(), with_usage_reporting());
    let fixtures = fixtures();
    for (index, fixture) in fixtures.iter().enumerate() {
        let event_id = run_pipeline(&proxy.state, fixture).await;
        let events = proxy.usage_events(index + 1).await;
        let event = events
            .iter()
            .find(|event| event.id == event_id)
            .unwrap_or_else(|| panic!("{}: no event was reported", fixture.name));
        let actual = Expected {
            billing: event.billing,
            billing_signal: event.billing_signal.clone(),
            model: event.model.clone(),
            model_signal: event.model_signal.clone(),
            served_by: event.served_by.clone(),
            input_tokens: event.input_tokens,
            output_tokens: event.output_tokens,
            cache_read_tokens: event.cache_read_tokens,
            cache_write_tokens: event.cache_write_tokens,
        };
        assert_eq!(actual, fixture.expect, "fixture {}", fixture.name);
        assert_eq!(event.provider, fixture.request.host, "{}", fixture.name);
        assert_eq!(event.status, fixture.response.status, "{}", fixture.name);
    }
}

type UpstreamAnswers = Arc<HashMap<String, (u16, BTreeMap<String, String>, Vec<u8>)>>;

/// A fake upstream that answers each fixture's request with that fixture's response, picked by a header.
async fn answer_with_fixture(
    State(answers): State<UpstreamAnswers>,
    headers: HeaderMap,
) -> Response {
    let name = headers.get(FIXTURE_HEADER).unwrap().to_str().unwrap();
    let (status, response_headers, body) = answers.get(name).unwrap();
    let mut response = Response::new(axum::body::Body::from(body.clone()));
    *response.status_mut() = StatusCode::from_u16(*status).unwrap();
    *response.headers_mut() = header_map(response_headers);
    response.into_response()
}

#[tokio::test]
async fn the_client_passes_every_response_through_unchanged_and_counts_the_same_tokens() {
    let fixtures = fixtures();
    let answers: UpstreamAnswers = Arc::new(
        fixtures
            .iter()
            .map(|fixture| {
                let response = &fixture.response;
                let answer = (
                    response.status,
                    response.headers.clone(),
                    response.body_bytes(),
                );
                (fixture.name.clone(), answer)
            })
            .collect(),
    );
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", upstream.local_addr().unwrap());
    let router = Router::new()
        .fallback(answer_with_fixture)
        .with_state(answers);
    tokio::spawn(async move { axum::serve(upstream, router).await });

    let config = Config {
        upstream: base,
        ..Config::default()
    };
    let proxy = TestProxy::new(config, with_usage_reporting());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(api::serve(listener, proxy.state.clone()));
    let client = reqwest::Client::new();

    for (index, fixture) in fixtures.iter().enumerate() {
        let sent = client
            .post(format!("{address}/v1/messages"))
            .header(CONTENT_TYPE, "application/json")
            .header(FIXTURE_HEADER, &fixture.name)
            .body(fixture.request.body_bytes())
            .send()
            .await
            .unwrap();
        let name = &fixture.name;
        assert_eq!(sent.status().as_u16(), fixture.response.status, "{name}");
        for (header, value) in &fixture.response.headers {
            let received = sent
                .headers()
                .get(header)
                .and_then(|value| value.to_str().ok());
            assert_eq!(received, Some(value.as_str()), "{name}: header {header}");
        }
        let received_body = sent.bytes().await.unwrap();
        assert_eq!(
            received_body.as_ref(),
            fixture.response.body_bytes().as_slice(),
            "{name}: the body the client got differs from the upstream's"
        );

        let events = proxy.usage_events(index + 1).await;
        let event = events
            .get(index)
            .unwrap_or_else(|| panic!("{name}: no event"));
        let counted = (
            event.input_tokens,
            event.output_tokens,
            event.cache_read_tokens,
            event.cache_write_tokens,
        );
        let expected = &fixture.expect;
        let wanted = (
            expected.input_tokens,
            expected.output_tokens,
            expected.cache_read_tokens,
            expected.cache_write_tokens,
        );
        assert_eq!(counted, wanted, "{name}: tokens through the real proxy");
        assert_eq!(event.status, fixture.response.status, "{name}");
    }
}

#[test]
fn every_verified_signal_has_a_fixture_that_proves_it() {
    let table: Value = serde_json::from_str(BUILTIN_SIGNALS).unwrap();
    let signals = table["signals"].as_array().unwrap();
    let sets: HashMap<&str, &str> = signals
        .iter()
        .map(|signal| {
            (
                signal["id"].as_str().unwrap(),
                signal["sets"].as_str().unwrap(),
            )
        })
        .collect();

    let mut covered = HashSet::new();
    for fixture in fixtures() {
        for id in &fixture.covers {
            let fact = sets
                .get(id.as_str())
                .unwrap_or_else(|| panic!("{} covers `{id}`, which is not a signal", fixture.name));
            let proven = match *fact {
                "billing" => fixture.expect.billing_signal.as_deref() == Some(id),
                "model" => fixture.expect.model_signal.as_deref() == Some(id),
                _ => fixture.expect.served_by.is_some(),
            };
            assert!(
                proven,
                "{} says it covers `{id}` but does not expect that signal's result",
                fixture.name
            );
            covered.insert(id.clone());
        }
    }

    let missing: Vec<&str> = signals
        .iter()
        .filter(|signal| signal["verified"] == true)
        .map(|signal| signal["id"].as_str().unwrap())
        .filter(|id| !covered.contains(*id))
        .collect();
    assert!(
        missing.is_empty(),
        "verified signals without a fixture in tests/provider_fixtures/: {missing:?}"
    );
}
