//! The localhost API proxy. A tool (Claude Code, Codex, ...) is pointed at this port; chat requests on routes the
//! signed snapshot lists are read and screened, and everything else streams through with its body unread.
use super::audit::AuditAction;
use super::guard::{check_local_request, check_path, GuardError};
use super::screen::{screen_body_offloaded, Outcome, Screened};
use super::signals::Evidence;
use super::usage_tap::{Encoding, Tap};
use super::{AppState, ProxyError};
use crate::backend::new_event;
use crate::brand;
use crate::config::is_https_or_loopback;
use crate::platform;
use crate::policy::ActivePolicy;
use axum::body::{to_bytes, Body, Bytes};
use axum::extract::State;
use axum::http::header::{
    CONNECTION, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, HOST, PROXY_AUTHENTICATE,
    PROXY_AUTHORIZATION, TE, TRAILER, TRANSFER_ENCODING, UPGRADE,
};
use axum::http::{request::Parts, HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Router;
use contract::{FailureCondition, Format};
use engine::{unreadable_message, LocalRoute, Report};
use futures_util::StreamExt;
use serde_json::json;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpListener;

const PAC_PATH: &str = "/proxy.pac";
const HEALTH_PATH: &str = "/health";
const KEEP_ALIVE: HeaderName = HeaderName::from_static("keep-alive");
const PROXY_CONNECTION: HeaderName = HeaderName::from_static("proxy-connection");
/// Describe a single connection, not the message, so a proxy must not pass them on.
const HOP_BY_HOP: [HeaderName; 9] = [
    CONNECTION,
    TRANSFER_ENCODING,
    UPGRADE,
    TE,
    TRAILER,
    KEEP_ALIVE,
    PROXY_AUTHORIZATION,
    PROXY_AUTHENTICATE,
    PROXY_CONNECTION,
];
const PAC_CONTENT_TYPE: &str = "application/x-ns-proxy-autoconfig";
const FALLBACK_BLOCK_RULE: &str = "policy";

#[derive(Clone)]
struct ApiContext {
    state: Arc<AppState>,
    port: u16,
}

/// What the scan learned about a request, for the usage event.
#[derive(Default)]
struct Seen {
    model: String,
    findings: usize,
    evidence: Evidence,
}

pub fn router(state: Arc<AppState>, port: u16) -> Router {
    Router::new()
        .fallback(handle)
        .with_state(ApiContext { state, port })
}

pub async fn serve(listener: TcpListener, state: Arc<AppState>) -> Result<(), ProxyError> {
    let address = listener.local_addr().map_err(ProxyError::Serve)?;
    tracing::info!("API proxy listening on {address}");
    axum::serve(listener, router(state, address.port()))
        .await
        .map_err(ProxyError::Serve)
}

async fn handle(State(context): State<ApiContext>, request: Request<Body>) -> Response {
    let state = &context.state;
    let (mut parts, body) = request.into_parts();
    let authority = parts.uri.authority().map(|authority| authority.as_str());
    if let Err(error) = check_local_request(&parts.headers, authority, context.port) {
        return rejected(&error);
    }
    let active = state.policy();
    if parts.method == Method::GET && parts.uri.path() == HEALTH_PATH {
        return health(&active);
    }
    if parts.method == Method::GET && parts.uri.path() == PAC_PATH {
        return pac(state, &active);
    }
    let path_error = check_path(parts.uri.path()).err().or_else(|| {
        active
            .policy
            .is_local_route_variant(parts.uri.path())
            .then_some(GuardError::RouteVariant)
    });
    if let Some(error) = path_error {
        let destination = host_of(&active.effective.upstream);
        state
            .audit
            .record(AuditAction::Rejected, &destination, 0, &[]);
        tracing::warn!("refused a request with an ambiguous path: {error}");
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            &format!("{} {error}", brand::BLOCKED_PREFIX),
        );
    }
    let route = active
        .policy
        .local_route(parts.uri.path(), &active.effective.upstream);

    if !route.enabled || !route.chat {
        let body = untouched_body(has_body(&parts), body);
        return forward(state, parts, body, &route, None).await;
    }

    let limit = state.config.limits.max_body_bytes;
    let Ok(mut raw) = to_bytes(body, limit).await else {
        let why = format!("request body unreadable or over {limit} bytes");
        let destination = host_of(&route.upstream);
        let screened = Screened::blocked(FailureCondition::Unscannable, &why, Report::default(), 0);
        state.conclude(&screened, &destination, &destination);
        return blocked(
            engine::decision::UNSCANNABLE_RULE_ID,
            &unreadable_message(&why),
        );
    };
    // Signals read the body as sent: one that is compressed or rewritten below is not seen by a body signal.
    let evidence = state.signals.classify_request(
        &host_of(&route.upstream),
        &route.path,
        &parts.headers,
        &raw,
    );
    let mut seen = Seen {
        evidence,
        ..Seen::default()
    };
    if !raw.is_empty() {
        let started = Instant::now();
        let screened = screen_body_offloaded(
            active.clone(),
            Format::Json,
            parts
                .headers
                .get(CONTENT_ENCODING)
                .map(|value| value.as_bytes().to_vec()),
            raw.clone(),
            state.config.limits.max_decoded_bytes,
        )
        .await;
        let destination = host_of(&route.upstream);
        state.conclude(&screened, &destination, &destination);
        tracing::debug!(
            method = %parts.method,
            path = parts.uri.path(),
            bytes = raw.len(),
            findings = screened.report.findings.len(),
            elapsed_ms = elapsed_ms(started),
            "request screened"
        );
        seen = Seen {
            model: screened.model.clone(),
            findings: screened.report.findings.len(),
            evidence: seen.evidence,
        };
        match screened.outcome {
            Outcome::Allow => {}
            Outcome::Rewrite(rewritten) => {
                raw = Bytes::from(rewritten);
                parts.headers.remove(CONTENT_ENCODING);
            }
            Outcome::Block { rule_ids, message } => {
                let mut event = new_event(
                    &destination,
                    &seen.model,
                    StatusCode::BAD_REQUEST.as_u16(),
                    true,
                    seen.findings,
                    seen.evidence.billing,
                );
                seen.evidence.stamp(&mut event);
                state.usage.report(event);
                return blocked(&rule_ids.join(","), &message);
            }
        }
    }
    parts.headers.remove(CONTENT_LENGTH);
    forward(state, parts, reqwest::Body::from(raw), &route, Some(seen)).await
}

fn elapsed_ms(since: Instant) -> f64 {
    since.elapsed().as_secs_f64() * 1000.0
}

fn has_body(parts: &Parts) -> bool {
    let sized = parts
        .headers
        .get(CONTENT_LENGTH)
        .is_some_and(|length| length != "0");
    sized || parts.headers.contains_key(TRANSFER_ENCODING)
}

/// A request we are not reading: passed through as a stream, or nothing at all when it has no body.
fn untouched_body(has_body: bool, body: Body) -> reqwest::Body {
    if has_body {
        return reqwest::Body::wrap_stream(body.into_data_stream());
    }
    reqwest::Body::from(Bytes::new())
}

fn host_of(upstream: &str) -> String {
    upstream
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or_default()
        .to_string()
}

fn health(active: &ActivePolicy) -> Response {
    axum::Json(json!({"version": env!("CARGO_PKG_VERSION"), "policy_version": active.version}))
        .into_response()
}

/// Removes the headers that belong to this hop only: the fixed list plus any header the `Connection` header names.
fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let named: Vec<HeaderName> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect();
    for name in named.iter().chain(HOP_BY_HOP.iter()) {
        headers.remove(name);
    }
}

/// Proxy auto-config for browsers (installed by `inveil browser-setup`): hosts of enabled browser tools go to the
/// browser proxy.
fn pac(state: &AppState, active: &ActivePolicy) -> Response {
    let script = platform::pac_script(
        &active.policy.decrypted_hosts(),
        &active.policy.usable_domains,
        state.config.listen.browser_port,
        active.effective.failure_modes.service_down,
    );
    ([(CONTENT_TYPE, PAC_CONTENT_TYPE)], script).into_response()
}

fn rejected(error: &GuardError) -> Response {
    error_response(
        StatusCode::FORBIDDEN,
        "permission_error",
        &format!("{} {error}", brand::BLOCKED_PREFIX),
    )
}

fn blocked(rule_ids: &str, message: &str) -> Response {
    let mut response = error_response(StatusCode::BAD_REQUEST, "invalid_request_error", message);
    let rules = HeaderValue::from_str(rule_ids)
        .unwrap_or_else(|_| HeaderValue::from_static(FALLBACK_BLOCK_RULE));
    response.headers_mut().insert(brand::BLOCKED_HEADER, rules);
    response
}

/// Anthropic-shaped error so the tool prints the message.
fn error_response(status: StatusCode, kind: &str, message: &str) -> Response {
    let body = json!({"type": "error", "error": {"type": kind, "message": message}});
    (status, axum::Json(body)).into_response()
}

async fn forward(
    state: &AppState,
    parts: Parts,
    body: reqwest::Body,
    route: &LocalRoute,
    seen: Option<Seen>,
) -> Response {
    if !is_https_or_loopback(&route.upstream) {
        return error_response(
            StatusCode::BAD_GATEWAY,
            "api_error",
            &format!("{} the upstream must use https", brand::PRODUCT),
        );
    }
    let query = parts
        .uri
        .query()
        .map(|query| format!("?{query}"))
        .unwrap_or_default();
    let url = format!("{}{}{query}", route.upstream, route.path);
    let mut headers = parts.headers;
    headers.remove(HOST);
    strip_hop_by_hop(&mut headers);
    let sent = Instant::now();
    let upstream = match state
        .http
        .request(parts.method, url)
        .headers(headers)
        .body(body)
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) => {
            tracing::warn!("could not reach the upstream: {}", error.without_url());
            return error_response(
                StatusCode::BAD_GATEWAY,
                "api_error",
                &format!("{} could not reach the upstream", brand::PRODUCT),
            );
        }
    };
    let status = upstream.status();
    tracing::debug!(
        status = status.as_u16(),
        elapsed_ms = elapsed_ms(sent),
        "upstream answered"
    );

    let mut response_headers = upstream.headers().clone();
    strip_hop_by_hop(&mut response_headers);
    let is_event_stream = upstream
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.contains("text/event-stream"));

    let body = match seen {
        None => Body::from_stream(upstream.bytes_stream()),
        Some(seen) => {
            let host = host_of(&route.upstream);
            let event = new_event(
                &host,
                &seen.model,
                status.as_u16(),
                false,
                seen.findings,
                seen.evidence.billing,
            );
            let reader = state.signals.response_reader(
                &host,
                &route.path,
                &seen.evidence,
                &response_headers,
            );
            let encoding = Encoding::from_headers(&response_headers);
            let mut tap = Tap::new(
                state.usage.clone(),
                event,
                is_event_stream,
                encoding,
                reader,
            );
            Body::from_stream(upstream.bytes_stream().map(move |chunk| {
                if let Ok(bytes) = &chunk {
                    tap.observe(bytes);
                }
                chunk
            }))
        }
    };
    let mut response = Response::new(body);
    *response.status_mut() = status;
    *response.headers_mut() = response_headers;
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::proxy::test_support::{builtin_with, redact_rules, CapturedLog, TestProxy};
    use axum::body::to_bytes;
    use contract::Via;
    use serde_json::{json, Value};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    const SSN_TEXT: &str = "my ssn is 123-45-6789";

    struct Rig {
        proxy: TestProxy,
        address: String,
        http: reqwest::Client,
        upstream_requests: Arc<AtomicUsize>,
    }

    /// A fake upstream that echoes what it was sent, and the real localhost proxy in front of it.
    async fn rig_with(config: Config, change: impl FnOnce(&mut contract::Snapshot)) -> Rig {
        rig_expiring(config, change, None).await
    }

    async fn rig_expiring(
        config: Config,
        change: impl FnOnce(&mut contract::Snapshot),
        expires_at: Option<u64>,
    ) -> Rig {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_address = upstream.local_addr().unwrap();
        let upstream_requests = Arc::new(AtomicUsize::new(0));
        let counted = upstream_requests.clone();
        let echo = Router::new().fallback(move |request: Request<Body>| async move {
            counted.fetch_add(1, Ordering::SeqCst);
            let (parts, body) = request.into_parts();
            let bytes = to_bytes(body, 1 << 20).await.unwrap();
            axum::Json(json!({
                "method": parts.method.as_str(),
                "uri": parts.uri.to_string(),
                "content_type": parts.headers.get(CONTENT_TYPE).and_then(|value| value.to_str().ok()),
                "headers": parts.headers.keys().map(|name| name.as_str()).collect::<Vec<_>>(),
                "body": String::from_utf8_lossy(&bytes),
            }))
        });
        tokio::spawn(async move { axum::serve(upstream, echo).await });

        let base = format!("http://{upstream_address}");
        let mut config = config;
        config.upstream = base.clone();
        let snapshot = builtin_with(|snapshot| {
            snapshot
                .tools
                .iter_mut()
                .filter(|tool| tool.via == Via::Local && tool.id == "codex-api")
                .for_each(|tool| tool.upstream = Some(base.clone()));
            change(snapshot);
        });
        let proxy = TestProxy::with_expiry(config, snapshot, expires_at);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(serve(listener, proxy.state.clone()));
        Rig {
            proxy,
            address,
            http: reqwest::Client::new(),
            upstream_requests,
        }
    }

    /// Sends the request target exactly as written: an HTTP client would tidy `..` and `%2e` segments away first.
    async fn raw_request(
        rig: &Rig,
        method: &str,
        target: &str,
        extra_headers: &str,
        body: &str,
    ) -> String {
        let host = rig.address.trim_start_matches("http://");
        let mut stream = TcpStream::connect(host).await.unwrap();
        let request = format!(
            "{method} {target} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\n{extra_headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        response
    }

    #[tokio::test]
    async fn paths_the_upstream_could_rewrite_never_reach_it_with_an_unscanned_chat_body() {
        let rig = rig().await;
        let body = json!({"input": SSN_TEXT}).to_string();
        for target in [
            "/v1/x/../messages",
            "/v1/./messages",
            "/v1/x/%2e%2e/messages",
            "/v1/x/%2E%2E/messages",
            "/v1/x/..%2fmessages",
            "/v1%2fmessages",
            "/v1%5cmessages",
            "/v1/%6dessages",
            "/v1//messages",
            "/v1/messages;x=1",
            "/v1\\messages",
            "/openai/v1/x/../responses",
            "/openai/v1/x/%2e%2e/responses",
            "/openai/../v1/messages",
        ] {
            let response = raw_request(&rig, "POST", target, "", &body).await;
            assert!(response.starts_with("HTTP/1.1 400"), "{target}: {response}");
        }
        assert_eq!(
            rig.upstream_requests.load(Ordering::SeqCst),
            0,
            "the upstream saw a request it could not have scanned"
        );
        assert!(rig.proxy.audit_text().contains(r#""action":"rejected""#));
    }

    #[tokio::test]
    async fn case_and_trailing_slash_variants_of_a_chat_route_are_refused_not_forwarded_unread() {
        let rig = rig().await;
        let body = json!({"input": SSN_TEXT}).to_string();
        for target in [
            "/v1/messages/",
            "/V1/Messages",
            "/openai/v1/responses/",
            "/openai/V1/responses",
        ] {
            let response = raw_request(&rig, "POST", target, "", &body).await;
            assert!(response.starts_with("HTTP/1.1 400"), "{target}: {response}");
        }
        assert_eq!(rig.upstream_requests.load(Ordering::SeqCst), 0);
        assert!(rig.proxy.audit_text().contains(r#""action":"rejected""#));
    }

    #[tokio::test]
    async fn a_canonical_chat_path_is_still_scanned_and_forwarded() {
        let rig = rig().await;
        let response = raw_request(
            &rig,
            "POST",
            "/v1/messages?beta=true",
            "",
            r#"{"input":"hi"}"#,
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert_eq!(rig.upstream_requests.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn health_reports_only_the_versions_to_a_loopback_host_and_never_reaches_the_upstream() {
        let rig = rig().await;
        let response = rig
            .http
            .get(format!("{}/health", rig.address))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(
            response.json::<Value>().await.unwrap(),
            json!({
                "version": env!("CARGO_PKG_VERSION"),
                "policy_version": rig.proxy.state.policy().version,
            })
        );
        let foreign = rig
            .http
            .get(format!("{}/health", rig.address))
            .header("host", "evil.example:8787")
            .send()
            .await
            .unwrap();
        assert_eq!(foreign.status(), 403);
        assert_eq!(rig.upstream_requests.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn hop_by_hop_headers_are_not_forwarded_to_the_upstream() {
        let rig = rig().await;
        let response = raw_request(
            &rig,
            "POST",
            "/openai/v1/files",
            "Keep-Alive: timeout=5\r\nTE: trailers\r\nProxy-Authorization: Basic eDp5\r\nProxy-Connection: keep-alive\r\nUpgrade: websocket\r\nX-Hop: secret\r\nConnection: X-Hop\r\nX-End-To-End: kept\r\n",
            "{}",
        )
        .await;
        let echoed: Value =
            serde_json::from_str(response.split("\r\n\r\n").nth(1).unwrap().trim()).unwrap();
        let received: Vec<&str> = echoed["headers"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        for header in [
            "keep-alive",
            "te",
            "proxy-authorization",
            "proxy-connection",
            "upgrade",
            "x-hop",
        ] {
            assert!(
                !received.contains(&header),
                "{header} was forwarded: {received:?}"
            );
        }
        assert!(received.contains(&"x-end-to-end"));
    }

    async fn rig() -> Rig {
        rig_with(Config::default(), |_| {}).await
    }

    #[tokio::test]
    async fn only_chat_routes_are_read_and_other_requests_pass_through_untouched() {
        let rig = rig().await;
        let proxy = &rig.address;

        let upload = rig
            .http
            .post(format!("{proxy}/openai/v1/files?x=1"))
            .header("content-type", "application/octet-stream")
            .body(vec![0u8, 159, 146, 150])
            .send()
            .await
            .unwrap();
        assert_eq!(upload.status(), 200);
        let echoed: Value = upload.json().await.unwrap();
        assert_eq!(echoed["uri"], "/v1/files?x=1", "prefix removed, query kept");
        assert_eq!(echoed["content_type"], "application/octet-stream");

        let get = rig
            .http
            .get(format!("{proxy}/openai/v1/models"))
            .send()
            .await
            .unwrap();
        assert_eq!(get.json::<Value>().await.unwrap()["method"], "GET");

        let clean = rig
            .http
            .post(format!("{proxy}/openai/v1/responses"))
            .json(&json!({"input": "hello"}))
            .send()
            .await
            .unwrap();
        assert_eq!(clean.status(), 200);
        let echoed: Value = clean.json().await.unwrap();
        assert_eq!(echoed["uri"], "/v1/responses");
        assert!(echoed["body"].as_str().unwrap().contains("hello"));
    }

    #[tokio::test]
    async fn a_chat_route_with_an_ssn_is_blocked_with_400_before_reaching_the_upstream() {
        let rig = rig().await;
        for path in ["/openai/v1/responses", "/v1/messages"] {
            let response = rig
                .http
                .post(format!("{}{path}", rig.address))
                .json(&json!({"input": SSN_TEXT}))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), 400, "{path}");
            assert!(response.headers().contains_key(brand::BLOCKED_HEADER));
            let body: Value = response.json().await.unwrap();
            assert!(
                body["error"]["message"]
                    .as_str()
                    .unwrap()
                    .contains("INVEIL BLOCKED"),
                "{path}: {body}"
            );
        }
        let events = rig.proxy.usage_events(2).await;
        assert!(events
            .iter()
            .all(|event| event.blocked && event.status == 400));
        assert!(rig.proxy.audit_text().contains("\"action\":\"block\""));
    }

    #[tokio::test]
    async fn the_default_route_reads_claude_chat_and_leaves_other_calls_alone() {
        let rig = rig().await;
        let models = rig
            .http
            .post(format!("{}/v1/models", rig.address))
            .body("not json at all")
            .send()
            .await
            .unwrap();
        assert_eq!(models.status(), 200, "/v1/models is not a chat route");
        let messages = rig
            .http
            .post(format!("{}/v1/messages", rig.address))
            .body("not json at all")
            .send()
            .await
            .unwrap();
        assert_eq!(
            messages.status(),
            400,
            "a chat route we cannot read is blocked (fail closed)"
        );
    }

    #[tokio::test]
    async fn a_redact_rule_rewrites_the_body_the_upstream_sees() {
        let rig = rig_with(Config::default(), |snapshot| {
            redact_rules(snapshot, &["ssn"])
        })
        .await;
        let response = rig
            .http
            .post(format!("{}/v1/messages", rig.address))
            .json(&json!({"model": "m1", "input": SSN_TEXT}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let echoed: Value = response.json().await.unwrap();
        let sent = echoed["body"].as_str().unwrap();
        assert!(
            sent.contains("[REDACTED:ssn]") && !sent.contains("123-45-6789"),
            "{sent}"
        );
        assert!(rig.proxy.audit_text().contains("\"action\":\"redact\""));
    }

    #[tokio::test]
    async fn dry_run_logs_but_lets_the_request_through_unless_the_server_enforces() {
        let config = Config {
            dry_run: true,
            ..Config::default()
        };
        let rig = rig_with(config.clone(), |_| {}).await;
        let sent = rig
            .http
            .post(format!("{}/v1/messages", rig.address))
            .json(&json!({"input": SSN_TEXT}))
            .send()
            .await
            .unwrap();
        assert_eq!(
            sent.status(),
            200,
            "local dry run applies when the server says nothing"
        );
        assert!(rig.proxy.audit_text().contains("dry_run"));

        let enforced = rig_with(config, |snapshot| snapshot.settings.dry_run = Some(false)).await;
        let blocked = enforced
            .http
            .post(format!("{}/v1/messages", enforced.address))
            .json(&json!({"input": SSN_TEXT}))
            .send()
            .await
            .unwrap();
        assert_eq!(
            blocked.status(),
            400,
            "a server that enforces cannot be overridden locally"
        );
    }

    #[tokio::test]
    async fn requests_not_addressed_to_our_loopback_address_or_carrying_an_origin_are_refused() {
        let rig = rig().await;
        let url = format!("{}/v1/models", rig.address);
        let rebinding = rig
            .http
            .get(&url)
            .header("host", "evil.example:8787")
            .send()
            .await
            .unwrap();
        assert_eq!(rebinding.status(), 403);
        let wrong_port = rig
            .http
            .get(&url)
            .header("host", "127.0.0.1:1")
            .send()
            .await
            .unwrap();
        assert_eq!(wrong_port.status(), 403);
        let web_page = rig
            .http
            .get(&url)
            .header("origin", "https://evil.example")
            .send()
            .await
            .unwrap();
        assert_eq!(web_page.status(), 403);
        assert_eq!(rig.http.get(&url).send().await.unwrap().status(), 200);
    }

    #[tokio::test]
    async fn chat_is_blocked_once_an_expired_policy_has_the_closed_mode() {
        let config = Config::default();
        let mut snapshot = builtin_with(|snapshot| {
            snapshot.settings.failure_modes.policy_expired = Some(contract::FailMode::Closed)
        });
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        snapshot.tools.clear();
        let mut config = config;
        config.upstream = format!("http://{}", upstream.local_addr().unwrap());
        let proxy = TestProxy::with_expiry(config, snapshot, Some(1));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, proxy.state.clone()));
        let response = reqwest::Client::new()
            .post(format!("http://{address}/v1/messages"))
            .json(&json!({"input": "hello"}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 400);
        let body: Value = response.json().await.unwrap();
        assert!(body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("expired"));
    }

    #[tokio::test]
    async fn an_expired_policy_with_the_open_mode_passes_chat_and_audits_every_pass_through() {
        let rig = rig_expiring(
            Config::default(),
            |snapshot| {
                snapshot.settings.failure_modes.policy_expired = Some(contract::FailMode::Open);
            },
            Some(1),
        )
        .await;
        let response = rig
            .http
            .post(format!("{}/v1/messages", rig.address))
            .json(&json!({"input": "hello"}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let audit = rig.proxy.audit_text();
        assert!(audit.contains(r#""action":"fail_open""#), "{audit}");
        assert!(audit.contains(r#""condition":"policy_expired""#), "{audit}");
    }

    #[tokio::test]
    async fn an_unreadable_body_follows_the_unscannable_mode_and_open_is_audited() {
        let post = |rig: &Rig| {
            rig.http
                .post(format!("{}/v1/messages", rig.address))
                .body("not json")
                .send()
        };
        let closed = rig().await;
        assert_eq!(post(&closed).await.unwrap().status(), 400);
        assert!(closed.proxy.audit_text().contains(r#""action":"block""#));

        let open = rig_with(Config::default(), |snapshot| {
            snapshot.settings.failure_modes.unscannable = Some(contract::FailMode::Open);
        })
        .await;
        assert_eq!(post(&open).await.unwrap().status(), 200);
        let audit = open.proxy.audit_text();
        assert!(audit.contains(r#""action":"fail_open""#), "{audit}");
        assert!(audit.contains(r#""condition":"unscannable""#), "{audit}");
    }

    #[tokio::test]
    async fn the_served_pac_follows_the_service_down_mode() {
        let pac_for = |mode: Option<contract::FailMode>| async move {
            let rig = rig_with(Config::default(), |snapshot| {
                snapshot.settings.failure_modes.service_down = mode;
            })
            .await;
            rig.http
                .get(format!("{}{PAC_PATH}", rig.address))
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap()
        };
        assert!(pac_for(None).await.contains("; DIRECT"), "open by default");
        let open = pac_for(Some(contract::FailMode::Open)).await;
        assert!(open.contains("; DIRECT"));
        let closed = pac_for(Some(contract::FailMode::Closed)).await;
        assert!(closed.contains("PROXY 127.0.0.1:8788\""), "{closed}");
        assert!(!closed.contains("; DIRECT"));
    }

    #[tokio::test]
    async fn debug_and_trace_logs_carry_metadata_only_never_request_content() {
        const SECRET_TEXT: &str = "SENTINEL-PROMPT-TEXT-7731";
        const SECRET_HEADER: &str = "SENTINEL-AUTH-TOKEN-4492";
        let log = CapturedLog::install_globally();

        let rig = rig_with(Config::default(), |snapshot| {
            redact_rules(snapshot, &["email"])
        })
        .await;
        let bodies = [
            json!({"input": format!("{SECRET_TEXT} a clean prompt")}),
            json!({"input": format!("{SECRET_TEXT} {SSN_TEXT}")}),
            json!({"input": format!("{SECRET_TEXT} write to jane.doe@example.com")}),
        ];
        for body in bodies {
            rig.http
                .post(format!("{}/v1/messages", rig.address))
                .header("authorization", format!("Bearer {SECRET_HEADER}"))
                .json(&body)
                .send()
                .await
                .unwrap();
        }
        rig.http
            .post(format!(
                "{}/openai/v1/files?token={SECRET_HEADER}",
                rig.address
            ))
            .body(SECRET_TEXT)
            .send()
            .await
            .unwrap();

        let output = log.text();
        assert!(
            output.contains("request screened"),
            "debug lines were produced: {output}"
        );
        for secret in [
            SECRET_TEXT,
            SECRET_HEADER,
            "123-45-6789",
            "jane.doe@example.com",
        ] {
            assert!(
                !output.contains(secret),
                "{secret} leaked into the log:\n{output}"
            );
            assert!(
                !rig.proxy.audit_text().contains(secret),
                "{secret} leaked into the audit log"
            );
        }
    }
}
