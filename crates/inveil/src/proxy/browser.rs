//! The browser proxy: a local forward proxy for AI chat sites that talk to the server in a format the API proxy
//! cannot read (claude.ai uses protobuf, grok.com a WebSocket). Browsers reach it through the PAC file that
//! `inveil browser-setup` installs. Only hosts that have `endpoints` in the signed snapshot are decrypted; every
//! other connection is tunnelled untouched.
//!
//! Headers: the only request header this module reads is Content-Encoding, to unpack the body. Cookies,
//! Authorization, CSRF and session tokens are never read, logged or changed: requests are forwarded with exactly
//! the headers the browser sent, except Content-Encoding and Content-Length when the body was rewritten.
use super::audit::AuditAction;
use super::guard::{check_path, GuardError};
use super::screen::{
    on_failure, screen_body_offloaded, screen_frame_offloaded, screen_websocket_text, Outcome,
    Screened,
};
use super::{browser_ca, AppState, ProxyError};
use crate::backend::new_event;
use crate::brand;
use crate::policy::ActivePolicy;
use axum::http::HeaderMap;
use bytes::BytesMut;
use contract::{FailureCondition, Format};
use engine::connect::{self, Cut, Frame};
use engine::{is_covered, normalize_host, unreadable_message};
use http_body_util::{BodyExt, Full, Limited};
use hudsucker::certificate_authority::{CertificateAuthority, RcgenAuthority};
use hudsucker::futures::{stream, StreamExt};
use hudsucker::hyper::body::Bytes;
use hudsucker::hyper::header::{
    HeaderValue, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, HOST, UPGRADE,
};
use hudsucker::hyper::http::request::Parts;
use hudsucker::hyper::http::uri::{Authority, Scheme};
use hudsucker::hyper::{Method, Request, Response, StatusCode, Uri};
use hudsucker::rustls::crypto::aws_lc_rs;
use hudsucker::rustls::{ClientConfig, ServerConfig};
use hudsucker::tokio_tungstenite::tungstenite::Message;
use hudsucker::{
    Body, HttpContext, HttpHandler, Proxy, RequestOrResponse, WebSocketContext, WebSocketHandler,
};
use hyper_rustls::ConfigBuilderExt;
use std::collections::HashSet;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::net::TcpListener;

/// Largest HTTP/2 header block accepted in either direction. The library default (16 KiB) is smaller than what
/// real sites send, and a header block over the limit fails the whole request with a 502. 256 KiB is about what
/// Chrome itself accepts.
#[cfg(feature = "http2")]
const MAX_HTTP2_HEADER_LIST: u32 = 256 << 10;
/// Unlisted routes mentioned by `trace` logging, so a busy site cannot grow the set without bound.
const MAX_TRACED_ROUTES: usize = 1000;
/// The only port a CONNECT may target: AI services are reached over HTTPS.
pub(crate) const HTTPS_PORT: u16 = 443;
const HTTP1_ALPN: &[u8] = b"http/1.1";
const BLOCKED_STREAM_CODE: &str = "permission_denied";
const STREAM_TOO_LARGE: &str = "a message over the frame size limit in a stream";

#[derive(Clone)]
struct ChatHandler {
    state: Arc<AppState>,
    connect_port: u16,
    /// Routes already reported by `trace`, so each unlisted route is mentioned once, not on every request.
    traced: Arc<Mutex<HashSet<String>>>,
}

/// What to do with one frame of a stream: send these bytes (as they came, or rewritten), or stop the stream.
enum FrameVerdict {
    Send(Bytes),
    Stop(String),
}

/// Issues the certificate (and TLS settings) for each decrypted host. Hosts with a WebSocket route are offered
/// HTTP/1.1 only: browsers open WebSockets over HTTP/1.1, and WebSockets over HTTP/2 are not verified against a
/// real session. Every other host gets HTTP/2 when it is compiled in.
struct RouteAwareAuthority {
    inner: RcgenAuthority,
    state: Arc<AppState>,
}

impl CertificateAuthority for RouteAwareAuthority {
    async fn gen_server_config(&self, authority: &Authority) -> Arc<ServerConfig> {
        let started = Instant::now();
        let name = normalize_host(authority.host());
        let normalized = Authority::try_from(name.as_ref()).unwrap_or_else(|_| authority.clone());
        let config = self.inner.gen_server_config(&normalized).await;
        tracing::debug!(
            host = authority.host(),
            elapsed_ms = started.elapsed().as_secs_f64() * 1000.0,
            "certificate ready"
        );
        let websocket = self.state.policy().policy.has_websocket_routes(&name);
        if cfg!(feature = "http2") && websocket {
            let mut http1_only = (*config).clone();
            http1_only.alpn_protocols = vec![HTTP1_ALPN.to_vec()];
            return Arc::new(http1_only);
        }
        config
    }
}

type ClientBuilder = hudsucker::hyper_util::client::legacy::Builder;
type ServerBuilder =
    hudsucker::hyper_util::server::conn::auto::Builder<hudsucker::hyper_util::rt::TokioExecutor>;

/// The proxy's upstream client and its server for browsers, with the larger HTTP/2 header limit.
#[cfg(feature = "http2")]
fn http_builders() -> (ClientBuilder, ServerBuilder) {
    use hudsucker::hyper_util::rt::TokioExecutor;
    let mut client = ClientBuilder::new(TokioExecutor::new());
    let mut server = ServerBuilder::new(TokioExecutor::new());
    client.http2_max_header_list_size(MAX_HTTP2_HEADER_LIST);
    server.http2().max_header_list_size(MAX_HTTP2_HEADER_LIST);
    (client, server)
}

#[cfg(not(feature = "http2"))]
fn http_builders() -> (ClientBuilder, ServerBuilder) {
    use hudsucker::hyper_util::rt::TokioExecutor;
    (
        ClientBuilder::new(TokioExecutor::new()),
        ServerBuilder::new(TokioExecutor::new()),
    )
}

/// Upstream TLS trusts the operating system's roots, so a company that inspects TLS with its own CA still works.
fn upstream_connector() -> Result<
    impl hudsucker::hyper_util::client::legacy::connect::Connect + Clone + Send + Sync + 'static,
    ProxyError,
> {
    let to_error =
        |error: &dyn std::fmt::Display| ProxyError::Browser(format!("upstream TLS: {error}"));
    let tls = ClientConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|error| to_error(&error))?
        .with_native_roots()
        .map_err(|error| to_error(&error))?
        .with_no_client_auth();
    let builder = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_http1();
    #[cfg(feature = "http2")]
    let builder = builder.enable_http2();
    Ok(builder.build())
}

/// Starts the browser proxy if `inveil browser-setup` has created a CA. Without one, browsers are not routed here.
pub async fn start(state: Arc<AppState>, ca_directory: &Path) -> Result<(), ProxyError> {
    let authority = match browser_ca::load_authority(ca_directory) {
        Ok(Some(authority)) => authority,
        Ok(None) => return Ok(()),
        Err(error) => {
            tracing::warn!("browser CA unusable, run `inveil browser-setup` again: {error}");
            return Ok(());
        }
    };
    let address = crate::util::loopback(state.config.listen.browser_port);
    let listener = TcpListener::bind(address)
        .await
        .map_err(|source| ProxyError::Bind { address, source })?;
    let policy = state.policy();
    browser_ca::warn_if_outdated(ca_directory, &policy.policy.ca_domains);
    tracing::debug!(
        "browser proxy decrypts: {}",
        policy.policy.decrypted_hosts().join(", ")
    );
    tokio::spawn(async move {
        if let Err(error) = run(state, authority, listener, HTTPS_PORT).await {
            tracing::error!("browser proxy stopped: {error}");
        }
    });
    Ok(())
}

async fn run(
    state: Arc<AppState>,
    authority: RcgenAuthority,
    listener: TcpListener,
    connect_port: u16,
) -> Result<(), ProxyError> {
    let authority = RouteAwareAuthority {
        inner: authority,
        state: state.clone(),
    };
    // Make each listed host's certificate now, so the first connection to it does not wait for one.
    for host in state.policy().policy.decrypted_hosts() {
        if let Ok(name) = Authority::try_from(host.as_str()) {
            authority.gen_server_config(&name).await;
        }
    }
    let handler = ChatHandler {
        state,
        connect_port,
        traced: Arc::default(),
    };
    let (client, server) = http_builders();
    let proxy = Proxy::builder()
        .with_listener(listener)
        .with_ca(authority)
        .with_http_connector(upstream_connector()?)
        .with_http_handler(handler.clone())
        .with_websocket_handler(handler)
        .with_client(client)
        .with_server(server)
        .build()
        .map_err(|error| ProxyError::Browser(error.to_string()))?;
    tracing::info!("browser proxy running");
    proxy
        .start()
        .await
        .map_err(|error| ProxyError::Browser(error.to_string()))
}

impl ChatHandler {
    /// Why a request must not be served, if so. Browsers reach this proxy for decrypted hosts only (the PAC sends
    /// nothing else), so anything else is another program or a web page trying to use it as an open proxy. On a
    /// decrypted host every request except a plain read must also have a path the site cannot reinterpret as a
    /// scanned route (see [`check_path`]) and must not be a case or trailing-slash variant of one. That covers
    /// WebSocket upgrades, which are GETs. Plain reads cannot be a chat or a WebSocket, so pages whose assets have
    /// percent-encoded names keep loading.
    fn refusal(&self, request: &Request<Body>) -> Option<Response<Body>> {
        let policy = self.state.policy();
        let host = request.uri().host().unwrap_or_default();
        if let Err(error) = self.check_target(request, &policy) {
            tracing::warn!(host, "browser proxy refused a request: {error}");
            return Some(forbidden_response(&error));
        }
        if !policy.policy.decrypts(host) || is_plain_read(request) {
            return None;
        }
        let path = request.uri().path();
        let error = check_path(path).err().or_else(|| {
            policy
                .policy
                .is_route_variant(host, path)
                .then_some(GuardError::RouteVariant)
        })?;
        tracing::warn!(host, "browser proxy refused a request: {error}");
        self.state.audit.record(AuditAction::Rejected, host, 0, &[]);
        Some(json_response(
            StatusCode::BAD_REQUEST,
            serde_json::json!({ "error": format!("{} {error}", brand::BLOCKED_PREFIX) }),
        ))
    }

    fn check_target(
        &self,
        request: &Request<Body>,
        policy: &ActivePolicy,
    ) -> Result<(), GuardError> {
        check_target(
            request,
            policy,
            &self.state.config.upstream,
            self.connect_port,
            |host| policy.policy.decrypts(host),
        )
    }

    fn decrypts_connect(&self, request: &Request<Body>) -> bool {
        let Some(host) = request.uri().host() else {
            return false;
        };
        let decrypt = self.state.policy().policy.decrypts(host);
        tracing::debug!(host, decrypt, "CONNECT");
        decrypt
    }

    /// The chat route a request belongs to. Only POSTs to listed routes are read; everything else is `None`.
    fn chat_format(&self, request: &Request<Body>) -> Option<Format> {
        if request.method() != Method::POST {
            return None;
        }
        self.state
            .policy()
            .policy
            .format_for(request.uri().host()?, request.uri().path())
    }

    /// `trace` only: says once per route that it is not one we read, to find a route missing from the catalog.
    fn trace_unlisted(&self, kind: &str, host: &str, path: &str, detail: &str) {
        if !tracing::enabled!(tracing::Level::TRACE) {
            return;
        }
        let mut traced = crate::util::lock(&self.traced);
        if traced.len() < MAX_TRACED_ROUTES && traced.insert(format!("{kind} {host}{path}")) {
            tracing::trace!("{kind} {host}{path}: not a chat route, forwarded untouched{detail}");
        }
    }

    /// Records the decision and reports usage. Later frames of a stream do not count as a new chat send, but their
    /// findings are always reported.
    fn finish(&self, screened: &Screened, host: &str, counts_as_send: bool) {
        let policy = self.state.policy();
        let label = policy.policy.label_for_host(host);
        self.state.conclude(screened, host, &label);
        let blocked = matches!(screened.outcome, Outcome::Block { .. });
        if counts_as_send || blocked || !screened.report.findings.is_empty() {
            let status = if blocked {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::OK
            };
            let evidence = self
                .state
                .signals
                .classify_request(host, "", &HeaderMap::new(), &[]);
            let mut event = new_event(
                host,
                &screened.model,
                status.as_u16(),
                blocked,
                screened.report.findings.len(),
                evidence.billing,
            );
            evidence.stamp(&mut event);
            self.state.usage.report(event);
        }
    }

    async fn frame_verdict(&self, host: &str, frame: Frame, first: bool) -> FrameVerdict {
        let raw = frame.raw.clone();
        let limit = self.state.config.limits.max_decoded_bytes;
        let screened = screen_frame_offloaded(self.state.policy(), frame, limit).await;
        self.finish(&screened, host, first);
        match screened.outcome {
            Outcome::Allow => FrameVerdict::Send(raw),
            Outcome::Rewrite(replacement) => FrameVerdict::Send(Bytes::from(replacement)),
            Outcome::Block { message, .. } => FrameVerdict::Stop(message),
        }
    }

    /// A streaming request (Cursor's agent): the body stays open for the whole conversation, so it cannot be
    /// buffered. The first frame, the user's prompt, is held until it is whole and checked, so a block happens
    /// before anything is sent upstream. Every later frame (more user turns, tool results such as files the agent
    /// read) is checked as it passes. A block after the first frame ends the stream.
    async fn stream_request(&self, host: &str, parts: Parts, body: Body) -> RequestOrResponse {
        let mut incoming = Box::pin(body.into_data_stream());
        let mut buffer = BytesMut::new();

        let first = loop {
            match connect::cut(&mut buffer) {
                Cut::Frame(frame) => break frame,
                Cut::TooLarge => {
                    let screened = on_failure(
                        &self.state.policy(),
                        FailureCondition::Unscannable,
                        STREAM_TOO_LARGE,
                        0,
                    );
                    self.finish(&screened, host, true);
                    if let Outcome::Block { message, .. } = screened.outcome {
                        return blocked_stream_response(&message).into();
                    }
                    let rest =
                        stream::once(async move { Ok::<Bytes, hudsucker::Error>(buffer.freeze()) })
                            .chain(incoming);
                    return Request::from_parts(parts, Body::from_stream(rest)).into();
                }
                Cut::Incomplete => match incoming.next().await {
                    Some(Ok(chunk)) => buffer.extend_from_slice(&chunk),
                    // The stream ended before a whole frame: nothing we can read, so forward what there is.
                    _ => {
                        return Request::from_parts(parts, Body::from(Full::new(buffer.freeze())))
                            .into()
                    }
                },
            }
        };
        let first_frame = match self.frame_verdict(host, first, true).await {
            FrameVerdict::Send(bytes) => bytes,
            FrameVerdict::Stop(message) => return blocked_stream_response(&message).into(),
        };

        let (handler, host) = (self.clone(), host.to_string());
        let rest = stream::unfold(
            (incoming, buffer, false),
            move |(mut incoming, mut buffer, finished)| {
                let (handler, host) = (handler.clone(), host.clone());
                async move {
                    if finished {
                        return None;
                    }
                    let end = |message: String, incoming, buffer| {
                        Some((
                            Err(std::io::Error::other(message)),
                            (incoming, buffer, true),
                        ))
                    };
                    loop {
                        match connect::cut(&mut buffer) {
                            Cut::Frame(frame) => {
                                return match handler.frame_verdict(&host, frame, false).await {
                                    FrameVerdict::Send(bytes) => {
                                        Some((Ok(bytes), (incoming, buffer, false)))
                                    }
                                    FrameVerdict::Stop(message) => end(message, incoming, buffer),
                                };
                            }
                            Cut::TooLarge => {
                                return end(STREAM_TOO_LARGE.to_string(), incoming, buffer)
                            }
                            Cut::Incomplete => match incoming.next().await {
                                Some(Ok(chunk)) => buffer.extend_from_slice(&chunk),
                                Some(Err(error)) => {
                                    return end(error.to_string(), incoming, buffer)
                                }
                                None if buffer.is_empty() => return None,
                                None => {
                                    let leftover = buffer.split().freeze();
                                    return Some((Ok(leftover), (incoming, buffer, true)));
                                }
                            },
                        }
                    }
                }
            },
        );
        let body =
            stream::once(async move { Ok::<Bytes, std::io::Error>(first_frame) }).chain(rest);
        Request::from_parts(parts, Body::from_stream(body)).into()
    }

    async fn request_body(
        &self,
        host: &str,
        format: Format,
        parts: Parts,
        body: Body,
    ) -> RequestOrResponse {
        let active = self.state.policy();
        let limit = self.state.config.limits.max_body_bytes;
        let Ok(collected) = Limited::new(body, limit).collect().await else {
            let why = format!("request body unreadable or over {limit} bytes");
            let screened = Screened::blocked(
                FailureCondition::Unscannable,
                &why,
                engine::Report::default(),
                0,
            );
            self.finish(&screened, host, true);
            return blocked_response(&unreadable_message(&why)).into();
        };
        let bytes = collected.to_bytes();
        let started = Instant::now();
        let screened = screen_body_offloaded(
            active,
            format,
            parts
                .headers
                .get(CONTENT_ENCODING)
                .map(|value| value.as_bytes().to_vec()),
            bytes.clone(),
            self.state.config.limits.max_decoded_bytes,
        )
        .await;
        self.finish(&screened, host, true);
        tracing::debug!(
            host,
            path = parts.uri.path(),
            bytes = bytes.len(),
            elapsed_ms = started.elapsed().as_secs_f64() * 1000.0,
            findings = screened.report.findings.len(),
            "chat request screened"
        );
        let mut parts = parts;
        match screened.outcome {
            Outcome::Allow => Request::from_parts(parts, Body::from(Full::new(bytes))).into(),
            Outcome::Rewrite(rewritten) => {
                // The new body is not compressed and has a new length; every other header stays as sent.
                parts.headers.remove(CONTENT_ENCODING);
                parts.headers.remove(CONTENT_LENGTH);
                Request::from_parts(parts, Body::from(Full::new(Bytes::from(rewritten)))).into()
            }
            Outcome::Block { message, .. } => blocked_response(&message).into(),
        }
    }
}

/// The guard every browser-facing proxy applies before it serves a request, so none of them is an open proxy. A
/// CONNECT may only target `connect_port` on a host the catalog or the CA names; any other request must be https for
/// a host `decrypts` accepts, and its `Host` header must name the same host.
pub(crate) fn check_target(
    request: &Request<Body>,
    policy: &ActivePolicy,
    default_upstream: &str,
    connect_port: u16,
    decrypts: impl Fn(&str) -> bool,
) -> Result<(), GuardError> {
    let uri = request.uri();
    let host = uri.host().ok_or(GuardError::NotAProxyTarget)?;
    if request.method() == Method::CONNECT {
        let allowed =
            uri.port_u16() == Some(connect_port) && may_tunnel(host, policy, default_upstream);
        return allowed.then_some(()).ok_or(GuardError::TunnelNotAllowed);
    }
    if uri.scheme() != Some(&Scheme::HTTPS) || !decrypts(host) {
        return Err(GuardError::NotAProxyTarget);
    }
    let claimed = request
        .headers()
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split(':').next().unwrap_or_default());
    match claimed {
        Some(claimed) if normalize_host(claimed) != normalize_host(host) => {
            Err(GuardError::HostMismatch)
        }
        _ => Ok(()),
    }
}

/// Hosts a CONNECT may reach: those the catalog names (any tool, any host, including the upstreams of local tools
/// and the default upstream) and anything under a domain the CA covers.
fn may_tunnel(host: &str, policy: &ActivePolicy, default_upstream: &str) -> bool {
    let host = normalize_host(host);
    let upstream_hosts = policy
        .policy
        .tools
        .iter()
        .filter_map(|tool| tool.upstream.as_deref())
        .chain([default_upstream])
        .filter_map(|upstream| reqwest::Url::parse(upstream).ok())
        .filter_map(|url| url.host_str().map(|host| normalize_host(host).into_owned()));
    let catalog_hosts = policy
        .policy
        .tools
        .iter()
        .flat_map(|tool| tool.hosts.iter())
        .map(|entry| normalize_host(&entry.host).into_owned());
    is_covered(&host, &policy.policy.ca_domains)
        || upstream_hosts
            .chain(catalog_hosts)
            .any(|known| known == host.as_ref())
}

/// A request that cannot be a chat (a plain read) has nothing for the path checks to protect.
fn is_plain_read(request: &Request<Body>) -> bool {
    matches!(
        *request.method(),
        Method::GET | Method::HEAD | Method::OPTIONS
    ) && !request.headers().contains_key(UPGRADE)
}

/// Browsers may write the host in capitals or with a trailing dot (`chatgpt.com.`). The site gets the plain form,
/// which also keeps the TLS server name valid for the upstream connection.
fn with_normalized_host(request: Request<Body>) -> Request<Body> {
    let Some(host) = request.uri().host() else {
        return request;
    };
    let normalized = normalize_host(host);
    if normalized == host {
        return request;
    }
    let authority = match request.uri().port_u16() {
        Some(port) => format!("{normalized}:{port}"),
        None => normalized.into_owned(),
    };
    let (mut parts, body) = request.into_parts();
    let rebuilt = Uri::builder()
        .scheme(parts.uri.scheme().cloned().unwrap_or(Scheme::HTTPS))
        .authority(authority)
        .path_and_query(
            parts
                .uri
                .path_and_query()
                .map_or("/", |path_and_query| path_and_query.as_str()),
        )
        .build();
    if let Ok(uri) = rebuilt {
        parts.uri = uri;
    }
    Request::from_parts(parts, body)
}

fn json_response(status: StatusCode, body: serde_json::Value) -> Response<Body> {
    let mut response = Response::new(Body::from(Full::new(Bytes::from(body.to_string()))));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

/// The error a Connect/gRPC-web client understands: `permission_denied` is not retried and its message is shown,
/// where a bare HTTP 400 is retried and reported as an opaque failure.
fn blocked_stream_response(message: &str) -> Response<Body> {
    json_response(
        StatusCode::FORBIDDEN,
        serde_json::json!({ "code": BLOCKED_STREAM_CODE, "message": message }),
    )
}

pub(crate) fn forbidden_response(error: &GuardError) -> Response<Body> {
    json_response(
        StatusCode::FORBIDDEN,
        serde_json::json!({ "error": format!("{} {error}", brand::BLOCKED_PREFIX) }),
    )
}

fn blocked_response(message: &str) -> Response<Body> {
    json_response(
        StatusCode::BAD_REQUEST,
        serde_json::json!({ "error": message }),
    )
}

impl HttpHandler for ChatHandler {
    /// The site could not be reached (or answered badly). Say why, with the cause chain: a bare 502 is hard to
    /// debug. Error text only; no URL, no headers.
    async fn handle_error(
        &mut self,
        _ctx: &HttpContext,
        error: hudsucker::hyper_util::client::legacy::Error,
    ) -> Response<Body> {
        let mut cause = String::new();
        let mut source = std::error::Error::source(&error);
        while let Some(inner) = source {
            cause.push_str(&format!(" <- {inner}"));
            source = inner.source();
        }
        tracing::warn!("browser proxy could not forward a request: {error}{cause}");
        let mut response = Response::new(Body::empty());
        *response.status_mut() = StatusCode::BAD_GATEWAY;
        response
    }

    async fn should_intercept_connect(
        &mut self,
        _ctx: &HttpContext,
        request: &Request<Body>,
    ) -> bool {
        self.decrypts_connect(request)
    }

    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        request: Request<Body>,
    ) -> RequestOrResponse {
        if let Some(refusal) = self.refusal(&request) {
            return refusal.into();
        }
        let request = with_normalized_host(request);
        let Some(format) = self.chat_format(&request) else {
            if request.method() == Method::POST {
                let header = |name| {
                    request
                        .headers()
                        .get(name)
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or("-")
                };
                let detail = format!(
                    " (content-type {}, length {})",
                    header(CONTENT_TYPE),
                    header(CONTENT_LENGTH)
                );
                self.trace_unlisted(
                    "POST",
                    request.uri().host().unwrap_or_default(),
                    request.uri().path(),
                    &detail,
                );
            }
            return request.into();
        };
        let host = request.uri().host().unwrap_or_default().to_string();
        let (parts, body) = request.into_parts();
        if format == Format::ConnectStream {
            return self.stream_request(&host, parts, body).await;
        }
        self.request_body(&host, format, parts, body).await
    }
}

impl WebSocketHandler for ChatHandler {
    /// Messages the browser sends over a WebSocket (grok.com chats), only on routes listed as `websocket-json`.
    /// A frame that is not JSON passes. A blocked frame is dropped, so the site's UI just sees no reply.
    async fn handle_message(
        &mut self,
        ctx: &WebSocketContext,
        message: Message,
    ) -> Option<Message> {
        let WebSocketContext::ClientToServer { dst, .. } = ctx else {
            return Some(message);
        };
        let (host, path) = (dst.host().unwrap_or_default(), dst.path());
        let active = self.state.policy();
        if !active.policy.is_websocket_route(host, path) {
            self.trace_unlisted("WS", host, path, "");
            return Some(message);
        }
        let Message::Text(text) = &message else {
            return Some(message);
        };
        let Some(screened) = screen_websocket_text(&active, text.as_str()) else {
            return Some(message);
        };
        self.finish(&screened, host, false);
        match screened.outcome {
            Outcome::Allow => Some(message),
            Outcome::Block { .. } => None,
            Outcome::Rewrite(rewritten) => String::from_utf8(rewritten).ok().map(Message::text),
        }
    }
}

#[cfg(test)]
mod tests;
