use super::*;
use crate::config::Config;
use crate::proxy::test_support::{builtin_with, redact_rules, CapturedLog, TestProxy};
use engine::connect::{encode, Cut};
use serde_json::Value;
use std::io::Write;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const CURSOR: &str = "agentn.global.api5.cursor.sh";
const SSN_TEXT: &str = "my ssn is 123-45-6789";

fn handler(proxy: &TestProxy) -> ChatHandler {
    ChatHandler {
        state: proxy.state.clone(),
        connect_port: HTTPS_PORT,
        traced: Arc::default(),
    }
}

fn proxy_redacting(rule_ids: &[&str]) -> TestProxy {
    TestProxy::new(
        Config::default(),
        builtin_with(|snapshot| redact_rules(snapshot, rule_ids)),
    )
}

/// Starts the real proxy on a free local port with the CA the fixture created, returning its address and the
/// CA certificate so a client can trust it.
async fn start_proxy(proxy: &TestProxy) -> (SocketAddr, String) {
    start_proxy_tunnelling_to(proxy, HTTPS_PORT).await
}

async fn start_proxy_tunnelling_to(proxy: &TestProxy, connect_port: u16) -> (SocketAddr, String) {
    let authority = browser_ca::load_authority(&proxy.ca_directory)
        .unwrap()
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(run(proxy.state.clone(), authority, listener, connect_port));
    let certificate =
        std::fs::read_to_string(browser_ca::certificate_path(&proxy.ca_directory)).unwrap();
    (address, certificate)
}

fn client_through(address: SocketAddr, certificate: &str) -> reqwest::Client {
    reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(format!("http://{address}")).unwrap())
        .add_root_certificate(reqwest::Certificate::from_pem(certificate.as_bytes()).unwrap())
        .build()
        .unwrap()
}

#[tokio::test]
async fn blocks_a_chat_with_an_ssn_over_real_https_and_trusts_only_the_ca() {
    let proxy = proxy_redacting(&[]);
    let (address, certificate) = start_proxy(&proxy).await;
    let response = client_through(address, &certificate)
        .post("https://chatgpt.com/backend-api/f/conversation")
        .body(r#"{"messages":[{"content":{"parts":["my ssn is 123-45-6789"]}}]}"#)
        .send()
        .await
        .expect("TLS through the proxy works, so the leaf certificate is valid for chatgpt.com");
    assert_eq!(response.status(), 400);
    assert!(response.text().await.unwrap().contains("INVEIL BLOCKED"));
    assert!(proxy.audit_text().contains("\"action\":\"block\""));
}

#[tokio::test]
async fn tunnels_unlisted_hosts_without_decrypting_them() {
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    tokio::spawn(async move {
        let Ok((mut socket, _)) = echo.accept().await else {
            return;
        };
        let mut buffer = [0u8; 4];
        if socket.read_exact(&mut buffer).await.is_ok() {
            socket.write_all(&buffer).await.ok();
        }
    });

    let proxy = TestProxy::new(
        Config {
            upstream: format!("http://127.0.0.1:{echo_port}"),
            ..Config::default()
        },
        builtin_with(|_| {}),
    );
    let (address, _) = start_proxy_tunnelling_to(&proxy, echo_port).await;
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    let connect =
        format!("CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\nHost: 127.0.0.1:{echo_port}\r\n\r\n");
    stream.write_all(connect.as_bytes()).await.unwrap();
    let mut reply = Vec::new();
    while !reply.ends_with(b"\r\n\r\n") {
        reply.push(stream.read_u8().await.unwrap());
    }
    assert!(
        reply.starts_with(b"HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&reply)
    );
    stream.write_all(b"ping").await.unwrap();
    let mut echoed = [0u8; 4];
    stream.read_exact(&mut echoed).await.unwrap();
    assert_eq!(
        &echoed, b"ping",
        "plain bytes in, same bytes out: no TLS was terminated"
    );
}

fn post_parts(uri: &str) -> Parts {
    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .body(())
        .unwrap()
        .into_parts()
        .0
}

async fn rewritten_body(request: RequestOrResponse) -> String {
    let RequestOrResponse::Request(request) = request else {
        panic!("expected the request to be forwarded");
    };
    let collected = request.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(collected.to_vec()).unwrap()
}

#[tokio::test]
async fn a_redact_rule_rewrites_the_chat_body_and_a_clean_body_is_forwarded_unchanged() {
    let handler = handler(&proxy_redacting(&["ssn"]));
    let body = |text: &str| Body::from(Full::new(Bytes::from(text.to_string())));
    let uri = "https://chatgpt.com/backend-api/f/conversation";

    let redacted = handler
        .request_body(
            "chatgpt.com",
            Format::Json,
            post_parts(uri),
            body(r#"{"parts":["ssn 123-45-6789"]}"#),
        )
        .await;
    assert_eq!(
        rewritten_body(redacted).await,
        r#"{"parts":["ssn [REDACTED:ssn]"]}"#
    );

    let clean = handler
        .request_body(
            "chatgpt.com",
            Format::Json,
            post_parts(uri),
            body(r#"{"parts":["hello"]}"#),
        )
        .await;
    assert_eq!(rewritten_body(clean).await, r#"{"parts":["hello"]}"#);
}

#[tokio::test]
async fn a_body_that_cannot_be_read_is_blocked() {
    let handler = handler(&proxy_redacting(&[]));
    let uri = "https://chatgpt.com/backend-api/f/conversation";
    let response = handler
        .request_body(
            "chatgpt.com",
            Format::Json,
            post_parts(uri),
            Body::from(Full::new(Bytes::from("not json"))),
        )
        .await;
    assert!(
        matches!(response, RequestOrResponse::Response(response) if response.status() == StatusCode::BAD_REQUEST)
    );
}

#[tokio::test]
async fn chat_is_blocked_once_an_expired_policy_has_the_closed_mode() {
    let snapshot = builtin_with(|snapshot| {
        snapshot.settings.failure_modes.policy_expired = Some(contract::FailMode::Closed)
    });
    let handler = handler(&TestProxy::with_expiry(
        Config::default(),
        snapshot,
        Some(1),
    ));
    let uri = "https://chatgpt.com/backend-api/f/conversation";
    let response = handler
        .request_body(
            "chatgpt.com",
            Format::Json,
            post_parts(uri),
            Body::from(Full::new(Bytes::from(r#"{"parts":["hi"]}"#))),
        )
        .await;
    assert!(matches!(response, RequestOrResponse::Response(_)));
}

#[tokio::test]
async fn only_listed_post_routes_on_decrypted_hosts_are_chats() {
    let proxy = proxy_redacting(&[]);
    let handler = handler(&proxy);
    let request = |method: Method, uri: &str| {
        Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .unwrap()
    };
    let post = |uri: &str| request(Method::POST, uri);
    assert!(handler
        .chat_format(&post("https://chatgpt.com/backend-api/f/conversation"))
        .is_some());
    assert!(handler
        .chat_format(&post("https://chatgpt.com/ces/v1/telemetry/intake"))
        .is_none());
    assert!(handler
        .chat_format(&post("https://example.com/backend-api/f/conversation"))
        .is_none());
    assert!(handler
        .chat_format(&request(
            Method::GET,
            "https://chatgpt.com/backend-api/f/conversation"
        ))
        .is_none());
    assert!(
        handler
            .chat_format(&post("https://grok.com/ws/anything"))
            .is_none(),
        "a websocket route is not an HTTP chat"
    );
    assert!(proxy
        .state
        .policy()
        .policy
        .is_websocket_route("grok.com", "/ws/anything"));
    assert!(handler
        .chat_format(&post("https://grok.com/rest/app-chat/conversations/new"))
        .is_some());
    assert!(handler
        .chat_format(&post("https://grok.com/monitoring"))
        .is_none());
}

#[tokio::test]
async fn a_tool_switched_off_in_the_policy_is_not_intercepted() {
    let proxy = proxy_redacting(&[]);
    let handler = handler(&proxy);
    let post = Request::builder()
        .method(Method::POST)
        .uri("https://chatgpt.com/backend-api/f/conversation")
        .body(Body::empty())
        .unwrap();
    assert!(handler.chat_format(&post).is_some());
    proxy.replace_policy(&builtin_with(|snapshot| {
        snapshot
            .tools
            .iter_mut()
            .filter(|tool| tool.id == "chatgpt-web")
            .for_each(|tool| tool.enabled = false);
    }));
    assert!(handler.chat_format(&post).is_none());
}

#[tokio::test]
async fn hosts_with_websocket_routes_are_offered_http1_only() {
    let proxy = proxy_redacting(&[]);
    let authority = RouteAwareAuthority {
        inner: browser_ca::load_authority(&proxy.ca_directory)
            .unwrap()
            .unwrap(),
        state: proxy.state.clone(),
    };
    let alpn = |host: &'static str| {
        let authority = &authority;
        async move {
            authority
                .gen_server_config(&Authority::from_static(host))
                .await
                .alpn_protocols
                .clone()
        }
    };
    assert_eq!(alpn("grok.com").await, [HTTP1_ALPN.to_vec()]);
    assert_eq!(
        alpn("chatgpt.com").await,
        [HTTP1_ALPN.to_vec()],
        "chatgpt.com has one too (Codex)"
    );
    let claude = alpn("claude.ai").await;
    assert!(claude.contains(&HTTP1_ALPN.to_vec()));
    assert_eq!(claude.contains(&b"h2".to_vec()), cfg!(feature = "http2"));
}

#[tokio::test]
async fn unlisted_routes_are_traced_once() {
    CapturedLog::install_globally();
    let handler = handler(&proxy_redacting(&[]));
    for _ in 0..5 {
        handler.trace_unlisted("POST", "claude.ai", "/api/ping", "");
    }
    handler.trace_unlisted("POST", "claude.ai", "/api/other", "");
    assert_eq!(handler.traced.lock().unwrap().len(), 2);
}

// Streaming (Cursor's agent).

/// A protobuf message whose field 1 holds `text` (like the agent's opening prompt).
fn prompt_message(text: &str) -> Vec<u8> {
    let mut message = vec![0x0a, u8::try_from(text.len()).unwrap()];
    message.extend_from_slice(text.as_bytes());
    message
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

fn conversation(frames: &[(u8, Vec<u8>)]) -> Vec<u8> {
    frames
        .iter()
        .flat_map(|(flags, message)| encode(*flags, message).unwrap().to_vec())
        .collect()
}

fn chunked(stream: &[u8], chunk: usize) -> Body {
    let pieces: Vec<Result<Bytes, hudsucker::Error>> = stream
        .chunks(chunk)
        .map(|piece| Ok(Bytes::copy_from_slice(piece)))
        .collect();
    Body::from_stream(stream::iter(pieces))
}

/// Runs a stream through the handler, delivering it in `chunk`-sized pieces; `Err` means the stream was blocked.
async fn run_stream(handler: &ChatHandler, stream: &[u8], chunk: usize) -> Result<Vec<u8>, String> {
    let parts = post_parts(&format!("https://{CURSOR}/agent.v1.AgentService/Run"));
    match handler
        .stream_request(CURSOR, parts, chunked(stream, chunk))
        .await
    {
        RequestOrResponse::Request(request) => request
            .into_body()
            .collect()
            .await
            .map(|collected| collected.to_bytes().to_vec())
            .map_err(|error| error.to_string()),
        RequestOrResponse::Response(response) => {
            Err(format!("blocked with status {}", response.status()))
        }
    }
}

#[tokio::test]
async fn a_clean_stream_passes_through_byte_for_byte_however_it_arrives() {
    let stream = conversation(&[
        (0, prompt_message("hello there, how are you")),
        (1, gzip(&prompt_message("some context"))),
        (0, vec![1, 2, 3, 4]),
        (0, prompt_message("a later turn")),
    ]);
    let handler = handler(&proxy_redacting(&[]));
    for chunk in [1, 7, 64, stream.len()] {
        assert_eq!(
            run_stream(&handler, &stream, chunk).await.unwrap(),
            stream,
            "chunks of {chunk}"
        );
    }
}

#[tokio::test]
async fn pii_in_the_opening_prompt_blocks_the_stream_before_anything_is_sent() {
    let stream = conversation(&[
        (0, prompt_message(SSN_TEXT)),
        (0, prompt_message("never forwarded")),
    ]);
    let result = run_stream(&handler(&proxy_redacting(&[])), &stream, 9).await;
    assert_eq!(result.unwrap_err(), "blocked with status 403 Forbidden");
}

#[tokio::test]
async fn pii_in_a_later_frame_ends_the_stream_after_the_earlier_frames_went_through() {
    let opening = encode(0, &prompt_message("a harmless opening prompt"))
        .unwrap()
        .to_vec();
    let stream = [
        opening.clone(),
        conversation(&[(0, prompt_message("tool result: ssn 123-45-6789"))]),
    ]
    .concat();
    let handler = handler(&proxy_redacting(&[]));
    let parts = post_parts(&format!("https://{CURSOR}/agent.v1.AgentService/Run"));
    let RequestOrResponse::Request(request) = handler
        .stream_request(CURSOR, parts, chunked(&stream, 11))
        .await
    else {
        panic!("the opening prompt is clean, so the stream starts");
    };

    let mut body = request.into_body();
    let mut received = Vec::new();
    let ended_with_error = loop {
        match body.frame().await {
            Some(Ok(frame)) => {
                received.extend_from_slice(frame.data_ref().map_or(&[][..], |data| &data[..]))
            }
            Some(Err(_)) => break true,
            None => break false,
        }
    };
    assert_eq!(
        received, opening,
        "the earlier frame was forwarded untouched, nothing from the blocked frame"
    );
    assert!(ended_with_error, "and then the stream was cut");
}

#[tokio::test]
async fn a_redacted_frame_is_resent_with_the_right_length_and_the_rest_is_untouched() {
    let later = conversation(&[
        (0, vec![9, 9, 9, 9]),
        (0, prompt_message("another clean turn")),
    ]);
    let stream = [
        conversation(&[(0, prompt_message("my ssn is 123-45-6789 ok"))]),
        later.clone(),
    ]
    .concat();
    let sent = run_stream(&handler(&proxy_redacting(&["ssn"])), &stream, 5)
        .await
        .unwrap();

    let mut buffer = BytesMut::from(&sent[..]);
    let Cut::Frame(first) = connect::cut(&mut buffer) else {
        panic!("no first frame");
    };
    assert_eq!(first.flags, 0);
    assert_eq!(
        first.message.to_vec(),
        prompt_message("my ssn is [REDACTED:ssn] ok")
    );
    assert_eq!(
        buffer.to_vec(),
        later,
        "everything after the redacted frame is byte for byte what the client sent"
    );
}

#[tokio::test]
async fn a_compressed_frame_is_read_and_a_redacted_one_goes_out_uncompressed() {
    let secret = gzip(&prompt_message("file contents: ssn 123-45-6789 here"));
    let blocking = handler(&proxy_redacting(&[]));
    assert_eq!(
        run_stream(&blocking, &conversation(&[(1, secret.clone())]), 13)
            .await
            .unwrap_err(),
        "blocked with status 403 Forbidden"
    );

    let sent = run_stream(
        &handler(&proxy_redacting(&["ssn"])),
        &conversation(&[(1, secret)]),
        13,
    )
    .await
    .unwrap();
    let mut buffer = BytesMut::from(&sent[..]);
    let Cut::Frame(frame) = connect::cut(&mut buffer) else {
        panic!("no frame");
    };
    assert_eq!(
        frame.flags, 0,
        "the compressed flag is cleared because the message is no longer compressed"
    );
    assert_eq!(
        frame.message.to_vec(),
        prompt_message("file contents: ssn [REDACTED:ssn] here")
    );
}

#[tokio::test]
async fn frames_that_are_not_protobuf_are_scanned_as_text_and_unreadable_compression_is_blocked() {
    let handler = handler(&proxy_redacting(&[]));
    let plain = conversation(&[(0, b"\xff\xfe plain bytes that are not a message".to_vec())]);
    assert_eq!(run_stream(&handler, &plain, 100).await.unwrap(), plain);
    let leaky = conversation(&[(
        0,
        b"\xff\xfe free text with ssn 123-45-6789 inside".to_vec(),
    )]);
    assert!(run_stream(&handler, &leaky, 100).await.is_err());
    let unknown = conversation(&[(1, b"not gzip, not zstd, just bytes!".to_vec())]);
    assert!(run_stream(&handler, &unknown, 100).await.is_err());
}

#[tokio::test]
async fn a_stream_with_pii_is_blocked_over_real_https_and_a_clean_one_is_not_read_as_a_chat_post() {
    let proxy = proxy_redacting(&[]);
    let (address, certificate) = start_proxy(&proxy).await;
    let blocked = conversation(&[(0, prompt_message(SSN_TEXT))]);
    let response = client_through(address, &certificate)
        .post(format!("https://{CURSOR}/agent.v1.AgentService/Run"))
        .header("content-type", "application/connect+proto")
        .body(blocked)
        .send()
        .await
        .expect("TLS through the proxy works for the cursor host");
    assert_eq!(
        response.status(),
        403,
        "a Connect client treats permission_denied as final"
    );
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["code"], BLOCKED_STREAM_CODE);
    assert!(body["message"].as_str().unwrap().contains("INVEIL BLOCKED"));
}

fn request_to(method: Method, uri: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn connect_is_limited_to_port_443_on_hosts_the_catalog_names() {
    let handler = handler(&proxy_redacting(&[]));
    let allowed = [
        "chatgpt.com:443",
        "CHATGPT.com:443",
        "claude.ai:443",
        "api.anthropic.com:443",
        "assets.claude.ai:443",
    ];
    for target in allowed {
        let request = request_to(Method::CONNECT, target);
        assert!(handler.refusal(&request).is_none(), "{target}");
    }
    let refused = [
        "chatgpt.com:8443",
        "chatgpt.com:22",
        "chatgpt.com",
        "evil.example:443",
        "127.0.0.1:443",
        "169.254.169.254:443",
        "notchatgpt.com:443",
    ];
    for target in refused {
        let request = request_to(Method::CONNECT, target);
        let response = handler
            .refusal(&request)
            .unwrap_or_else(|| panic!("{target} was allowed"));
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{target}");
    }
}

#[tokio::test]
async fn plain_requests_must_be_https_requests_for_a_decrypted_host() {
    let handler = handler(&proxy_redacting(&[]));
    let refused = [
        "/backend-api/f/conversation",
        "http://169.254.169.254/latest/meta-data",
        "http://chatgpt.com/backend-api/f/conversation",
        "https://evil.example/",
        "https://api.anthropic.com/v1/messages",
    ];
    for uri in refused {
        let response = handler
            .refusal(&request_to(Method::GET, uri))
            .unwrap_or_else(|| panic!("{uri} was allowed"));
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{uri}");
    }
    assert!(handler
        .refusal(&request_to(Method::GET, "https://chatgpt.com/"))
        .is_none());

    let rebinding = Request::builder()
        .uri("/")
        .header(HOST, "evil.example:8788")
        .body(Body::empty())
        .unwrap();
    assert!(handler.refusal(&rebinding).is_some());
    let mismatch = Request::builder()
        .uri("https://chatgpt.com/")
        .header(HOST, "evil.example")
        .body(Body::empty())
        .unwrap();
    assert!(handler.refusal(&mismatch).is_some());
    let matching = Request::builder()
        .uri("https://chatgpt.com/")
        .header(HOST, "chatgpt.com:443")
        .body(Body::empty())
        .unwrap();
    assert!(handler.refusal(&matching).is_none());
}

#[tokio::test]
async fn a_chat_post_whose_path_the_site_could_rewrite_is_refused_and_audited() {
    let proxy = proxy_redacting(&[]);
    let handler = handler(&proxy);
    for path in [
        "/backend-api/x/../f/conversation",
        "/backend-api/x/%2e%2e/f/conversation",
        "/backend-api//f/conversation",
        "/backend-api/f/conversation;x=1",
    ] {
        let request = request_to(Method::POST, &format!("https://chatgpt.com{path}"));
        let response = handler
            .refusal(&request)
            .unwrap_or_else(|| panic!("{path} was allowed"));
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{path}");
    }
    assert!(proxy.audit_text().contains(r#""action":"rejected""#));
    let page = request_to(Method::GET, "https://chatgpt.com/_next/static/%5Bid%5D.js");
    assert!(handler.refusal(&page).is_none(), "browsing is not affected");
}

fn upgrade_to(uri: &str) -> Request<Body> {
    Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header(UPGRADE, "websocket")
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn a_websocket_upgrade_or_any_write_with_an_ambiguous_path_is_refused_and_audited() {
    let proxy = proxy_redacting(&[]);
    let handler = handler(&proxy);
    for path in ["/ws/x/../anything", "/ws/%61nything", "//ws/anything"] {
        let response = handler
            .refusal(&upgrade_to(&format!("https://grok.com{path}")))
            .unwrap_or_else(|| panic!("upgrade of {path} was allowed"));
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{path}");
    }
    for method in [Method::PUT, Method::PATCH, Method::DELETE] {
        let request = request_to(method.clone(), "https://chatgpt.com/backend-api/x/../me");
        assert!(handler.refusal(&request).is_some(), "{method}");
    }
    assert!(proxy.audit_text().contains(r#""action":"rejected""#));
    assert!(handler
        .refusal(&upgrade_to("https://grok.com/ws/anything"))
        .is_none());
    assert!(
        handler
            .refusal(&request_to(Method::GET, "https://chatgpt.com/a/../b"))
            .is_none(),
        "a plain read cannot be a chat"
    );
}

#[tokio::test]
async fn case_and_trailing_slash_variants_of_a_chat_route_are_refused_not_forwarded_unread() {
    let proxy = proxy_redacting(&[]);
    let handler = handler(&proxy);
    for path in [
        "/backend-api/f/conversation/",
        "/Backend-Api/f/conversation",
        "/BACKEND-API/F/CONVERSATION/",
    ] {
        let request = request_to(Method::POST, &format!("https://chatgpt.com{path}"));
        let response = handler
            .refusal(&request)
            .unwrap_or_else(|| panic!("{path} was allowed"));
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{path}");
    }
    assert!(proxy.audit_text().contains(r#""action":"rejected""#));
    for path in ["/backend-api/f/conversation", "/backend-api/me"] {
        let request = request_to(Method::POST, &format!("https://chatgpt.com{path}"));
        assert!(handler.refusal(&request).is_none(), "{path}");
    }
}

#[tokio::test]
async fn hosts_written_in_capitals_or_with_a_trailing_dot_are_still_intercepted() {
    let proxy = proxy_redacting(&[]);
    let handler = handler(&proxy);
    for target in [
        "CLAUDE.AI:443",
        "chatgpt.com.:443",
        "ChatGPT.com.:443",
        "claude.ai:443",
    ] {
        let request = request_to(Method::CONNECT, target);
        assert!(handler.refusal(&request).is_none(), "{target}");
        assert!(handler.decrypts_connect(&request), "{target}");
    }
    for target in ["claude.ai.evil.com.:443", "notclaude.ai.:443"] {
        let request = request_to(Method::CONNECT, target);
        assert!(!handler.decrypts_connect(&request), "{target}");
    }

    let spelled = request_to(
        Method::POST,
        "https://CHATGPT.COM./backend-api/f/conversation",
    );
    assert!(handler.refusal(&spelled).is_none());
    assert!(handler.chat_format(&spelled).is_some());
    let spelled_variant = request_to(
        Method::POST,
        "https://CHATGPT.COM./backend-api/F/conversation",
    );
    assert!(handler.refusal(&spelled_variant).is_some());
}

#[test]
fn a_host_in_capitals_or_with_a_trailing_dot_is_sent_to_the_site_in_plain_form() {
    let rewritten = with_normalized_host(request_to(
        Method::POST,
        "https://CHATGPT.COM.:443/backend-api/f/conversation?x=1",
    ));
    assert_eq!(
        rewritten.uri().to_string(),
        "https://chatgpt.com:443/backend-api/f/conversation?x=1"
    );
    let plain = request_to(Method::GET, "https://chatgpt.com/");
    assert_eq!(
        with_normalized_host(plain).uri().to_string(),
        "https://chatgpt.com/"
    );
}
