//! `inveil discover <host-or-tool> --record`: a developer command that shows what an AI tool sends, so a catalog entry
//! can be written from evidence.
//!
//! It runs its own proxy on the browser port, decrypts only the named hosts and passes every request on untouched.
//! What it keeps per request is the host, method, path, content type and a format guess made from the content type.
//! Query strings, headers other than Content-Type, request bodies and responses are never read or stored, and the
//! result is printed when you press Ctrl-C and not written anywhere. It does nothing without `--record`.
use crate::config::Config;
use crate::error::AppError;
use crate::policy::ActivePolicy;
use crate::proxy::browser::{check_target, forbidden_response, HTTPS_PORT};
use crate::proxy::browser_ca;
use crate::proxy::GuardError;
use crate::runtime::Runtime;
use crate::util::lock;
use hudsucker::hyper::header::CONTENT_TYPE;
use hudsucker::hyper::Request;
use hudsucker::rustls::crypto::aws_lc_rs;
use hudsucker::{Body, HttpContext, HttpHandler, Proxy, RequestOrResponse};
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

const MIN_IDENTIFIER_LENGTH: usize = 8;
const IDENTIFIER_PLACEHOLDER: &str = "{id}";

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
struct Observation {
    host: String,
    method: String,
    path: String,
    content_type: String,
    format_guess: &'static str,
}

#[derive(Serialize)]
struct Entry<'a> {
    #[serde(flatten)]
    observation: &'a Observation,
    count: u64,
}

#[derive(Clone)]
struct Recorder {
    hosts: Arc<Vec<String>>,
    policy: Arc<ActivePolicy>,
    default_upstream: Arc<str>,
    seen: Arc<Mutex<BTreeMap<Observation, u64>>>,
}

impl Recorder {
    /// The guard of the real browser proxy: no tunnels to arbitrary hosts or ports, only https for the recorded hosts.
    fn check_target(&self, request: &Request<Body>) -> Result<(), GuardError> {
        check_target(
            request,
            &self.policy,
            &self.default_upstream,
            HTTPS_PORT,
            |host| engine::is_covered(host, &self.hosts),
        )
    }
}

impl HttpHandler for Recorder {
    async fn should_intercept_connect(
        &mut self,
        _ctx: &HttpContext,
        request: &Request<Body>,
    ) -> bool {
        request
            .uri()
            .host()
            .is_some_and(|host| engine::is_covered(host, &self.hosts))
    }

    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        request: Request<Body>,
    ) -> RequestOrResponse {
        if let Err(error) = self.check_target(&request) {
            tracing::warn!("the recording proxy refused a request: {error}");
            return forbidden_response(&error).into();
        }
        let content_type = request
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(media_type)
            .unwrap_or_default();
        let observation = Observation {
            host: request.uri().host().unwrap_or_default().to_string(),
            method: request.method().to_string(),
            path: normalize_path(request.uri().path()),
            format_guess: guess_format(&content_type),
            content_type,
        };
        *lock(&self.seen).entry(observation).or_default() += 1;
        request.into()
    }
}

/// `application/json; charset=utf-8` becomes `application/json`.
fn media_type(header: &str) -> String {
    header
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
}

/// Replaces path segments that look like identifiers, so one conversation does not become one entry per request.
fn normalize_path(path: &str) -> String {
    path.split('/')
        .map(|segment| {
            let long_enough = segment.len() >= MIN_IDENTIFIER_LENGTH;
            let identifier = long_enough
                && segment
                    .chars()
                    .all(|character| character.is_ascii_hexdigit() || character == '-')
                || !segment.is_empty()
                    && segment.chars().all(|character| character.is_ascii_digit());
            if identifier {
                IDENTIFIER_PLACEHOLDER
            } else {
                segment
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// The catalog `format` a content type suggests; `unknown` means the body has to be inspected by hand.
fn guess_format(content_type: &str) -> &'static str {
    if content_type.contains("connect+") {
        return "connect-stream";
    }
    if content_type.contains("proto") {
        return "protobuf";
    }
    if content_type.contains("json") {
        return "json";
    }
    if content_type.contains("x-www-form-urlencoded") {
        return "form";
    }
    "unknown"
}

pub async fn run(config: Config, target: &str, record: bool) -> Result<String, AppError> {
    if !record {
        return Err(AppError::Usage(
            "discover records the hosts, paths, methods and content types of requests (never bodies, queries or other headers); add --record to start"
                .into(),
        ));
    }
    let runtime = Runtime::new(Arc::new(config))?;
    let policy = runtime.initial_policy()?;
    let hosts: Vec<String> = match policy.policy.tools.iter().find(|tool| tool.id == target) {
        Some(tool) => tool.hosts.iter().map(|entry| entry.host.clone()).collect(),
        None => vec![target.to_string()],
    };
    if hosts.is_empty() || !hosts.iter().all(|host| engine::valid_host(host)) {
        return Err(AppError::Usage(format!(
            "{target} is not a catalog tool with browser hosts or a plain host name"
        )));
    }
    let uncovered: Vec<&String> = hosts
        .iter()
        .filter(|host| !engine::is_covered(host, &policy.policy.usable_domains))
        .collect();
    if !uncovered.is_empty() {
        return Err(AppError::Usage(format!(
            "the browser CA does not cover {uncovered:?}. Add the domain to ca_domains in a rules file you sign (`inveil sign`), \
             then run `inveil browser-setup` to make a CA that covers it"
        )));
    }
    let Some(authority) = browser_ca::load_authority(&runtime.ca_directory())? else {
        return Err(AppError::Usage(
            "there is no browser CA yet; run `inveil browser-setup` first".into(),
        ));
    };
    let address = crate::util::loopback(runtime.config.listen.browser_port);
    let listener = TcpListener::bind(address).await.map_err(|source| {
        AppError::Usage(format!(
            "cannot listen on {address}: {source}. Stop the running inveil service first"
        ))
    })?;

    let recorder = Recorder {
        hosts: Arc::new(hosts.clone()),
        policy: Arc::new(policy),
        default_upstream: runtime.config.upstream.as_str().into(),
        seen: Arc::default(),
    };
    let proxy = Proxy::builder()
        .with_listener(listener)
        .with_ca(authority)
        .with_rustls_connector(aws_lc_rs::default_provider())
        .with_http_handler(recorder.clone())
        .with_graceful_shutdown(async {
            if let Err(error) = tokio::signal::ctrl_c().await {
                tracing::error!("cannot listen for Ctrl-C: {error}");
            }
        })
        .build()
        .map_err(|error| AppError::Usage(format!("cannot start the recording proxy: {error}")))?;
    eprintln!(
        "Recording {} on {address}. Use the tool now (browsers reach this through the proxy auto-config); press Ctrl-C when done.",
        hosts.join(", ")
    );
    proxy
        .start()
        .await
        .map_err(|error| AppError::Usage(format!("the recording proxy stopped: {error}")))?;

    let seen = lock(&recorder.seen);
    let entries: Vec<Entry> = seen
        .iter()
        .map(|(observation, count)| Entry {
            observation,
            count: *count,
        })
        .collect();
    serde_json::to_string_pretty(&entries).map_err(|error| AppError::Usage(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::PolicyBuilder;
    use hudsucker::hyper::Method;
    use std::path::PathBuf;

    #[test]
    fn content_types_lose_their_parameters() {
        assert_eq!(
            media_type("Application/JSON; charset=utf-8"),
            "application/json"
        );
    }

    #[test]
    fn identifiers_in_paths_are_collapsed_and_the_query_is_not_part_of_the_path() {
        assert_eq!(
            normalize_path(
                "/backend-api/conversation/3f2a9c1e-77b0-4d51-9c3e-0a1b2c3d4e5f/messages"
            ),
            "/backend-api/conversation/{id}/messages"
        );
        assert_eq!(normalize_path("/v1/threads/12345"), "/v1/threads/{id}");
        assert_eq!(
            normalize_path("/rest/app-chat/conversations"),
            "/rest/app-chat/conversations"
        );
    }

    #[test]
    fn formats_are_guessed_from_the_content_type_alone() {
        assert_eq!(guess_format("application/connect+proto"), "connect-stream");
        assert_eq!(guess_format("application/x-protobuf"), "protobuf");
        assert_eq!(guess_format("application/json"), "json");
        assert_eq!(guess_format("application/x-www-form-urlencoded"), "form");
        assert_eq!(guess_format(""), "unknown");
    }

    fn recorder_for(hosts: &[&str]) -> Recorder {
        let policy = PolicyBuilder::new(Arc::new(Config::default()), PathBuf::new())
            .builtin()
            .unwrap();
        Recorder {
            hosts: Arc::new(hosts.iter().map(|host| host.to_string()).collect()),
            policy: Arc::new(policy),
            default_upstream: Config::default().upstream.as_str().into(),
            seen: Arc::default(),
        }
    }

    fn request_to(method: Method, uri: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .unwrap()
    }

    #[test]
    fn the_recording_proxy_is_no_open_proxy() {
        let recorder = recorder_for(&["claude.ai"]);
        for (method, target) in [
            (Method::CONNECT, "evil.example:443"),
            (Method::CONNECT, "169.254.169.254:443"),
            (Method::CONNECT, "claude.ai:8443"),
            (Method::GET, "http://169.254.169.254/latest/meta-data"),
            (Method::GET, "https://evil.example/"),
            (Method::GET, "http://claude.ai/"),
        ] {
            assert!(
                recorder.check_target(&request_to(method, target)).is_err(),
                "{target}"
            );
        }
        for (method, target) in [
            (Method::CONNECT, "claude.ai:443"),
            (Method::CONNECT, "CLAUDE.AI.:443"),
            (Method::GET, "https://claude.ai/"),
        ] {
            assert!(
                recorder.check_target(&request_to(method, target)).is_ok(),
                "{target}"
            );
        }
    }

    #[tokio::test]
    async fn nothing_is_recorded_without_the_flag() {
        let error = run(Config::default(), "claude.ai", false)
            .await
            .unwrap_err();
        assert!(matches!(error, AppError::Usage(message) if message.contains("--record")));
    }
}
