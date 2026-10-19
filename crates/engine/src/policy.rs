//! A snapshot compiled for the request hot path. It is built once, off the hot path, when a snapshot arrives and then
//! swapped in as one value, so a request does a couple of hash lookups and nothing else to learn whether it is ours
//! to read:
//! - which hosts are decrypted at all (a `HashMap` keyed by host, not a scan over tools),
//! - which routes on a host carry chat (exact paths in a map, a few prefixes in a short list),
//! - whether a local tool is switched on.
//!
//! A host or route that is not listed costs one failed lookup, and its traffic is forwarded untouched: only the exact
//! and prefix routes the snapshot names are read. A path that differs from an exact route only by case or a trailing
//! slash is not forwarded unread but refused (`is_route_variant`), because an upstream may treat it as that route.
//! Hosts are compared in lower case without a trailing dot, the way a browser may spell them.
use crate::scan::{PatternError, Scanner};
use contract::{Endpoint, Format, Match, Snapshot, Tool, Via};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

/// One transport's routes on a host: exact paths in a map, a few prefixes in a short list.
#[derive(Default)]
struct RouteTable {
    exact: HashMap<String, Format>,
    /// The exact paths in lower case, to recognise a case variant of a route that is not itself a route.
    exact_folded: HashSet<String>,
    /// Few per host, so a linear walk is as fast as anything else.
    prefixes: Vec<(String, Format)>,
}

impl RouteTable {
    fn add(&mut self, endpoint: &Endpoint) {
        match endpoint.matching {
            Match::Exact => {
                self.exact_folded.insert(endpoint.path.to_ascii_lowercase());
                self.exact.insert(endpoint.path.clone(), endpoint.format);
            }
            Match::Prefix => self.prefixes.push((endpoint.path.clone(), endpoint.format)),
        }
    }

    fn has_routes(&self) -> bool {
        !self.exact.is_empty() || !self.prefixes.is_empty()
    }

    fn find(&self, path: &str) -> Option<Format> {
        let path = without_account_prefix(path);
        self.exact
            .get(path)
            .or_else(|| {
                self.prefixes
                    .iter()
                    .find(|(prefix, _)| path.starts_with(prefix.as_str()))
                    .map(|(_, format)| format)
            })
            .copied()
    }

    /// True for a path that is not a route but differs from an exact route only by case or a trailing slash. An
    /// upstream that folds those would read it as the chat route while this proxy forwarded it unread.
    fn is_variant(&self, path: &str) -> bool {
        let path = without_account_prefix(path);
        if self.find(path).is_some() {
            return false;
        }
        let folded = path.to_ascii_lowercase();
        self.exact_folded
            .contains(folded.strip_suffix('/').unwrap_or(&folded))
    }
}

/// HTTP chat routes and WebSocket routes are kept apart, so one can never be mistaken for the other.
#[derive(Default)]
struct HostRoutes {
    http: RouteTable,
    websocket: RouteTable,
}

/// A tool pointed at the client's localhost proxy.
struct LocalTool {
    /// The path the tool uses on our one port; `None` is the default route.
    prefix: Option<String>,
    upstream: String,
    enabled: bool,
    /// Routes, as the upstream sees them, that carry chat.
    routes: RouteTable,
}

/// Where a localhost-proxy request goes and whether it is read.
#[derive(Debug, PartialEq, Eq)]
pub struct LocalRoute {
    /// Base URL of the upstream, no trailing slash.
    pub upstream: String,
    /// The request path as the upstream should see it (the tool's prefix removed).
    pub path: String,
    /// False when the tool is switched off: forward untouched.
    pub enabled: bool,
    /// True when this is a chat route, the only kind of request that is read.
    pub chat: bool,
}

/// How the installer points a local tool at the client: set `env_var` to the proxy URL plus `prefix`.
#[derive(Debug, PartialEq, Eq)]
pub struct LocalToolWiring<'a> {
    pub tool_id: &'a str,
    pub env_var: &'a str,
    pub prefix: Option<&'a str>,
}

pub struct Policy {
    pub scanner: Scanner,
    /// Host to the one tool it belongs to (a host shared by several tools is not in here), for notices.
    host_labels: HashMap<String, String>,
    /// Only hosts the browser proxy will decrypt: enabled browser tools, with routes, inside the domains the backend
    /// allows and the CA on disk was made for.
    routes: HashMap<String, HostRoutes>,
    local_tools: Vec<LocalTool>,
    pub tools: Vec<Tool>,
    /// What the backend allows the CA to cover.
    pub ca_domains: Vec<String>,
    /// `ca_domains` that the CA on disk also covers.
    pub usable_domains: Vec<String>,
}

impl Policy {
    /// `snapshot` must have passed [`crate::validate::validate`]. `deny` is the effective deny list (local and
    /// server) and `ca_on_disk` the domain list of the CA the browser setup made (empty if there is none).
    pub fn build(
        snapshot: &Snapshot,
        deny: &[String],
        ca_on_disk: &[String],
    ) -> Result<Self, PatternError> {
        let scanner = Scanner::from_rules(&snapshot.pii, deny)?;
        let usable_domains: Vec<String> = snapshot
            .ca_domains
            .iter()
            .filter(|domain| ca_on_disk.contains(domain))
            .cloned()
            .collect();
        Ok(Self {
            scanner,
            host_labels: host_labels(&snapshot.tools),
            routes: browser_routes(&snapshot.tools, &usable_domains),
            local_tools: local_tools(&snapshot.tools),
            tools: snapshot.tools.clone(),
            ca_domains: snapshot.ca_domains.clone(),
            usable_domains,
        })
    }

    /// Is this host decrypted by the browser proxy?
    pub fn decrypts(&self, host: &str) -> bool {
        self.routes.contains_key(normalize_host(host).as_ref())
    }

    /// The body format of the HTTP chat route this request path belongs to, or `None` for everything else on the host.
    pub fn format_for(&self, host: &str, path: &str) -> Option<Format> {
        self.routes
            .get(normalize_host(host).as_ref())?
            .http
            .find(path)
    }

    /// Is this a variant (case, trailing slash) of an exact chat or WebSocket route on a decrypted host, which the
    /// proxy refuses rather than forwards unread?
    pub fn is_route_variant(&self, host: &str, path: &str) -> bool {
        self.routes
            .get(normalize_host(host).as_ref())
            .is_some_and(|routes| routes.http.is_variant(path) || routes.websocket.is_variant(path))
    }

    /// What to call a host in a notice: its tool's name when it belongs to exactly one tool, otherwise the host.
    pub fn label_for_host(&self, host: &str) -> String {
        self.host_labels
            .get(normalize_host(host).as_ref())
            .cloned()
            .unwrap_or_else(|| host.to_string())
    }

    /// Does this decrypted host have any WebSocket route?
    pub fn has_websocket_routes(&self, host: &str) -> bool {
        self.routes
            .get(normalize_host(host).as_ref())
            .is_some_and(|routes| routes.websocket.has_routes())
    }

    /// Is this a WebSocket route whose outgoing frames are read?
    pub fn is_websocket_route(&self, host: &str, path: &str) -> bool {
        self.routes
            .get(normalize_host(host).as_ref())
            .is_some_and(|routes| routes.websocket.find(path).is_some())
    }

    /// Hosts the browser proxy decrypts, sorted (for the PAC script and logs).
    pub fn decrypted_hosts(&self) -> Vec<String> {
        let mut hosts: Vec<String> = self.routes.keys().cloned().collect();
        hosts.sort();
        hosts
    }

    /// The enabled local tools the snapshot says how to wire, so the installer needs no list of its own.
    pub fn local_tool_wiring(&self) -> Vec<LocalToolWiring<'_>> {
        self.tools
            .iter()
            .filter(|tool| tool.enabled && tool.via == Via::Local)
            .filter_map(|tool| {
                Some(LocalToolWiring {
                    tool_id: &tool.id,
                    env_var: tool.env_var.as_deref()?,
                    prefix: tool.prefix.as_deref(),
                })
            })
            .collect()
    }

    /// Which upstream a localhost-proxy request goes to, and whether it is read. A tool with a prefix owns the paths
    /// under it; everything else is the default route, which goes to `default_upstream`. A request is read only if it
    /// is on a chat route of an enabled tool. If the catalog has no default tool, the default route is read in full
    /// (the safe choice for something we do not know).
    pub fn local_route(&self, path: &str, default_upstream: &str) -> LocalRoute {
        if let Some((tool, upstream_path)) = self.owning_tool(path) {
            return LocalRoute {
                upstream: tool.upstream.clone(),
                path: upstream_path.to_string(),
                enabled: tool.enabled,
                chat: tool.routes.find(upstream_path).is_some(),
            };
        }
        let default_tool = self.local_tools.iter().find(|tool| tool.prefix.is_none());
        LocalRoute {
            upstream: default_upstream.trim_end_matches('/').to_string(),
            path: path.to_string(),
            enabled: default_tool.is_none_or(|tool| tool.enabled),
            chat: default_tool.is_none_or(|tool| tool.routes.find(path).is_some()),
        }
    }

    /// Is this localhost-proxy path a variant (case, trailing slash) of an exact chat route of the tool it belongs
    /// to? Such a request is refused rather than forwarded unread.
    pub fn is_local_route_variant(&self, path: &str) -> bool {
        match self.owning_tool(path) {
            Some((tool, upstream_path)) => tool.routes.is_variant(upstream_path),
            None => self
                .local_tools
                .iter()
                .find(|tool| tool.prefix.is_none())
                .is_some_and(|tool| tool.routes.is_variant(path)),
        }
    }

    /// The tool whose prefix owns `path`, with the path as that tool's upstream sees it.
    fn owning_tool<'a>(&self, path: &'a str) -> Option<(&LocalTool, &'a str)> {
        self.local_tools.iter().find_map(|tool| {
            let prefix = tool.prefix.as_deref()?;
            let rest = path.strip_prefix(prefix)?;
            let boundary = rest.is_empty() || rest.starts_with('/');
            boundary.then_some((tool, if rest.is_empty() { "/" } else { rest }))
        })
    }
}

/// A host as a browser may write it: in any case, with the root label's trailing dot (`chatgpt.com.`).
pub fn normalize_host(host: &str) -> Cow<'_, str> {
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Cow::Owned(host.to_ascii_lowercase());
    }
    Cow::Borrowed(host)
}

/// True for hosts under one of `domains`, i.e. hosts a CA built for those domains can vouch for.
pub fn is_covered(host: &str, domains: &[String]) -> bool {
    let host = normalize_host(host);
    domains.iter().any(|domain| {
        let domain = normalize_host(domain);
        host == domain
            || host
                .strip_suffix(domain.as_ref())
                .is_some_and(|rest| rest.ends_with('.'))
    })
}

fn browser_routes(tools: &[Tool], usable_domains: &[String]) -> HashMap<String, HostRoutes> {
    let mut routes: HashMap<String, HostRoutes> = HashMap::new();
    let hosts = tools
        .iter()
        .filter(|tool| tool.enabled && tool.via == Via::Browser)
        .flat_map(|tool| tool.hosts.iter());
    for host in hosts {
        if host.endpoints.is_empty() || !is_covered(&host.host, usable_domains) {
            continue;
        }
        let entry = routes
            .entry(normalize_host(&host.host).into_owned())
            .or_default();
        for endpoint in &host.endpoints {
            let table = if endpoint.format == Format::WebsocketJson {
                &mut entry.websocket
            } else {
                &mut entry.http
            };
            table.add(endpoint);
        }
    }
    routes
}

fn local_tools(tools: &[Tool]) -> Vec<LocalTool> {
    tools
        .iter()
        .filter(|tool| tool.via == Via::Local)
        .filter_map(|tool| {
            let mut routes = RouteTable::default();
            tool.endpoints
                .iter()
                .for_each(|endpoint| routes.add(endpoint));
            Some(LocalTool {
                prefix: tool.prefix.clone(),
                upstream: tool.upstream.as_deref()?.trim_end_matches('/').to_string(),
                enabled: tool.enabled,
                routes,
            })
        })
        .collect()
}

fn host_labels(tools: &[Tool]) -> HashMap<String, String> {
    let mut owners: HashMap<Cow<str>, Vec<&str>> = HashMap::new();
    let browser_tools = tools
        .iter()
        .filter(|tool| tool.enabled && tool.via == Via::Browser);
    for tool in browser_tools {
        for host in &tool.hosts {
            owners
                .entry(normalize_host(&host.host))
                .or_default()
                .push(tool.name.as_str());
        }
    }
    owners
        .into_iter()
        .filter(|(_, names)| names.len() == 1)
        .map(|(host, names)| (host.to_string(), names[0].to_string()))
        .collect()
}

/// Some sites put the signed-in account number in front of every path (`/u/1/...`); routes are written without it.
fn without_account_prefix(path: &str) -> &str {
    let Some(rest) = path.strip_prefix("/u/") else {
        return path;
    };
    let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
    match rest.as_bytes().get(digits) {
        Some(b'/') if digits > 0 => &rest[digits..],
        _ => path,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{ca_domains, example_snapshot};

    const ANTHROPIC: &str = "https://api.anthropic.com";

    fn policy() -> Policy {
        Policy::build(&example_snapshot(), &[], &ca_domains()).unwrap()
    }

    fn policy_with_tools_off(off: &[&str]) -> Policy {
        let mut snapshot = example_snapshot();
        for tool in snapshot
            .tools
            .iter_mut()
            .filter(|tool| off.contains(&tool.id.as_str()))
        {
            tool.enabled = false;
        }
        Policy::build(&snapshot, &[], &ca_domains()).unwrap()
    }

    #[test]
    fn only_listed_routes_on_listed_hosts_match() {
        let policy = policy();
        assert_eq!(
            policy.format_for("chatgpt.com", "/backend-api/f/conversation"),
            Some(Format::Json)
        );
        for path in [
            "/",
            "/backend-api/me",
            "/ces/v1/telemetry/intake",
            "/backend-api/f/conversation/prepare",
            "/static/app.js",
        ] {
            assert_eq!(policy.format_for("chatgpt.com", path), None, "{path}");
        }
        assert_eq!(
            policy.format_for("example.com", "/backend-api/f/conversation"),
            None
        );
        assert!(policy.decrypts("chatgpt.com") && !policy.decrypts("example.com"));
    }

    #[test]
    fn exact_routes_are_exact_and_prefix_routes_are_prefixes() {
        let policy = policy();
        let claude = "/claudeai-rpc/anthropic.bard.api.v1alpha.ConversationService/PerformAction";
        assert_eq!(
            policy.format_for("claude.ai", claude),
            Some(Format::Protobuf)
        );
        assert_eq!(
            policy.format_for("claude.ai", &format!("{claude}/extra")),
            None
        );
        assert_eq!(
            policy.format_for(
                "claude.ai",
                "/claudeai-rpc/anthropic.bard.api.v1alpha.ConversationService/StreamTimeline"
            ),
            None
        );
        assert_eq!(
            policy.format_for("grok.com", "/rest/app-chat/conversations/new"),
            Some(Format::Json)
        );
        assert_eq!(policy.format_for("grok.com", "/rest/skills"), None);
    }

    #[test]
    fn account_numbers_in_front_of_a_path_are_ignored() {
        let policy = policy();
        let chat = "/_/BardChatUi/data/assistant.lamda.BardFrontendService/StreamGenerate";
        assert_eq!(
            policy.format_for("gemini.google.com", chat),
            Some(Format::Form)
        );
        assert_eq!(
            policy.format_for("gemini.google.com", &format!("/u/2{chat}")),
            Some(Format::Form)
        );
        assert_eq!(
            policy.format_for("gemini.google.com", "/_/BardChatUi/data/batchexecute"),
            None
        );
        assert_eq!(without_account_prefix("/u/12/x"), "/x");
        assert_eq!(without_account_prefix("/u/x/y"), "/u/x/y");
        assert_eq!(without_account_prefix("/users/1/x"), "/users/1/x");
    }

    #[test]
    fn cursors_agent_stream_is_a_streaming_route() {
        let policy = policy();
        assert_eq!(
            policy.format_for("agentn.global.api5.cursor.sh", "/agent.v1.AgentService/Run"),
            Some(Format::ConnectStream)
        );
        assert_eq!(
            policy.format_for("api2.cursor.sh", "/aiserver.v1.DashboardService/GetMe"),
            None,
            "other Cursor hosts are not decrypted"
        );
        assert_eq!(
            policy.format_for(
                "agentn.global.api5.cursor.sh",
                "/agent.v1.AgentService/Other"
            ),
            None
        );
    }

    #[test]
    fn notices_name_the_tool_when_a_host_belongs_to_one_and_the_host_when_it_is_shared() {
        let policy = policy();
        assert_eq!(
            policy.label_for_host("agentn.global.api5.cursor.sh"),
            "Cursor Agent (CLI)"
        );
        assert_eq!(policy.label_for_host("claude.ai"), "Claude (browser)");
        assert_eq!(
            policy.label_for_host("chatgpt.com"),
            "chatgpt.com",
            "ChatGPT web and Codex share it"
        );
        assert_eq!(policy.label_for_host("unknown.example"), "unknown.example");
    }

    #[test]
    fn websocket_routes_are_kept_apart_from_http_routes() {
        let policy = policy();
        assert!(policy.is_websocket_route("grok.com", "/ws/anything"));
        assert!(policy.has_websocket_routes("grok.com"));
        assert_eq!(
            policy.format_for("grok.com", "/ws/anything"),
            None,
            "a websocket route is not an HTTP chat"
        );
        assert!(!policy.is_websocket_route("chatgpt.com", "/ws/anything"));
        assert!(!policy.is_websocket_route("example.com", "/ws/anything"));
        assert!(!policy.has_websocket_routes("claude.ai"));
    }

    #[test]
    fn hosts_outside_the_ca_or_the_backend_list_are_never_decrypted() {
        let only_claude =
            Policy::build(&example_snapshot(), &[], &["claude.ai".to_string()]).unwrap();
        assert_eq!(
            only_claude.decrypted_hosts(),
            ["claude.ai"],
            "the CA on disk only covers claude.ai"
        );

        let mut no_domains = example_snapshot();
        no_domains.ca_domains.clear();
        let none = Policy::build(&no_domains, &[], &ca_domains()).unwrap();
        assert!(
            none.decrypted_hosts().is_empty(),
            "no domains from the backend means nothing is decrypted"
        );
    }

    #[test]
    fn covers_listed_domains_and_their_subdomains_only() {
        let listed = ca_domains();
        assert!(is_covered("claude.ai", &listed));
        assert!(is_covered("www.claude.ai", &listed));
        assert!(is_covered("gemini.google.com", &listed));
        assert!(!is_covered("google.com", &listed));
        assert!(!is_covered("notclaude.ai", &listed));
        assert!(!is_covered("claude.ai.evil.com", &listed));
        assert!(!is_covered("bank.example", &listed));
        assert!(!is_covered("claude.ai", &[]));
    }

    #[test]
    fn switched_off_tools_are_not_decrypted_or_scanned() {
        assert!(
            policy_with_tools_off(&["chatgpt-web"]).decrypts("chatgpt.com"),
            "Codex still uses it"
        );
        let off = policy_with_tools_off(&["chatgpt-web", "codex", "claude-code"]);
        assert!(!off.decrypts("chatgpt.com") && off.decrypts("claude.ai"));
        assert!(!off.local_route("/v1/messages", ANTHROPIC).enabled);
    }

    #[test]
    fn localhost_requests_are_routed_to_the_right_upstream_and_only_chat_is_read() {
        let policy = policy();
        let claude = policy.local_route("/v1/messages", ANTHROPIC);
        assert_eq!(
            claude,
            LocalRoute {
                upstream: ANTHROPIC.into(),
                path: "/v1/messages".into(),
                enabled: true,
                chat: true
            }
        );
        assert!(
            !policy.local_route("/v1/models", ANTHROPIC).chat,
            "other calls are forwarded untouched"
        );
        let api = policy.local_route("/openai/v1/responses", ANTHROPIC);
        assert_eq!(
            (api.upstream.as_str(), api.path.as_str(), api.chat),
            ("https://api.openai.com", "/v1/responses", true)
        );
        for path in ["/openai/v1/models", "/openai/v1/files"] {
            assert!(!policy.local_route(path, ANTHROPIC).chat, "{path}");
        }
        assert_eq!(
            policy
                .local_route("/openaix/v1/messages", ANTHROPIC)
                .upstream,
            ANTHROPIC
        );
        assert_eq!(policy.local_route("/openai", ANTHROPIC).path, "/");
    }

    #[test]
    fn a_default_upstream_override_is_honoured_and_switched_off_tools_are_forwarded_untouched() {
        let policy = policy_with_tools_off(&["codex-api"]);
        assert_eq!(
            policy
                .local_route("/v1/messages", "https://gateway.example/")
                .upstream,
            "https://gateway.example"
        );
        assert!(
            !policy
                .local_route("/openai/v1/responses", ANTHROPIC)
                .enabled
        );
    }

    #[test]
    fn without_a_default_tool_the_default_route_is_read_in_full() {
        let mut snapshot = example_snapshot();
        snapshot.tools.retain(|tool| tool.id != "claude-code");
        let policy = Policy::build(&snapshot, &[], &[]).unwrap();
        let route = policy.local_route("/anything", ANTHROPIC);
        assert!(route.chat && route.enabled);
    }

    #[test]
    fn tool_wiring_comes_from_the_snapshot_not_from_a_built_in_list() {
        let policy = policy();
        let wiring = policy.local_tool_wiring();
        assert!(wiring.contains(&LocalToolWiring {
            tool_id: "claude-code",
            env_var: "ANTHROPIC_BASE_URL",
            prefix: None
        }));
        assert!(wiring.contains(&LocalToolWiring {
            tool_id: "codex-api",
            env_var: "OPENAI_BASE_URL",
            prefix: Some("/openai")
        }));
        let off = policy_with_tools_off(&["claude-code"]);
        assert!(off
            .local_tool_wiring()
            .iter()
            .all(|tool| tool.tool_id != "claude-code"));
    }

    #[test]
    fn hosts_match_in_any_case_and_with_a_trailing_dot() {
        let policy = policy();
        for host in ["CLAUDE.AI", "claude.ai.", "Claude.Ai.", "claude.ai"] {
            assert!(policy.decrypts(host), "{host}");
        }
        assert!(!policy.decrypts("claude.ai.evil.com") && !policy.decrypts("claude.ai.."));
        assert_eq!(
            policy.format_for("CHATGPT.COM.", "/backend-api/f/conversation"),
            Some(Format::Json)
        );
        assert_eq!(policy.label_for_host("CLAUDE.AI."), "Claude (browser)");
        assert!(policy.is_websocket_route("GROK.COM.", "/ws/anything"));
        let listed = ca_domains();
        assert!(is_covered("WWW.Claude.AI.", &listed));
        assert!(!is_covered("claude.ai.evil.com.", &listed));
    }

    #[test]
    fn case_and_trailing_slash_variants_of_an_exact_route_are_recognised_but_are_not_routes() {
        let policy = policy();
        let chat = "/backend-api/f/conversation";
        for path in [
            "/backend-api/f/conversation/",
            "/Backend-API/f/conversation",
            "/BACKEND-API/F/CONVERSATION/",
        ] {
            assert_eq!(policy.format_for("chatgpt.com", path), None, "{path}");
            assert!(policy.is_route_variant("chatgpt.com", path), "{path}");
        }
        assert!(!policy.is_route_variant("chatgpt.com", chat));
        assert!(!policy.is_route_variant("chatgpt.com", "/backend-api/me"));
        assert!(!policy.is_route_variant("example.com", "/Backend-API/f/conversation"));
        assert!(policy.is_route_variant(
            "CLAUDE.AI.",
            "/claudeai-rpc/anthropic.bard.api.v1alpha.conversationservice/performaction"
        ));
    }

    #[test]
    fn variants_of_exact_localhost_routes_are_recognised() {
        let policy = policy();
        assert!(policy.is_local_route_variant("/v1/messages/"));
        assert!(policy.is_local_route_variant("/V1/Messages"));
        assert!(policy.is_local_route_variant("/openai/V1/responses"));
        assert!(!policy.is_local_route_variant("/v1/messages"));
        assert!(!policy.is_local_route_variant("/v1/models"));
        assert!(!policy.is_local_route_variant("/openai/v1/responses"));
    }

    #[test]
    fn a_bad_deny_pattern_fails_the_build() {
        assert!(Policy::build(&example_snapshot(), &["(".to_string()], &[]).is_err());
    }
}
