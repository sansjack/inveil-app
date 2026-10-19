//! The proxy auto-config script, the environment that routes one tool through the proxy, and parsers for the output
//! of the OS tools that report proxy settings.
use contract::FailMode;
use std::path::Path;

const MAX_HOST_LENGTH: usize = 253;
const MAX_LABEL_LENGTH: usize = 63;
const LOOPBACK: &str = "127.0.0.1";
const DEFAULT_NO_PROXY: &str = "localhost,127.0.0.1";

/// True for hosts under one of `domains`, i.e. hosts a CA built for those domains can vouch for.
fn is_covered(host: &str, domains: &[String]) -> bool {
    let host = host.to_ascii_lowercase();
    domains.iter().any(|domain| {
        let domain = domain.to_ascii_lowercase();
        host == domain
            || host
                .strip_suffix(domain.as_str())
                .is_some_and(|rest| rest.ends_with('.'))
    })
}

/// Letters, digits and hyphens in dot-separated labels. Anything else could break out of the JavaScript string.
fn is_plain_hostname(host: &str) -> bool {
    host.len() <= MAX_HOST_LENGTH
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= MAX_LABEL_LENGTH
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '-')
        })
}

/// The PAC script browsers fetch from the proxy. Only covered hosts with plain hostnames are sent to it, matched
/// in lower case with or without the trailing dot browsers keep in `https://chatgpt.com./`. When
/// `service_down` is `Open`, a browser falls back to a direct connection if the proxy is down, so a stopped client
/// cannot take AI sites offline; when it is `Closed`, the sites become unreachable instead.
pub fn pac_script(
    hosts: &[String],
    domains: &[String],
    port: u16,
    service_down: FailMode,
) -> String {
    let hosts = hosts
        .iter()
        .filter(|host| is_plain_hostname(host) && is_covered(host, domains))
        .map(|host| format!("\"{}\"", host.to_ascii_lowercase()))
        .collect::<Vec<_>>()
        .join(", ");
    let route = match service_down {
        FailMode::Closed => format!("PROXY {LOOPBACK}:{port}"),
        FailMode::Open => format!("PROXY {LOOPBACK}:{port}; DIRECT"),
    };
    format!(
        r#"function FindProxyForURL(url, host) {{
  var chat = [{hosts}];
  var name = host.toLowerCase();
  for (var i = 0; i < chat.length; i++) {{
    if (name === chat[i] || name === chat[i] + ".") return "{route}";
  }}
  return "DIRECT";
}}
"#
    )
}

/// The environment that sends one process's HTTPS traffic through the browser proxy and makes it trust our CA.
/// `SSL_CERT_FILE` is deliberately not set: it would replace the tool's trusted roots instead of adding ours.
pub fn proxy_environment(
    port: u16,
    ca_certificate: &Path,
    existing_no_proxy: &str,
) -> Vec<(&'static str, String)> {
    let proxy = format!("http://{LOOPBACK}:{port}");
    let no_proxy = if existing_no_proxy.is_empty() {
        DEFAULT_NO_PROXY.to_string()
    } else {
        format!("{existing_no_proxy},{DEFAULT_NO_PROXY}")
    };
    let ca_certificate = ca_certificate.display().to_string();
    vec![
        ("HTTPS_PROXY", proxy.clone()),
        ("https_proxy", proxy),
        ("NO_PROXY", no_proxy.clone()),
        ("no_proxy", no_proxy),
        ("CODEX_CA_CERTIFICATE", ca_certificate.clone()),
        ("NODE_EXTRA_CA_CERTS", ca_certificate),
    ]
}

/// True when `networksetup -getautoproxyurl` output names exactly `pac_url`.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(super) fn networksetup_reports_pac(output: &str, pac_url: &str) -> bool {
    output
        .lines()
        .filter_map(|line| line.strip_prefix("URL:"))
        .any(|url| url.trim() == pac_url)
}

/// `gsettings get` prints strings in single quotes, e.g. `'http://127.0.0.1:8788/proxy.pac'`.
#[cfg_attr(any(target_os = "macos", windows), allow(dead_code))]
pub(super) fn gsettings_string(output: &str) -> &str {
    let trimmed = output.trim();
    trimmed
        .strip_prefix('\'')
        .and_then(|rest| rest.strip_suffix('\''))
        .unwrap_or(trimmed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    #[test]
    fn covers_listed_domains_and_their_subdomains_only() {
        let domains = strings(&["claude.ai", "chatgpt.com"]);
        assert!(is_covered("claude.ai", &domains));
        assert!(is_covered("api.claude.ai", &domains));
        assert!(!is_covered("evilclaude.ai", &domains));
        assert!(!is_covered("claude.ai.evil.com", &domains));
    }

    #[test]
    fn pac_with_service_down_open_falls_back_to_direct_and_only_routes_covered_hosts() {
        let hosts = strings(&["claude.ai", "chatgpt.com", "bank.example"]);
        let script = pac_script(
            &hosts,
            &strings(&["claude.ai", "chatgpt.com"]),
            8788,
            FailMode::Open,
        );
        assert!(script.contains(r#"var chat = ["claude.ai", "chatgpt.com"];"#));
        assert!(script.contains(r#"return "PROXY 127.0.0.1:8788; DIRECT";"#));
        assert!(!script.contains("bank.example"));
    }

    #[test]
    fn pac_matches_hosts_in_any_case_and_with_a_trailing_dot() {
        let script = pac_script(
            &strings(&["Claude.AI", "chatgpt.com"]),
            &strings(&["claude.ai", "chatgpt.com"]),
            8788,
            FailMode::Open,
        );
        assert!(script.contains(r#"var chat = ["claude.ai", "chatgpt.com"];"#));
        assert!(script.contains("var name = host.toLowerCase();"));
        assert!(script.contains(r#"name === chat[i] || name === chat[i] + ".""#));
        assert!(is_covered("CHATGPT.com", &strings(&["chatgpt.com"])));
    }

    #[test]
    fn pac_with_service_down_closed_drops_the_direct_fallback() {
        let script = pac_script(
            &strings(&["claude.ai"]),
            &strings(&["claude.ai"]),
            8788,
            FailMode::Closed,
        );
        assert!(script.contains(r#"return "PROXY 127.0.0.1:8788";"#));
        assert!(!script.contains("; DIRECT"));
    }

    #[test]
    fn pac_drops_hosts_that_could_break_out_of_the_javascript_string() {
        let hosts = strings(&[
            r#"evil.claude.ai"; alert(1); ""#,
            "a.claude.ai\nb",
            "x$(id).claude.ai",
            "<script>.claude.ai",
            "a&b.claude.ai",
            "-bad.claude.ai",
            "double..claude.ai",
            "ok.claude.ai",
        ]);
        let script = pac_script(&hosts, &strings(&["claude.ai"]), 1, FailMode::Open);
        assert!(script.contains(r#"var chat = ["ok.claude.ai"];"#));
        assert!(!script.contains("alert"));
    }

    #[test]
    fn environment_adds_our_ca_without_replacing_the_tools_own_roots() {
        let environment = proxy_environment(8788, Path::new("/tmp/ca.pem"), "internal.example");
        let value = |name: &str| {
            environment
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value.as_str())
        };
        assert_eq!(value("HTTPS_PROXY"), Some("http://127.0.0.1:8788"));
        assert_eq!(value("NODE_EXTRA_CA_CERTS"), Some("/tmp/ca.pem"));
        assert_eq!(
            value("NO_PROXY"),
            Some("internal.example,localhost,127.0.0.1")
        );
        assert_eq!(value("SSL_CERT_FILE"), None);
    }

    #[test]
    fn environment_defaults_no_proxy_to_loopback() {
        let environment = proxy_environment(1, Path::new("/c"), "");
        assert!(environment.contains(&("no_proxy", "localhost,127.0.0.1".to_string())));
    }

    #[test]
    fn networksetup_output_must_name_exactly_our_pac() {
        let ours = "URL: http://127.0.0.1:8788/proxy.pac\nEnabled: Yes\n";
        assert!(networksetup_reports_pac(
            ours,
            "http://127.0.0.1:8788/proxy.pac"
        ));
        assert!(!networksetup_reports_pac(
            ours,
            "http://127.0.0.1:8788/proxy.pac.evil"
        ));
        assert!(!networksetup_reports_pac(
            "URL: http://corp.example/proxy.pac\nEnabled: Yes\n",
            "http://127.0.0.1:8788/proxy.pac"
        ));
        assert!(!networksetup_reports_pac(
            "URL: (null)\nEnabled: No\n",
            "http://127.0.0.1:8788/proxy.pac"
        ));
    }

    #[test]
    fn gsettings_strings_lose_their_quotes() {
        assert_eq!(
            gsettings_string("'http://x/proxy.pac'\n"),
            "http://x/proxy.pac"
        );
        assert_eq!(gsettings_string("''\n"), "");
    }
}
