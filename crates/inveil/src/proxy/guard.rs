//! The localhost proxy listens on a port any local program or web page can reach. Two checks keep it from being
//! used as a confused deputy (DNS rebinding, a malicious page posting to localhost): the `Host` must be the
//! loopback address and port we listen on, and a request carrying an `Origin` header (which browsers add to
//! cross-origin requests and command-line tools never send) is refused.
use axum::http::header::{HOST, ORIGIN};
use axum::http::HeaderMap;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GuardError {
    #[error("the request is not addressed to this proxy's loopback address")]
    ForeignHost,
    #[error("browser cross-origin requests are not accepted")]
    CrossOrigin,
    #[error("the request path is not in canonical form (dot segments, encoded characters, `//`, `;` or `\\`)")]
    NonCanonicalPath,
    #[error("the request path differs from a scanned route only by case or a trailing slash")]
    RouteVariant,
    #[error("tunnels are limited to port 443 on hosts in the catalog")]
    TunnelNotAllowed,
    #[error("only https requests to a host this proxy decrypts are accepted")]
    NotAProxyTarget,
    #[error("the Host header does not match the host the request is for")]
    HostMismatch,
}

const LOOPBACK_NAMES: [&str; 3] = ["127.0.0.1", "localhost", "[::1]"];

/// `authority` is the URI authority for HTTP/2 requests, which carry no `Host` header.
pub fn check_local_request(
    headers: &HeaderMap,
    authority: Option<&str>,
    port: u16,
) -> Result<(), GuardError> {
    if headers.contains_key(ORIGIN) {
        return Err(GuardError::CrossOrigin);
    }
    let host = headers
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .or(authority)
        .ok_or(GuardError::ForeignHost)?;
    if !is_loopback_authority(host, port) {
        return Err(GuardError::ForeignHost);
    }
    Ok(())
}

/// The route a request matches is decided on the path exactly as received, while the upstream may resolve dot
/// segments, percent-encoding and path parameters itself. A path that those could rewrite is refused instead of
/// interpreted, so the string that is routed is the string that is forwarded.
pub fn check_path(path: &str) -> Result<(), GuardError> {
    let ambiguous = path.contains(['%', '\\', ';'])
        || path.contains("//")
        || path
            .split('/')
            .any(|segment| segment == "." || segment == "..");
    if ambiguous {
        return Err(GuardError::NonCanonicalPath);
    }
    Ok(())
}

fn is_loopback_authority(authority: &str, port: u16) -> bool {
    let Some((name, authority_port)) = authority.rsplit_once(':') else {
        return false;
    };
    let name = name.to_ascii_lowercase();
    authority_port
        .parse::<u16>()
        .is_ok_and(|parsed| parsed == port)
        && LOOPBACK_NAMES.contains(&name.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(*name, HeaderValue::from_static(value));
        }
        map
    }

    #[test]
    fn loopback_names_on_our_port_are_accepted() {
        for host in [
            "127.0.0.1:8787",
            "localhost:8787",
            "LOCALHOST:8787",
            "[::1]:8787",
        ] {
            assert_eq!(
                check_local_request(&headers(&[("host", host)]), None, 8787),
                Ok(()),
                "{host}"
            );
        }
    }

    #[test]
    fn other_hosts_ports_and_missing_hosts_are_refused() {
        for host in [
            "evil.example:8787",
            "127.0.0.1:9999",
            "127.0.0.1",
            "127.0.0.1.evil.example:8787",
            "0.0.0.0:8787",
        ] {
            assert_eq!(
                check_local_request(&headers(&[("host", host)]), None, 8787),
                Err(GuardError::ForeignHost),
                "{host}"
            );
        }
        assert_eq!(
            check_local_request(&HeaderMap::new(), None, 8787),
            Err(GuardError::ForeignHost)
        );
        assert_eq!(
            check_local_request(&HeaderMap::new(), Some("127.0.0.1:8787"), 8787),
            Ok(())
        );
    }

    #[test]
    fn paths_the_upstream_could_rewrite_are_refused() {
        for path in [
            "/v1/x/../messages",
            "/v1/./messages",
            "/v1/x/%2e%2e/messages",
            "/v1/x/%2E%2E/messages",
            "/v1%2fmessages",
            "/v1%5Cmessages",
            "/v1/%6dessages",
            "/v1//messages",
            "/v1/messages;x=1",
            "/v1\\messages",
            "/..",
        ] {
            assert_eq!(
                check_path(path),
                Err(GuardError::NonCanonicalPath),
                "{path}"
            );
        }
        for path in [
            "/",
            "/v1/messages",
            "/v1beta/models/gemini:generateContent",
            "/a.b/..c/d..",
        ] {
            assert_eq!(check_path(path), Ok(()), "{path}");
        }
    }

    #[test]
    fn any_origin_header_is_refused_even_with_a_loopback_host() {
        let request = headers(&[
            ("host", "127.0.0.1:8787"),
            ("origin", "https://evil.example"),
        ]);
        assert_eq!(
            check_local_request(&request, None, 8787),
            Err(GuardError::CrossOrigin)
        );
    }
}
