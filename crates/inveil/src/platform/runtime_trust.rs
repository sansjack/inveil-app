//! How each runtime learns about the browser CA, and the environment that gives one process both the proxy and the
//! CA. Variables are always scoped to one process: a global `SSL_CERT_FILE` would replace the roots of every tool on
//! the machine, so it is only ever produced for a runtime that needs it and only for that runtime's process.
use super::proxy::proxy_environment;
use super::{io_error, PlatformError};
use base64::Engine;
use std::fs;
use std::path::{Path, PathBuf};

/// The bundle of the system roots plus our CA, written next to the CA certificate.
pub const BUNDLE_FILE: &str = "ca-bundle.pem";
/// Set by `proxy_environment` for every tool; this module sets the CA variables only for the runtime that reads them.
const CA_VARIABLES: [&str; 2] = ["CODEX_CA_CERTIFICATE", "NODE_EXTRA_CA_CERTS"];
const PEM_LINE_LENGTH: usize = 64;
const PEM_BEGIN: &str = "-----BEGIN CERTIFICATE-----";
const PEM_END: &str = "-----END CERTIFICATE-----";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeKind {
    OsStoreBrowser,
    Firefox,
    Node,
    Python,
    Rust,
    Go,
    Codex,
    Curl,
    Git,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trust {
    /// Reads the operating system's trust store and proxy settings, so the PAC file and the stored CA are enough.
    OperatingSystem,
    /// Keeps its own certificate store.
    FirefoxStore,
    /// These variables name a file whose certificates are added to the runtime's own roots: the CA certificate.
    ExtraCaFile(&'static [&'static str]),
    /// These variables name a file that replaces the runtime's roots, so it must be the bundle of system roots plus ours.
    Bundle(&'static [&'static str]),
}

impl RuntimeKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::OsStoreBrowser => "Chrome, Edge, Brave and Safari",
            Self::Firefox => "Firefox",
            Self::Node => "Node.js",
            Self::Python => "Python",
            Self::Rust => "Rust",
            Self::Go => "Go",
            Self::Codex => "Codex",
            Self::Curl => "curl",
            Self::Git => "git",
        }
    }

    pub fn trust(self) -> Trust {
        match self {
            Self::OsStoreBrowser => Trust::OperatingSystem,
            Self::Firefox => Trust::FirefoxStore,
            Self::Node => Trust::ExtraCaFile(&["NODE_EXTRA_CA_CERTS"]),
            Self::Codex => Trust::ExtraCaFile(&["CODEX_CA_CERTIFICATE"]),
            Self::Python => Trust::Bundle(&["REQUESTS_CA_BUNDLE", "SSL_CERT_FILE"]),
            Self::Rust | Self::Go => Trust::Bundle(&["SSL_CERT_FILE"]),
            Self::Curl => Trust::Bundle(&["CURL_CA_BUNDLE"]),
            Self::Git => Trust::Bundle(&["GIT_SSL_CAINFO"]),
        }
    }

    /// True when the runtime is routed with `HTTPS_PROXY` rather than the system proxy settings.
    pub fn uses_proxy_environment(self) -> bool {
        matches!(self.trust(), Trust::ExtraCaFile(_) | Trust::Bundle(_))
    }

    /// The runtime of a catalog tool that is not a browser. A tool the table does not know is a browser.
    pub fn for_tool(tool_id: &str) -> Self {
        match tool_id {
            "codex" => Self::Codex,
            "cursor" => Self::Node,
            _ => Self::OsStoreBrowser,
        }
    }

    /// The runtime of a program started with `inveil run`, from its file name.
    pub fn for_program(program: &str) -> Option<Self> {
        let name = Path::new(program).file_stem()?.to_str()?;
        match name {
            "node" | "npm" | "npx" | "bun" => Some(Self::Node),
            "python" | "python3" | "pip" | "pip3" | "uv" => Some(Self::Python),
            "cargo" | "rustc" => Some(Self::Rust),
            "go" => Some(Self::Go),
            "codex" => Some(Self::Codex),
            "curl" => Some(Self::Curl),
            "git" => Some(Self::Git),
            _ => None,
        }
    }
}

/// The environment for one process of `runtime`: the proxy variables from [`proxy_environment`] plus the variables
/// that make that runtime trust our CA. Empty for runtimes that follow the operating system's settings or need
/// something no variable can carry.
pub fn tool_environment(
    runtime: RuntimeKind,
    port: u16,
    ca_certificate: &Path,
    bundle: &Path,
    existing_no_proxy: &str,
) -> Vec<(&'static str, String)> {
    let (variables, file) = match runtime.trust() {
        Trust::ExtraCaFile(variables) => (variables, ca_certificate),
        Trust::Bundle(variables) => (variables, bundle),
        Trust::OperatingSystem | Trust::FirefoxStore => return Vec::new(),
    };
    let mut environment: Vec<(&'static str, String)> =
        proxy_environment(port, ca_certificate, existing_no_proxy)
            .into_iter()
            .filter(|(name, _)| !CA_VARIABLES.contains(name))
            .collect();
    let file = file.display().to_string();
    environment.extend(variables.iter().map(|name| (*name, file.clone())));
    environment
}

pub fn bundle_path(ca_directory: &Path) -> PathBuf {
    ca_directory.join(BUNDLE_FILE)
}

/// Writes the system roots followed by our CA to `bundle`, for the runtimes whose variable replaces their roots.
pub fn write_ca_bundle(ca_certificate: &Path, bundle: &Path) -> Result<(), PlatformError> {
    let ours = fs::read_to_string(ca_certificate).map_err(io_error(ca_certificate))?;
    let system_roots = rustls_native_certs::load_native_certs().certs;
    if system_roots.is_empty() {
        return Err(PlatformError::NoSystemRoots);
    }
    fs::write(bundle, bundle_pem(&system_roots, &ours)).map_err(io_error(bundle))
}

fn bundle_pem(system_roots: &[impl AsRef<[u8]>], ours: &str) -> String {
    let mut bundle = String::new();
    for certificate in system_roots {
        let encoded = base64::engine::general_purpose::STANDARD.encode(certificate.as_ref());
        bundle.push_str(PEM_BEGIN);
        bundle.push('\n');
        for line in encoded.as_bytes().chunks(PEM_LINE_LENGTH) {
            bundle.push_str(&String::from_utf8_lossy(line));
            bundle.push('\n');
        }
        bundle.push_str(PEM_END);
        bundle.push('\n');
    }
    bundle.push_str(ours);
    bundle
}

#[cfg(test)]
mod tests {
    use super::*;

    fn environment_of(runtime: RuntimeKind) -> Vec<(&'static str, String)> {
        tool_environment(
            runtime,
            8788,
            Path::new("/data/ca/ca.pem"),
            Path::new("/data/ca/ca-bundle.pem"),
            "",
        )
    }

    fn value(environment: &[(&'static str, String)], name: &str) -> Option<String> {
        environment
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value.clone())
    }

    #[test]
    fn runtimes_that_follow_the_system_get_no_environment() {
        for runtime in [RuntimeKind::OsStoreBrowser, RuntimeKind::Firefox] {
            assert!(environment_of(runtime).is_empty(), "{runtime:?}");
        }
    }

    #[test]
    fn node_adds_our_ca_to_its_roots_and_never_sets_ssl_cert_file() {
        let environment = environment_of(RuntimeKind::Node);
        assert_eq!(
            value(&environment, "NODE_EXTRA_CA_CERTS").as_deref(),
            Some("/data/ca/ca.pem")
        );
        assert_eq!(
            value(&environment, "HTTPS_PROXY").as_deref(),
            Some("http://127.0.0.1:8788")
        );
        assert_eq!(value(&environment, "CODEX_CA_CERTIFICATE"), None);
        assert_eq!(value(&environment, "SSL_CERT_FILE"), None);
    }

    #[test]
    fn codex_gets_only_its_own_ca_variable() {
        let environment = environment_of(RuntimeKind::Codex);
        assert_eq!(
            value(&environment, "CODEX_CA_CERTIFICATE").as_deref(),
            Some("/data/ca/ca.pem")
        );
        assert_eq!(value(&environment, "NODE_EXTRA_CA_CERTS"), None);
        assert_eq!(value(&environment, "SSL_CERT_FILE"), None);
    }

    #[test]
    fn python_points_every_variable_at_the_bundle_not_the_bare_ca() {
        let environment = environment_of(RuntimeKind::Python);
        for name in ["REQUESTS_CA_BUNDLE", "SSL_CERT_FILE"] {
            assert_eq!(
                value(&environment, name).as_deref(),
                Some("/data/ca/ca-bundle.pem"),
                "{name}"
            );
        }
    }

    #[test]
    fn bundle_runtimes_each_get_their_own_variable() {
        let expected = [
            (RuntimeKind::Rust, "SSL_CERT_FILE"),
            (RuntimeKind::Go, "SSL_CERT_FILE"),
            (RuntimeKind::Curl, "CURL_CA_BUNDLE"),
            (RuntimeKind::Git, "GIT_SSL_CAINFO"),
        ];
        for (runtime, name) in expected {
            let environment = environment_of(runtime);
            assert_eq!(
                value(&environment, name).as_deref(),
                Some("/data/ca/ca-bundle.pem"),
                "{runtime:?}"
            );
        }
    }

    #[test]
    fn ssl_cert_file_is_only_set_for_runtimes_that_read_it_and_never_for_the_rest() {
        let readers = [RuntimeKind::Python, RuntimeKind::Rust, RuntimeKind::Go];
        let others = [
            RuntimeKind::OsStoreBrowser,
            RuntimeKind::Firefox,
            RuntimeKind::Node,
            RuntimeKind::Codex,
            RuntimeKind::Curl,
            RuntimeKind::Git,
        ];
        for runtime in readers {
            assert!(
                value(&environment_of(runtime), "SSL_CERT_FILE").is_some(),
                "{runtime:?}"
            );
        }
        for runtime in others {
            assert_eq!(
                value(&environment_of(runtime), "SSL_CERT_FILE"),
                None,
                "{runtime:?}"
            );
        }
    }

    #[test]
    fn existing_no_proxy_entries_are_kept() {
        let environment = tool_environment(
            RuntimeKind::Node,
            1,
            Path::new("/c"),
            Path::new("/b"),
            "internal.example",
        );
        assert_eq!(
            value(&environment, "NO_PROXY").as_deref(),
            Some("internal.example,localhost,127.0.0.1")
        );
    }

    #[test]
    fn programs_map_to_runtimes_by_file_name() {
        assert_eq!(
            RuntimeKind::for_program("/usr/bin/python3"),
            Some(RuntimeKind::Python)
        );
        assert_eq!(RuntimeKind::for_program("codex"), Some(RuntimeKind::Codex));
        assert_eq!(RuntimeKind::for_program("some-tool"), None);
    }

    #[test]
    fn catalog_tools_that_are_not_browsers_map_to_their_runtime() {
        assert_eq!(RuntimeKind::for_tool("codex"), RuntimeKind::Codex);
        assert_eq!(
            RuntimeKind::for_tool("claude-web"),
            RuntimeKind::OsStoreBrowser
        );
    }

    #[test]
    fn the_bundle_holds_every_system_root_then_our_ca() {
        let ours = "-----BEGIN CERTIFICATE-----\nOURS\n-----END CERTIFICATE-----\n";
        let bundle = bundle_pem(&[vec![0_u8; 100], vec![1_u8; 3]], ours);
        assert_eq!(bundle.matches(PEM_BEGIN).count(), 3);
        assert!(bundle.ends_with(ours));
        let longest = bundle.lines().map(str::len).max().unwrap_or(0);
        assert!(longest <= PEM_LINE_LENGTH.max(PEM_BEGIN.len()));
    }

    #[test]
    fn the_bundle_is_written_next_to_the_ca() {
        let directory = tempfile::tempdir().unwrap();
        let certificate = directory.path().join("ca.pem");
        fs::write(&certificate, "OURS\n").unwrap();
        let bundle = bundle_path(directory.path());
        assert_eq!(bundle, directory.path().join(BUNDLE_FILE));

        write_ca_bundle(&certificate, &bundle).unwrap();

        let text = fs::read_to_string(&bundle).unwrap();
        assert!(text.contains(PEM_BEGIN));
        assert!(text.ends_with("OURS\n"));
    }
}
