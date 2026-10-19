//! Install -> status -> uninstall in a sandbox directory. Run with `cargo test -p inveil --test platform_e2e -- --ignored`.
//! `INVEIL_PLATFORM_SANDBOX` is read only in test builds, and this file compiles the platform module as one. It keeps
//! every file under a temp directory and turns system commands into no-ops, so this never touches the real service
//! manager, trust store or proxy settings.

#[path = "../src/platform/mod.rs"]
mod platform;

use std::fs;

const PAC_URL: &str = "http://127.0.0.1:8788/proxy.pac";

#[test]
#[ignore = "end-to-end lifecycle, run by the CI e2e job"]
fn service_lifecycle_in_a_sandbox() {
    let sandbox = tempfile::tempdir().unwrap();
    std::env::set_var(platform::SANDBOX_VARIABLE, sandbox.path());

    let data_dir = platform::data_dir().unwrap();
    assert!(data_dir.starts_with(sandbox.path()));
    let log = platform::default_log_path().unwrap();
    assert!(log.starts_with(sandbox.path()));
    fs::create_dir_all(&data_dir).unwrap();
    let exe = platform::install_exe_path().unwrap();
    fs::write(&exe, "binary").unwrap();

    assert!(!platform::service_installed().unwrap());
    assert!(!platform::restart_service().unwrap());

    platform::install_service(&exe, &log).unwrap();
    assert!(platform::service_installed().unwrap());
    assert!(platform::restart_service().unwrap());

    let definition = if cfg!(target_os = "macos") {
        sandbox
            .path()
            .join("Library/LaunchAgents/com.inveil.proxy.plist")
    } else if cfg!(windows) {
        data_dir.join("inveil-task.xml")
    } else {
        sandbox.path().join(".config/systemd/user/inveil.service")
    };
    let definition_bytes = fs::read(&definition).unwrap();
    let definition_text = if cfg!(windows) {
        let units: Vec<u16> = definition_bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes(*pair))
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8(definition_bytes).unwrap()
    };
    assert!(definition_text.contains(exe.to_str().unwrap()));

    let certificate = data_dir.join("ca.pem");
    platform::write_private_file(&certificate, "certificate").unwrap();
    platform::trust_ca(&certificate).unwrap();
    assert!(platform::ca_trusted().unwrap());
    platform::set_pac(PAC_URL).unwrap();
    assert!(platform::pac_applied(PAC_URL).unwrap());
    platform::clear_pac(PAC_URL).unwrap();
    platform::untrust_ca(&certificate).unwrap();
    platform::write_pid_file().unwrap();
    platform::notify("inveil", "Blocked a message").unwrap();

    platform::stop_service().unwrap();
    platform::uninstall_service().unwrap();
    assert!(!platform::service_installed().unwrap());
    assert!(!definition.exists());
    platform::uninstall_service().unwrap();
}

#[test]
fn each_runtime_gets_the_proxy_and_only_the_variables_it_reads() {
    let directory = tempfile::tempdir().unwrap();
    let certificate = directory.path().join("ca.pem");
    fs::write(&certificate, "certificate").unwrap();
    let bundle = platform::bundle_path(directory.path());

    platform::write_ca_bundle(&certificate, &bundle).unwrap();
    let python = platform::tool_environment(
        platform::RuntimeKind::Python,
        8788,
        &certificate,
        &bundle,
        "",
    );
    let node =
        platform::tool_environment(platform::RuntimeKind::Node, 8788, &certificate, &bundle, "");

    let names = |environment: &[(&str, String)]| -> Vec<String> {
        environment
            .iter()
            .map(|(name, _)| name.to_string())
            .collect()
    };
    assert!(names(&python).contains(&"SSL_CERT_FILE".to_string()));
    assert!(!names(&node).contains(&"SSL_CERT_FILE".to_string()));
    assert!(platform::RuntimeKind::Python.uses_proxy_environment());
    assert!(!platform::RuntimeKind::OsStoreBrowser.uses_proxy_environment());
    assert_eq!(platform::RuntimeKind::Firefox.name(), "Firefox");
    assert!(platform::pac_script(
        &["claude.ai".into()],
        &["claude.ai".into()],
        8788,
        contract::FailMode::Open,
    )
    .contains("claude.ai"));
    assert!(!platform::proxy_environment(8788, &certificate, "").is_empty());
}
