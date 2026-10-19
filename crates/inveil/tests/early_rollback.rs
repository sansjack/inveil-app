#![allow(clippy::unwrap_used, clippy::expect_used)]
//! An update that fails before the service is up (here: on its configuration) must still be rolled back, because the
//! rollback counter runs at the very start of `inveil run`, ahead of the configuration and the logging.
use ring::digest;
use std::fs;
use std::path::Path;
use std::process::{Command, Output};

const BINARY: &str = env!("CARGO_BIN_EXE_inveil");
const PENDING_MARKER: &str = ".inveil-update-pending";
const PREVIOUS_CONTENT: &[u8] = b"previous binary";
const ATTEMPTS_BEFORE_ROLLBACK: u32 = 3;

fn sha256_hex(bytes: &[u8]) -> String {
    digest::digest(&digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn run_with_broken_config(executable: &Path, config: &Path) -> Output {
    Command::new(executable)
        .arg("--config")
        .arg(config)
        .arg("run")
        .output()
        .unwrap()
}

#[test]
fn a_new_binary_that_fails_on_its_configuration_is_rolled_back() {
    let install_dir = tempfile::tempdir().unwrap();
    let executable = install_dir
        .path()
        .join(Path::new(BINARY).file_name().unwrap());
    fs::copy(BINARY, &executable).unwrap();
    fs::write(install_dir.path().join("inveil.prev"), PREVIOUS_CONTENT).unwrap();
    let marker = serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "sha256": sha256_hex(&fs::read(&executable).unwrap()),
        "starts": 0,
    });
    fs::write(install_dir.path().join(PENDING_MARKER), marker.to_string()).unwrap();
    let config = install_dir.path().join("broken.toml");
    fs::write(&config, "this is = not [valid toml").unwrap();

    for attempt in 1..=ATTEMPTS_BEFORE_ROLLBACK {
        let output = run_with_broken_config(&executable, &config);
        assert!(!output.status.success(), "attempt {attempt}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("invalid configuration"), "{stderr}");
    }
    assert_ne!(fs::read(&executable).unwrap(), PREVIOUS_CONTENT);

    let output = run_with_broken_config(&executable, &config);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("previous version is restored"), "{stderr}");
    assert_eq!(fs::read(&executable).unwrap(), PREVIOUS_CONTENT);
    assert!(!install_dir.path().join(PENDING_MARKER).exists());
}

#[test]
fn commands_other_than_run_do_not_count_as_a_start() {
    let install_dir = tempfile::tempdir().unwrap();
    let executable = install_dir
        .path()
        .join(Path::new(BINARY).file_name().unwrap());
    fs::copy(BINARY, &executable).unwrap();
    let marker = serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "sha256": sha256_hex(&fs::read(&executable).unwrap()),
        "starts": 0,
    });
    let marker_path = install_dir.path().join(PENDING_MARKER);
    fs::write(&marker_path, marker.to_string()).unwrap();
    let config = install_dir.path().join("broken.toml");
    fs::write(&config, "this is = not [valid toml").unwrap();

    for _ in 0..=ATTEMPTS_BEFORE_ROLLBACK {
        Command::new(&executable)
            .arg("--config")
            .arg(&config)
            .arg("status")
            .output()
            .unwrap();
    }

    let after: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&marker_path).unwrap()).unwrap();
    assert_eq!(after["starts"], 0);
}
