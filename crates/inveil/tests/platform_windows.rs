//! Windows-only checks that need the real `icacls`. They write only to a temp file.
#![cfg(windows)]

#[path = "../src/platform/mod.rs"]
mod platform;

#[test]
fn private_files_grant_access_to_the_current_user_only() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("ca.key");

    platform::write_private_file(&path, "secret").unwrap();

    let output = std::process::Command::new("icacls")
        .arg(&path)
        .output()
        .unwrap();
    let acl = String::from_utf8_lossy(&output.stdout);
    let user = std::env::var("USERNAME").unwrap();
    assert!(acl.contains(&user), "{acl}");
    for broad_group in ["Everyone", "BUILTIN\\Users", "Authenticated Users"] {
        assert!(!acl.contains(broad_group), "{acl}");
    }
}
