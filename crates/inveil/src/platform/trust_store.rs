//! Pieces of trust-store handling that are pure, so they are tested on every OS.
use super::PlatformError;

/// Upper bound on same-named certificates removed in one go; renewals leave one behind each time.
const MAX_SAME_NAME_CERTIFICATES: usize = 32;
const SECURITY_HASH_PREFIX: &str = "SHA-1 hash:";

/// Runs `remove` until `is_present` is false, because stores delete one match per call and renewals leave
/// duplicates with the same name.
#[cfg_attr(all(target_os = "macos", not(test)), allow(dead_code))]
pub(super) fn remove_while_present(
    mut is_present: impl FnMut() -> Result<bool, PlatformError>,
    mut remove: impl FnMut() -> Result<(), PlatformError>,
) -> Result<(), PlatformError> {
    for _ in 0..MAX_SAME_NAME_CERTIFICATES {
        if !is_present()? {
            return Ok(());
        }
        remove()?;
    }
    if !is_present()? {
        return Ok(());
    }
    Err(PlatformError::CommandFailed {
        program: "trust store".to_string(),
        detail: format!("certificate still present after {MAX_SAME_NAME_CERTIFICATES} removals"),
    })
}

/// The `security add-trusted-cert` arguments. Trust is limited to the SSL policy so the CA cannot vouch for code
/// signing, mail or other uses.
#[cfg_attr(not(any(test, target_os = "macos")), allow(dead_code))]
pub(super) fn macos_add_trusted_args<'a>(keychain: &'a str, certificate: &'a str) -> Vec<&'a str> {
    vec![
        "add-trusted-cert",
        "-r",
        "trustRoot",
        "-p",
        "ssl",
        "-k",
        keychain,
        certificate,
    ]
}

/// The hashes in `security find-certificate -a -Z` output, one per matching certificate.
#[cfg_attr(not(any(test, target_os = "macos")), allow(dead_code))]
pub(super) fn security_certificate_hashes(output: &str) -> Vec<&str> {
    output
        .lines()
        .filter_map(|line| line.strip_prefix(SECURITY_HASH_PREFIX))
        .map(str::trim)
        .collect()
}

/// The `security delete-certificate` arguments for one certificate; `-t` also drops its trust settings.
#[cfg_attr(not(any(test, target_os = "macos")), allow(dead_code))]
pub(super) fn macos_delete_args<'a>(hash: &'a str, keychain: &'a str) -> Vec<&'a str> {
    vec!["delete-certificate", "-Z", hash, "-t", keychain]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn macos_trust_is_limited_to_the_ssl_policy() {
        let args = macos_add_trusted_args("login.keychain-db", "ca.pem");
        assert_eq!(
            args,
            [
                "add-trusted-cert",
                "-r",
                "trustRoot",
                "-p",
                "ssl",
                "-k",
                "login.keychain-db",
                "ca.pem"
            ]
        );
    }

    #[test]
    fn macos_removal_names_each_certificate_by_hash_and_drops_its_trust_settings() {
        let output = "keychain: \"/Users/me/Library/Keychains/login.keychain-db\"\n\
            SHA-256 hash: AAAA\n\
            SHA-1 hash: 1111111111111111111111111111111111111111\n\
            \"labl\"<blob>=\"Inveil Browser CA\"\n\
            SHA-1 hash: 2222222222222222222222222222222222222222\n";
        let hashes = security_certificate_hashes(output);
        assert_eq!(
            hashes,
            [
                "1111111111111111111111111111111111111111",
                "2222222222222222222222222222222222222222"
            ]
        );
        assert_eq!(
            macos_delete_args(hashes[1], "login.keychain-db"),
            [
                "delete-certificate",
                "-Z",
                "2222222222222222222222222222222222222222",
                "-t",
                "login.keychain-db"
            ]
        );
    }

    #[test]
    fn removes_every_duplicate_certificate() {
        let remaining = Cell::new(3);
        remove_while_present(
            || Ok(remaining.get() > 0),
            || {
                remaining.set(remaining.get() - 1);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(remaining.get(), 0);
    }

    #[test]
    fn removes_nothing_when_the_certificate_is_absent() {
        let removals = Cell::new(0);
        remove_while_present(
            || Ok(false),
            || {
                removals.set(removals.get() + 1);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(removals.get(), 0);
    }

    #[test]
    fn gives_up_when_the_store_keeps_reporting_the_certificate() {
        let removals = Cell::new(0);
        let result = remove_while_present(
            || Ok(true),
            || {
                removals.set(removals.get() + 1);
                Ok(())
            },
        );
        assert!(matches!(result, Err(PlatformError::CommandFailed { .. })));
        assert_eq!(removals.get(), MAX_SAME_NAME_CERTIFICATES);
    }
}
