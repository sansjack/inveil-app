//! The CA behind the browser proxy, the PAC script that routes chat sites to it, and the environment that points one
//! command at it.
//!
//! - The CA is created on this device and its private key never leaves it.
//! - Its certificate carries a Name Constraints extension limiting it to the domains in the signed snapshot
//!   (`ca_domains`; none are compiled in), which operating systems and most browsers enforce. Even a leaked key cannot
//!   vouch for a bank or a mail site. A new domain from the backend means a new CA.
//!   The extension also excludes every IPv4 and IPv6 address and permits e-mail names only under the reserved
//!   `.invalid` domain, so a leaked key cannot mint certificates for IP literals or mailboxes. rcgen cannot express URI
//!   constraints, and a directoryName constraint would be applied to the leaf subjects this proxy issues, so neither
//!   is set; the key usage below (serverAuth only) is what rules those uses out.
//! - It is a leaf-signer only (path length 0), usable for TLS servers only, and expires after a year; setup renews it
//!   when it gets old.
use crate::brand;
use crate::platform::{self, PlatformError};
use hudsucker::certificate_authority::RcgenAuthority;
use hudsucker::rcgen::{
    BasicConstraints, CertificateParams, CidrSubnet, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, GeneralSubtree, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    NameConstraints,
};
use hudsucker::rustls::crypto::aws_lc_rs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

const CA_VALID_DAYS: i64 = 365;
const CA_BACKDATE_DAYS: i64 = 1;
const CA_ORGANISATION: &str = "inveil";
/// Renew when the CA is older than this, well before it expires.
const CA_RENEW_AFTER: Duration = Duration::from_secs(300 * 24 * 3600);
/// Reserved by RFC 2606, so no real mailbox lives under it.
const PERMITTED_EMAIL_DOMAIN: &str = "invalid";
const LEAF_CERTIFICATE_CACHE_SIZE: u64 = 1_000;
pub const CERT_FILE: &str = "ca.pem";
const KEY_FILE: &str = "ca.key";
/// The domains this CA was created for (a JSON array), kept so a later snapshot can be compared with it.
const DOMAINS_FILE: &str = "domains.json";

#[derive(Debug, thiserror::Error)]
pub enum CaError {
    #[error("cannot create the browser CA ({stage}): {source}")]
    Generate {
        stage: &'static str,
        source: hudsucker::rcgen::Error,
    },
    #[error("cannot use the browser CA: {0}")]
    Unusable(hudsucker::rcgen::Error),
    #[error("cannot write {path}: {source}")]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("cannot write the CA private key: {0}")]
    PrivateKey(#[from] PlatformError),
    #[error("cannot remove {path}: {source}")]
    Remove {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("the browser CA needs at least one domain")]
    NoDomains,
    #[error("the CA domain list is not valid JSON: {0}")]
    DomainList(#[from] serde_json::Error),
}

pub fn ca_directory(data_dir: &Path) -> PathBuf {
    data_dir.join(brand::CA_DIR_NAME)
}

pub fn certificate_path(ca_directory: &Path) -> PathBuf {
    ca_directory.join(CERT_FILE)
}

pub fn pac_url(port: u16) -> String {
    format!("http://127.0.0.1:{port}/proxy.pac")
}

/// The domains the CA on disk was created for (empty when there is none or the list is unreadable).
pub fn domains_on_disk(ca_directory: &Path) -> Vec<String> {
    std::fs::read_to_string(ca_directory.join(DOMAINS_FILE))
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

/// Says so when the signed list has grown past what this CA was created for. Those domains stay undecrypted until
/// the CA is renewed, which needs the user, so it cannot happen silently.
pub fn warn_if_outdated(ca_directory: &Path, snapshot_domains: &[String]) {
    let on_disk = domains_on_disk(ca_directory);
    if on_disk.is_empty() {
        return;
    }
    let missing: Vec<&String> = snapshot_domains
        .iter()
        .filter(|domain| !on_disk.contains(domain))
        .collect();
    if !missing.is_empty() {
        tracing::warn!(
            "the browser CA does not cover {missing:?}; run `inveil browser-setup` to renew it"
        );
    }
}

/// The CA for the running proxy, or `None` when `browser-setup` has not been run.
pub fn load_authority(ca_directory: &Path) -> Result<Option<RcgenAuthority>, CaError> {
    let (Ok(certificate), Ok(key)) = (
        std::fs::read_to_string(certificate_path(ca_directory)),
        std::fs::read_to_string(ca_directory.join(KEY_FILE)),
    ) else {
        return Ok(None);
    };
    authority_from_pem(&certificate, &key).map(Some)
}

pub fn authority_from_pem(certificate: &str, key: &str) -> Result<RcgenAuthority, CaError> {
    let issuer = KeyPair::from_pem(key)
        .and_then(|pair| Issuer::from_ca_cert_pem(certificate, pair))
        .map_err(CaError::Unusable)?;
    Ok(RcgenAuthority::new(
        issuer,
        LEAF_CERTIFICATE_CACHE_SIZE,
        aws_lc_rs::default_provider(),
    ))
}

/// Returns (certificate PEM, private key PEM).
pub fn generate_ca(domains: &[String]) -> Result<(String, String), CaError> {
    if domains.is_empty() {
        return Err(CaError::NoDomains);
    }
    let failed = |stage| move |source| CaError::Generate { stage, source };
    let key = KeyPair::generate().map_err(failed("key"))?;
    let mut params = CertificateParams::new(Vec::<String>::new()).map_err(failed("params"))?;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let mut permitted_subtrees: Vec<GeneralSubtree> = domains
        .iter()
        .map(|domain| GeneralSubtree::DnsName(domain.clone()))
        .collect();
    permitted_subtrees.push(GeneralSubtree::Rfc822Name(
        PERMITTED_EMAIL_DOMAIN.to_string(),
    ));
    params.name_constraints = Some(NameConstraints {
        permitted_subtrees,
        excluded_subtrees: vec![
            GeneralSubtree::IpAddress(CidrSubnet::V4([0; 4], [0; 4])),
            GeneralSubtree::IpAddress(CidrSubnet::V6([0; 16], [0; 16])),
        ],
    });
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, platform::CA_NAME);
    params
        .distinguished_name
        .push(DnType::OrganizationName, CA_ORGANISATION);
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(CA_BACKDATE_DAYS);
    params.not_after = now + time::Duration::days(CA_VALID_DAYS);
    let certificate = params.self_signed(&key).map_err(failed("certificate"))?;
    Ok((certificate.pem(), key.serialize_pem()))
}

#[derive(Debug, PartialEq, Eq)]
pub enum CaStatus {
    Missing,
    Current,
    Expiring,
    /// The signed list names domains the CA was not created for.
    Outdated,
}

pub fn status(ca_directory: &Path, wanted: &[String]) -> CaStatus {
    let age = std::fs::metadata(certificate_path(ca_directory))
        .and_then(|metadata| metadata.modified())
        .ok()
        .and_then(|modified| SystemTime::now().duration_since(modified).ok());
    let Some(age) = age else {
        return CaStatus::Missing;
    };
    let on_disk = domains_on_disk(ca_directory);
    if !wanted.iter().all(|domain| on_disk.contains(domain)) {
        return CaStatus::Outdated;
    }
    if age > CA_RENEW_AFTER {
        return CaStatus::Expiring;
    }
    CaStatus::Current
}

/// Writes a fresh CA for `domains`, replacing any earlier one. Returns the certificate path.
pub fn create(ca_directory: &Path, domains: &[String]) -> Result<PathBuf, CaError> {
    let (certificate, key) = generate_ca(domains)?;
    std::fs::create_dir_all(ca_directory).map_err(|source| CaError::Write {
        path: ca_directory.to_path_buf(),
        source,
    })?;
    platform::write_private_file(&ca_directory.join(KEY_FILE), &key)?;
    let certificate_file = certificate_path(ca_directory);
    write_file(&certificate_file, certificate.as_bytes())?;
    write_file(
        &ca_directory.join(DOMAINS_FILE),
        serde_json::to_string(domains)?.as_bytes(),
    )?;
    Ok(certificate_file)
}

pub fn remove(ca_directory: &Path) -> Result<(), CaError> {
    if !ca_directory.exists() {
        return Ok(());
    }
    std::fs::remove_dir_all(ca_directory).map_err(|source| CaError::Remove {
        path: ca_directory.to_path_buf(),
        source,
    })
}

fn write_file(path: &Path, contents: &[u8]) -> Result<(), CaError> {
    std::fs::write(path, contents).map_err(|source| CaError::Write {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hudsucker::rcgen::SanType;
    use hudsucker::rustls::pki_types::{
        pem::PemObject, CertificateDer, ServerName, TrustAnchor, UnixTime,
    };
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    const LISTED: [&str; 3] = ["claude.ai", "chatgpt.com", "gemini.google.com"];

    fn domains(list: &[&str]) -> Vec<String> {
        list.iter().map(|domain| domain.to_string()).collect()
    }

    struct TestCa {
        issuer: Issuer<'static, KeyPair>,
        anchor: TrustAnchor<'static>,
    }

    fn test_ca() -> TestCa {
        let (certificate_pem, key_pem) = generate_ca(&domains(&LISTED)).unwrap();
        let issuer =
            Issuer::from_ca_cert_pem(&certificate_pem, KeyPair::from_pem(&key_pem).unwrap())
                .unwrap();
        let ca_der = CertificateDer::from_pem_slice(certificate_pem.as_bytes()).unwrap();
        let anchor = webpki::anchor_from_trusted_cert(&ca_der)
            .unwrap()
            .to_owned();
        TestCa { issuer, anchor }
    }

    /// Whether webpki accepts a server certificate carrying exactly these names, checked against `host`.
    fn accepts(ca: &TestCa, names: Vec<SanType>, host: ServerName<'_>) -> bool {
        let leaf_key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.subject_alt_names = names;
        let leaf = params.signed_by(&leaf_key, &ca.issuer).unwrap();
        let leaf_der = leaf.der().clone();
        let end_entity = webpki::EndEntityCert::try_from(&leaf_der).unwrap();
        end_entity
            .verify_for_usage(
                webpki::ALL_VERIFICATION_ALGS,
                std::slice::from_ref(&ca.anchor),
                &[],
                UnixTime::now(),
                webpki::KeyUsage::server_auth(),
                None,
                None,
            )
            .and_then(|_| end_entity.verify_is_valid_for_subject_name(&host))
            .is_ok()
    }

    fn dns(host: &str) -> SanType {
        SanType::DnsName(host.try_into().unwrap())
    }

    /// The property the whole design leans on: a leaked CA key must not be able to vouch for other sites.
    #[test]
    fn ca_vouches_only_for_the_domains_it_was_made_for() {
        let ca = test_ca();
        let cases = [
            ("claude.ai", true),
            ("www.chatgpt.com", true),
            ("gemini.google.com", true),
            ("google.com", false),
            ("grok.com", false),
            ("bank.example.com", false),
            ("claude.ai.evil.com", false),
        ];
        for (host, trusted) in cases {
            let accepted = accepts(&ca, vec![dns(host)], ServerName::try_from(host).unwrap());
            assert_eq!(accepted, trusted, "{host}");
        }
    }

    #[test]
    fn ca_does_not_vouch_for_ip_addresses() {
        let ca = test_ca();
        let ipv4 = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
        let ipv6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        for address in [ipv4, ipv6] {
            let host = ServerName::IpAddress(address.into());
            assert!(!accepts(
                &ca,
                vec![SanType::IpAddress(address)],
                host.clone()
            ));
            assert!(!accepts(
                &ca,
                vec![dns("claude.ai"), SanType::IpAddress(address)],
                host
            ));
        }
    }

    #[test]
    fn ca_does_not_vouch_for_email_addresses_next_to_a_listed_domain() {
        let ca = test_ca();
        let host = ServerName::try_from("claude.ai").unwrap();
        let email = SanType::Rfc822Name("user@claude.ai".try_into().unwrap());
        assert!(!accepts(&ca, vec![dns("claude.ai"), email], host));
    }

    #[test]
    fn ca_certificate_names_server_authentication_as_its_only_extended_key_usage() {
        const EXTENDED_KEY_USAGE_OID: [u8; 3] = [0x55, 0x1D, 0x25];
        const SERVER_AUTH_OID: [u8; 8] = [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
        const ANY_EXTENDED_KEY_USAGE_OID: [u8; 4] = [0x55, 0x1D, 0x25, 0x00];
        fn contains(haystack: &[u8], needle: &[u8]) -> bool {
            haystack
                .windows(needle.len())
                .any(|window| window == needle)
        }
        let (certificate_pem, _) = generate_ca(&domains(&LISTED)).unwrap();
        let der = CertificateDer::from_pem_slice(certificate_pem.as_bytes()).unwrap();
        assert!(contains(&der, &EXTENDED_KEY_USAGE_OID));
        assert!(contains(&der, &SERVER_AUTH_OID));
        assert!(!contains(&der, &ANY_EXTENDED_KEY_USAGE_OID));
    }

    #[test]
    fn refuses_to_create_a_ca_without_domains() {
        assert!(matches!(generate_ca(&[]), Err(CaError::NoDomains)));
    }

    #[test]
    fn the_ca_on_disk_is_tracked_and_renewed_when_the_domain_list_grows() {
        let directory = tempfile::tempdir().unwrap();
        let ca_directory = ca_directory(directory.path());
        assert_eq!(status(&ca_directory, &domains(&LISTED)), CaStatus::Missing);
        create(&ca_directory, &domains(&LISTED)).unwrap();
        assert_eq!(status(&ca_directory, &domains(&LISTED)), CaStatus::Current);
        assert_eq!(domains_on_disk(&ca_directory), domains(&LISTED));
        assert_eq!(
            status(&ca_directory, &domains(&["claude.ai", "grok.com"])),
            CaStatus::Outdated
        );
        assert!(load_authority(&ca_directory).unwrap().is_some());
        remove(&ca_directory).unwrap();
        assert!(load_authority(&ca_directory).unwrap().is_none());
    }
}
