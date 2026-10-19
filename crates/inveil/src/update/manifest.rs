//! Fetching and judging the signed update manifest. The signature is verified before the payload is parsed; only then
//! are version, channel, expiry, replay and target checked.
use super::fetch::{read_capped, FetchError, Fetcher};
use super::state::{SeenRelease, UpdateState};
use super::UpdateContext;
use crate::trust_state::StateError;
use contract::{Artifact, UpdateManifest, MANIFEST_SCHEMA};
use engine::freshness::{check_revocations, LocalAnchors, Rejection};
use engine::signing::{verify_envelope, PublicKeyBytes, Role, Trust, Verified, VerifyError};
use semver::Version;
use std::collections::BTreeSet;
use std::time::Duration;

const MAX_MANIFEST_BYTES: u64 = 256 * 1024;
const MANIFEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error(transparent)]
    Fetch(#[from] FetchError),
    #[error("manifest is not valid UTF-8")]
    NotUtf8,
    #[error(transparent)]
    Signature(#[from] VerifyError),
    #[error(transparent)]
    Revocation(#[from] Rejection),
    #[error(transparent)]
    State(#[from] StateError),
    #[error("unsupported manifest schema {0}")]
    Schema(u8),
    #[error("manifest is for channel {found}, expected {expected}")]
    WrongChannel { expected: String, found: String },
    #[error("manifest expired at {expires_at} (now {now})")]
    Expired { expires_at: u64, now: u64 },
    #[error("invalid version {0:?} in manifest")]
    InvalidVersion(String),
    #[error(
        "manifest requires at least {min_supported}, which is newer than its own version {version}"
    )]
    MinSupportedAboveVersion {
        min_supported: Version,
        version: Version,
    },
    #[error("refusing downgrade: manifest offers {offered}, running {current}")]
    Downgrade { offered: Version, current: Version },
    #[error("refusing replayed manifest: {offered} is older than {seen}, which was already seen")]
    Replay { offered: Version, seen: Version },
    #[error("version {0} was seen before with a different binary hash")]
    ConflictingArtifact(Version),
    #[error("manifest has no binary for {0}")]
    NoArtifactForTarget(String),
}

#[derive(Debug)]
pub struct Candidate {
    pub version: Version,
    pub artifact: Artifact,
    pub notes_url: Option<String>,
    /// The running version is below `min_supported`.
    pub mandatory: bool,
}

/// Distinct signers a manifest needs: what it asks for, but never fewer than the locally pinned `min_signatures`.
fn required_signatures(manifest: &UpdateManifest, min_signatures: usize) -> usize {
    usize::from(manifest.threshold).max(min_signatures).max(1)
}

/// Signatures from pinned keys that are not revoked, counted once per public key, against the larger of the
/// manifest's own threshold and the local `min_signatures`. Key ids the manifest revokes are honoured only if it still
/// meets that threshold without them and leaves enough pinned keys; the caller persists them once it accepts the
/// manifest.
pub fn verify_manifest(
    trust: &Trust,
    min_signatures: usize,
    now: u64,
    text: &str,
    revoked_key_ids: &BTreeSet<String>,
    revoked_public_keys: &BTreeSet<PublicKeyBytes>,
) -> Result<Verified<UpdateManifest>, ManifestError> {
    let active = trust.without_revoked(revoked_key_ids, revoked_public_keys);
    let verified =
        verify_envelope::<UpdateManifest>(Role::Update, &active, min_signatures.max(1), now, text)?;
    let required = required_signatures(&verified.value, min_signatures);
    if verified.signed_by.len() < required {
        return Err(VerifyError::NotEnoughSignatures {
            valid: verified.signed_by.len(),
            required,
        }
        .into());
    }
    let pinned_key_ids: Vec<String> = active.keys.iter().map(|key| key.key_id.clone()).collect();
    let anchors = LocalAnchors {
        audience: None,
        pinned_key_ids: &pinned_key_ids,
        required_signatures: required,
    };
    check_revocations(
        &verified.signed_by,
        &verified.value.revoked_key_ids,
        &anchors,
    )?;
    Ok(verified)
}

pub struct Expectations<'a> {
    pub channel: &'a str,
    pub current: &'a Version,
    pub target: &'a str,
    pub now: u64,
    pub seen: Option<&'a SeenRelease>,
}

fn parse_version(text: &str) -> Result<Version, ManifestError> {
    Version::parse(text).map_err(|_| ManifestError::InvalidVersion(text.to_string()))
}

/// A release that passed every check that does not depend on which binary is wanted.
pub struct Offer {
    pub version: Version,
    /// The running version is below `min_supported`.
    pub mandatory: bool,
    seen_version: Option<Version>,
}

/// Schema, channel, expiry, `min_supported`, replay and downgrade. `Ok(None)` means the manifest is valid and offers
/// nothing newer than the running version.
pub fn check_release(
    manifest: &UpdateManifest,
    expected: &Expectations,
) -> Result<Option<Offer>, ManifestError> {
    if manifest.schema != MANIFEST_SCHEMA {
        return Err(ManifestError::Schema(manifest.schema));
    }
    if manifest.channel != expected.channel {
        return Err(ManifestError::WrongChannel {
            expected: expected.channel.to_string(),
            found: manifest.channel.clone(),
        });
    }
    if expected.now >= manifest.expires_at {
        return Err(ManifestError::Expired {
            expires_at: manifest.expires_at,
            now: expected.now,
        });
    }

    let version = parse_version(&manifest.version)?;
    let min_supported = manifest
        .min_supported
        .as_deref()
        .map(parse_version)
        .transpose()?;
    if let Some(min_supported) = &min_supported {
        if *min_supported > version {
            return Err(ManifestError::MinSupportedAboveVersion {
                min_supported: min_supported.clone(),
                version,
            });
        }
    }

    let seen_version = expected
        .seen
        .map(|seen| parse_version(&seen.version))
        .transpose()?;
    if let Some(seen_version) = &seen_version {
        if version < *seen_version {
            return Err(ManifestError::Replay {
                offered: version,
                seen: seen_version.clone(),
            });
        }
    }
    if version < *expected.current {
        return Err(ManifestError::Downgrade {
            offered: version,
            current: expected.current.clone(),
        });
    }
    if version == *expected.current {
        return Ok(None);
    }
    Ok(Some(Offer {
        mandatory: min_supported.is_some_and(|min_supported| *expected.current < min_supported),
        version,
        seen_version,
    }))
}

/// `check_release`, then the binary for `expected.target`. `Ok(None)` means nothing newer is offered.
pub fn check_manifest(
    manifest: &UpdateManifest,
    expected: &Expectations,
) -> Result<Option<Candidate>, ManifestError> {
    let Some(offer) = check_release(manifest, expected)? else {
        return Ok(None);
    };
    let artifact = manifest
        .artifacts
        .get(expected.target)
        .ok_or_else(|| ManifestError::NoArtifactForTarget(expected.target.to_string()))?;
    let same_version_seen = offer.seen_version.as_ref() == Some(&offer.version);
    let seen_other_hash = expected
        .seen
        .is_some_and(|seen| seen.artifact_sha256 != artifact.sha256);
    if same_version_seen && seen_other_hash {
        return Err(ManifestError::ConflictingArtifact(offer.version));
    }

    Ok(Some(Candidate {
        mandatory: offer.mandatory,
        version: offer.version,
        artifact: artifact.clone(),
        notes_url: manifest.notes_url.clone(),
    }))
}

/// Persists the newest release and the key ids it revokes only for a manifest that was accepted and offers something.
pub fn fetch_candidate(
    context: &UpdateContext,
    fetcher: &dyn Fetcher,
    feed_url: &str,
) -> Result<Option<Candidate>, ManifestError> {
    let reader = fetcher.open(feed_url, MANIFEST_TIMEOUT)?;
    let bytes = read_capped(reader, MAX_MANIFEST_BYTES)?;
    let text = String::from_utf8(bytes).map_err(|_| ManifestError::NotUtf8)?;

    let mut stored = context.state.load::<UpdateState>()?;
    let verified = verify_manifest(
        &context.trust,
        context.min_signatures,
        context.now,
        &text,
        &stored.state.revoked_key_ids,
        &stored.state.revoked_public_keys,
    )?;
    let manifest = verified.value;

    let candidate = check_manifest(
        &manifest,
        &Expectations {
            channel: &context.channel,
            current: &context.current,
            target: &context.target,
            now: context.now,
            seen: stored.state.releases.get(&manifest.channel),
        },
    )?;
    let Some(candidate) = candidate else {
        return Ok(None);
    };

    stored
        .state
        .revoked_public_keys
        .extend(context.trust.public_keys_of(&manifest.revoked_key_ids));
    stored
        .state
        .revoked_key_ids
        .extend(manifest.revoked_key_ids);
    stored.state.releases.insert(
        manifest.channel,
        SeenRelease {
            version: candidate.version.to_string(),
            artifact_sha256: candidate.artifact.sha256.clone(),
        },
    );
    context.state.save(&mut stored)?;
    Ok(Some(candidate))
}
