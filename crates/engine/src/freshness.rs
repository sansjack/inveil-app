//! Decides whether a verified snapshot may replace what the client already holds. Pure: the caller loads the stored
//! high-water mark, passes the clock, and persists the mark returned on acceptance (outside the folder an attacker who
//! can swap files could reach, such as the OS keychain). Without this a validly signed but old file could be replayed
//! to undo a policy tightening.
use crate::signing::Verified;
use contract::Snapshot;
use serde::{Deserialize, Serialize};

/// The newest content ever accepted.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct HighWaterMark {
    pub version: u64,
    pub payload_sha256: String,
}

/// What freshness needs to know about a verified file.
#[derive(Clone, Copy, Debug)]
pub struct Candidate<'a> {
    pub version: u64,
    pub expires_at: u64,
    pub payload_sha256: &'a str,
    pub signed_by: &'a [String],
    pub revoked_key_ids: &'a [String],
    pub audience: Option<&'a str>,
}

impl<'a> Candidate<'a> {
    pub fn from_snapshot(verified: &'a Verified<Snapshot>) -> Self {
        Self {
            version: verified.value.version,
            expires_at: verified.value.expires_at,
            payload_sha256: &verified.payload_sha256,
            signed_by: &verified.signed_by,
            revoked_key_ids: &verified.value.revoked_key_ids,
            audience: verified.value.audience.as_deref(),
        }
    }
}

/// What the client has pinned locally, which no payload may override.
#[derive(Clone, Copy, Debug)]
pub struct LocalAnchors<'a> {
    /// The organisation the client is enrolled in, if any.
    pub audience: Option<&'a str>,
    /// Ids of the pinned keys and roots that are not revoked yet.
    pub pinned_key_ids: &'a [String],
    /// Distinct signers a payload needs, whatever the payload itself asks for.
    pub required_signatures: usize,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Rejection {
    #[error("version {offered} is older than the version {held} already accepted")]
    Rollback { offered: u64, held: u64 },
    #[error("version {version} was already accepted with different content")]
    SameVersionDifferentContent { version: u64 },
    #[error("expired at {expires_at}")]
    Expired { expires_at: u64 },
    #[error("meant for audience {offered:?}, this client is enrolled in {expected:?}")]
    WrongAudience {
        offered: Option<String>,
        expected: String,
    },
    #[error(
        "only {valid} signer(s) remain once the keys it revokes are excluded, {required} required"
    )]
    RevocationBelowThreshold { valid: usize, required: usize },
    #[error("it would leave {remaining} pinned key(s), {required} required; re-pin keys locally instead")]
    RevokesTooManyKeys { remaining: usize, required: usize },
}

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Persist this as the new high-water mark, then use the file.
    Accept(HighWaterMark),
    Reject(Rejection),
}

pub fn check(
    candidate: &Candidate,
    mark: Option<&HighWaterMark>,
    anchors: &LocalAnchors,
    now: u64,
) -> Verdict {
    match find_rejection(candidate, mark, anchors, now) {
        Some(rejection) => Verdict::Reject(rejection),
        None => Verdict::Accept(HighWaterMark {
            version: candidate.version,
            payload_sha256: candidate.payload_sha256.to_string(),
        }),
    }
}

/// A payload may revoke keys only if it still meets the full local threshold without them and leaves enough pinned
/// keys behind; otherwise one compromised signer could lock every legitimate key out.
pub fn check_revocations(
    signed_by: &[String],
    revoked_key_ids: &[String],
    anchors: &LocalAnchors,
) -> Result<(), Rejection> {
    if revoked_key_ids.is_empty() {
        return Ok(());
    }
    let required = anchors.required_signatures.max(1);
    let valid = signed_by
        .iter()
        .filter(|key_id| !revoked_key_ids.contains(key_id))
        .count();
    if valid < required {
        return Err(Rejection::RevocationBelowThreshold { valid, required });
    }
    let remaining = anchors
        .pinned_key_ids
        .iter()
        .filter(|key_id| !revoked_key_ids.contains(key_id))
        .count();
    if remaining < required {
        return Err(Rejection::RevokesTooManyKeys {
            remaining,
            required,
        });
    }
    Ok(())
}

fn find_rejection(
    candidate: &Candidate,
    mark: Option<&HighWaterMark>,
    anchors: &LocalAnchors,
    now: u64,
) -> Option<Rejection> {
    if let Err(rejection) =
        check_revocations(candidate.signed_by, candidate.revoked_key_ids, anchors)
    {
        return Some(rejection);
    }
    if now >= candidate.expires_at {
        return Some(Rejection::Expired {
            expires_at: candidate.expires_at,
        });
    }
    if let Some(expected) = anchors
        .audience
        .filter(|expected| candidate.audience != Some(expected))
    {
        return Some(Rejection::WrongAudience {
            offered: candidate.audience.map(String::from),
            expected: expected.to_string(),
        });
    }
    let mark = mark?;
    if candidate.version < mark.version {
        return Some(Rejection::Rollback {
            offered: candidate.version,
            held: mark.version,
        });
    }
    if candidate.version == mark.version && candidate.payload_sha256 != mark.payload_sha256 {
        return Some(Rejection::SameVersionDifferentContent {
            version: candidate.version,
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_000;
    const HASH: &str = "aaaa";

    fn ids(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| name.to_string()).collect()
    }

    fn candidate<'a>(
        signed_by: &'a [String],
        revoked: &'a [String],
        audience: Option<&'a str>,
    ) -> Candidate<'a> {
        Candidate {
            version: 5,
            expires_at: NOW + 10,
            payload_sha256: HASH,
            signed_by,
            revoked_key_ids: revoked,
            audience,
        }
    }

    fn anchors<'a>(
        audience: Option<&'a str>,
        pinned: &'a [String],
        required: usize,
    ) -> LocalAnchors<'a> {
        LocalAnchors {
            audience,
            pinned_key_ids: pinned,
            required_signatures: required,
        }
    }

    fn mark(version: u64, hash: &str) -> HighWaterMark {
        HighWaterMark {
            version,
            payload_sha256: hash.into(),
        }
    }

    fn verdict(mark: Option<&HighWaterMark>, audience: Option<&str>, now: u64) -> Verdict {
        let signers = ids(&["k1"]);
        let pinned = ids(&["k1"]);
        check(
            &candidate(&signers, &[], None),
            mark,
            &anchors(audience, &pinned, 1),
            now,
        )
    }

    #[test]
    fn the_first_file_is_accepted_and_becomes_the_mark() {
        assert_eq!(verdict(None, None, NOW), Verdict::Accept(mark(5, HASH)));
    }

    #[test]
    fn newer_versions_and_identical_repeats_are_accepted() {
        assert_eq!(
            verdict(Some(&mark(4, "bbbb")), None, NOW),
            Verdict::Accept(mark(5, HASH))
        );
        assert_eq!(
            verdict(Some(&mark(5, HASH)), None, NOW),
            Verdict::Accept(mark(5, HASH))
        );
    }

    #[test]
    fn an_older_version_is_a_rollback() {
        assert_eq!(
            verdict(Some(&mark(6, "bbbb")), None, NOW),
            Verdict::Reject(Rejection::Rollback {
                offered: 5,
                held: 6
            })
        );
    }

    #[test]
    fn the_same_version_with_other_content_is_rejected() {
        assert_eq!(
            verdict(Some(&mark(5, "bbbb")), None, NOW),
            Verdict::Reject(Rejection::SameVersionDifferentContent { version: 5 })
        );
    }

    #[test]
    fn an_expired_file_is_rejected_at_and_after_its_expiry() {
        let expected = Verdict::Reject(Rejection::Expired {
            expires_at: NOW + 10,
        });
        assert_eq!(verdict(None, None, NOW + 10), expected);
        assert_eq!(verdict(None, None, NOW + 11), expected);
        assert!(matches!(verdict(None, None, NOW + 9), Verdict::Accept(_)));
    }

    #[test]
    fn the_audience_must_match_when_the_client_is_enrolled() {
        let signers = ids(&["k1"]);
        let pinned = ids(&["k1"]);
        let enrolled = anchors(Some("acme"), &pinned, 1);
        let accepted = check(
            &candidate(&signers, &[], Some("acme")),
            None,
            &enrolled,
            NOW,
        );
        assert!(matches!(accepted, Verdict::Accept(_)));

        let other = check(
            &candidate(&signers, &[], Some("other")),
            None,
            &enrolled,
            NOW,
        );
        assert_eq!(
            other,
            Verdict::Reject(Rejection::WrongAudience {
                offered: Some("other".into()),
                expected: "acme".into()
            })
        );
        let none = check(&candidate(&signers, &[], None), None, &enrolled, NOW);
        assert!(matches!(
            none,
            Verdict::Reject(Rejection::WrongAudience { offered: None, .. })
        ));

        let standalone = anchors(None, &pinned, 1);
        let unenrolled = check(
            &candidate(&signers, &[], Some("other")),
            None,
            &standalone,
            NOW,
        );
        assert!(matches!(unenrolled, Verdict::Accept(_)));
        let neither = check(&candidate(&signers, &[], None), None, &standalone, NOW);
        assert!(matches!(neither, Verdict::Accept(_)));
    }

    #[test]
    fn revocations_are_honoured_only_when_the_threshold_holds_without_the_revoked_keys() {
        let pinned = ids(&["k1", "k2", "k3"]);
        let both = ids(&["k1", "k2"]);
        let revoked = ids(&["k2"]);

        let threshold_one = anchors(None, &pinned, 1);
        assert!(check_revocations(&both, &revoked, &threshold_one).is_ok());

        let threshold_two = anchors(None, &pinned, 2);
        assert_eq!(
            check_revocations(&both, &revoked, &threshold_two),
            Err(Rejection::RevocationBelowThreshold {
                valid: 1,
                required: 2
            })
        );
        assert!(matches!(
            check(&candidate(&both, &revoked, None), None, &threshold_two, NOW),
            Verdict::Reject(Rejection::RevocationBelowThreshold { .. })
        ));
    }

    #[test]
    fn a_key_cannot_revoke_itself_when_it_is_the_only_signer() {
        let pinned = ids(&["k1", "k2"]);
        let signer = ids(&["k1"]);
        assert_eq!(
            check_revocations(&signer, &signer, &anchors(None, &pinned, 1)),
            Err(Rejection::RevocationBelowThreshold {
                valid: 0,
                required: 1
            })
        );
    }

    #[test]
    fn a_payload_cannot_revoke_every_pinned_key() {
        let pinned = ids(&["k1", "k2"]);
        let signers = ids(&["k1", "delegated"]);
        let revoked = ids(&["k1", "k2"]);
        assert_eq!(
            check_revocations(&signers, &revoked, &anchors(None, &pinned, 1)),
            Err(Rejection::RevokesTooManyKeys {
                remaining: 0,
                required: 1
            })
        );
    }

    #[test]
    fn a_payload_that_revokes_nothing_needs_no_revocation_checks() {
        assert!(check_revocations(&[], &[], &anchors(None, &[], 2)).is_ok());
    }

    #[test]
    fn revocation_is_checked_before_anything_else() {
        let signers = ids(&["k1"]);
        let revoked = ids(&["k1"]);
        let pinned = ids(&["k1", "k2"]);
        let expired = check(
            &candidate(&signers, &revoked, None),
            Some(&mark(9, "x")),
            &anchors(None, &pinned, 1),
            NOW + 99,
        );
        assert!(matches!(
            expired,
            Verdict::Reject(Rejection::RevocationBelowThreshold { .. })
        ));
    }

    #[test]
    fn a_verified_snapshot_becomes_a_candidate() {
        let snapshot = Verified {
            value: crate::test_support::example_snapshot(),
            payload_sha256: HASH.into(),
            signed_by: vec!["policy".into()],
            delegation_audience: None,
        };
        let candidate = Candidate::from_snapshot(&snapshot);
        assert_eq!(candidate.version, 1);
        assert_eq!(candidate.audience, None);
    }
}
