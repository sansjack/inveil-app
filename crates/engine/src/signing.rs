//! Ed25519 signatures with a separate domain per role, so a signature made for one purpose never verifies for another.
//! Everything is checked against the exact payload bytes *before* the payload is parsed.
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use contract::{Delegation, SignatureEntry, SignedEnvelope};
use ring::digest;
use ring::signature::{self, Ed25519KeyPair, KeyPair};
use serde::de::DeserializeOwned;
use std::collections::BTreeSet;

const PUBLIC_KEY_LEN: usize = 32;
pub type PublicKeyBytes = [u8; PUBLIC_KEY_LEN];
/// Signatures beyond this many in one envelope are never looked at, so an attacker cannot make verification costly.
const MAX_SIGNATURES: usize = 16;
const AUDIENCE_ABSENT: u8 = 0;
const AUDIENCE_PRESENT: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Policy,
    Update,
    Delegation,
}

impl Role {
    fn domain(self) -> &'static [u8] {
        match self {
            Role::Policy => b"inveil-policy-v1\0",
            Role::Update => b"inveil-update-v1\0",
            Role::Delegation => b"inveil-delegation-v2\0",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinnedKey {
    pub key_id: String,
    pub public_key: PublicKeyBytes,
}

impl PinnedKey {
    pub fn from_base64(key_id: &str, public_key: &str) -> Result<Self, VerifyError> {
        let bytes = STANDARD
            .decode(public_key)
            .map_err(|_| VerifyError::BadKey(key_id.to_string()))?;
        let public_key = bytes
            .try_into()
            .map_err(|_| VerifyError::BadKey(key_id.to_string()))?;
        Ok(Self {
            key_id: key_id.to_string(),
            public_key,
        })
    }
}

/// Keys the client trusts. `roots` may only certify delegated signing keys; they never sign payloads directly. The
/// revoked sets also bar a delegated key, which is not pinned and so cannot be removed from `keys`.
#[derive(Clone, Debug, Default)]
pub struct Trust {
    pub keys: Vec<PinnedKey>,
    pub roots: Vec<PinnedKey>,
    pub revoked_key_ids: BTreeSet<String>,
    pub revoked_public_keys: BTreeSet<PublicKeyBytes>,
}

impl Trust {
    /// The same trust with every key and root removed whose id is in `key_ids` or whose public key is in
    /// `public_keys`, and with both sets applied to delegated keys as well.
    pub fn without_revoked(
        &self,
        key_ids: &BTreeSet<String>,
        public_keys: &BTreeSet<PublicKeyBytes>,
    ) -> Self {
        let keep = |keys: &[PinnedKey]| {
            keys.iter()
                .filter(|key| {
                    !key_ids.contains(&key.key_id) && !public_keys.contains(&key.public_key)
                })
                .cloned()
                .collect()
        };
        Self {
            keys: keep(&self.keys),
            roots: keep(&self.roots),
            revoked_key_ids: self.revoked_key_ids.union(key_ids).cloned().collect(),
            revoked_public_keys: self
                .revoked_public_keys
                .union(public_keys)
                .copied()
                .collect(),
        }
    }

    /// The public keys of the pinned keys and roots named in `key_ids`, so a revocation by id can be remembered by key
    /// too and survive the key being pinned again under another id.
    pub fn public_keys_of(&self, key_ids: &[String]) -> BTreeSet<PublicKeyBytes> {
        self.keys
            .iter()
            .chain(&self.roots)
            .filter(|key| key_ids.contains(&key.key_id))
            .map(|key| key.public_key)
            .collect()
    }
}

#[derive(Debug)]
pub struct Verified<T> {
    pub value: T,
    pub payload_sha256: String,
    pub signed_by: Vec<String>,
    /// Set when a delegated key signed and its certificate limits it to one audience; the payload must match it.
    pub delegation_audience: Option<String>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerifyError {
    #[error("the envelope is not in the expected format: {0}")]
    Envelope(String),
    #[error("only {valid} valid signature(s) from distinct trusted keys, {required} required")]
    NotEnoughSignatures { valid: usize, required: usize },
    #[error("the signed payload is not in the expected format: {0}")]
    Payload(String),
    #[error("invalid public key for {0}")]
    BadKey(String),
}

#[derive(Debug, thiserror::Error)]
pub enum SignError {
    #[error("the signing key is not a valid PKCS#8 Ed25519 key")]
    BadKey,
}

fn signed_bytes(role: Role, payload: &[u8]) -> Vec<u8> {
    [role.domain(), payload].concat()
}

struct TrustedDelegation {
    key: PinnedKey,
    audience: Option<String>,
}

fn is_valid(role: Role, public_key: &[u8], payload: &[u8], signature_b64: &str) -> bool {
    let Ok(signature_bytes) = STANDARD.decode(signature_b64) else {
        return false;
    };
    signature::UnparsedPublicKey::new(&signature::ED25519, public_key)
        .verify(&signed_bytes(role, payload), &signature_bytes)
        .is_ok()
}

fn push_field(bytes: &mut Vec<u8>, field: &[u8]) {
    bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
    bytes.extend_from_slice(field);
}

/// The bytes a root signs: every variable-length field is length-prefixed and the audience carries a presence byte,
/// so no two different delegations share an encoding (an absent audience differs from an empty one).
pub fn delegation_bytes(delegation: &Delegation) -> Vec<u8> {
    let mut bytes = Vec::new();
    push_field(&mut bytes, delegation.key_id.as_bytes());
    push_field(&mut bytes, delegation.public_key.as_bytes());
    bytes.extend_from_slice(&delegation.not_before.to_be_bytes());
    bytes.extend_from_slice(&delegation.not_after.to_be_bytes());
    match &delegation.audience {
        None => bytes.push(AUDIENCE_ABSENT),
        Some(audience) => {
            bytes.push(AUDIENCE_PRESENT);
            push_field(&mut bytes, audience.as_bytes());
        }
    }
    push_field(&mut bytes, delegation.root_key_id.as_bytes());
    bytes
}

/// The moment a delegation certificate's validity window is judged at.
#[derive(Clone, Copy)]
enum DelegationWindow {
    At(u64),
    /// Every other check applies; used only to read the payload's own issue time (see [`verify_envelope_as_issued`]).
    Unchecked,
}

impl DelegationWindow {
    fn contains(self, delegation: &Delegation) -> bool {
        match self {
            DelegationWindow::At(moment) => {
                (delegation.not_before..=delegation.not_after).contains(&moment)
            }
            DelegationWindow::Unchecked => true,
        }
    }
}

/// The delegated key, if a pinned root vouches for it, the window holds and neither its id nor its key is revoked.
fn trusted_delegation(
    trust: &Trust,
    delegation: &Delegation,
    window: DelegationWindow,
) -> Option<TrustedDelegation> {
    if !window.contains(delegation) || trust.revoked_key_ids.contains(&delegation.key_id) {
        return None;
    }
    let root = trust
        .roots
        .iter()
        .find(|root| root.key_id == delegation.root_key_id)?;
    let certified = is_valid(
        Role::Delegation,
        &root.public_key,
        &delegation_bytes(delegation),
        &delegation.signature,
    );
    if !certified {
        return None;
    }
    let key = PinnedKey::from_base64(&delegation.key_id, &delegation.public_key).ok()?;
    if trust.revoked_public_keys.contains(&key.public_key) {
        return None;
    }
    Some(TrustedDelegation {
        key,
        audience: delegation.audience.clone(),
    })
}

/// Lower-case hex, for digests computed incrementally (large downloads) as well as [`sha256_hex`].
pub fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex_lower(digest::digest(&digest::SHA256, bytes).as_ref())
}

/// Verifies at least `threshold` signatures from distinct trusted keys, then parses the payload. Two pins for the
/// same public key count once, and only the first `MAX_SIGNATURES` entries are examined.
pub fn verify_envelope<T: DeserializeOwned>(
    role: Role,
    trust: &Trust,
    threshold: usize,
    now: u64,
    envelope: &str,
) -> Result<Verified<T>, VerifyError> {
    verify_in_window(role, trust, threshold, DelegationWindow::At(now), envelope)
}

/// Like [`verify_envelope`], but a delegation certificate's validity window is judged at the moment the payload says it
/// was issued (`issued_at`) instead of now. For re-reading a payload that was accepted earlier, such as a cached
/// snapshot, which must stay loadable after the delegated key that signed it has expired. The caller must make sure the
/// payload is one it accepted before: an expired key could otherwise sign anything dated inside its old window.
pub fn verify_envelope_as_issued<T: DeserializeOwned>(
    role: Role,
    trust: &Trust,
    threshold: usize,
    envelope: &str,
    issued_at: impl Fn(&T) -> u64,
) -> Result<Verified<T>, VerifyError> {
    let unchecked: Verified<T> = verify_in_window(
        role,
        trust,
        threshold,
        DelegationWindow::Unchecked,
        envelope,
    )?;
    let window = DelegationWindow::At(issued_at(&unchecked.value));
    verify_in_window(role, trust, threshold, window, envelope)
}

fn verify_in_window<T: DeserializeOwned>(
    role: Role,
    trust: &Trust,
    threshold: usize,
    window: DelegationWindow,
    envelope: &str,
) -> Result<Verified<T>, VerifyError> {
    let envelope: SignedEnvelope =
        serde_json::from_str(envelope).map_err(|error| VerifyError::Envelope(error.to_string()))?;
    let payload = envelope.payload.as_bytes();

    let delegated = envelope
        .delegation
        .as_ref()
        .and_then(|delegation| trusted_delegation(trust, delegation, window));
    let candidates = trust
        .keys
        .iter()
        .chain(delegated.iter().map(|delegated| &delegated.key))
        .filter(|key| !trust.revoked_public_keys.contains(&key.public_key));

    let mut signed_by: Vec<String> = vec![];
    let mut signing_keys: Vec<PublicKeyBytes> = vec![];
    for entry in envelope.signatures.iter().take(MAX_SIGNATURES) {
        let Some(key) = candidates.clone().find(|key| key.key_id == entry.key_id) else {
            continue;
        };
        if signing_keys.contains(&key.public_key)
            || !is_valid(role, &key.public_key, payload, &entry.signature)
        {
            continue;
        }
        signing_keys.push(key.public_key);
        signed_by.push(key.key_id.clone());
    }
    if signed_by.is_empty() || signed_by.len() < threshold {
        return Err(VerifyError::NotEnoughSignatures {
            valid: signed_by.len(),
            required: threshold.max(1),
        });
    }

    let delegation_audience = delegated
        .filter(|delegated| {
            let pinned_directly = trust
                .keys
                .iter()
                .any(|key| key.public_key == delegated.key.public_key);
            signing_keys.contains(&delegated.key.public_key) && !pinned_directly
        })
        .and_then(|delegated| delegated.audience);
    let value = serde_json::from_str(&envelope.payload)
        .map_err(|error| VerifyError::Payload(error.to_string()))?;
    Ok(Verified {
        value,
        payload_sha256: sha256_hex(payload),
        signed_by,
        delegation_audience,
    })
}

/// Signs `payload` for `role` with a PKCS#8 Ed25519 private key.
pub fn sign_payload(
    role: Role,
    key_id: &str,
    pkcs8: &[u8],
    payload: &str,
) -> Result<SignatureEntry, SignError> {
    sign_bytes(role, key_id, pkcs8, payload.as_bytes())
}

/// Signs a delegation certificate with the root's PKCS#8 key; the result goes in [`Delegation::signature`].
pub fn sign_delegation(
    root_key_id: &str,
    pkcs8: &[u8],
    delegation: &Delegation,
) -> Result<SignatureEntry, SignError> {
    sign_bytes(
        Role::Delegation,
        root_key_id,
        pkcs8,
        &delegation_bytes(delegation),
    )
}

fn sign_bytes(
    role: Role,
    key_id: &str,
    pkcs8: &[u8],
    payload: &[u8],
) -> Result<SignatureEntry, SignError> {
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8).map_err(|_| SignError::BadKey)?;
    let signature = STANDARD.encode(pair.sign(&signed_bytes(role, payload)).as_ref());
    Ok(SignatureEntry {
        key_id: key_id.to_string(),
        signature,
    })
}

/// Public half of a PKCS#8 key, for pinning.
pub fn public_key_of(pkcs8: &[u8]) -> Result<PublicKeyBytes, SignError> {
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8).map_err(|_| SignError::BadKey)?;
    pair.public_key()
        .as_ref()
        .try_into()
        .map_err(|_| SignError::BadKey)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;

    const NOW: u64 = 100;

    fn new_key(key_id: &str) -> (Vec<u8>, PinnedKey) {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .unwrap()
            .as_ref()
            .to_vec();
        let public_key = public_key_of(&pkcs8).unwrap();
        (
            pkcs8,
            PinnedKey {
                key_id: key_id.into(),
                public_key,
            },
        )
    }

    fn envelope(payload: &str, signatures: Vec<SignatureEntry>) -> String {
        serde_json::to_string(&SignedEnvelope {
            payload: payload.into(),
            signatures,
            delegation: None,
        })
        .unwrap()
    }

    fn trust(keys: &[&PinnedKey]) -> Trust {
        Trust {
            keys: keys.iter().map(|key| (*key).clone()).collect(),
            roots: vec![],
            ..Trust::default()
        }
    }

    #[test]
    fn accepts_a_payload_signed_by_a_pinned_key() {
        let (private, public) = new_key("a");
        let signed = envelope(
            "{\"n\":1}",
            vec![sign_payload(Role::Policy, "a", &private, "{\"n\":1}").unwrap()],
        );
        let verified: Verified<serde_json::Value> =
            verify_envelope(Role::Policy, &trust(&[&public]), 1, NOW, &signed).unwrap();
        assert_eq!(verified.value["n"], 1);
        assert_eq!(verified.signed_by, ["a"]);
    }

    #[test]
    fn a_signature_for_one_role_is_rejected_for_another() {
        let (private, public) = new_key("a");
        let signed = envelope(
            "{}",
            vec![sign_payload(Role::Update, "a", &private, "{}").unwrap()],
        );
        assert!(verify_envelope::<serde_json::Value>(
            Role::Policy,
            &trust(&[&public]),
            1,
            NOW,
            &signed
        )
        .is_err());
    }

    #[test]
    fn any_change_to_the_payload_is_rejected() {
        let (private, public) = new_key("a");
        let signature = sign_payload(Role::Policy, "a", &private, "{\"n\":1}").unwrap();
        let signed = envelope("{\"n\":2}", vec![signature]);
        assert!(verify_envelope::<serde_json::Value>(
            Role::Policy,
            &trust(&[&public]),
            1,
            NOW,
            &signed
        )
        .is_err());
    }

    #[test]
    fn threshold_needs_distinct_keys_and_ignores_repeats() {
        let (private_a, public_a) = new_key("a");
        let (private_b, public_b) = new_key("b");
        let sign =
            |private: &[u8], id: &str| sign_payload(Role::Update, id, private, "{}").unwrap();
        let repeated = envelope("{}", vec![sign(&private_a, "a"), sign(&private_a, "a")]);
        let pinned = trust(&[&public_a, &public_b]);
        assert!(
            verify_envelope::<serde_json::Value>(Role::Update, &pinned, 2, NOW, &repeated).is_err()
        );
        let both = envelope("{}", vec![sign(&private_a, "a"), sign(&private_b, "b")]);
        assert!(verify_envelope::<serde_json::Value>(Role::Update, &pinned, 2, NOW, &both).is_ok());
    }

    #[test]
    fn unknown_keys_never_count() {
        let (private, _) = new_key("a");
        let (_, other) = new_key("b");
        let signed = envelope(
            "{}",
            vec![sign_payload(Role::Policy, "a", &private, "{}").unwrap()],
        );
        assert!(verify_envelope::<serde_json::Value>(
            Role::Policy,
            &trust(&[&other]),
            1,
            NOW,
            &signed
        )
        .is_err());
    }

    fn delegation_for(
        policy: &PinnedKey,
        audience: Option<&str>,
        root_private: &[u8],
    ) -> Delegation {
        let mut delegation = Delegation {
            key_id: "policy-1".into(),
            public_key: STANDARD.encode(policy.public_key),
            not_before: 50,
            not_after: 150,
            audience: audience.map(String::from),
            root_key_id: "root".into(),
            signature: String::new(),
        };
        delegation.signature = sign_delegation("root", root_private, &delegation)
            .unwrap()
            .signature;
        delegation
    }

    fn delegated_envelope(policy_private: &[u8], delegation: Delegation) -> String {
        let signature = sign_payload(Role::Policy, "policy-1", policy_private, "{}").unwrap();
        serde_json::to_string(&SignedEnvelope {
            payload: "{}".into(),
            signatures: vec![signature],
            delegation: Some(delegation),
        })
        .unwrap()
    }

    #[test]
    fn delegated_keys_work_only_inside_their_window() {
        let (root_private, root) = new_key("root");
        let (policy_private, policy) = new_key("policy-1");
        let signed = delegated_envelope(
            &policy_private,
            delegation_for(&policy, None, &root_private),
        );
        let pinned = Trust {
            keys: vec![],
            roots: vec![root],
            ..Trust::default()
        };
        assert!(
            verify_envelope::<serde_json::Value>(Role::Policy, &pinned, 1, NOW, &signed).is_ok()
        );
        assert!(
            verify_envelope::<serde_json::Value>(Role::Policy, &pinned, 1, 151, &signed).is_err()
        );
    }

    #[test]
    fn a_delegation_limited_to_an_audience_reports_it() {
        let (root_private, root) = new_key("root");
        let (policy_private, policy) = new_key("policy-1");
        let pinned = Trust {
            keys: vec![],
            roots: vec![root],
            ..Trust::default()
        };
        let limited = delegated_envelope(
            &policy_private,
            delegation_for(&policy, Some("acme"), &root_private),
        );
        let verified: Verified<serde_json::Value> =
            verify_envelope(Role::Policy, &pinned, 1, NOW, &limited).unwrap();
        assert_eq!(verified.delegation_audience.as_deref(), Some("acme"));

        let unlimited = delegated_envelope(
            &policy_private,
            delegation_for(&policy, None, &root_private),
        );
        let verified: Verified<serde_json::Value> =
            verify_envelope(Role::Policy, &pinned, 1, NOW, &unlimited).unwrap();
        assert_eq!(verified.delegation_audience, None);
    }

    #[test]
    fn a_tampered_delegation_audience_invalidates_the_certificate() {
        let (root_private, root) = new_key("root");
        let (policy_private, policy) = new_key("policy-1");
        let mut delegation = delegation_for(&policy, Some("acme"), &root_private);
        delegation.audience = Some("other".into());
        let signed = delegated_envelope(&policy_private, delegation);
        let pinned = Trust {
            keys: vec![],
            roots: vec![root],
            ..Trust::default()
        };
        assert!(
            verify_envelope::<serde_json::Value>(Role::Policy, &pinned, 1, NOW, &signed).is_err()
        );
    }

    fn issued_envelope(policy_private: &[u8], delegation: Delegation, issued_at: u64) -> String {
        let payload = format!("{{\"issued_at\":{issued_at}}}");
        let signature = sign_payload(Role::Policy, "policy-1", policy_private, &payload).unwrap();
        serde_json::to_string(&SignedEnvelope {
            payload,
            signatures: vec![signature],
            delegation: Some(delegation),
        })
        .unwrap()
    }

    fn issued_at(value: &serde_json::Value) -> u64 {
        value["issued_at"].as_u64().unwrap_or_default()
    }

    fn delegating_root() -> (Vec<u8>, PinnedKey, Trust) {
        let (root_private, root) = new_key("root");
        let trust = Trust {
            roots: vec![root.clone()],
            ..Trust::default()
        };
        (root_private, root, trust)
    }

    #[test]
    fn a_payload_issued_inside_the_delegation_window_stays_verifiable_after_it_lapses() {
        let (root_private, _, pinned) = delegating_root();
        let (policy_private, policy) = new_key("policy-1");
        let delegation = delegation_for(&policy, None, &root_private);
        let signed = issued_envelope(&policy_private, delegation, 100);
        let lapsed = 10_000;

        assert!(
            verify_envelope::<serde_json::Value>(Role::Policy, &pinned, 1, lapsed, &signed)
                .is_err()
        );
        assert!(verify_envelope_as_issued::<serde_json::Value>(
            Role::Policy,
            &pinned,
            1,
            &signed,
            issued_at
        )
        .is_ok());
    }

    #[test]
    fn a_payload_issued_outside_the_delegation_window_is_refused_even_when_read_as_issued() {
        let (root_private, _, pinned) = delegating_root();
        let (policy_private, policy) = new_key("policy-1");
        for outside in [49, 151] {
            let delegation = delegation_for(&policy, None, &root_private);
            let signed = issued_envelope(&policy_private, delegation, outside);
            assert!(verify_envelope_as_issued::<serde_json::Value>(
                Role::Policy,
                &pinned,
                1,
                &signed,
                issued_at
            )
            .is_err());
        }
    }

    #[test]
    fn a_revoked_delegated_key_id_is_refused() {
        let (root_private, _, pinned) = delegating_root();
        let (policy_private, policy) = new_key("policy-1");
        let signed = delegated_envelope(
            &policy_private,
            delegation_for(&policy, None, &root_private),
        );
        let revoked =
            pinned.without_revoked(&BTreeSet::from(["policy-1".to_string()]), &BTreeSet::new());

        assert!(
            verify_envelope::<serde_json::Value>(Role::Policy, &pinned, 1, NOW, &signed).is_ok()
        );
        assert!(
            verify_envelope::<serde_json::Value>(Role::Policy, &revoked, 1, NOW, &signed).is_err()
        );
    }

    #[test]
    fn a_revoked_delegated_public_key_is_refused_under_any_id() {
        let (root_private, _, pinned) = delegating_root();
        let (policy_private, policy) = new_key("policy-1");
        let signed = delegated_envelope(
            &policy_private,
            delegation_for(&policy, None, &root_private),
        );
        let revoked =
            pinned.without_revoked(&BTreeSet::new(), &BTreeSet::from([policy.public_key]));

        assert!(
            verify_envelope::<serde_json::Value>(Role::Policy, &revoked, 1, NOW, &signed).is_err()
        );
    }

    #[test]
    fn a_pinned_key_revoked_by_id_is_remembered_by_its_public_key() {
        let (private, key) = new_key("a");
        let signed = envelope(
            "{}",
            vec![sign_payload(Role::Policy, "a", &private, "{}").unwrap()],
        );
        let pinned = trust(&[&key]);
        let remembered = pinned.public_keys_of(&["a".to_string()]);
        let repinned = trust(&[&PinnedKey {
            key_id: "renamed".into(),
            public_key: key.public_key,
        }])
        .without_revoked(&BTreeSet::new(), &remembered);

        assert_eq!(remembered, BTreeSet::from([key.public_key]));
        assert!(repinned.keys.is_empty());
        assert!(
            verify_envelope::<serde_json::Value>(Role::Policy, &repinned, 1, NOW, &signed).is_err()
        );
    }

    #[test]
    fn delegation_encoding_tells_a_missing_audience_from_an_empty_one() {
        let (root_private, _) = new_key("root");
        let (_, policy) = new_key("policy-1");
        let absent = delegation_for(&policy, None, &root_private);
        let empty = delegation_for(&policy, Some(""), &root_private);
        assert_ne!(delegation_bytes(&absent), delegation_bytes(&empty));
        assert_ne!(absent.signature, empty.signature);
    }

    #[test]
    fn delegation_encoding_does_not_depend_on_where_a_field_ends() {
        let (root_private, _) = new_key("root");
        let (_, policy) = new_key("policy-1");
        let mut first = delegation_for(&policy, Some("ab"), &root_private);
        let mut second = first.clone();
        first.key_id = "x".into();
        first.root_key_id = "yz".into();
        second.key_id = "xy".into();
        second.root_key_id = "z".into();
        assert_ne!(delegation_bytes(&first), delegation_bytes(&second));
    }

    #[test]
    fn a_delegation_certified_under_the_old_domain_is_rejected() {
        let (root_private, root) = new_key("root");
        let (policy_private, policy) = new_key("policy-1");
        let mut delegation = delegation_for(&policy, None, &root_private);
        let pair = Ed25519KeyPair::from_pkcs8(&root_private).unwrap();
        let legacy = [
            b"inveil-delegation-v1\0".as_slice(),
            &delegation_bytes(&delegation),
        ]
        .concat();
        delegation.signature = STANDARD.encode(pair.sign(&legacy).as_ref());
        let signed = delegated_envelope(&policy_private, delegation);
        let pinned = Trust {
            keys: vec![],
            roots: vec![root],
            ..Trust::default()
        };
        assert!(
            verify_envelope::<serde_json::Value>(Role::Policy, &pinned, 1, NOW, &signed).is_err()
        );
    }

    #[test]
    fn two_pins_for_the_same_public_key_count_once() {
        let (private, first) = new_key("first");
        let second = PinnedKey {
            key_id: "second".into(),
            public_key: first.public_key,
        };
        let signed = envelope(
            "{}",
            vec![
                sign_payload(Role::Update, "first", &private, "{}").unwrap(),
                sign_payload(Role::Update, "second", &private, "{}").unwrap(),
            ],
        );
        let pinned = trust(&[&first, &second]);
        let error = verify_envelope::<serde_json::Value>(Role::Update, &pinned, 2, NOW, &signed)
            .unwrap_err();
        assert_eq!(
            error,
            VerifyError::NotEnoughSignatures {
                valid: 1,
                required: 2
            }
        );
    }

    #[test]
    fn signatures_past_the_cap_are_never_examined() {
        let (private, public) = new_key("late");
        let (filler_private, filler) = new_key("filler");
        let mut signatures: Vec<SignatureEntry> = (0..MAX_SIGNATURES)
            .map(|_| sign_payload(Role::Policy, "filler", &filler_private, "{}").unwrap())
            .collect();
        signatures.push(sign_payload(Role::Policy, "late", &private, "{}").unwrap());
        let signed = envelope("{}", signatures);
        let pinned = trust(&[&filler, &public]);
        let error = verify_envelope::<serde_json::Value>(Role::Policy, &pinned, 2, NOW, &signed)
            .unwrap_err();
        assert_eq!(
            error,
            VerifyError::NotEnoughSignatures {
                valid: 1,
                required: 2
            }
        );
    }

    #[test]
    fn revoked_ids_are_removed_from_keys_and_roots() {
        let (_, key) = new_key("a");
        let (_, root) = new_key("r");
        let pinned = Trust {
            keys: vec![key],
            roots: vec![root],
            ..Trust::default()
        };
        let remaining = pinned.without_revoked(
            &BTreeSet::from(["a".to_string(), "r".to_string()]),
            &BTreeSet::new(),
        );
        assert!(remaining.keys.is_empty() && remaining.roots.is_empty());
    }

    fn flip_bit(bytes: &mut [u8], bit: usize) {
        bytes[bit / 8] ^= 1 << (bit % 8);
    }

    #[test]
    fn flipping_any_single_bit_of_the_payload_is_rejected() {
        let payload = "{\"schema\":1,\"version\":7}";
        let (private, public) = new_key("a");
        let signature = sign_payload(Role::Policy, "a", &private, payload).unwrap();
        let pinned = trust(&[&public]);
        for bit in 0..payload.len() * 8 {
            if bit % 8 == 7 {
                continue;
            }
            let mut tampered = payload.as_bytes().to_vec();
            flip_bit(&mut tampered, bit);
            let tampered = String::from_utf8(tampered).unwrap();
            let signed = envelope(&tampered, vec![signature.clone()]);
            assert!(
                verify_envelope::<serde_json::Value>(Role::Policy, &pinned, 1, NOW, &signed)
                    .is_err(),
                "bit {bit} was accepted"
            );
        }
    }

    #[test]
    fn flipping_any_single_bit_of_the_signature_is_rejected() {
        let payload = "{\"schema\":1}";
        let (private, public) = new_key("a");
        let signature = sign_payload(Role::Policy, "a", &private, payload).unwrap();
        let mut raw = STANDARD.decode(&signature.signature).unwrap();
        let pinned = trust(&[&public]);
        for bit in 0..raw.len() * 8 {
            flip_bit(&mut raw, bit);
            let tampered = SignatureEntry {
                key_id: "a".into(),
                signature: STANDARD.encode(&raw),
            };
            let signed = envelope(payload, vec![tampered]);
            assert!(
                verify_envelope::<serde_json::Value>(Role::Policy, &pinned, 1, NOW, &signed)
                    .is_err(),
                "bit {bit} was accepted"
            );
            flip_bit(&mut raw, bit);
        }
    }
}
