//! Signed test vectors in `contract/v1/vectors`, for backends in any language to check their signer against.
//! Run with `UPDATE_VECTORS=1 cargo test -p engine --test vectors` to rewrite them after changing the contract.
//! The keys are derived from fixed seeds that are public in this file: never use them for anything real.
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use contract::{SignedEnvelope, Snapshot, UpdateManifest};
use engine::{sign_payload, validate, verify_envelope, PinnedKey, Role, Trust, VerifyError};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::path::PathBuf;

type TestResult = Result<(), Box<dyn Error>>;

const NOW: u64 = 1_700_000_100;
const ISSUED_AT: u64 = 1_700_000_000;
const EXPIRES_AT: u64 = 1_700_086_400;
const HIGH_WATER_VERSION: u64 = 7;
const PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x53, 0x02, 0x01, 0x01, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];
const PKCS8_PUBLIC_KEY_PREFIX: [u8; 5] = [0xa1, 0x23, 0x03, 0x21, 0x00];

const DOMAINS: [(&str, &str); 3] = [
    ("policy", "inveil-policy-v1\\0"),
    ("update", "inveil-update-v1\\0"),
    ("delegation", "inveil-delegation-v2\\0"),
];

struct TestKey {
    key_id: &'static str,
    role: &'static str,
    seed: u8,
}

const KEYS: [TestKey; 5] = [
    TestKey {
        key_id: "policy-1",
        role: "policy",
        seed: 1,
    },
    TestKey {
        key_id: "policy-2",
        role: "policy",
        seed: 2,
    },
    TestKey {
        key_id: "update-1",
        role: "update",
        seed: 3,
    },
    TestKey {
        key_id: "update-2",
        role: "update",
        seed: 4,
    },
    TestKey {
        key_id: "attacker-1",
        role: "untrusted",
        seed: 5,
    },
];

#[derive(Serialize, Deserialize)]
struct VectorManifest {
    format: u8,
    description: String,
    /// The time every vector is evaluated at, in Unix seconds.
    now: u64,
    /// Highest snapshot version a client has accepted before; a lower one is a rollback.
    high_water_version: u64,
    /// Domain prefixes as text; each ends with a NUL byte, written `\0` here.
    domains: std::collections::BTreeMap<String, String>,
    keys: Vec<ManifestKey>,
    vectors: Vec<VectorEntry>,
}

#[derive(Serialize, Deserialize)]
struct ManifestKey {
    key_id: String,
    role: String,
    /// Base64 Ed25519 public key.
    public_key: String,
}

#[derive(Serialize, Deserialize)]
struct VectorEntry {
    file: String,
    description: String,
    /// `policy` or `update`: the signing domain the envelope is verified under.
    role: String,
    /// Signatures from distinct trusted keys that the verifier must require.
    threshold: usize,
    /// Key ids the verifier pins for this vector.
    trusted_key_ids: Vec<String>,
    /// Whether signature verification succeeds.
    signature: String,
    /// What a client does with the verified payload: `accept`, `reject_expired` or `reject_rollback`.
    client_outcome: String,
}

struct Vector {
    entry: VectorEntry,
    envelope: SignedEnvelope,
}

fn pkcs8_for(seed: u8) -> Result<Vec<u8>, Box<dyn Error>> {
    let pair = Ed25519KeyPair::from_seed_unchecked(&[seed; 32])
        .map_err(|_| "cannot derive the test key")?;
    Ok([
        &PKCS8_PREFIX[..],
        &[seed; 32],
        &PKCS8_PUBLIC_KEY_PREFIX,
        pair.public_key().as_ref(),
    ]
    .concat())
}

fn key(key_id: &str) -> Result<&'static TestKey, Box<dyn Error>> {
    KEYS.iter()
        .find(|candidate| candidate.key_id == key_id)
        .ok_or_else(|| format!("unknown test key {key_id}").into())
}

fn public_key_base64(key_id: &str) -> Result<String, Box<dyn Error>> {
    let pair = Ed25519KeyPair::from_seed_unchecked(&[key(key_id)?.seed; 32])
        .map_err(|_| "cannot derive the test key")?;
    Ok(STANDARD.encode(pair.public_key().as_ref()))
}

fn sign(role: Role, signers: &[&str], payload: &str) -> Result<SignedEnvelope, Box<dyn Error>> {
    let mut signatures = vec![];
    for key_id in signers {
        let pkcs8 = pkcs8_for(key(key_id)?.seed)?;
        signatures.push(sign_payload(role, key_id, &pkcs8, payload)?);
    }
    Ok(SignedEnvelope {
        payload: payload.to_string(),
        signatures,
        delegation: None,
    })
}

fn snapshot_payload(version: u64, expires_at: u64) -> Result<String, Box<dyn Error>> {
    let snapshot: Snapshot = serde_json::from_value(serde_json::json!({
        "schema": 1,
        "version": version,
        "issued_at": ISSUED_AT,
        "expires_at": expires_at,
        "audience": "org-example",
        "pii": [{
            "id": "ssn",
            "label": "US Social Security number",
            "pattern": "\\b\\d{3}-\\d{2}-\\d{4}\\b",
            "validator": "ssn",
            "action": "block",
            "enabled": true
        }],
        "tools": [{
            "id": "claude-code",
            "name": "Claude Code",
            "via": "local",
            "enabled": true,
            "upstream": "https://api.anthropic.com",
            "prefix": null,
            "env_var": "ANTHROPIC_BASE_URL",
            "endpoints": [{ "path": "/v1/messages", "match": "exact", "format": "json" }],
            "hosts": []
        }],
        "settings": { "dry_run": false, "usage_reporting": "optional" }
    }))?;
    validate(&snapshot)?;
    Ok(serde_json::to_string(&snapshot)?)
}

fn manifest_payload() -> Result<String, Box<dyn Error>> {
    let manifest: UpdateManifest = serde_json::from_value(serde_json::json!({
        "schema": 1,
        "channel": "stable",
        "version": "1.2.3",
        "published_at": ISSUED_AT,
        "expires_at": EXPIRES_AT,
        "threshold": 2,
        "artifacts": {
            "linux-x86_64": {
                "url": "https://example.com/releases/inveil-1.2.3-linux-x86_64",
                "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
                "size": 1024
            }
        },
        "revoked_key_ids": []
    }))?;
    Ok(serde_json::to_string(&manifest)?)
}

fn flip_signature_byte(envelope: &mut SignedEnvelope) -> TestResult {
    let entry = envelope.signatures.first_mut().ok_or("no signature")?;
    let mut bytes = STANDARD.decode(&entry.signature)?;
    bytes[0] ^= 0x01;
    entry.signature = STANDARD.encode(bytes);
    Ok(())
}

fn entry(
    file: &str,
    description: &str,
    role: &str,
    threshold: usize,
    trusted: &[&str],
    signature: &str,
    client_outcome: &str,
) -> VectorEntry {
    VectorEntry {
        file: file.to_string(),
        description: description.to_string(),
        role: role.to_string(),
        threshold,
        trusted_key_ids: trusted.iter().map(|id| id.to_string()).collect(),
        signature: signature.to_string(),
        client_outcome: client_outcome.to_string(),
    }
}

fn build_vectors() -> Result<Vec<Vector>, Box<dyn Error>> {
    let policy_keys = ["policy-1", "policy-2"];
    let update_keys = ["update-1", "update-2"];
    let good = snapshot_payload(HIGH_WATER_VERSION, EXPIRES_AT)?;
    let mut vectors = vec![];

    vectors.push(Vector {
        entry: entry(
            "policy-good.json",
            "A snapshot signed by a pinned policy key.",
            "policy",
            1,
            &policy_keys,
            "valid",
            "accept",
        ),
        envelope: sign(Role::Policy, &["policy-1"], &good)?,
    });
    vectors.push(Vector {
        entry: entry(
            "policy-good-two-signatures.json",
            "Signed by two distinct pinned keys; passes a threshold of 2.",
            "policy",
            2,
            &policy_keys,
            "valid",
            "accept",
        ),
        envelope: sign(Role::Policy, &["policy-1", "policy-2"], &good)?,
    });
    vectors.push(Vector {
        entry: entry(
            "policy-below-threshold.json",
            "One valid signature where the verifier requires two.",
            "policy",
            2,
            &policy_keys,
            "invalid",
            "reject_signature",
        ),
        envelope: sign(Role::Policy, &["policy-1"], &good)?,
    });

    let mut tampered_payload = sign(Role::Policy, &["policy-1"], &good)?;
    tampered_payload.payload = good.replacen("\"version\":7", "\"version\":8", 1);
    vectors.push(Vector {
        entry: entry(
            "policy-tampered-payload.json",
            "The payload was edited after signing (version 7 became 8).",
            "policy",
            1,
            &policy_keys,
            "invalid",
            "reject_signature",
        ),
        envelope: tampered_payload,
    });

    let mut tampered_signature = sign(Role::Policy, &["policy-1"], &good)?;
    flip_signature_byte(&mut tampered_signature)?;
    vectors.push(Vector {
        entry: entry(
            "policy-tampered-signature.json",
            "One bit of the signature was flipped.",
            "policy",
            1,
            &policy_keys,
            "invalid",
            "reject_signature",
        ),
        envelope: tampered_signature,
    });

    let mut wrong_key = sign(Role::Policy, &["attacker-1"], &good)?;
    wrong_key.signatures[0].key_id = "policy-1".to_string();
    vectors.push(Vector {
        entry: entry(
            "policy-wrong-key.json",
            "Signed by an unpinned key that claims the id of a pinned one.",
            "policy",
            1,
            &policy_keys,
            "invalid",
            "reject_signature",
        ),
        envelope: wrong_key,
    });

    vectors.push(Vector {
        entry: entry(
            "policy-unknown-key-id.json",
            "Signed by a key whose id is not pinned.",
            "policy",
            1,
            &policy_keys,
            "invalid",
            "reject_signature",
        ),
        envelope: sign(Role::Policy, &["attacker-1"], &good)?,
    });

    let mut wrong_role = sign(Role::Update, &["policy-1"], &good)?;
    wrong_role.signatures[0].key_id = "policy-1".to_string();
    vectors.push(Vector {
        entry: entry(
            "policy-wrong-role.json",
            "A pinned policy key signed under the update domain; it must not verify as a policy.",
            "policy",
            1,
            &policy_keys,
            "invalid",
            "reject_signature",
        ),
        envelope: wrong_role,
    });

    vectors.push(Vector {
        entry: entry(
            "policy-expired.json",
            "Validly signed, but expires_at is before the evaluation time.",
            "policy",
            1,
            &policy_keys,
            "valid",
            "reject_expired",
        ),
        envelope: sign(
            Role::Policy,
            &["policy-1"],
            &snapshot_payload(HIGH_WATER_VERSION, NOW - 1)?,
        )?,
    });
    vectors.push(Vector {
        entry: entry(
            "policy-lower-version.json",
            "Validly signed, but its version is below the client's high-water mark (rollback).",
            "policy",
            1,
            &policy_keys,
            "valid",
            "reject_rollback",
        ),
        envelope: sign(
            Role::Policy,
            &["policy-1"],
            &snapshot_payload(HIGH_WATER_VERSION - 1, EXPIRES_AT)?,
        )?,
    });

    let manifest = manifest_payload()?;
    vectors.push(Vector {
        entry: entry(
            "update-good.json",
            "An update manifest signed by two distinct pinned update keys.",
            "update",
            2,
            &update_keys,
            "valid",
            "accept",
        ),
        envelope: sign(Role::Update, &["update-1", "update-2"], &manifest)?,
    });
    vectors.push(Vector {
        entry: entry(
            "update-one-signature.json",
            "A manifest that needs two signers carries only one.",
            "update",
            2,
            &update_keys,
            "invalid",
            "reject_signature",
        ),
        envelope: sign(Role::Update, &["update-1"], &manifest)?,
    });
    let mut update_tampered = sign(Role::Update, &["update-1", "update-2"], &manifest)?;
    update_tampered.payload = manifest.replacen("\"size\":1024", "\"size\":2048", 1);
    vectors.push(Vector {
        entry: entry(
            "update-tampered.json",
            "The artifact size was edited after signing.",
            "update",
            2,
            &update_keys,
            "invalid",
            "reject_signature",
        ),
        envelope: update_tampered,
    });
    vectors.push(Vector {
        entry: entry(
            "update-wrong-role.json",
            "Update keys signed under the policy domain; it must not verify as an update.",
            "update",
            2,
            &update_keys,
            "invalid",
            "reject_signature",
        ),
        envelope: sign(Role::Policy, &["update-1", "update-2"], &manifest)?,
    });
    Ok(vectors)
}

fn vector_directory() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../contract/v1/vectors")
}

fn render_files() -> Result<Vec<(String, String)>, Box<dyn Error>> {
    let vectors = build_vectors()?;
    let mut files = vec![];
    let mut entries = vec![];
    for vector in vectors {
        let mut text = serde_json::to_string_pretty(&vector.envelope)?;
        text.push('\n');
        files.push((vector.entry.file.clone(), text));
        entries.push(vector.entry);
    }
    let mut keys = vec![];
    for test_key in KEYS
        .iter()
        .filter(|candidate| candidate.role != "untrusted")
    {
        keys.push(ManifestKey {
            key_id: test_key.key_id.to_string(),
            role: test_key.role.to_string(),
            public_key: public_key_base64(test_key.key_id)?,
        });
    }
    let manifest = VectorManifest {
        format: 1,
        description: "Signed envelopes and the outcome every verifier must reach. The keys are test keys derived from public seeds.".to_string(),
        now: NOW,
        high_water_version: HIGH_WATER_VERSION,
        domains: DOMAINS
            .iter()
            .map(|(role, domain)| (role.to_string(), domain.to_string()))
            .collect(),
        keys,
        vectors: entries,
    };
    let mut text = serde_json::to_string_pretty(&manifest)?;
    text.push('\n');
    files.push(("manifest.json".to_string(), text));
    Ok(files)
}

#[test]
fn regenerate_vectors() -> TestResult {
    let update = std::env::var_os("UPDATE_VECTORS").is_some();
    let mut drifted = vec![];
    for (name, expected) in render_files()? {
        let path = vector_directory().join(&name);
        if update {
            std::fs::write(&path, &expected)?;
            continue;
        }
        if std::fs::read_to_string(&path).ok().as_deref() != Some(expected.as_str()) {
            drifted.push(name);
        }
    }
    assert!(
        drifted.is_empty(),
        "vectors out of date: {drifted:?}; run `UPDATE_VECTORS=1 cargo test -p engine --test vectors`"
    );
    Ok(())
}

fn trust_for(manifest: &VectorManifest, entry: &VectorEntry) -> Result<Trust, Box<dyn Error>> {
    let mut keys = vec![];
    for key_id in &entry.trusted_key_ids {
        let listed = manifest
            .keys
            .iter()
            .find(|candidate| &candidate.key_id == key_id)
            .ok_or("vector pins a key the manifest does not list")?;
        keys.push(PinnedKey::from_base64(key_id, &listed.public_key)?);
    }
    Ok(Trust {
        keys,
        roots: vec![],
        ..Trust::default()
    })
}

fn client_outcome(
    manifest: &VectorManifest,
    entry: &VectorEntry,
    payload: &str,
) -> Result<&'static str, Box<dyn Error>> {
    if entry.role != "policy" {
        return Ok("accept");
    }
    let snapshot: Snapshot = serde_json::from_str(payload)?;
    if snapshot.expires_at <= manifest.now {
        return Ok("reject_expired");
    }
    if snapshot.version < manifest.high_water_version {
        return Ok("reject_rollback");
    }
    Ok("accept")
}

#[test]
fn committed_vectors_verify_as_declared() -> TestResult {
    let manifest: VectorManifest = serde_json::from_str(&std::fs::read_to_string(
        vector_directory().join("manifest.json"),
    )?)?;
    assert!(!manifest.vectors.is_empty());
    for entry in &manifest.vectors {
        let envelope = std::fs::read_to_string(vector_directory().join(&entry.file))?;
        let trust = trust_for(&manifest, entry)?;
        let role = match entry.role.as_str() {
            "policy" => Role::Policy,
            "update" => Role::Update,
            other => return Err(format!("unknown role {other}").into()),
        };
        let result = verify_envelope::<serde_json::Value>(
            role,
            &trust,
            entry.threshold,
            manifest.now,
            &envelope,
        );
        match entry.signature.as_str() {
            "valid" => {
                let verified = result.map_err(|error| format!("{}: {error}", entry.file))?;
                let payload = serde_json::from_str::<SignedEnvelope>(&envelope)?.payload;
                let outcome = client_outcome(&manifest, entry, &payload)?;
                assert_eq!(outcome, entry.client_outcome, "{}", entry.file);
                assert!(!verified.signed_by.is_empty(), "{}", entry.file);
            }
            "invalid" => {
                assert!(
                    matches!(result, Err(VerifyError::NotEnoughSignatures { .. })),
                    "{} should fail signature verification",
                    entry.file
                );
                assert_eq!(entry.client_outcome, "reject_signature", "{}", entry.file);
            }
            other => return Err(format!("unknown expectation {other}").into()),
        }
    }
    Ok(())
}
