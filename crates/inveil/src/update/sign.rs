//! `inveil keygen`, `inveil sign` and `inveil verify`: the offline tooling an administrator or release pipeline uses
//! to produce and check signed envelopes. Private keys are only ever read from a file or the environment and never
//! printed.
use super::args::Arguments;
use super::download::hash_file;
use super::files::{create_private_file, failed};
use super::manifest::{check_release, verify_manifest, Expectations};
use super::{host_target, running_version, UpdateError};
use crate::config::{Config, PinnedKeyConfig};
use crate::util::unix_seconds;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use contract::{SignedEnvelope, Snapshot, UpdateManifest};
use engine::signing::{public_key_of, sha256_hex, sign_payload, PinnedKey, Role, Trust};
use ring::rand::SystemRandom;
use ring::signature::Ed25519KeyPair;
use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::Path;

const ARTIFACT_PREFIX: &str = "inveil-";
const ENV_KEY_PREFIX: &str = "env:";
const SUGGESTED_KEY_ID_HEX_LEN: usize = 16;

fn parse_role(name: &str) -> Result<Role, UpdateError> {
    match name {
        "policy" => Ok(Role::Policy),
        "update" => Ok(Role::Update),
        other => Err(UpdateError::Usage(format!(
            "unknown role {other:?}, expected policy or update"
        ))),
    }
}

fn read_key(source: &str) -> Result<Vec<u8>, UpdateError> {
    let encoded = match source.strip_prefix(ENV_KEY_PREFIX) {
        Some(name) => std::env::var(name)
            .map_err(|_| UpdateError::Key(format!("environment variable {name} is not set")))?,
        None => fs::read_to_string(source).map_err(failed("read", Path::new(source)))?,
    };
    STANDARD
        .decode(encoded.trim())
        .map_err(|_| UpdateError::Key("the key is not base64 PKCS#8".to_string()))
}

/// Strict parsing here catches a malformed payload at signing time instead of on every client.
fn validate_payload(role: Role, payload: &str) -> Result<(), UpdateError> {
    let result = match role {
        Role::Update => serde_json::from_str::<UpdateManifest>(payload).map(drop),
        Role::Policy => serde_json::from_str::<Snapshot>(payload).map(drop),
        Role::Delegation => return Err(UpdateError::Usage("cannot sign delegations here".into())),
    };
    result.map_err(|error| UpdateError::Payload(error.to_string()))
}

/// `inveil keygen --out <file>`: writes a new private key (mode 0600, never overwriting) and prints the public half.
pub fn run_keygen(args: &[String]) -> Result<String, UpdateError> {
    let arguments = Arguments::parse(args, &["--out"], &[])?;
    let out = Path::new(arguments.required("--out")?);
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
        .map_err(|_| UpdateError::Key("the system random generator failed".to_string()))?;
    let public_key = public_key_of(pkcs8.as_ref())?;

    let mut file = create_private_file(out).map_err(failed("create", out))?;
    file.write_all(STANDARD.encode(pkcs8.as_ref()).as_bytes())
        .map_err(failed("write", out))?;

    let suggested_id = &sha256_hex(&public_key)[..SUGGESTED_KEY_ID_HEX_LEN];
    Ok(format!(
        "public_key: {}\nsuggested key_id: {suggested_id}\nprivate key written to {} (owner-only)",
        STANDARD.encode(public_key),
        out.display()
    ))
}

/// `inveil sign --role <policy|update> --key <file|env:NAME> --key-id <id> [--co-sign] <payload.json | envelope.json>`
///
/// With `--co-sign` the input is an existing envelope and the new signature is appended to it.
pub fn run_sign(args: &[String]) -> Result<String, UpdateError> {
    let arguments = Arguments::parse(args, &["--role", "--key", "--key-id"], &["--co-sign"])?;
    let role = parse_role(arguments.required("--role")?)?;
    let key_id = arguments.required("--key-id")?;
    let pkcs8 = read_key(arguments.required("--key")?)?;
    let input_path = Path::new(arguments.single_positional("input file")?);
    let input = fs::read_to_string(input_path).map_err(failed("read", input_path))?;

    let mut envelope = if arguments.has("--co-sign") {
        serde_json::from_str::<SignedEnvelope>(&input)
            .map_err(|error| UpdateError::Payload(format!("{}: {error}", input_path.display())))?
    } else {
        SignedEnvelope {
            payload: input,
            signatures: vec![],
            delegation: None,
        }
    };
    validate_payload(role, &envelope.payload)?;
    if envelope
        .signatures
        .iter()
        .any(|entry| entry.key_id == key_id)
    {
        return Err(UpdateError::Usage(format!(
            "the envelope is already signed by {key_id}"
        )));
    }

    let signature = sign_payload(role, key_id, &pkcs8, &envelope.payload)?;
    envelope.signatures.push(signature);
    serde_json::to_string_pretty(&envelope).map_err(|error| UpdateError::Payload(error.to_string()))
}

fn pinned_keys(configured: &[PinnedKeyConfig]) -> Result<Vec<PinnedKey>, UpdateError> {
    configured
        .iter()
        .map(|key| Ok(PinnedKey::from_base64(&key.key_id, &key.public_key)?))
        .collect()
}

pub fn update_trust(config: &Config) -> Result<Trust, UpdateError> {
    Ok(Trust {
        keys: pinned_keys(&config.update.pinned_keys)?,
        roots: vec![],
        ..Trust::default()
    })
}

fn command_line_keys(entries: &[String]) -> Result<Vec<PinnedKey>, UpdateError> {
    entries
        .iter()
        .map(|entry| {
            let (key_id, public_key) = entry.split_once('=').ok_or_else(|| {
                UpdateError::Usage(format!("--pinned-key {entry:?} is not <id>=<base64 key>"))
            })?;
            Ok(PinnedKey::from_base64(key_id, public_key)?)
        })
        .collect()
}

/// `inveil-linux-x86_64` or `inveil-windows-aarch64.exe` -> `linux-x86_64` / `windows-aarch64`.
fn target_of(artifact: &Path) -> Result<&str, UpdateError> {
    let name = artifact.file_name().and_then(|name| name.to_str());
    let target = name
        .and_then(|name| name.strip_prefix(ARTIFACT_PREFIX))
        .map(|name| name.strip_suffix(".exe").unwrap_or(name));
    target.ok_or_else(|| {
        UpdateError::Usage(format!(
            "cannot infer the target from {}; expected {ARTIFACT_PREFIX}<os>-<arch>[.exe]",
            artifact.display()
        ))
    })
}

fn check_artifact(
    manifest: &UpdateManifest,
    artifact: &Path,
    target: &str,
) -> Result<String, UpdateError> {
    let entry = manifest.artifacts.get(target).ok_or_else(|| {
        UpdateError::ArtifactMismatch(format!("the manifest has no binary for {target}"))
    })?;
    let size = fs::metadata(artifact)
        .map_err(failed("inspect", artifact))?
        .len();
    if size != entry.size {
        return Err(UpdateError::ArtifactMismatch(format!(
            "{} is {size} bytes, the manifest signs {}",
            artifact.display(),
            entry.size
        )));
    }
    let hash = hash_file(artifact).map_err(failed("read", artifact))?;
    if hash != entry.sha256 {
        return Err(UpdateError::ArtifactMismatch(format!(
            "{} has sha256 {hash}, the manifest signs {}",
            artifact.display(),
            entry.sha256
        )));
    }
    Ok(format!(
        "artifact: {target} matches the manifest ({size} bytes, sha256 {hash})"
    ))
}

fn parse_min_signatures(text: &str) -> Result<usize, UpdateError> {
    text.parse().ok().filter(|count| *count > 0).ok_or_else(|| {
        UpdateError::Usage(format!(
            "--min-signatures {text:?} is not a positive number"
        ))
    })
}

/// `inveil verify [--role policy|update] [--pinned-key <id>=<base64>]... [--min-signatures N] [--channel NAME]
/// [--artifact <binary>] <envelope.json>`
///
/// Keys given on the command line replace the configured ones, so no configuration file is needed. An update manifest
/// gets the same checks as an install: signatures against the larger of its threshold and the local minimum, expiry,
/// channel, schema, `min_supported`, and that it is not older than this binary.
pub fn run_verify(config: &Config, args: &[String]) -> Result<String, UpdateError> {
    let arguments = Arguments::parse(
        args,
        &[
            "--role",
            "--pinned-key",
            "--artifact",
            "--min-signatures",
            "--channel",
        ],
        &[],
    )?;
    let role = parse_role(arguments.value("--role").unwrap_or("update"))?;
    let path = Path::new(arguments.single_positional("envelope file")?);
    let text = fs::read_to_string(path).map_err(failed("read", path))?;
    let now = unix_seconds();
    let cli_keys = command_line_keys(arguments.values("--pinned-key"))?;

    if role == Role::Update {
        let trust = match cli_keys.is_empty() {
            true => update_trust(config)?,
            false => Trust {
                keys: cli_keys,
                roots: vec![],
                ..Trust::default()
            },
        };
        let min_signatures = match arguments.value("--min-signatures") {
            Some(text) => parse_min_signatures(text)?,
            None => config.update.required_signatures(),
        };
        let verified = verify_manifest(
            &trust,
            min_signatures,
            now,
            &text,
            &BTreeSet::new(),
            &BTreeSet::new(),
        )?;
        let manifest = verified.value;
        let artifact = arguments.value("--artifact").map(Path::new);
        let target = match artifact {
            Some(artifact) => target_of(artifact)?.to_string(),
            None => host_target(),
        };
        let current = running_version()?;
        let offered = check_release(
            &manifest,
            &Expectations {
                channel: arguments
                    .value("--channel")
                    .unwrap_or(&config.update.channel),
                current: &current,
                target: &target,
                now,
                seen: None,
            },
        )?;
        let relation = match offered {
            Some(offer) if offer.mandatory => "newer than this binary (required)",
            Some(_) => "newer than this binary",
            None => "the same version as this binary",
        };
        let mut report = format!(
            "valid update manifest\nversion: {} ({relation})\nchannel: {}\nthreshold: {}\nsigners: {}\npayload_sha256: {}",
            manifest.version,
            manifest.channel,
            manifest.threshold,
            verified.signed_by.join(", "),
            verified.payload_sha256
        );
        if let Some(artifact) = artifact {
            report.push('\n');
            report.push_str(&check_artifact(&manifest, artifact, &target)?);
        }
        return Ok(report);
    }

    if arguments.value("--artifact").is_some() {
        return Err(UpdateError::Usage(
            "--artifact only applies to --role update".to_string(),
        ));
    }
    let trust = match cli_keys.is_empty() {
        true => Trust {
            keys: pinned_keys(&config.backend.pinned_keys)?,
            roots: pinned_keys(&config.backend.root_keys)?,
            ..Trust::default()
        },
        false => Trust {
            keys: cli_keys,
            roots: vec![],
            ..Trust::default()
        },
    };
    let verified = engine::verify_snapshot(&trust, now, &text)?;
    Ok(format!(
        "valid policy snapshot\nversion: {}\naudience: {}\nsigners: {}\npayload_sha256: {}",
        verified.value.version,
        verified.value.audience.as_deref().unwrap_or("(any)"),
        verified.signed_by.join(", "),
        verified.payload_sha256
    ))
}
