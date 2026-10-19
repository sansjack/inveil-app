#!/usr/bin/env python3
"""Build and check the inveil update manifest. Standard library only.

generate: write the unsigned manifest payload from the raw binaries in a directory.
validate: refuse an unsigned manifest payload that does not match the tag, the repository and the packaged
          artifacts. Runs in the job that holds the update key, before anything is signed.
check:    compare a signed envelope's payload with the files on disk and report how
          many signatures it carries, so callers can decide whether `inveil verify`
          can already meet the manifest's threshold.
"""
import argparse
import hashlib
import json
import re
import sys
import time
from pathlib import Path

MANIFEST_SCHEMA = 1
BINARY_NAME = re.compile(r"^inveil-(macos|linux|windows)-(x86_64|aarch64)(\.exe)?$")
EXPECTED_TARGETS = {
    "macos-x86_64",
    "macos-aarch64",
    "linux-x86_64",
    "linux-aarch64",
    "windows-x86_64",
    "windows-aarch64",
}
SECONDS_PER_DAY = 86_400
MINIMUM_OFFICIAL_THRESHOLD = 2
MAXIMUM_THRESHOLD = 16
MIN_VALID_DAYS = 30
MAX_VALID_DAYS = 400
MAX_PUBLISHED_AGE_DAYS = 14
MAX_CLOCK_SKEW_SECONDS = 300
TAG_PATTERN = re.compile(r"^v(\d+\.\d+\.\d+)(-rc\.\d+)?$")
SEMVER_PATTERN = re.compile(r"^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$")
REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
ALLOWED_FIELDS = {
    "schema",
    "channel",
    "version",
    "published_at",
    "expires_at",
    "min_supported",
    "threshold",
    "artifacts",
    "notes_url",
    "revoked_key_ids",
}


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_sums(path: Path) -> dict[str, str]:
    sums = {}
    for line in path.read_text().splitlines():
        digest, _, name = line.partition("  ")
        sums[name.strip().lstrip("*")] = digest
    return sums


def collect_binaries(dist: Path) -> dict[str, Path]:
    binaries = {}
    for path in sorted(dist.iterdir()):
        match = BINARY_NAME.match(path.name)
        if match:
            binaries[f"{match.group(1)}-{match.group(2)}"] = path
    return binaries


def generate(args: argparse.Namespace) -> None:
    dist = Path(args.dist)
    sums = read_sums(dist / "SHA256SUMS")
    binaries = collect_binaries(dist)
    missing = EXPECTED_TARGETS - binaries.keys()
    if missing:
        sys.exit(f"missing binaries for: {', '.join(sorted(missing))}")

    artifacts = {}
    for target, path in binaries.items():
        digest = sha256_of(path)
        if sums.get(path.name) != digest:
            sys.exit(f"{path.name}: SHA256SUMS does not match the file on disk")
        artifacts[target] = {
            "url": f"https://github.com/{args.repo}/releases/download/{args.tag}/{path.name}",
            "sha256": digest,
            "size": path.stat().st_size,
        }

    now = int(time.time())
    manifest = {
        "schema": MANIFEST_SCHEMA,
        "channel": args.channel,
        "version": args.version,
        "published_at": now,
        "expires_at": now + args.valid_days * SECONDS_PER_DAY,
        "threshold": args.threshold,
        "artifacts": artifacts,
        "notes_url": f"https://github.com/{args.repo}/releases/tag/{args.tag}",
    }
    Path(args.output).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")


def binary_name(target: str) -> str:
    return f"inveil-{target}" + (".exe" if target.startswith("windows-") else "")


def validate(args: argparse.Namespace) -> None:
    errors = []
    payload_path = Path(args.payload)
    tag_match = TAG_PATTERN.match(args.tag)
    if not tag_match:
        sys.exit(f"{args.tag} is not vX.Y.Z or vX.Y.Z-rc.N")
    if not REPOSITORY_PATTERN.match(args.repo):
        sys.exit(f"{args.repo} is not owner/name")
    version = args.tag[1:]
    channel = "beta" if tag_match.group(2) else "stable"
    expected_file = "update-manifest-beta.json" if channel == "beta" else "update-manifest.json"
    if payload_path.name != expected_file:
        errors.append(f"file name is {payload_path.name}, a {channel} release signs {expected_file}")

    manifest = json.loads(payload_path.read_text())
    unknown = set(manifest) - ALLOWED_FIELDS
    if unknown:
        errors.append(f"unknown fields: {', '.join(sorted(unknown))}")
    if manifest.get("schema") != MANIFEST_SCHEMA:
        errors.append(f"schema is {manifest.get('schema')}, expected {MANIFEST_SCHEMA}")
    if manifest.get("version") != version:
        errors.append(f"version is {manifest.get('version')}, the tag says {version}")
    if manifest.get("channel") != channel:
        errors.append(f"channel is {manifest.get('channel')}, the tag {args.tag} is a {channel} release")

    threshold = manifest.get("threshold")
    minimum = 1 if args.allow_unofficial else MINIMUM_OFFICIAL_THRESHOLD
    if not isinstance(threshold, int) or isinstance(threshold, bool) or not minimum <= threshold <= MAXIMUM_THRESHOLD:
        errors.append(f"threshold is {threshold}, expected {minimum} to {MAXIMUM_THRESHOLD}")

    now = int(time.time())
    published_at = manifest.get("published_at")
    expires_at = manifest.get("expires_at")
    if not isinstance(published_at, int) or not now - MAX_PUBLISHED_AGE_DAYS * SECONDS_PER_DAY <= published_at <= now + MAX_CLOCK_SKEW_SECONDS:
        errors.append(f"published_at {published_at} is not within the last {MAX_PUBLISHED_AGE_DAYS} days")
    if not isinstance(expires_at, int) or not now + MIN_VALID_DAYS * SECONDS_PER_DAY <= expires_at <= now + MAX_VALID_DAYS * SECONDS_PER_DAY:
        errors.append(f"expires_at {expires_at} is not {MIN_VALID_DAYS} to {MAX_VALID_DAYS} days from now")

    min_supported = manifest.get("min_supported")
    if min_supported is not None and not SEMVER_PATTERN.match(str(min_supported)):
        errors.append(f"min_supported {min_supported!r} is not a version")
    if manifest.get("revoked_key_ids") and not args.allow_revocations:
        errors.append("revoked_key_ids is not empty; pass --allow-revocations for a deliberate key rotation")
    notes_url = manifest.get("notes_url")
    if notes_url is not None and notes_url != f"https://github.com/{args.repo}/releases/tag/{args.tag}":
        errors.append(f"notes_url {notes_url} is not this release's page")

    artifacts = manifest.get("artifacts", {})
    if set(artifacts) != EXPECTED_TARGETS:
        errors.append(f"targets are {sorted(artifacts)}, expected {sorted(EXPECTED_TARGETS)}")
    dist = Path(args.dist)
    for target in sorted(set(artifacts) & EXPECTED_TARGETS):
        entry = artifacts[target]
        name = binary_name(target)
        expected_url = f"https://github.com/{args.repo}/releases/download/{args.tag}/{name}"
        if set(entry) != {"url", "sha256", "size"}:
            errors.append(f"{target}: fields are {sorted(entry)}, expected url, sha256, size")
            continue
        if entry["url"] != expected_url:
            errors.append(f"{target}: url {entry['url']} is not {expected_url}")
        path = dist / name
        if not path.is_file():
            errors.append(f"{target}: {name} was not among the packaged artifacts")
            continue
        if not SHA256_PATTERN.match(str(entry["sha256"])) or sha256_of(path) != entry["sha256"]:
            errors.append(f"{target}: sha256 does not match the packaged {name}")
        if entry["size"] != path.stat().st_size:
            errors.append(f"{target}: size {entry['size']} does not match the packaged {name} ({path.stat().st_size})")

    if errors:
        sys.exit("refusing to sign " + payload_path.name + ":\n  " + "\n  ".join(errors))
    print(f"manifest {payload_path.name} matches {args.tag} ({channel}), {args.repo} and the packaged artifacts")


def check(args: argparse.Namespace) -> None:
    dist = Path(args.dist)
    envelope = json.loads(Path(args.envelope).read_text())
    manifest = json.loads(envelope["payload"])
    if manifest["version"] != args.version:
        sys.exit(f"manifest version {manifest['version']} != expected {args.version}")

    for target, entry in manifest["artifacts"].items():
        name = f"inveil-{target}" + (".exe" if target.startswith("windows-") else "")
        path = dist / name
        if sha256_of(path) != entry["sha256"] or path.stat().st_size != entry["size"]:
            sys.exit(f"{name}: does not match the signed manifest")

    print(f"signatures={len(envelope['signatures'])}")
    print(f"threshold={manifest['threshold']}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    gen = commands.add_parser("generate")
    gen.add_argument("--dist", required=True)
    gen.add_argument("--version", required=True)
    gen.add_argument("--tag", required=True)
    gen.add_argument("--channel", choices=["stable", "beta"], required=True)
    gen.add_argument("--repo", required=True, help="owner/name")
    gen.add_argument("--threshold", type=int, required=True)
    gen.add_argument("--valid-days", type=int, default=180)
    gen.add_argument("--output", required=True)
    gen.set_defaults(handler=generate)

    val = commands.add_parser("validate")
    val.add_argument("--payload", required=True)
    val.add_argument("--dist", required=True, help="directory holding the packaged raw binaries")
    val.add_argument("--tag", required=True)
    val.add_argument("--repo", required=True, help="owner/name")
    val.add_argument("--allow-unofficial", action="store_true", help="accept a threshold of 1 (forks)")
    val.add_argument("--allow-revocations", action="store_true", help="accept a non-empty revoked_key_ids")
    val.set_defaults(handler=validate)

    chk = commands.add_parser("check")
    chk.add_argument("--dist", required=True)
    chk.add_argument("--version", required=True)
    chk.add_argument("--envelope", required=True)
    chk.set_defaults(handler=check)

    args = parser.parse_args()
    args.handler(args)


if __name__ == "__main__":
    main()
