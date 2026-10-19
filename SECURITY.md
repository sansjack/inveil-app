# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Report it privately through GitHub: go to the repository's Security tab and choose "Report a vulnerability" (private vulnerability reporting, GitHub security advisories). If you cannot use GitHub, email SECURITY_CONTACT_EMAIL.

Include what you found, the affected version and platform, steps or a proof of concept to reproduce, and the impact you expect. Use synthetic data only.

## What to expect

| Step | Target |
|---|---|
| Acknowledgement | Within 3 business days |
| Initial assessment (severity, affected versions) | Within 7 days |
| Fix or mitigation for confirmed high and critical issues | Within 30 days, sooner when actively exploited |
| Public disclosure | After a fix is released, coordinated with you; 90 days at most unless we agree otherwise |

We will credit you in the advisory and changelog unless you prefer not to be named. These are targets for a volunteer-run project, not guarantees. We do not run a bug bounty.

## Supported versions

Inveil is pre-1.0. Security fixes are made for the latest released minor version only. Upgrade to the latest release before reporting something that may already be fixed.

| Version | Supported |
|---|---|
| Latest 0.x release | Yes |
| Older releases | No |

## Scope

In scope: the `inveil` binary and its crates, the install scripts, the signing and verification code, the updater, the contract and its test vectors, and the release pipeline.

Out of scope: weaknesses that require local administrator rights (see [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), which lists what Inveil does not defend against), detector misses and false positives (open a normal issue), denial of service by a user against their own machine, and vulnerabilities in third-party backends.

## Key compromise runbook

Three kinds of keys exist (see [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)). The update key matters most because it can ship code.

### Update key

Suspected or confirmed leak of an update signing key:

1. Contain. Remove the secrets of the `release-manifest-signing` and `release-platform-signing` environments, disable the release workflow, and unpublish the current manifest if there is any doubt about it.
2. Assess the threshold. With `threshold` 2, one leaked key cannot sign a manifest alone; continue from step 3 without panic. With `threshold` 1, treat every manifest signed since the suspected leak as untrusted.
3. Generate a new key (`inveil keygen --out update.key`) and add it to the `release-manifest-signing` environment (never put both update keys in CI; the second key stays with a maintainer).
4. Publish a release whose manifest is signed by the uncompromised key and the new key, and lists the compromised key in `revoked_key_ids`. Clients that still meet the threshold accept it and drop the old key.
5. If no uncompromised key remains, clients cannot be fixed remotely. Publish an advisory with the new public key, a fresh `install.sh` with the new key pinned, and instructions to set `update.mode = "off"` and reinstall. Revoke the old key in the release notes.
6. Rotate any other secret that was exposed, review the workflow run history and artifact attestations, and publish an advisory.

### Policy (rules) key

1. Generate a new policy key and re-sign the current rules with a higher `version`.
2. Add the new key to `backend.pinned_keys` on clients (configuration management, MDM or an enrollment bundle) alongside the old one.
3. Once clients have the new key, publish a snapshot that lists the old key in `revoked_key_ids`, then remove the old pin.
4. In hosted mode with delegation, revoke the delegated key by letting it expire and listing it in `revoked_key_ids`. The root key never touches a server.

### Root key

Offline root keys certify delegated policy keys. If one leaks, treat all delegations as suspect: generate a new root, distribute it through `backend.root_keys`, issue new delegations, and remove the old root from client configuration.

### Other

- Enrollment tokens and device credentials: revoke on the backend; the next request from the device fails.
- Browser CA key: remove the CA from the trust store (`inveil uninstall`), delete it from the data directory and re-run `inveil install` to create a new one.
- Report anything you cannot resolve through the channel above.

## Hardening you can verify

Releases are built in CI with pinned actions and attached provenance, an SBOM and `SHA256SUMS`. `SHA256SUMS` is served from the same origin as the binaries, so it detects corruption and is not verification evidence by itself; the build attestation and the signed update manifest are. The official `install.sh` and `install.ps1` are rendered at release time with the pinned update keys and attached to the release, so those keys are only as trustworthy as the release they come from. Verification commands are in the [README](README.md#verify-a-download).
