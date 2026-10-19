# Releasing

How a release is cut, which keys and secrets it needs, and how a fork runs its own.

## Overview

Pushing a tag `vX.Y.Z` (stable) or `vX.Y.Z-rc.N` (beta channel) from `main` runs [`release.yml`](../.github/workflows/release.yml). The tag must match the workspace version, be reachable from `main`, and point at the current tip of `main` (or within `RELEASE_MAX_COMMITS_BEHIND` commits of it, default 0). The workflow:

1. Checks the signing policy: a manifest threshold of at least 2 and at least two distinct pinned update keys, or the release fails (see "Fork override" below).
2. Builds and tests every target with `--locked` and path-remapping flags: Linux, macOS and Windows on x86_64 and aarch64. These jobs hold no secrets.
3. Signs and notarises the macOS binaries and signs the Windows binaries in a separate job that holds the signing identities, compiles nothing and checks out no code.
4. Packages the signed binaries, generates the SBOM, renders `install.sh` and `install.ps1` with the pinned keys, computes `SHA256SUMS`, and builds the unsigned update manifest. Again no secrets.
5. Signs the manifest in a minimal job that receives the unsigned manifest, the packaged binaries (downloaded by exact artifact name) and one update key from its own protected environment. Before any key is read it validates the manifest: version equals the tag, channel matches the tag kind (`-rc.N` is `beta`), threshold is at least 2, `expires_at` is 30 to 400 days away, every artifact URL is exactly `https://github.com/<repo>/releases/download/<tag>/<file>`, all six targets are present, and every `sha256` and `size` matches the packaged file it re-hashes. Anything else is refused and nothing is signed.
6. Attaches build provenance attestations.
7. Creates a draft GitHub Release with every file.
8. Downloads the assets back in a job with the write token, hands them to unprivileged jobs on each OS, which re-check hashes and the manifest signature, run `install.sh` or `install.ps1` end to end against the draft, and run `inveil --version`. No job that executes a downloaded binary has a token. The install test needs the manifest's full signature threshold, so if the co-signature is missing the last step of `verify-download` fails and says why (it never silently skips). Forks with `ALLOW_UNOFFICIAL_RELEASE=true` get a warning instead.

Between steps 5 and 6, `cosign-manifest` adds the second update signature in its own environment and merges both into one envelope. After step 8 passes, `publish` waits for approval in `release-publish`, publishes the draft, and calls [`verify-published-release.yml`](../.github/workflows/verify-published-release.yml) against the published assets; if that fails, `unpublish-on-failure` turns the release back into a draft. Beta tags produce `update-manifest-beta.json` only. Once a beta release passes verification, `roll-beta-feed` copies its signed `update-manifest-beta.json.sig` to the rolling `beta` release (created on first use), which is the feed beta clients poll: GitHub has no fixed URL for the newest pre-release.

## Before the first release

### 1. Generate the update keys

Keep the update key off every server that hosts files, and ideally in a hardware token or KMS. For the CI key:

```sh
inveil keygen --out update.key
```

It prints the public key and a suggested `key_id`. The private key file is base64 PKCS#8 text. Generate a second, separate key for the co-signature the same way, on a different machine. Never reuse a policy (rules) key as an update key; their signing domains differ, but separate keys limit the damage of a leak.

Official releases need two distinct keys, and **no job or environment holds both**: `UPDATE_SIGNING_KEY` lives in `release-manifest-signing` and `UPDATE_COSIGNING_KEY` in `release-manifest-cosigning`. `sign-manifest.sh` refuses to sign with more than one key unless `ALLOW_UNOFFICIAL_RELEASE=true`, and `sign-manifest` fails if `UPDATE_COSIGNING_KEY` is present in its environment. See [THREAT_MODEL.md](THREAT_MODEL.md) R3 for what this separation does and does not protect against.

### 2. Create the release environments

Settings, Environments. Create four, so that approving one never exposes another's secrets:

- `release-platform-signing`: used by the `sign-platform` job only. Holds the Apple and Windows identities.
- `release-manifest-signing`: used by the `sign-manifest` job only. Holds the first update key (`UPDATE_SIGNING_KEY`) and nothing else.
- `release-manifest-cosigning`: used by the `cosign-manifest` job only. Holds the second update key (`UPDATE_COSIGNING_KEY`) and nothing else. Give it a different required reviewer from `release-manifest-signing` where you can.
- `release-publish`: used by the `publish` job only. No secrets; its required reviewer is the "ship it" click after every verify-download job passed.

Give each at least one required reviewer (prefer different people, and enable "prevent self-review"), and restrict deployment to the `main` branch and tags `v*`. Only the secrets below belong to these environments, not to the repository. The reviewer approving a release is approving a run of `.github/workflows/release.yml` and `.github/scripts/sign-manifest.sh` as they exist at the tag, so read the diff of both. Remember that a tag on an old commit runs that old commit's workflow: the tip-of-`main` check in `preflight` is defence in depth, not a boundary, and only the tag ruleset (see "Repository settings") and these environment restrictions actually stop it.

### 3. Secrets and variables

Secrets, by environment (`release-manifest-signing` holds the first row, `release-manifest-cosigning` the second, `release-platform-signing` the rest):

| Name | Purpose |
|---|---|
| `UPDATE_SIGNING_KEY` | Contents of the CI update private key file. |
| `UPDATE_COSIGNING_KEY` | Contents of the second update private key file, in `release-manifest-cosigning` only. The workflow fails if it also appears in `release-manifest-signing`. |
| `MACOS_CERTIFICATE_P12_BASE64` | Developer ID Application certificate, base64 of the `.p12`. |
| `MACOS_CERTIFICATE_PASSWORD` | Password of the `.p12`. |
| `MACOS_SIGNING_IDENTITY` | Name of the signing identity. |
| `APPLE_NOTARY_KEY`, `APPLE_NOTARY_KEY_ID`, `APPLE_NOTARY_ISSUER` | App Store Connect API key for notarisation. |
| `WINDOWS_CERTIFICATE_PFX_BASE64` | Authenticode certificate, base64 of the `.pfx`. |
| `WINDOWS_CERTIFICATE_PASSWORD` | Password of the `.pfx`. |

Variables (repository variables, because they are public and unprivileged jobs read them):

| Name | Purpose |
|---|---|
| `UPDATE_KEY_ID` | `key_id` of the CI update key. |
| `UPDATE_COSIGN_KEY_ID` | `key_id` of the second update key. |
| `UPDATE_PUBLIC_KEYS` | Whitespace-separated `<key_id>=<base64 public key>` entries for every update key. Baked into `install.sh` and `install.ps1`, used to check the key in `sign-manifest.sh` and in the smoke jobs. Only `A-Za-z0-9+/=._-` and spaces are accepted, because the value is templated into a shell script. |
| `UPDATE_MANIFEST_THRESHOLD` | Number of distinct signatures the manifest declares. Official releases need 2 or more. |
| `INSTALLER_MIN_SIGNATURES` | Minimum signatures the rendered installers demand. Defaults to 2. Below 2 the installer additionally needs `--allow-single-signature`. |
| `RELEASE_MAX_COMMITS_BEHIND` | How many commits the tagged commit may be behind `main`. Defaults to 0 (the tag must be the tip). |
| `ALLOW_UNOFFICIAL_RELEASE` | `true` only on forks; see below. |

The signature is made by OpenSSL, piped from the secret straight into `openssl pkeyutl` without touching the disk, by `sign-manifest.sh`. No binary built by the workflow ever sees the update key, which is why there is no signer build step: a compromised dependency compiled in CI cannot read it. The residual risk is the workflow and script at the tagged commit, which is why each environment needs a required reviewer, the tag ruleset limits who can tag, and the second key signs in a separate environment after re-validating the payload against the packaged artifacts.

Preferred end state: move the update key into a KMS or hardware token (cloud KMS with Ed25519 support, or a YubiKey held by a maintainer) and have `sign-manifest.sh` call it, so the key never exists as a repository secret at all. Until then the key is a GitHub environment secret, and an administrator who can edit the environment or the workflow can extract it. This is why the two keys live in separate environments: one leaked environment secret alone cannot produce a manifest the installers and clients accept.

Windows signing (OV certificate or a cloud signing service) and Apple Developer ID are open decisions for the maintainers; the workflow currently expects the certificate secrets above.

#### Fork override

A fork that cannot meet the two-key rule sets the repository variable `ALLOW_UNOFFICIAL_RELEASE` to `true`. The policy check then only warns, `sign-manifest.sh` accepts a threshold of 1 and a second key in CI, a missing signing key leaves the manifest unsigned, and the installers can be templated with `INSTALLER_MIN_SIGNATURES=1` (users then need `--allow-single-signature`). Nothing built that way should be described as an official release.

### 4. Publish the key fingerprints

Put the update public keys (`<key_id>=<base64>`) in the release notes and keep a list of past and current keys here, so users can pin them in `update.pinned_keys` and compare what `install.sh` prints (the SHA-256 of the raw 32-byte key).

<!-- release-numbers: update public keys and fingerprints -->

### 5. Installer scripts

`scripts/install.sh` and `scripts/install.ps1` are templates. The release job runs `.github/scripts/render-installers.sh`, which fills `@@UPDATE_PUBLIC_KEYS@@` and `@@MIN_SIGNATURES@@` from the repository variables and attaches the results as release assets, so `https://github.com/<org>/inveil-app/releases/latest/download/install.sh` exists. Values are placed inside single-quoted strings and anything outside a strict allow-list (quotes, backslashes, `$`, backticks, newlines) is refused. A web host can serve the same file with `@@BACKEND_URL@@` and `@@BACKEND_PINNED_KEYS@@` filled in too (`render-installers.sh` takes `BACKEND_URL` and `BACKEND_PINNED_KEYS`); see [ENROLLMENT.md](ENROLLMENT.md).

The enrollment bundle the installers build carries `update.keys`, `update.min_signatures` (the installer's effective minimum, at least 2 unless `--allow-single-signature`) and `update.feed_url` (the signed `.json.sig` envelope), so the 2-of-N rule also holds for the in-app updater. In managed mode the `[update]` table must come from the system-wide file; see [ENROLLMENT.md](ENROLLMENT.md#managed-mode).

What the installers do and do not guarantee is stated in the header of each script. In short: the Ed25519 signatures are verified by OpenSSL before anything downloaded is executed, which needs OpenSSL 3 (Homebrew `openssl@3` on macOS, Git for Windows on Windows); without it they refuse to install. The pinned keys are only as trustworthy as the host serving the script.

## Cutting a release

1. On an up-to-date `main` with a clean tree, run `scripts/release.sh minor` (or `patch`, `major`, an exact `X.Y.Z`, or `X.Y.Z-rc.N` for the beta channel). It sets the workspace version in `Cargo.toml`, moves the `CHANGELOG.md` `Unreleased` entries under the new version and date (stable only), runs `cargo test --workspace --locked`, then commits `chore: release vX.Y.Z` and creates the annotated tag locally. It pushes nothing.
2. Review with `git show vX.Y.Z`. To abandon it: `git tag -d vX.Y.Z && git reset --hard HEAD~1`.
3. Push both (you do this manually): `git push origin main && git push origin vX.Y.Z`.
4. In the Actions run, approve `release-platform-signing`, `release-manifest-signing` and `release-manifest-cosigning` when asked.
5. Wait for the verify-download jobs: they install the draft end to end on every OS with both signatures.
6. Approve `release-publish`. The release is published, `Verify published release` runs against the published assets over https, and if it fails the release is turned back into a draft automatically (the installers and the update feed read `latest/download`).
7. Fill the release-time numbers in the README (artifact hashes, benchmarks, coverage).

To re-check a published release later, run the `Verify published release` workflow by hand with the tag. For a release published with only one signature, add the second by hand: download `update-manifest*.json.sig`, run `inveil sign --role update --co-sign` with the second key, check with `inveil verify --role update --min-signatures 2`, and upload with `gh release upload <tag> --clobber`.

The update feed (`update.feed_url`) is the signed envelope `https://github.com/<org>/inveil-app/releases/latest/download/update-manifest.json.sig`, not an unsigned payload; none is published.

Users check a release as described in the README: `gh attestation verify <file> -R <org>/inveil-app`, the signature check in `install.sh`, and `sha256sum -c SHA256SUMS --ignore-missing` (which only detects corruption, since it comes from the same origin as the files).

## Key rotation and compromise

- Rotation: pin the new key next to the old one, publish a release whose manifest carries signatures from both, then drop the old key. Clients with the old key list keep working until they update.
- Compromise: follow the runbook in [SECURITY.md](../SECURITY.md). Revoke by listing the key in `revoked_key_ids` of the next signed manifest, and re-pin through a fresh install script for devices that cannot update.

## Forks

A fork can run the same workflow with its own keys.

1. Generate your own update keys (above) and set the secrets and variables in your own `release-platform-signing` and `release-manifest-signing` environments.
2. Change the brand strings in [`crates/inveil/src/brand.rs`](../crates/inveil/src/brand.rs) and the repository URL in the workspace `Cargo.toml` and `scripts/install.sh` / `scripts/install.ps1` (`GITHUB_RELEASES_URL`). The name and logo are not licensed for forks ([TRADEMARKS.md](../TRADEMARKS.md)).
3. Point clients at your feed and keys: `update.feed_url` (the signed `update-manifest.json.sig`) and `update.pinned_keys` in configuration, and template the install scripts with `render-installers.sh`. `INVEIL_UPDATE_PUBLIC_KEYS` only works with `INVEIL_INSTALL_TESTING=1`, for tests.
4. Without signing secrets your fork still builds and tests; it will not produce signed manifests.

## Repository settings

Set these once, under Settings.

- General: add the description and topics. Social preview: upload [`docs/assets/og.png`](assets/og.png) (1200x630). Regenerate it with `scripts/render-og.sh`; see [assets/README.md](assets/README.md).
- Branches, protect `main`: require a pull request with at least one approving review from a code owner ([`CODEOWNERS`](../.github/CODEOWNERS)), require status checks to pass (select every job of the CI workflow: rustfmt, clippy, tests on every OS, MSRV, cross-check, cargo-deny, docs build, schema drift and the install script job), require branches to be up to date, require signed commits, require linear history, block force pushes and deletions, and include administrators.
- Tags: add a tag ruleset for `v*` that restricts creation to maintainers (a small bypass list, not "anyone with write access"), blocks updates and deletions, and requires linear history. This is the control that matters: a workflow runs from the tagged commit, so anyone who can push a `v*` tag on an old or crafted commit runs that commit's copy of `release.yml`, including any weaker `preflight`. The tip-of-`main` check in `preflight`, the environment branch/tag restrictions and the required reviewers all help, but a tag nobody else can create is what keeps them honest. Also set the environments' deployment protection ("Deployment branches and tags") to `main` and `v*`, so a signing job cannot start from any other ref.
- Code security: enable private vulnerability reporting, Dependabot alerts and security updates, and secret scanning with push protection.
- Actions: set the default workflow permissions to read-only, and allow only the actions pinned in the workflows.
- Issues: sync labels from [`.github/labels.yml`](../.github/labels.yml) and add `good first issue` and `help wanted`.
