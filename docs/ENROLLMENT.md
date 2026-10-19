# Enrollment

Enrollment binds an installed client to an organisation on your backend without rebuilding the binary. There is one signed binary for everyone; the organisation comes from an enrollment bundle and a server-issued device credential.

Enrollment is optional. A self-hoster can skip it and use `auth.mode = "none"` or `auth.mode = "static_token"`. See [SELF_HOSTING.md](SELF_HOSTING.md).

## Why not a per-organisation build

Embedding an organisation key in the binary after signing breaks Authenticode and macOS notarisation, needs a signing pipeline per organisation, and the key is extractable from the binary anyway. The organisation identity for metrics comes from the device credential, which the backend ties to the organisation.

## Flow

1. An administrator creates an enrollment token on the backend (per user, or one shared by many users).
2. The install script builds the bundle (`enrollment.json` content) and pipes it to `inveil enroll --bundle` on standard input; by hand you can pass a file.
3. The client sends `POST /v1/enroll { token, client_version, device_label? }`.
4. The backend validates the token, derives the organisation (and optionally the user), and returns `{ device_credential, expires_at?, org_id? }`.
5. The client stores the credential and the `org_id` in the OS keychain and discards the token. From then on it rejects any rules snapshot whose `audience` is not that `org_id`, so a snapshot (or a delegated signing key) made for another organisation cannot be replayed here. A backend that omits `org_id` gets no audience binding.
6. Every later `GET /v1/rules` and `POST /v1/usage` carries the credential as a bearer token. The backend attributes usage from the credential, so there is no organisation field in a request that the client could forge.

An enrolled device is a Team device: it follows the organisation's signed `settings` (see [Enrolled devices](CONFIGURATION.md#enrolled-devices)), and it sends a heartbeat to `POST /v1/usage` unless `usage_reporting` is `disabled`. To fetch new rules right away, run `inveil refetch`.

Revoking a device credential stops its rules and usage immediately.

## Token properties

The backend decides these; the client only forwards the token.

- Opaque, 256 bits of randomness, stored hashed on the server.
- Bound to an organisation.
- Expires (for example 7 days).
- Maximum uses: 1 for a per-user link, N for a company-wide link.
- Revocable.
- Answer every failure (unknown, expired, revoked, used up) with the same 403 so tokens cannot be probed.

A hardware identifier is optional and off by default. If you collect one, check your data-protection obligations first.

## Bundle format

`enrollment.json` carries the same information as the bootstrap configuration. Unknown fields are rejected.

```json
{
  "backend_url": "https://inveil.example.com",
  "pinned_keys": [{ "key_id": "policy-1", "public_key": "<base64 Ed25519>" }],
  "enrollment_token": "<opaque token>",
  "auth": { "mode": "enrolled" },
  "update": {
    "feed_url": "https://updates.example.com/update-manifest.json.sig",
    "pinned_keys": [{ "key_id": "update-1", "public_key": "<base64 Ed25519>" }],
    "min_signatures": 2
  }
}
```

| Field | Required | Maps to |
|---|---|---|
| `backend_url` | yes | `backend.url` |
| `pinned_keys` | yes | `backend.pinned_keys`: the policy keys. Each entry is `{ key_id, public_key }`. |
| `enrollment_token` | yes | Redeemed once with `POST /v1/enroll`, then discarded. |
| `auth` | no | `[auth]`. Defaults to `{ "mode": "enrolled" }`. |
| `update` | no | `[update]`: `feed_url`, `pinned_keys` (`keys` is accepted as an alias) and `min_signatures`. `feed_url` must be the signed envelope, `.../update-manifest.json.sig`, never an unsigned payload. `min_signatures`, when omitted, defaults on the client to 2 once the bundle pins two or more distinct update keys (and 1 for a single key); an explicit value always wins. The install scripts always write all three: the pinned update keys, the minimum they themselves enforced (2 unless you passed `--allow-single-signature`) and the stable signed feed URL (for the beta channel, the versioned release URL). |

### Managed mode

In managed mode the `[update]` table must come from the system-wide file (see [CONFIGURATION.md](CONFIGURATION.md)), which locks `update`. The bundle is written to the per-user `inveil.toml`, whose `[update]` table a managed client ignores, so a managed fleet has to put `feed_url`, `pinned_keys` and `min_signatures = 2` in the system-wide file through MDM. Relying on the install script's bundle alone puts the update keys in the per-user file, which Solo and Team installs read; only MDM locks them in the system-wide file.

Run `inveil enroll --bundle enrollment.json`, or `inveil enroll --bundle -` to read the bundle from standard input, which is how the install scripts pass it so the token never touches disk or a command line. The installer option `--bundle <file>` / `-Bundle <file>` is different by design: it passes your file to `inveil enroll` as it is, so the one-time token stays on disk wherever you put it. Delete the file after enrolling (the installer reminds you), and prefer `INVEIL_ENROLL_TOKEN` when you can. The configuration is written to the per-user `inveil.toml` (or the file given by `--config`) only after the backend accepted the token. The device credential and the organisation id returned by the backend go to the OS keychain. A self-hoster can write the bundle by hand.

## Install script

`install.sh` (macOS, Linux) and `install.ps1` (Windows) are attached to every release, rendered at release time with the project's pinned update keys. The copies in [`scripts/`](../scripts) are templates. Whoever runs a backend can render them with their own keys and backend URL (`.github/scripts/render-installers.sh`) and host them.

Pass the token in the `INVEIL_ENROLL_TOKEN` environment variable, never as an argument, so it does not appear in process listings or shell history:

```sh
curl -fsSL https://app.example.com/install.sh | INVEIL_ENROLL_TOKEN=<token> sh -s -- --enroll
```

The `iwr | iex` one-liner cannot take parameters. On Windows run the script as a script block, as shown in the header of `install.ps1`:

```powershell
$env:INVEIL_ENROLL_TOKEN = '<token>'
& ([scriptblock]::Create((Invoke-WebRequest -UseBasicParsing https://app.example.com/install.ps1).Content)) -Enroll
```

What the script does, in order: detects OS and architecture and refuses unknown ones; downloads the signed manifest (`update-manifest.json.sig`) and verifies its Ed25519 signatures with OpenSSL 3 against the keys pinned in the script, requiring a minimum number of distinct keys; checks expiry and channel; downloads the binary and checks its SHA-256 and size against the signed entry; only then runs `inveil verify` from the binary as a second check, installs to the per-user directory without administrator rights, and runs `inveil enroll` with the bundle on standard input and `inveil install`. It prints the pinned key fingerprints so you or your MDM can compare them.

Flags (`install.sh`, then `install.ps1`):

| `install.sh` | `install.ps1` | Meaning |
|---|---|---|
| `--enroll` | `-Enroll` | Enroll using the token in `INVEIL_ENROLL_TOKEN`. |
| `--bundle <file>` | `-Bundle <file>` | Enroll from an `enrollment.json` file instead of a token. |
| `--backend-url <url>` | `-BackendUrl <url>` | Backend for enrollment: https, or http only for `localhost`, `127.0.0.1` or `[::1]`. The URL is parsed, and userinfo (`http://localhost:1@evil.com`) is refused. |
| `--pinned-key <id=b64>` | `-PinnedKey <id=b64>` | Policy public key for enrollment; repeatable. |
| `--no-enroll` | `-NoEnroll` | Install the binary only. |
| `--version <x.y.z>` | `-Version <x.y.z>` | Install exactly this release; also permits an older one. |
| `--min-version <x.y.z>` | `-MinVersion <x.y.z>` | Refuse a signed manifest older than this version. A "latest known version" hint; see below. |
| `--channel <name>` | `-Channel <name>` | `stable` (default) or `beta`; `beta` requires a version. |
| `--allow-single-signature` | `-AllowSingleSignature` | Accept a script rendered with fewer than 2 signatures (self-hosters with one update key). |
| `--uninstall` | `-Uninstall` | Run `inveil uninstall` and remove the binary. |
| `--dry-run` | `-DryRun` | Print what would happen. |
| `-h`, `--help` | | Show help. |

Safety properties: the whole script runs inside a function so a truncated download executes nothing, https only, no `sudo`, no `eval` of downloaded data, a private temporary directory removed on exit, and re-running upgrades in place.

## Trust honesty

Replay on a fresh install: the installers check the manifest's expiry against the local clock, and an older manifest that has not expired is still validly signed. With nothing installed there is no version to compare with, so whoever controls the download path could serve an older, still-valid release, with its known bugs. The signed manifest at the stable URL is the latest release, but the installer cannot tell it is looking at the stable URL's content. Pass `--min-version`/`-MinVersion` with the newest version you know of (from the release notes or your MDM policy) to refuse anything older, and keep manifest validity short (the release workflow uses 180 days). After the first install the updater's persisted high-water mark prevents any rollback.

`curl | sh` is as trustworthy as the origin serving the script. The script verifies the signed manifest against its embedded keys before it executes anything, but those keys are the trust root: a compromised host serving `install.sh` can serve a script with its own keys. Compare the printed fingerprints with the release notes out of band. `SHA256SUMS` is served from the same origin as the binaries, so it detects corruption only.

If that is not enough, verify manually, leading with the attestation:

1. Download the binary, `SHA256SUMS` and `update-manifest.json.sig` from the release.
2. `gh attestation verify <file> -R sansjack/inveil-app`. Optionally `sha256sum -c SHA256SUMS --ignore-missing` to catch corruption.
3. Put `enrollment.json` next to the binary and run `inveil enroll --bundle enrollment.json`, then `inveil install`.

## MDM and packages

For fleets, push the binary and `enrollment.json` with your MDM (Jamf, Intune, a pkg or MSI) and run `inveil enroll --bundle <path>` then `inveil install` as the logged-in user. Install the managed configuration (`mode = "managed"`) in the system-wide location so standard users cannot edit it. See [THREAT_MODEL.md](THREAT_MODEL.md) for what that does and does not guarantee.
