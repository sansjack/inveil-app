# Updater

The updater only installs a binary that a pinned key signed. It is conservative by default: `update.mode = "notify"` checks and tells the user, and never installs silently.

## Modes

| `update.mode` | Behaviour |
|---|---|
| `off` | No update checks. |
| `notify` (default) | Check the feed on `check_hours`, tell the user, never download. |
| `download` | Also download and verify. Install is a manual step. |
| `install` | Also apply, with automatic rollback. |

Devices enrolled through `install.sh` or `install.ps1` start in `install` mode. The administrator can choose the mode and interval for every device in the signed snapshot (`settings.update.mode`, `settings.update.check_hours`); a value set there replaces the local one in the running service, without a restart. The feed URL, channel, pinned update keys and `min_signatures` never come from the backend: they stay in the local file, so a compromised backend cannot steer a client to a binary its pinned keys did not sign. Clients older than 0.2.2 reject a snapshot that carries `settings.update`, so send it only once the fleet is on 0.2.2 or later. `inveil update` run by hand reads the local file only.

Commands: `inveil update --check` reports without changing anything; `inveil update` follows `update.mode`; `inveil verify <manifest>` checks a manifest against `update.pinned_keys` (the default role is `update`; use `--role policy` for a rules file). For an update manifest `verify` applies the same checks as an install: signatures, expiry, channel (`--channel` overrides `update.channel`), schema, `min_supported`, and that it is not older than the running binary. `--min-signatures N` overrides `update.min_signatures`, and `--artifact <binary>` also compares the file with the signed hash and size.

## Flow

1. Fetch the manifest over https (no redirect to http, size cap, timeout). The feed is the signed envelope (`update-manifest.json.sig`: payload plus signatures) in the update domain. `update.feed_url` must point at that envelope, never at an unsigned payload; releases do not publish one.
2. Verify the signature before anything else. At least `max(manifest threshold, update.min_signatures)` distinct public keys must have signed (two pinned ids for one key count once, and at most 16 signature entries are examined), so a manifest cannot lower the threshold the client pinned. Then check: version is higher than the running one (no downgrade) and not older than the newest ever seen, not expired, the channel matches, a target exists for this OS and architecture, and `min_supported` is consistent. Versions are compared as semver, so `1.2.3-rc.1` is older than `1.2.3`.
3. Download the raw binary named in the manifest to a private temporary directory on the same filesystem as the install directory. Enforce the declared `size` and stream a SHA-256.
4. Verify the hash, run the staged binary once with `--version` (it must start and report the manifest's version; otherwise nothing is installed), then record a pending-update marker next to the executable, move the file into place, and re-hash the installed file so a swap between check and use is caught.
5. Apply atomically. On Unix, rename over the old executable and keep `inveil.prev`. On Windows, rename the running executable to `.old`, move the new one in, delete `.old` on next start. A crash between those two renames leaves no executable; run any other `inveil` (for example `inveil.prev`) as `inveil update --recover` to rebuild it from `inveil.prev` (or `.old` when there is no `inveil.prev`) and clear the marker.
6. Restart, and judge the result. The process that replaces the binary is often the service itself, which the restart kills, so the new binary judges itself:
   - Inside the service (the periodic check) the process exits with status 75, a non-zero status that launchd (`KeepAlive`), systemd (`Restart=on-failure`) and the Task Scheduler (restart on failure) all restart.
   - `inveil update` run by hand restarts the service itself, polls `GET /health` on the API port until it reports the manifest's version, and restores `inveil.prev` if it does not.
   - At every start of the service the marker is read first, before the configuration is loaded or logging starts, so a new binary that fails early is still counted and rolled back. If the installed binary is the pending one, the start is counted; a binary that reports a version other than the manifest's, or that has started more than three times without binding its port, is replaced by `inveil.prev` and the process exits so the supervisor starts the old one. Once the service has bound its port it clears the marker. A marker whose binary is not the installed one (the swap never finished) is discarded.

   The updater does not run while a browser CA or proxy change is in progress. A foreground `inveil run` with no installed service installs the file but does not restart; the next start validates it the same way.

The updater never executes a downloaded installer and never shells out with downloaded data. Archives are for humans only; the updater reads no container formats.

## Manifest

See [CONTRACT.md](CONTRACT.md#update-manifest). Notable fields: `channel` (`stable`, `beta`), `threshold` (distinct pinned update keys that must have signed; official releases use two), `revoked_key_ids`, and per-target `artifacts` entries keyed `<os>-<arch>` such as `macos-aarch64`, `windows-x86_64`, `linux-x86_64`.

## Keys

Update keys are separate from rules keys and live where the web host cannot reach them. The update keys come from `update.pinned_keys`; the install script fills them in for the official build. Forks and self-hosters set their own `update.feed_url` and `update.pinned_keys`, or `update.mode = "off"`. Generate a key with `inveil keygen --out update.key` and sign a manifest with `inveil sign --role update --key update.key --key-id <id> manifest.json`. Add a second signature with `--co-sign envelope.json`. To rotate, the manifest is signed by both the old and new key for one release, then the old key is dropped. Replay protection: the highest accepted manifest version is persisted per channel in `update-state.json`, together with every revoked key id.

`update.min_signatures` (default 2 when two or more distinct update keys are pinned, else 1; the official bundle sets 2) is pinned locally and a manifest cannot lower it. `revoked_key_ids` in a manifest are remembered by public key as well as by id, and are honoured only if it still meets the full requirement without them and leaves enough pinned keys; they are saved only when the manifest is accepted and offers a newer release, never from a manifest that is refused or that offers nothing. Recovery from a compromised or lost key is a local re-pin with a new key id.

The persisted state (`update-state.json`, and for rules `rules.trust-state.json`) carries a counter that is mirrored in the OS keychain. A file that is missing, older or different from the keychain's record is refused with a message that says which files to delete if nobody tampered with it; see [THREAT_MODEL.md](THREAT_MODEL.md#local-state).

## Install script

`install.sh` and `install.ps1` do not rely on the updater. They verify the same signed envelope before executing anything they downloaded, using OpenSSL 3 (`openssl pkeyutl -verify -rawin` over `inveil-update-v1\0` followed by the payload) against the keys pinned in the script, and require at least `MIN_SIGNATURES` (default 2) distinct pinned keys. They then check expiry, channel, that the version is not older than the installed one (unless `--version` pins it), and the binary's SHA-256 and size against the signed manifest entry, and only then run `inveil verify` as a second check. `--min-version <x.y.z>` (`-MinVersion`) refuses a manifest older than the version you name; use it on fresh installs, because a fresh install has no installed version to compare with and the installers check expiry with the local clock only, so an older but unexpired signed manifest would otherwise be accepted (see [ENROLLMENT.md](ENROLLMENT.md#trust-honesty)). The enrollment bundle the scripts build carries `update.min_signatures` (their own minimum, 2 by default) and the signed `update.feed_url`, so the in-app updater enforces the same 2-of-N rule; in managed mode those must also be set in the system-wide file. Stock macOS (LibreSSL) cannot verify Ed25519, so the script needs Homebrew `openssl@3` there and refuses to install otherwise; Windows needs an OpenSSL 3 such as the one in Git for Windows. The script does not evaluate `revoked_key_ids`. The script is itself unauthenticated: its pinned keys are only as trustworthy as the host that served it.

## Platform signatures

Update signing and platform signing are separate. The updater verifies the project signature; the operating system verifies Developer ID and notarisation on macOS and Authenticode on Windows. When the official build is used, the updater also checks the platform signature identity pinned alongside the update keys (planned).

## Failure matrix covered by tests

Tampered manifest, tampered artefact, wrong target, downgrade, expired manifest, truncated download, hash mismatch, key rotation, interrupted apply (rollback), a manifest asking for fewer signers than the local minimum, revocations that would lock out the signer, a binary that will not run, a new binary that never becomes healthy (rolled back at its own start), and a crash mid-apply. The Windows rename-and-restart path and the keychain are not exercised by the test suite on other platforms.
