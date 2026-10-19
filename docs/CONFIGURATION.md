# Configuration

Settings are layered, highest priority first: command-line flags, `INVEIL_*` environment variables, `inveil.toml`, built-in defaults. Environment variables exist for the keys listed below. The file is strict: an unknown key is an error at startup, not a silent no-op. An annotated copy is in [`examples/inveil.toml`](../examples/inveil.toml).

The per-user file is `inveil.toml` in the per-user data directory (`~/Library/Application Support/inveil` on macOS, `$XDG_DATA_HOME/inveil` or `~/.local/share/inveil` on Linux, `%LOCALAPPDATA%\inveil` on Windows); `--config FILE` uses that file instead. inveil never looks for a configuration file in the current directory: a cloned repository that ships an `inveil.toml` would otherwise control the trust roots (`backend.pinned_keys`, `update.feed_url`, `update.pinned_keys`, `update.mode`), `rules_file`, `data_dir` and `failure_modes` of whoever runs `inveil update`, `run` or `doctor` there. `inveil init` writes a starting file (and `rules.example.json`) into the current directory, or to the path given by `--config`, and says how to use it: pass it with `--config` or move it to the per-user directory. The system-wide file is `inveil.toml` in `/Library/Application Support/inveil` (macOS), `/etc/inveil` (Linux) or the Windows ProgramData folder plus `\inveil` (usually `C:\ProgramData\inveil`), writable only by administrators. On Windows that folder is read from the machine registry (`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`, value `ProgramData`), never from the `ProgramData` environment variable, which a standard user can set for their own processes; this is untested on a real Windows machine. Both files are read and merged table by table; other values, arrays included, are replaced. When the system-wide file sets `mode = "managed"`, it locks every key except the few listed under [User-adjustable keys in managed mode](#user-adjustable-keys-in-managed-mode): `mode`, `offline`, `rules_file`, `backend`, `auth`, `usage`, `update`, `data_dir`, `state_keychain`, `listen`, `upstream`, `dry_run`, `failure_modes`, `block_unscannable`, `browser_fail_closed`, `deny`, `limits`, `notify` and `logging.audit_file`. The per-user file, the `INVEIL_*` variables and flags cannot change a locked key, and a locked key the system-wide file does not set keeps its default. In particular `dry_run` is `false` in managed mode unless the system-wide file or the signed settings say otherwise, so a user cannot switch enforcement off with `--dry-run` or `INVEIL_DRY_RUN`.

### Environment variables

| Variable | Key |
|---|---|
| `INVEIL_MODE` | `mode` |
| `INVEIL_OFFLINE` | `offline` |
| `INVEIL_RULES_FILE` | `rules_file` |
| `INVEIL_BACKEND_URL` | `backend.url` |
| `INVEIL_BACKEND_RULES_PATH` | `backend.rules_path` |
| `INVEIL_AUTH_MODE` | `auth.mode` |
| `INVEIL_UPSTREAM` | `upstream` |
| `INVEIL_DRY_RUN` | `dry_run` |
| `INVEIL_BLOCK_UNSCANNABLE` | `block_unscannable` (alias, see [Failure modes](#failure-modes)) |
| `INVEIL_MAX_TOKENS` | `max_tokens` |
| `INVEIL_BROWSER_FAIL_CLOSED` | `browser_fail_closed` |
| `INVEIL_NOTIFY` | `notify` |
| `INVEIL_LISTEN_PORT` | `listen.port` |
| `INVEIL_BROWSER_PORT` | `listen.browser_port` |
| `INVEIL_USAGE_SINK` | `usage.sink` |
| `INVEIL_LOG_LEVEL` | `logging.level` |
| `INVEIL_LOG_FILE` | `logging.file` |
| `INVEIL_AUDIT_FILE` | `logging.audit_file` |
| `INVEIL_DATA_DIR` | `data_dir` |
| `INVEIL_DEBUG` | `1` turns on debug lines, `trace` also turns on trace lines |


### User-adjustable keys in managed mode

`max_tokens` (merged with the signed limit by taking the smaller non-zero value), `logging.level`, `logging.file`, `logging.debug` and `logging.trace` (debug still needs the signed `allow_debug`). The lock list is one table in [`crates/inveil/src/config/load.rs`](../crates/inveil/src/config/load.rs), and a test fails if a configuration key is in neither list, so a new key cannot be left unlocked by accident.

### Enrolled devices

A client enrolled through an organisation email invite (`auth.mode = "enrolled"`) with a `backend.url` is a Team device: it follows the organisation's signed settings like a managed one, except that it starts on the built-in rules before its first fetch, even though `mode` is not `managed`. Local `dry_run = true` and local `open` failure modes (including the legacy `block_unscannable = false` and `browser_fail_closed = false`) are ignored, with a warning at startup naming each key; they are not refused, so existing installs keep starting. Local `offline = true` is ignored unless the signed settings set `allow_offline` (no warning is logged). The trust anchors (`backend.url`, `backend.pinned_keys`, `backend.root_keys`) stay local.

The difference from MDM (`mode = "managed"` in the system-wide file) is where the file lives. A Team device has no system-wide file (a `mode = "managed"` in the per-user file or environment does not turn it into an MDM device), so the per-user configuration still applies to the keys the signed settings do not govern, and a local `open` is ignored rather than refused. An MDM device refuses a local `open` at startup and locks the keys listed above.

## Local only and server-enforced

The trust root (backend URL and pinned keys) can only come from local configuration, never from the backend. Other policy settings can also arrive in the signed snapshot's `settings`. The client merges the two and never lets local configuration loosen anything: `dry_run = false` from the server forces enforcement, `deny` lists are unioned, `max_tokens` takes the lowest non-zero value, and `allowed_upstreams` must contain the local `upstream`. Failure modes are the one setting the signed policy may loosen (see [Failure modes](#failure-modes)); local configuration can only tighten them.

## Reference

Types and defaults match [`crates/inveil/src/config.rs`](../crates/inveil/src/config.rs).

### Top level

| Key | Type | Default | Notes |
|---|---|---|---|
| `mode` | `standalone` or `managed` | `standalone` | Who owns policy. |
| `offline` | bool | `false` | No network at all. On a managed or enrolled client honoured only if signed `allow_offline` is true. |
| `rules_file` | path | unset | Local signed snapshot used instead of a backend. |
| `upstream` | string | `https://api.anthropic.com` | Default upstream of the API proxy. Server: `allowed_upstreams`. |
| `dry_run` | bool | `false` | Log findings, forward unchanged. Server: `dry_run`. |
| `block_unscannable` | bool | unset | Alias for `failure_modes.unscannable`: `true` is `closed`, `false` is `open` (Solo only; ignored on an enrolled client, refused in managed mode). Unset: unscannable requests are blocked unless the signed policy says `open`. |
| `deny` | array of regex | `[]` | Extra blocked patterns. Server: `deny` (union). |
| `max_tokens` | integer | `0` | 0 is no limit. Server: `max_tokens` (lowest non-zero). |
| `browser_fail_closed` | bool | unset | Alias for `failure_modes.service_down`: `true` is `closed`, `false` is `open` (Solo only; ignored on an enrolled client, refused in managed mode). |
| `notify` | bool | `true` | Desktop notifications. Local only. |
| `data_dir` | path | per-user directory | State, CA, cache and logs. Local only. |
| `state_keychain` | bool | `true` | Anchor the anti-rollback state (snapshot high-water mark, revoked key ids, newest update seen) in the OS keychain, which also holds the key that authenticates every record, so a deleted, restored or forged file in `data_dir` is refused. Turn off only where no keychain exists. Locked in managed mode. Local only. |

### `[failure_modes]`

Each key takes `"open"` or `"closed"`. Unset keys follow the resolution order in [Failure modes](#failure-modes).

| Key | Type | Default | Notes |
|---|---|---|---|
| `default` | `open` or `closed` | unset | Used for every condition below without its own entry. |
| `unscannable` | `open` or `closed` | unset | Requests that cannot be read or scanned. |
| `scan_error` | `open` or `closed` | unset | Internal scanner failures. |
| `policy_expired` | `open` or `closed` | unset | Requests after the snapshot expired with no fresh one. |
| `service_down` | `open` or `closed` | unset | The browser PAC fallback while inveil is down. |

In `managed` mode `"open"` is refused at startup; only the signed policy can choose it. An enrolled client ignores a local `"open"` with a warning instead. In a Solo setup `"open"` is yours to choose, unless the signed policy sets the same condition.

### `[backend]`

| Key | Type | Default | Notes |
|---|---|---|---|
| `url` | string | unset | Unset means offline with built-in rules. Must be `https://`, loopback, or `allow_insecure_http = true`. Local only. |
| `rules_path` | string | `/v1/rules` | Local only. |
| `enroll_path` | string | `/v1/enroll` | Local only. |
| `poll_minutes` | integer | `30` | Server: `min_poll_seconds` raises the floor. |
| `pinned_keys` | array of `{ key_id, public_key }` | `[]` | Keys allowed to sign rules (base64 Ed25519). Local only, trust root. |
| `root_keys` | array of `{ key_id, public_key }` | `[]` | Offline keys that may certify short-lived policy keys. Local only, trust root. |
| `allow_insecure_http` | bool | `false` | Permit plain `http://`. Local only. |

### `[auth]`

| Key | Type | Default | Notes |
|---|---|---|---|
| `mode` | `none`, `static_token`, `enrolled`, `device_flow` | `none` | Local only. |
| `token_env` | string | unset | Environment variable holding the token for `static_token`; the OS keychain is used when unset. |

`[auth.device_flow]`, used only for `device_flow`:

| Key | Default |
|---|---|
| `client_id` | `inveil-client` |
| `code_path` | `/api/auth/device/code` |
| `token_path` | `/api/auth/device/token` |
| `session_path` | `/api/auth/get-session` |
| `jwt_path` | `/api/auth/token` |

### `[listen]`

| Key | Default | Notes |
|---|---|---|
| `port` | `8787` | Localhost API proxy. It also serves `/proxy.pac` (the PAC file browsers fetch) and `GET /health` (`{"version": "...", "policy_version": N}`, loopback `Host` only). |
| `browser_port` | `8788` | Localhost browser proxy. The PAC points browsers here; the PAC itself is served on `port`. |

Both listeners bind `127.0.0.1` only.

### `[limits]`

| Key | Type | Default | Notes |
|---|---|---|---|
| `max_body_bytes` | integer | `33554432` (32 MiB) | Largest request body read for scanning. A larger body is blocked as unscannable (or passed and audited when `unscannable` is `open`). |
| `max_decoded_bytes` | integer | `67108864` (64 MiB) | Largest a compressed body may expand to while being scanned. Same handling. |

Both must be at least 1. Local only.

### `[usage]`

| Key | Type | Default | Notes |
|---|---|---|---|
| `sink` | `http`, `file`, `none` | `none` | Server: `usage_reporting` (`required` forces reporting, `disabled` forbids it, `optional` leaves it local) and `heartbeat_seconds`. A managed or enrolled (`auth.mode = "enrolled"`) client with a `backend.url` reports to the backend under that setting whatever the local sink says: `required` sends events and heartbeats, `optional` sends heartbeats only (and events too if the local sink is `http`; on an enrolled device `file` or `none` send heartbeats only), `disabled` sends nothing. `heartbeat_seconds` defaults to 300. A Solo client sends only what its sink says. |
| `path` | string | `/v1/usage` | Backend path for `http`. |
| `file` | path | unset | Target for `file`. |

### `[logging]`

| Key | Type | Default | Notes |
|---|---|---|---|
| `level` | string | unset | Log filter. |
| `debug`, `trace` | bool | `false` | Metadata only, never content. Server: `allow_debug`. |
| `file` | path | unset | Log file. |
| `audit_file` | path | unset | JSONL stream of decisions. |

### `[update]`

| Key | Type | Default | Notes |
|---|---|---|---|
| `mode` | `off`, `notify`, `download`, `install` | `notify` | See [UPDATER.md](UPDATER.md). |
| `feed_url` | string | unset | Must be `https://` and point at the signed envelope, for example `https://github.com/<org>/inveil-app/releases/latest/download/update-manifest.json.sig`. Required when `mode` is `notify`, `download` or `install`: `inveil update` fails with "update.feed_url is not set" without it. |
| `channel` | string | `stable` | |
| `check_hours` | integer | `24` | |
| `pinned_keys` | array of `{ key_id, public_key }` | `[]` | Keys allowed to sign update manifests. The `update` section of an enrollment bundle carries these. |
| `min_signatures` | integer | `2` with two or more distinct `pinned_keys`, else `1` | Distinct update keys that must sign a manifest, whatever `threshold` the manifest states: a manifest can ask for more, never fewer. An explicit value wins over the default; the official bundle sets `2`. Must be at least 1 and no more than the number of `pinned_keys`. Local only. |

## Validation

The configuration is validated at startup and an error exits with a message naming the key. Among the checks: a `backend.url` must be `https://` (or loopback, or `allow_insecure_http`) and needs at least one pinned or root key; `rules_file` needs pinned keys; paths must start with `/`; `poll_minutes` must be at least 1; the two ports must be set and different; `upstream` must be `https://` or loopback; `usage.sink = "file"` needs `usage.file`; `usage.sink = "http"` and any `auth.mode` other than `none` need `backend.url`; `update.feed_url` must be `https://`.

## Failure modes

When inveil cannot make a normal decision, each condition resolves to `open` (let the traffic through) or `closed` (block it):

| Condition | When | Where it is applied |
|---|---|---|
| `unscannable` | The body cannot be read or scanned: unknown content encoding, not JSON, over the decoded-size limit, undecodable frame | At request time, by the client |
| `scan_error` | The scan task failed internally | At request time, by the client |
| `policy_expired` | The snapshot passed `expires_at` and no fresh one could be fetched | At request time, by the client |
| `service_down` | inveil is not running | When routing is written: the browser PAC served at `/proxy.pac` ends with `; DIRECT` for `open` and does not for `closed`. The API base-URL route is naturally closed (the connection is refused) |

A condition resolves, in order, to: (1) `closed` if local configuration says `closed` (for the condition or in `failure_modes.default`), which can always tighten; (2) the signed `failure_modes` entry for the condition, then the signed `failure_modes.default`, `open` or `closed`; (3) `closed` if a legacy signed flag asks for it (`block_unscannable`, `fail_closed_on_expiry`, `browser_fail_closed`); (4) `open` from local configuration, but only for a Solo setup (no enrolled device credential, not `managed`) and only for a condition the signed policy left alone (a specific local entry beats the local `default`); (5) the built-in mode, `closed` for the three request-time conditions and `open` for `service_down`. When the system-wide file declares `managed`, a local `open` is refused at startup, because only the signed policy may loosen a mode. On an enrolled (Team) client a local `open` is ignored with a warning at startup, and the client keeps starting. In `standalone` mode without enrollment (Solo), where one person is both administrator and user, local `open` is the owner's choice, but it never overrides a value the signed policy sets. The signed `failure_modes` entries take precedence over the legacy flags. The legacy local keys `block_unscannable` and `browser_fail_closed` are aliases for `failure_modes.unscannable` and `failure_modes.service_down`: `true` is `closed`, `false` is `open` (Solo only: ignored with a warning on an enrolled client, refused in managed mode; the `[failure_modes]` table wins over `false`). The resolved modes are part of `effective_config_hash`, are logged at startup and are reported in the usage `client` block.

Every request passed because a mode is `open` writes an audit line with `"action":"fail_open"` and the `condition`, and is counted in `fail_open_count` of the next usage batch or heartbeat (a running total since the client started). A body that could not be buffered at all (read error or over `limits.max_body_bytes`) is always blocked, because there is nothing left to forward. The built-in rules never expire, so `policy_expired` only applies to signed snapshots.

The Claude Code route is not covered yet: a stopped service stays closed there until a watchdog exists.

## Settings with no local key

`min_client_version` is only checked against the running version.
