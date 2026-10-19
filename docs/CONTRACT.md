# Contract v1

The contract is what a backend implements for the Inveil client. The Rust types in [`crates/contract`](../crates/contract/src) are the source of truth; [`contract/v1/openapi.yaml`](../contract/v1/openapi.yaml) restates them for other languages. JSON Schema files in [`contract/v1`](../contract/v1) are generated from the Rust types by `cargo test -p contract schema` (set `UPDATE_SCHEMAS=1` to rewrite them), and CI fails if they drift.

## Endpoints

Paths are defaults and can be changed in client configuration.

| Method and path | Required | Purpose |
|---|---|---|
| `GET /v1/rules` | yes | Returns a signed envelope whose payload is a `Snapshot`. |
| `POST /v1/usage` | no | Receives metadata-only usage batches (at most 100 events). |
| `POST /v1/enroll` | no | Exchanges an enrollment token for a device credential. See [ENROLLMENT.md](ENROLLMENT.md). |
| `GET /health` | no | Liveness. |
| Device-flow paths | only for `auth.mode = device_flow` | Configurable in `auth.device_flow.*`. Not part of this contract. |

Authentication depends on the client's `auth.mode`: nothing, a static bearer token, a device credential from `/v1/enroll`, or a device-flow access token. All are sent as `Authorization: Bearer <credential>`.

`GET /v1/rules` supports conditional requests. The `ETag` is the quoted lower-case hex SHA-256 of the exact payload string, and the client sends it back in `If-None-Match`. A server that cannot do conditional requests (a static file host) just answers 200 every time. A `304` only counts while the snapshot the client holds is unexpired: once it has expired the client stops sending `If-None-Match` and treats a `304` as an error, so only a newly signed snapshot renews policy. A `304` to a request without `If-None-Match` is also an error.

## Signed envelope

```json
{
  "payload": "{\"schema\":1,\"version\":7, ...}",
  "signatures": [{ "key_id": "policy-1", "signature": "<base64>" }],
  "delegation": null
}
```

- `payload` is a JSON document held as a string. It is signed as is and never re-encoded, so do not reformat it after signing.
- `signatures` holds one entry per signing key. `key_id` selects a pinned key; `signature` is base64 Ed25519.
- `delegation` is optional (hosted mode, below).
- Unknown fields are rejected.

## Signing domains

The bytes that are signed are a role-specific domain prefix followed by the payload bytes (the UTF-8 of the `payload` string). A signature made for one role never verifies for another.

| Role | Domain prefix (ends with a NUL byte) | Signs |
|---|---|---|
| Policy | `inveil-policy-v1\0` | Rules snapshots |
| Update | `inveil-update-v1\0` | Update manifests |
| Delegation | `inveil-delegation-v2\0` | Delegation certificates (`v1` certificates are refused) |

Algorithm for a verifier in any language:

1. Parse the envelope (strictly). Take `payload` as raw bytes.
2. Build the candidate key set: the pinned keys, plus the delegated key if `delegation` is present, its `root_key_id` is a pinned root, the current time is within `not_before` and `not_after` (for a cached snapshot that was accepted before, `issued_at` instead of the current time, see below), its key id and public key are not revoked, and the root's signature over the delegation fields verifies.
3. For each of the first 16 entries in `signatures` (later ones are ignored), find the candidate with the same `key_id` and verify the Ed25519 signature over `domain || payload`. Count each public key at most once: two pinned ids for the same key are one signer.
4. Require at least the locally required number of valid signatures from distinct keys. For rules that is 1. For an update manifest it is the larger of the manifest's `threshold` and the client's pinned `update.min_signatures`: a manifest can ask for more signers, never fewer.
5. Only now parse `payload` as the expected type.
6. If the signing key came from a delegation that names an `audience`, the snapshot's `audience` must be equal to it; otherwise the snapshot is refused.

**Delegation window and the cache.** A snapshot that has just been fetched is checked against the delegation window at the current time. A cached snapshot is re-read at every start, long after its delegation may have lapsed, so when the client loads its cache it judges the window at the snapshot's own `issued_at`, but only for the exact payload its high-water mark records as accepted. Anything else in the cache is checked at the current time, so a lapsed or leaked delegated key cannot plant a newer snapshot there. The snapshot's own `expires_at` still applies through `failure_modes.policy_expired`.

The delegation signature (domain `inveil-delegation-v2\0`, made by the root key) covers this exact byte string, so no two different delegations encode alike. Lengths and times are big-endian unsigned 64-bit integers:

```
len(key_id) || key_id
len(public_key) || public_key          (the base64 text)
not_before
not_after
0x00                                    when audience is absent
0x01 || len(audience) || audience       when audience is present (an empty audience is present)
len(root_key_id) || root_key_id
```

Public keys are base64 of the raw 32-byte Ed25519 key.

## Rules snapshot

The payload of `GET /v1/rules`.

| Field | Type | Notes |
|---|---|---|
| `schema` | integer | Must be `1`. The client refuses any other value. |
| `version` | integer | Strictly increasing per audience. A lower version, or the same version with different content, is refused. |
| `issued_at`, `expires_at` | integer | Unix seconds. |
| `audience` | string, optional | Organisation id. Refused if it differs from the client's enrolled organisation. |
| `pii` | array of rules | `id`, `label`, `pattern` (Rust `regex` syntax), `validator` (`luhn`, `ssn`, `iban` or null), `action` (`block`, `log`, `redact`), `enabled`. |
| `tools` | array, optional | A tool: `id`, `name`, `via` (`local` or `browser`), `enabled`, `upstream`, `prefix`, `env_var`, `endpoints`, `hosts`. |
| `ca_domains` | array of strings, optional | The only domains the browser CA may cover. |
| `settings` | object, optional | Server-enforced settings, below. |
| `revoked_key_ids` | array of strings, optional | Pinned keys to stop trusting. Honoured only if the snapshot still meets the client's full signature requirement without the revoked keys and leaves at least that many pinned keys; the client then remembers them for good. The client remembers each revoked pinned key by public key as well as by id, and an id or public key revoked this way also bars a delegated key. A refused snapshot revokes nothing. A key cannot be revoked by a snapshot it alone signed. |

An endpoint is `{ path, match: "exact" | "prefix", format }` with format one of `json`, `protobuf`, `protobuf-framed`, `form`, `websocket-json`, `connect-stream`. A host is `{ host, endpoints }`.

Unknown fields anywhere in the payload are rejected. The client also enforces size caps, validates hosts and refuses regexes that compile to something oversized.

### Settings

Local configuration can only make these stricter, never looser. A snapshot without `settings` leaves the client on its last good settings.

| Field | Meaning |
|---|---|
| `dry_run` | `false` forces enforcement. Null leaves the choice local. |
| `block_unscannable` | Legacy. `true` is the same as `failure_modes.unscannable = "closed"` when `failure_modes` says nothing about it. |
| `max_tokens` | Maximum estimated tokens per request. 0 or null: no server limit. Lowest non-zero value wins. |
| `deny` | Extra regexes to block. Unioned with local. |
| `browser_fail_closed` | Legacy. `true` is the same as `failure_modes.service_down = "closed"` when `failure_modes` says nothing about it. |
| `allowed_upstreams` | `https://host` values the local `upstream` must be one of. Empty: unrestricted. |
| `min_poll_seconds` | Floor for the polling interval. |
| `min_client_version` | Oldest client version allowed. |
| `allow_debug` | Whether local debug and trace logging may be enabled. |
| `usage_reporting` | `required`, `optional` or `disabled`. Null means `optional`. |
| `heartbeat_seconds` | With `required`, send a heartbeat at this interval even with no events. |
| `allow_offline` | Whether local configuration may run the client fully offline. |
| `fail_closed_on_expiry` | Legacy. `true` is the same as `failure_modes.policy_expired = "closed"` when `failure_modes` says nothing about it. Default false. |
| `failure_modes` | What to do per failure condition, see below. |

#### `failure_modes`

Each value is `"open"` (pass the traffic and record it) or `"closed"` (block it). All keys are optional.

| Key | Condition |
|---|---|
| `default` | Used for every condition without its own entry. |
| `unscannable` | The request body cannot be read or scanned. |
| `scan_error` | The scanner failed internally. |
| `policy_expired` | The snapshot expired and no fresh one is available. |
| `service_down` | The local service is down. Applied when routing is written (the browser PAC falls back to `DIRECT` for `open`), not at runtime. |

In managed mode local configuration can only choose `closed` and a local `open` is ignored; a standalone owner may choose either locally, and a signed value for the same condition wins over a local `open`. Without a signed or local value the client uses `closed` for the first three and `open` for `service_down`. A signed `failure_modes` value (including `default`) beats the legacy flags above. The resolved modes are part of the effective configuration hash.

## Usage batch

`POST /v1/usage` body:

```json
{
  "client": { "version": "0.1.0", "policy_version": 7, "config_hash": "<hex sha-256>",
              "failure_modes": { "unscannable": "closed", "scan_error": "closed", "policy_expired": "closed", "service_down": "open" },
              "fail_open_count": 0 },
  "events": [
    { "id": "...", "timestamp": 1760000000, "provider": "anthropic", "model": "...",
      "input_tokens": 10, "output_tokens": 20, "latency_ms": 800,
      "status": 200, "blocked": false, "findings": 0 }
  ]
}
```

At most 100 events. No content is ever included. Delivery is at least once, so deduplicate on `events[].id`. The `client` block lets the backend notice a device running a different policy version or a different effective configuration than the one it published. `failure_modes` (optional) lists the resolved mode of every condition, and `fail_open_count` is the number of requests passed through because a mode was `open` since the client started (both additive: older clients omit them, so treat them as absent or 0). The details of each pass-through are in the client's local audit log, not in the batch. With `usage_reporting = required`, a batch with an empty `events` list is a heartbeat.

## Enrollment

`POST /v1/enroll` takes `{ "token", "client_version", "device_label"? }` and returns `{ "device_credential", "expires_at"?, "org_id"? }`. See [ENROLLMENT.md](ENROLLMENT.md).

## Update manifest

Not served by `/v1`: it comes from the update feed. Same envelope, signed under the update domain. The payload has `schema` (1), `channel`, `version` (semver), `published_at`, `expires_at`, optional `min_supported`, `threshold` (distinct pinned update keys that must have signed; the client's own `update.min_signatures` is a floor it cannot lower; when unset it is 2 with two or more distinct pinned update keys and 1 with one), `artifacts` keyed by `<os>-<arch>` (each `{ url, sha256, size }`, a raw binary), optional `notes_url` and `revoked_key_ids`. See [UPDATER.md](UPDATER.md).

## Versioning

- Additive, backwards-compatible fields are allowed within v1 only if older clients can ignore them. Because clients reject unknown fields, an additive field in practice means a client release that understands it first; backends should send new fields only to clients at or above the version that reads them (use `min_client_version` to gate).
- A breaking change moves to `/v2` and `schema: 2`. A client refuses an unknown `schema`.
- The Rust types in `crates/contract` change together with `openapi.yaml`, the generated schemas and the vectors in one pull request.

## Test vectors

[`contract/v1/vectors/`](../contract/v1/vectors) holds signed envelopes generated by a test in the engine crate (`crates/engine/tests/vectors.rs`; the contract crate cannot sign without depending on the engine). `manifest.json` lists the pinned public keys, the signing domain prefixes, the evaluation time (`now`) and the highest accepted snapshot version (`high_water_version`). For each envelope file it states the `role`, the `threshold`, the key ids to pin (`trusted_key_ids`), whether the `signature` verifies, and the `client_outcome`:

| Vector | Signature | Client outcome |
|---|---|---|
| `policy-good`, `policy-good-two-signatures`, `update-good` | valid | accept |
| `policy-expired` | valid | `reject_expired`: `expires_at` is before `now` |
| `policy-lower-version` | valid | `reject_rollback`: `version` is below `high_water_version` |
| `policy-tampered-payload`, `policy-tampered-signature`, `update-tampered` | invalid | `reject_signature` |
| `policy-wrong-key`, `policy-unknown-key-id` | invalid | `reject_signature` |
| `policy-wrong-role`, `update-wrong-role` | invalid | `reject_signature`: signed under another role's domain |
| `policy-below-threshold`, `update-one-signature` | invalid | `reject_signature`: fewer distinct valid signatures than `threshold` |

A backend in any language can check its signer by verifying these files, and its verifier by producing the same outcomes. The vectors do not cover delegations. The signing keys are derived from seeds published in the test source: never use them for anything real. Regenerate with `UPDATE_VECTORS=1 cargo test -p engine --test vectors`; without the variable the same test fails if the committed files differ.
