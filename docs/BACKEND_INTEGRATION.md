# Adopting the contract in an existing backend

This guide is for teams that already run a backend with its own authentication, rule storage and usage pipeline and want to serve Inveil contract v1 from it. It is language neutral. If you only need a static signed file, read [SELF_HOSTING.md](SELF_HOSTING.md) instead. The wire shapes are defined in [CONTRACT.md](CONTRACT.md) and [`contract/v1/openapi.yaml`](../contract/v1/openapi.yaml); the JSON Schemas in [`contract/v1`](../contract/v1) are generated from the Rust types and are the machine-readable reference.

## What to build

| Endpoint | Required | Purpose |
|---|---|---|
| `GET /v1/rules` | yes | Returns a signed envelope whose payload is a `Snapshot`. Supports `ETag` and `If-None-Match`. |
| `POST /v1/enroll` | optional | Exchanges an enrollment token for a device credential. Not needed with `auth.mode = static_token`. |
| `POST /v1/usage` | optional | Receives usage metadata batches. Not needed when `settings.usage_reporting` is `disabled`. |

Paths are configurable in the client, so you can mount these next to your existing routes without renaming anything.

Map your existing concepts onto the contract in one place: a function that takes your stored rule set and the caller's organisation and returns a contract `Snapshot`. Keep that translation covered by a test that validates the output against the JSON Schema and verifies the signed result against the vectors in `contract/v1/vectors`.

Points where an existing data model usually differs:

- Field names are snake_case and parsing is strict: unknown fields are rejected. Drop any extra attributes your storage keeps (display metadata, vendor labels, internal ids) when you build the payload.
- Timestamps are Unix seconds as integers.
- Rules, tools and settings are plain data. Tools carry an `env_var` the installer points at the local proxy.

## Producing signed envelopes

A response body is `{ "payload": "<json string>", "signatures": [{ "key_id": "...", "signature": "<base64>" }] }`.

1. Serialise the snapshot to a JSON string once. The `payload` field holds that exact string and is never re-encoded or reformatted after signing.
2. Sign the bytes `"inveil-policy-v1\0" || payload` with Ed25519. The domain prefix is part of the signed message so a signature made for one role cannot be replayed as another. See [signing domains](CONTRACT.md#signing-domains).
3. Put the signature, base64 encoded, in `signatures` with the `key_id` clients pin in `backend.pinned_keys`.
4. Set the `ETag` header to the quoted lower-case hex SHA-256 of the payload string. Answer `304` when `If-None-Match` matches.

Key custody decides how much a backend compromise costs. In order of preference:

- A key in a KMS or HSM that supports Ed25519, called by a small signing service that logs every signature. The web tier never holds key material.
- An offline root key that signs short-lived delegations for an online policy key (see below).
- A key held by an administrator who signs with `inveil sign` and uploads the result. The serving host cannot alter the file.

If your KMS does not support Ed25519, you cannot use it directly; confirm support with your provider before designing around it.

### Snapshot fields that need a decision

- `version`: strictly increasing per audience. Store a counter next to the rule set and increment it on every save. Do not derive it from a timestamp that can repeat.
- `issued_at` and `expires_at`: a snapshot expires, so something must re-issue it. Either sign on request or run a scheduled job that refreshes and stores the signed result. Pick an `expires_at` well beyond the longest outage you will tolerate, or set `settings.failure_modes.policy_expired` to `"open"`. By default an expired snapshot blocks chat traffic.
- `audience`: the organisation id, taken from the verified credential, never from a request parameter. A client enrolled in organisation A rejects a snapshot made for organisation B.

### Delegated signing keys

For a hosted multi-tenant service, avoid a long-lived online policy key.

1. Generate a root key offline and pin it on clients under `backend.root_keys`.
2. Issue a delegation: `key_id`, `public_key`, `not_before`, `not_after` (days, not years), optional `audience`, `root_key_id`, signed by the root under the delegation domain.
3. Return the delegation in the envelope's `delegation` field next to `signatures`.
4. Separate drafting from signing. Admin edits create an unsigned draft. A signing action publishes it, records who and what, and is rate limited. Require a second approver for changes that loosen policy.

Binary updates are never signed by this service. The update key belongs in your release pipeline; see [RELEASING.md](RELEASING.md).

## Enrollment tokens and audience

Enrollment attributes a device to an organisation without any organisation field the client could forge.

1. Store tokens hashed. Columns: `token_hash`, `org_id`, optional `user_id`, `expires_at`, `max_uses`, `uses`, `revoked_at`, `created_by`.
2. In `POST /v1/enroll`, hash the presented token and consume one use atomically, for example `UPDATE tokens SET uses = uses + 1 WHERE token_hash = ? AND uses < max_uses AND revoked_at IS NULL AND expires_at > now` and check that one row changed. Answer every failure (unknown, expired, revoked, exhausted) with the same `403`.
3. Generate a device credential from 32 random bytes, store only its hash, return it once as `{ "device_credential": "...", "expires_at": ..., "org_id": "..." }`. Returning `org_id` lets the client check snapshot audiences.
4. Resolve every later request by credential. The bearer token identifies the device, the device row identifies the organisation and user. Rules and usage are then attributed to the organisation from the credential alone.
5. Revocation is an update of `revoked_at` on the token or credential. The next request fails with `401` or `403`.

See [ENROLLMENT.md](ENROLLMENT.md) for the client-side flow and the bundle format.

## Usage ingest and org attribution

`POST /v1/usage` receives `{ "client": { ... }, "events": [ ... ] }` with at most 100 events.

- Events carry metadata only (provider, model, token counts, latency, status, blocked, findings count). They never carry prompt content.
- Take the organisation and user from the credential, never from the body.
- `client` carries `version`, `policy_version`, `config_hash`, optional `failure_modes` and `fail_open_count`. Store them per device. Flag devices whose `config_hash` differs from the policy you published, or that go silent while `usage_reporting` is `required` or `optional` (enrolled and managed clients heartbeat under both). This is detection, not prevention; see [THREAT_MODEL.md](THREAT_MODEL.md).
- An empty `events` list is a heartbeat. Enrolled and managed clients send one every `heartbeat_seconds` (default 300) unless `usage_reporting` is `disabled`, so the backend can see which devices are alive and which policy version they run.
- Deduplicate on event `id`; clients retry after failures.
- Return any 2xx on success. `400` for malformed batches, `413` above 100 events.

## Settings and failure modes

`settings` is where administrators enforce policy. Local configuration may only make these stricter. Validate the object when it is saved and reject unknown keys. Fields: `dry_run`, `block_unscannable`, `max_tokens`, `deny`, `browser_fail_closed`, `allowed_upstreams`, `min_poll_seconds`, `min_client_version`, `allow_debug`, `usage_reporting`, `heartbeat_seconds`, `allow_offline`, `fail_closed_on_expiry`, and `failure_modes`.

`failure_modes` is `{ default, unscannable, scan_error, policy_expired, service_down }`, each `"open"` or `"closed"`. Each override falls back to `default`. `service_down` cannot be enforced by a stopped process, so it is applied when routing is written. Expose these in the admin interface with plain descriptions, and ask for confirmation when a change loosens something (for example `usage_reporting` to `optional`, or a failure mode to `open`).

## Per-organisation snapshots

Build and sign the snapshot per organisation, using the organisation resolved from the credential. Cache the signed result per organisation and version, and invalidate it when the rule set or settings change. An unauthenticated deployment (`auth.mode = none`) serves a single shared snapshot with no `audience`.

## Admin flow: create an install link

1. Add an admin-only action that creates an enrollment token for the administrator's organisation. Inputs: `max_uses` (1 for a personal link, N for a company-wide link), `expires_in_days`, optional user. Return the plaintext token once.
2. Show the command with the token filled in. The token goes in an environment variable, never an argument:

   ```sh
   curl -fsSL https://app.example.com/install.sh | INVEIL_ENROLL_TOKEN=<token> sh -s -- --enroll
   ```

3. Serve the install scripts from your own origin with your backend URL and pinned keys already filled in. The release workflow renders `install.sh` and `install.ps1` with the project's keys; for your own deployment, render the placeholders in the scripts under [`scripts`](../scripts) with your keys.
4. List existing links with uses and expiry, and provide a revoke action.

## Migrating an existing authentication system

- Keep your current endpoints running unchanged and serve contract v1 on the new paths in parallel. Old clients keep working until you retire them.
- Existing session or device-flow logins can stay as `auth.mode = "device_flow"` with the paths set under `auth.device_flow`. Move devices to `"enrolled"` when you are ready; the credential check is the only part of your auth that changes, and it can accept both token kinds side by side.
- If you reuse an existing Ed25519 key as the policy key, old and new signatures verify against the same public key. The domain prefix differs, so a legacy signature never verifies as a v1 one.
- Announce a date for removing legacy routes and check their traffic before removal.
