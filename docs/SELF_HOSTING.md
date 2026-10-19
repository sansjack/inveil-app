# Self-hosting

You do not need to write a backend to use Inveil. The minimum is one signed file on a static web server. The signature means the host cannot change what the client enforces, even if the host is compromised.

You need the `inveil` binary and any static file host.

## Choose a setup

| Setup | You run | Good for |
|---|---|---|
| Local file | Nothing. Set `offline = true` and `rules_file`. | One machine, air-gapped hosts |
| Static file | nginx, S3 or GitHub Pages serving one file | A team that wants one policy file |
| Static file plus enrollment and usage | A small service for `/v1/enroll` and `/v1/usage` | A team that wants per-device credentials and metrics |
| Managed | Any of the above, with `mode = "managed"` and `settings` in the signed file | An administrator who must enforce settings |

## Five-minute static backend

### 1. Generate a policy key

```sh
inveil keygen --out policy.key
```

This writes the private key to `policy.key` (owner-only, never overwrites an existing file) and prints the public key and a suggested `key_id`. Use that id wherever `policy-1` appears below. The private key is base64 PKCS#8 text. Keep it private and off the web host; `*.key` is already in `.gitignore`.

### 2. Write the rules

`rules.json` (the payload). `expires_at` here is one year ahead; you must re-sign before it passes.

```sh
cat > rules.json <<JSON
{
  "schema": 1,
  "version": 1,
  "issued_at": $(date +%s),
  "expires_at": $(( $(date +%s) + 31536000 )),
  "pii": [
    { "id": "ssn", "label": "US Social Security number", "pattern": "\\\\b\\\\d{3}-\\\\d{2}-\\\\d{4}\\\\b",
      "validator": "ssn", "action": "block", "enabled": true },
    { "id": "card", "label": "Payment card number", "pattern": "\\\\b(?:\\\\d[ -]?){13,19}\\\\b",
      "validator": "luhn", "action": "redact", "enabled": true }
  ],
  "tools": [
    { "id": "claude-code", "name": "Claude Code", "via": "local", "enabled": true,
      "upstream": "https://api.anthropic.com", "prefix": null, "env_var": "ANTHROPIC_BASE_URL",
      "endpoints": [{ "path": "/v1/messages", "match": "exact", "format": "json" }],
      "hosts": [] }
  ]
}
JSON
```

The unquoted heredoc makes the shell turn `\\\\` into `\\`, which is the JSON encoding of a single backslash in the regex. Check the result with `grep pattern rules.json`: it should show `\\b\\d{3}`. Every field is described in [CONTRACT.md](CONTRACT.md).

A tool `upstream` in the signed file must be an `https` URL; a snapshot with an `http` upstream (including loopback) is rejected. To test against a local server, keep the real `https` upstream in the signed rules and set the local `upstream` key in `inveil.toml` (for example `upstream = "http://127.0.0.1:9000"`), which redirects the tool's traffic to your test server. [`scripts/demo.sh`](../scripts/demo.sh) does exactly this.

Raise `version` every time you change the file. Clients refuse a lower version, and the same version with different content.

### 3. Sign it

```sh
inveil sign --role policy --key policy.key --key-id policy-1 rules.json > rules.signed.json
```

`rules.signed.json` is the envelope the client downloads. Do not edit it after signing. `inveil sign` parses the payload strictly first, so a typo is reported here instead of on every client. `--key` also accepts `env:NAME` to read the key from an environment variable.

### 4. Serve it

nginx:

```nginx
server {
    listen 443 ssl;
    server_name inveil.example.com;
    # ssl_certificate and ssl_certificate_key as usual

    location = /v1/rules {
        alias /srv/inveil/rules.signed.json;
        default_type application/json;
        add_header Cache-Control "no-cache";
    }
}
```

S3 (put CloudFront or another https front in front of the bucket; the client needs https):

```sh
aws s3 cp rules.signed.json s3://my-bucket/v1/rules \
  --content-type application/json --cache-control no-cache
```

The client calls `GET /v1/rules`. A static host will not answer conditional requests the way the contract describes; it sends the whole file each poll, which the client accepts.

### 5. Point the client at it

`inveil.toml`:

```toml
[backend]
url = "https://inveil.example.com"

[[backend.pinned_keys]]
key_id = "policy-1"
public_key = "PASTE_THE_BASE64_PUBLIC_KEY"
```

Then run `inveil run`. A backend URL must come with at least one pinned key, or the configuration is rejected at startup. Check a signed file against the pinned keys with `inveil verify rules.signed.json --role policy`.

To use a local file without any server, set `offline = true` and `rules_file = "/path/to/rules.signed.json"` instead of `[backend]`.

## Operating it

- Re-sign before `expires_at`. After expiry the client blocks chat traffic by default (`settings.failure_modes.policy_expired = "closed"`); set it to `"open"` to keep using the last good snapshot, with each request audited as `fail_open`. A cron job that bumps `version`, `issued_at` and `expires_at`, signs and uploads is enough.
- Rotate keys by pinning the new key next to the old one in client configuration, signing with the new `key_id`, then removing the old pin. List a retired key in `revoked_key_ids` of the next snapshot. Compromise steps are in [SECURITY.md](../SECURITY.md).
- Keep `policy.key` on an admin machine or in a secrets manager, never on the web host.

## Optional endpoints

### Usage

`POST /v1/usage` receives metadata-only batches. Skip it by leaving `usage.sink = "none"` (Solo) or by setting `settings.usage_reporting = "disabled"` (Team and MDM; otherwise an enrolled client still heartbeats). To collect metrics without a server, use `usage.sink = "file"` and ship the JSON lines yourself. The batch format is in [CONTRACT.md](CONTRACT.md).

### Enrollment

If you want a credential per device (so you can revoke one laptop and attribute usage), implement `POST /v1/enroll` and set `auth.mode = "enrolled"`. If one shared secret is enough, skip enrollment and use `auth.mode = "static_token"` with the token in the environment variable named by `auth.token_env`. See [ENROLLMENT.md](ENROLLMENT.md).

## Solo, Team or MDM

- Solo (default): you are administrator and user. Every setting is local and nothing needs to be enforced by the signed file.
- Team: devices enrolled through an invite (`auth.mode = "enrolled"`) follow the `settings` in the signed file; their local `dry_run = true` and `open` failure modes are ignored. No system-wide file is needed.
- MDM: an administrator owns policy. Add a `settings` object to the payload (for example `"dry_run": false`, `"usage_reporting": "required"`, `"allowed_upstreams": ["https://api.anthropic.com"]`), set `mode = "managed"`, and install the configuration in the system-wide location so standard users cannot edit it: `/Library/Application Support/inveil` on macOS, `/etc/inveil` on Linux, `%ProgramData%\inveil` on Windows. Local settings can only tighten what the signed file sets. This deters accidents and casual bypass; it does not stop a local administrator (see [THREAT_MODEL.md](THREAT_MODEL.md)).
