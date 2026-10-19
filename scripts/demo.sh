#!/bin/sh
# Reproducible demo for the README recording (vhs or asciinema): a local policy, one blocked request and one
# redacted request. Needs the `inveil` binary (set INVEIL to its path), python3 and curl. Nothing leaves the
# machine: the "AI provider" is a local echo server and the policy is signed with a throwaway key.
set -eu

INVEIL=${INVEIL:-inveil}
SECONDS_PER_YEAR=31536000

# Free ports chosen by the OS, so the demo never collides with a running inveil or another service. The three
# sockets are held open together so the ports are distinct, then released just before use.
ports=$(python3 - <<'PY'
import socket

sockets = [socket.socket() for _ in range(3)]
for sock in sockets:
    sock.bind(("127.0.0.1", 0))
print(" ".join(str(sock.getsockname()[1]) for sock in sockets))
PY
)
set -- $ports
PROXY_PORT=$1
BROWSER_PORT=$2
UPSTREAM_PORT=$3

work=$(mktemp -d)
pids=""
cleanup() {
    for pid in $pids; do
        kill "$pid" 2>/dev/null || true
    done
    rm -rf "$work"
}
trap cleanup EXIT INT TERM

say() {
    printf '\n$ %s\n' "$*"
}

# 1. A throwaway policy key, and rules signed with it.
"$INVEIL" keygen --out "$work/policy.key" > "$work/keygen.txt"
public_key=$(sed -n 's/^public_key: //p' "$work/keygen.txt")
now=$(date +%s)
cat > "$work/rules.json" <<JSON
{
  "schema": 1,
  "version": 1,
  "issued_at": $now,
  "expires_at": $((now + SECONDS_PER_YEAR)),
  "pii": [
    { "id": "ssn", "label": "US Social Security number", "pattern": "\\\\b\\\\d{3}-\\\\d{2}-\\\\d{4}\\\\b",
      "validator": "ssn", "action": "block", "enabled": true },
    { "id": "card", "label": "Payment card number", "pattern": "\\\\b(?:\\\\d[ -]?){13,19}\\\\b",
      "validator": "luhn", "action": "redact", "enabled": true }
  ],
  "tools": [
    { "id": "demo", "name": "Demo tool", "via": "local", "enabled": true,
      "upstream": "https://api.anthropic.com", "prefix": null, "env_var": null,
      "endpoints": [{ "path": "/v1/messages", "match": "exact", "format": "json" }],
      "hosts": [] }
  ]
}
JSON
"$INVEIL" sign --role policy --key "$work/policy.key" --key-id demo-1 "$work/rules.json" > "$work/rules.signed.json"

cat > "$work/inveil.toml" <<TOML
offline = true
rules_file = "$work/rules.signed.json"
upstream = "http://127.0.0.1:$UPSTREAM_PORT"
notify = false
state_keychain = false
data_dir = "$work/data"

[listen]
port = $PROXY_PORT
browser_port = $BROWSER_PORT

[[backend.pinned_keys]]
key_id = "demo-1"
public_key = "$public_key"
TOML

# 2. A stand-in AI provider that prints what it receives.
python3 - "$UPSTREAM_PORT" > "$work/upstream.log" 2>&1 <<'PY' &
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

class Echo(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("content-length", 0)))
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass

HTTPServer(("127.0.0.1", int(sys.argv[1])), Echo).serve_forever()
PY
pids="$pids $!"

# 3. The proxy.
"$INVEIL" run --config "$work/inveil.toml" > "$work/inveil.log" 2>&1 &
pids="$pids $!"

attempts=0
until curl -s -o /dev/null "http://127.0.0.1:$PROXY_PORT/"; do
    attempts=$((attempts + 1))
    if [ "$attempts" -ge 50 ]; then
        echo "the proxy did not start; see its log:" >&2
        cat "$work/inveil.log" >&2
        exit 1
    fi
    sleep 0.2
done

send() {
    curl -s -w '\nHTTP %{http_code}\n' "http://127.0.0.1:$PROXY_PORT/v1/messages" \
        -H 'content-type: application/json' -d "$1"
}

say "a request with a fake SSN is blocked"
send '{"model":"demo","max_tokens":1,"messages":[{"role":"user","content":"my ssn is 123-45-6789"}]}'

say "a fake card number is redacted before it reaches the provider"
send '{"model":"demo","max_tokens":1,"messages":[{"role":"user","content":"card 4242 4242 4242 4242"}]}'

say "a request with nothing sensitive passes through"
send '{"model":"demo","max_tokens":1,"messages":[{"role":"user","content":"hello"}]}'
