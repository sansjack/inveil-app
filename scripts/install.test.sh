#!/bin/sh
# Tests for install.sh against local fixture releases. No network.
# The fake `inveil` binary records every execution in $FAKE_MARKER, so the tests can prove that nothing from
# the download directory runs before the signed manifest has been verified.
# Needs an OpenSSL 3 that verifies Ed25519 (the same requirement as the installer).
set -eu

script_dir=$(cd "$(dirname "$0")" && pwd)
repo_dir=$(dirname "$script_dir")
installer="$script_dir/install.sh"
root=$(mktemp -d "${TMPDIR:-/tmp}/inveil-install-test.XXXXXX")
trap 'rm -rf "$root"' EXIT
mkdir "$root/tmp"
export TMPDIR="$root/tmp"

failures=0
pass() { printf 'ok   %s\n' "$1"; }
fail() {
  printf 'FAIL %s\n' "$1"
  failures=$((failures + 1))
}

for candidate in "${INVEIL_OPENSSL:-}" /opt/homebrew/opt/openssl@3/bin/openssl /usr/local/opt/openssl@3/bin/openssl openssl; do
  [ -n "$candidate" ] || continue
  command -v "$candidate" >/dev/null 2>&1 || continue
  if "$candidate" version | grep -q '^OpenSSL [3-9]'; then
    openssl_bin=$candidate
    break
  fi
done
[ -n "${openssl_bin:-}" ] || { echo "install.test.sh needs OpenSSL 3 (set INVEIL_OPENSSL)"; exit 1; }
export INVEIL_OPENSSL="$openssl_bin"

case $(uname -s) in
  Darwin) os=macos ;;
  Linux) os=linux ;;
  *) echo "unsupported test host"; exit 1 ;;
esac
case $(uname -m) in
  x86_64 | amd64) arch=x86_64 ;;
  *) arch=aarch64 ;;
esac
if [ "$os" = macos ] && [ "$arch" = x86_64 ] && [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)" = 1 ]; then
  arch=aarch64
fi
target="$os-$arch"
binary_name="inveil-$target"

hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

file_size() { wc -c <"$1" | tr -d ' '; }

# Keys: <name>.pem is the private key, <name>.pub the base64 raw public key.
make_key() {
  "$openssl_bin" genpkey -algorithm ed25519 -out "$root/$1.pem" 2>/dev/null
  "$openssl_bin" pkey -in "$root/$1.pem" -pubout -outform DER | tail -c 32 | "$openssl_bin" base64 -A >"$root/$1.pub"
}
pub() { cat "$root/$1.pub"; }

make_key alpha
make_key beta
make_key gamma
make_key mallory
keys_two="alpha=$(pub alpha) beta=$(pub beta)"

json_escape_file() {
  awk 'BEGIN { ORS = "" } { gsub(/\\/, "\\\\"); gsub(/"/, "\\\""); print $0 "\\n" }' "$1"
}

# make_envelope <out> <payload file> <payload file to sign> <id=key>...
make_envelope() {
  out=$1
  payload=$2
  signed_payload=$3
  shift 3
  { printf 'inveil-update-v1\0'; cat "$signed_payload"; } >"$root/message"
  {
    printf '{\n  "payload": "%s",\n  "signatures": [' "$(json_escape_file "$payload")"
    separator=""
    for signer in "$@"; do
      "$openssl_bin" pkeyutl -sign -rawin -inkey "$root/${signer#*=}.pem" -in "$root/message" -out "$root/signature"
      printf '%s\n    {\n      "key_id": "%s",\n      "signature": "%s"\n    }' "$separator" "${signer%%=*}" \
        "$("$openssl_bin" base64 -A <"$root/signature")"
      separator=","
    done
    printf '\n  ]\n}'
  } >"$out"
}

write_payload() {
  payload_file=$1 version=$2 manifest_channel=$3 expires_at=$4 threshold=$5 sha=$6 size=$7
  cat >"$payload_file" <<EOF
{
  "artifacts": {
    "$target": {
      "sha256": "$sha",
      "size": $size,
      "url": "https://example.invalid/$binary_name"
    }
  },
  "channel": "$manifest_channel",
  "expires_at": $expires_at,
  "published_at": 1,
  "schema": 1,
  "threshold": $threshold,
  "version": "$version"
}
EOF
}

write_binary() {
  cat >"$1/$binary_name" <<'FAKE'
#!/bin/sh
echo "$0 $*" >>"${FAKE_MARKER:-/dev/null}"
log="${FAKE_INVEIL_LOG:-/dev/null}"
case "$1" in
  --version) echo "inveil ${FAKE_INVEIL_VERSION:-9.9.9}" ;;
  verify)
    echo "verify $*" >>"$log"
    [ -z "${FAKE_VERIFY_FAIL:-}" ] || exit 1
    ;;
  enroll)
    echo "enroll $*" >>"$log"
    echo "bundle-body $(cat "$3")" >>"$log"
    ;;
  install) echo "install" >>"$log" ;;
  uninstall) echo "uninstall" >>"$log" ;;
esac
FAKE
  printf '# build %s\n' "$2" >>"$1/$binary_name"
  chmod 755 "$1/$binary_name"
}

far_future=4102444800
past=1000000000

# make_release <dir> <version> <channel> <expires_at> <threshold> <id=key>...
make_release() {
  release_dir=$1 release_version=$2 release_channel=$3 release_expires=$4 release_threshold=$5
  shift 5
  mkdir -p "$release_dir"
  write_binary "$release_dir" "$release_version"
  write_payload "$release_dir/payload.json" "$release_version" "$release_channel" "$release_expires" "$release_threshold" \
    "$(hash_file "$release_dir/$binary_name")" "$(file_size "$release_dir/$binary_name")"
  make_envelope "$release_dir/update-manifest.json.sig" "$release_dir/payload.json" "$release_dir/payload.json" "$@"
}

export INVEIL_INSTALL_TESTING=1
export INVEIL_UPDATE_PUBLIC_KEYS="$keys_two"
export FAKE_MARKER="$root/marker"
export FAKE_INVEIL_LOG="$root/log"
: >"$FAKE_MARKER"

fixture="$root/release"
make_release "$fixture" 9.9.9 stable "$far_future" 2 alpha=alpha beta=beta
base="file://$fixture"

run_installer() {
  INVEIL_INSTALL_BASE_URL=$base INVEIL_INSTALL_DIR="$install_dir" sh "$installer" "$@"
}

# Prefix assignments on a function call leak into the caller in dash, so scoped variables go through a subshell.
with_env() {
  (
    # shellcheck disable=SC2163 -- $1 is a NAME=value assignment
    export "$1"
    shift
    "$@"
  )
}

ran_from_download() {
  grep -q "$root/tmp/inveil-install" "$FAKE_MARKER"
}

# expect_rejected <name> <expected message> <release dir> [installer args]: nothing may run or be installed.
expect_rejected() {
  name=$1 message=$2 release=$3
  shift 3
  : >"$FAKE_MARKER"
  install_dir="$root/rejected-$(printf '%s' "$name" | tr -c 'A-Za-z0-9' '_')/bin"
  if INVEIL_INSTALL_BASE_URL="file://$release" INVEIL_INSTALL_DIR="$install_dir" sh "$installer" "$@" >"$root/rejected.out" 2>&1; then
    fail "$name was accepted"
  elif ! grep -q "$message" "$root/rejected.out"; then
    fail "$name: expected message '$message'"
    cat "$root/rejected.out"
  elif [ -e "$install_dir/inveil" ] || ran_from_download; then
    fail "$name: something was installed or executed"
  else
    pass "$name"
  fi
}

install_dir="$root/dry/bin"
if run_installer --dry-run >"$root/dry.out" 2>&1 && [ ! -e "$install_dir" ] && grep -q 'dry-run' "$root/dry.out" && grep -q 'sha256:' "$root/dry.out"; then
  pass "dry run prints the plan and the key fingerprint without touching disk"
else
  fail "dry run"
fi

raw_hash=$("$openssl_bin" base64 -d -A <"$root/alpha.pub" | { if command -v sha256sum >/dev/null 2>&1; then sha256sum; else shasum -a 256; fi; } | cut -d' ' -f1)
if grep -q "sha256:$raw_hash" "$root/dry.out"; then
  pass "prints the sha256 of the raw public key bytes"
else
  fail "fingerprint of raw key bytes"
fi

install_dir="$root/ok/bin"
: >"$FAKE_MARKER"
if run_installer >"$root/install.out" 2>&1 && "$install_dir/inveil" --version | grep -q 9.9.9; then
  pass "installs a release signed by two pinned keys"
else
  fail "install"
  cat "$root/install.out"
fi
if grep -q -- '--role update' "$root/log" && grep -q -- '--pinned-key alpha=' "$root/log" && grep -q -- "--artifact" "$root/log"; then
  pass "still runs inveil verify as a second check"
else
  fail "inveil verify arguments"
fi
if run_installer >"$root/rerun.out" 2>&1 && grep -q 'already up to date' "$root/rerun.out" && [ ! -e "$install_dir/inveil.prev" ]; then
  pass "re-running with the same release is a no-op"
else
  fail "idempotent re-run"
fi

upgrade="$root/upgrade"
make_release "$upgrade" 9.9.10 stable "$far_future" 2 alpha=alpha beta=beta
if INVEIL_INSTALL_BASE_URL="file://$upgrade" INVEIL_INSTALL_DIR="$install_dir" sh "$installer" >/dev/null 2>&1 && [ -f "$install_dir/inveil.prev" ]; then
  pass "upgrade keeps inveil.prev"
else
  fail "upgrade"
fi

forged="$root/forged"
make_release "$forged" 9.9.9 stable "$far_future" 2 alpha=alpha beta=beta
printf '# evil\n' >>"$forged/$binary_name"
write_payload "$forged/forged.json" 9.9.9 stable "$far_future" 2 "$(hash_file "$forged/$binary_name")" "$(file_size "$forged/$binary_name")"
make_envelope "$forged/update-manifest.json.sig" "$forged/forged.json" "$forged/payload.json" alpha=alpha beta=beta
expect_rejected "rejects a forged manifest whose signatures cover a different payload" "valid signature" "$forged"

tampered="$root/tampered"
make_release "$tampered" 9.9.9 stable "$far_future" 2 alpha=alpha beta=beta
printf '# evil\n' >>"$tampered/$binary_name"
printf '%s  %s\n' "$(hash_file "$tampered/$binary_name")" "$binary_name" >"$tampered/SHA256SUMS"
expect_rejected "rejects a tampered binary even with a matching forged SHA256SUMS" "mismatch" "$tampered"

single="$root/single"
make_release "$single" 9.9.9 stable "$far_future" 1 alpha=alpha
expect_rejected "rejects a single-signature manifest when two are required" "1 valid signature" "$single"

duplicate="$root/duplicate"
make_release "$duplicate" 9.9.9 stable "$far_future" 2 alpha=alpha dup=alpha
with_env INVEIL_UPDATE_PUBLIC_KEYS="$keys_two dup=$(pub alpha)" expect_rejected "counts one public key once even under two key ids" "1 valid signature" "$duplicate"

threshold_three="$root/threshold-three"
make_release "$threshold_three" 9.9.9 stable "$far_future" 3 alpha=alpha beta=beta
expect_rejected "honours a manifest threshold above the script minimum" "3 required" "$threshold_three"

wrong_key="$root/wrong-key"
make_release "$wrong_key" 9.9.9 stable "$far_future" 2 alpha=mallory beta=gamma
expect_rejected "rejects signatures made by keys that are not pinned" "valid signature" "$wrong_key"

unknown_id="$root/unknown-id"
make_release "$unknown_id" 9.9.9 stable "$far_future" 2 mallory=mallory gamma=gamma
expect_rejected "ignores signatures from unknown key ids" "valid signature" "$unknown_id"

expired="$root/expired"
make_release "$expired" 9.9.9 stable "$past" 2 alpha=alpha beta=beta
expect_rejected "rejects an expired manifest" "expired" "$expired"

wrong_channel="$root/wrong-channel"
make_release "$wrong_channel" 9.9.9 beta "$far_future" 2 alpha=alpha beta=beta
expect_rejected "rejects a manifest for another channel" "channel" "$wrong_channel"

older="$root/older"
make_release "$older" 9.0.0 stable "$far_future" 2 alpha=alpha beta=beta
install_dir="$root/older-install/bin"
FAKE_INVEIL_VERSION=9.9.9 INVEIL_INSTALL_BASE_URL=$base INVEIL_INSTALL_DIR="$install_dir" sh "$installer" >/dev/null 2>&1
: >"$FAKE_MARKER"
if FAKE_INVEIL_VERSION=9.9.9 INVEIL_INSTALL_BASE_URL="file://$older" INVEIL_INSTALL_DIR="$install_dir" sh "$installer" >"$root/older.out" 2>&1; then
  fail "older version was accepted"
elif grep -q 'refusing to downgrade' "$root/older.out" && ! ran_from_download; then
  pass "refuses a version older than the installed one"
else
  fail "downgrade message"
fi
mkdir -p "$root/pinned"
if INVEIL_INSTALL_BASE_URL="file://$older" INVEIL_INSTALL_DIR="$install_dir" sh "$installer" --version 9.0.0 >/dev/null 2>&1; then
  pass "installs an older version when --version pins it"
else
  fail "explicit --version downgrade"
fi
if INVEIL_INSTALL_BASE_URL="file://$older" INVEIL_INSTALL_DIR="$root/mismatch/bin" sh "$installer" --version 9.1.0 >/dev/null 2>&1; then
  fail "manifest for another version accepted under --version"
else
  pass "--version must match the signed manifest version"
fi

single_ok="$root/single-ok"
make_release "$single_ok" 9.9.9 stable "$far_future" 1 alpha=alpha
single_install="$root/single-ok/bin"
if INVEIL_MIN_SIGNATURES=1 INVEIL_UPDATE_PUBLIC_KEYS="alpha=$(pub alpha)" INVEIL_INSTALL_BASE_URL="file://$single_ok" \
  INVEIL_INSTALL_DIR="$single_install" sh "$installer" >"$root/single-ok.out" 2>&1; then
  fail "single signature accepted without --allow-single-signature"
elif INVEIL_MIN_SIGNATURES=1 INVEIL_UPDATE_PUBLIC_KEYS="alpha=$(pub alpha)" INVEIL_INSTALL_BASE_URL="file://$single_ok" \
  INVEIL_INSTALL_DIR="$single_install" sh "$installer" --allow-single-signature >/dev/null 2>&1 && [ -x "$single_install/inveil" ]; then
  pass "one signature needs MIN_SIGNATURES=1 and the explicit flag"
else
  fail "single signature with the flag"
fi

if INVEIL_INSTALL_TESTING=1 INVEIL_UPDATE_PUBLIC_KEYS="alpha=$(pub alpha)" INVEIL_INSTALL_BASE_URL=$base INVEIL_INSTALL_DIR="$root/onekey/bin" \
  sh "$installer" >"$root/onekey.out" 2>&1; then
  fail "installed with fewer pinned keys than required signatures"
elif grep -q 'only 1 distinct key' "$root/onekey.out"; then
  pass "refuses up front when too few keys are pinned"
else
  fail "too few pinned keys message"
fi

rendered="$root/rendered"
mkdir "$rendered"
if ( cd "$rendered" && UPDATE_PUBLIC_KEYS="$keys_two" MIN_SIGNATURES=2 sh "$repo_dir/.github/scripts/render-installers.sh" "$rendered" ) >/dev/null 2>&1 &&
  grep -q "^UPDATE_PUBLIC_KEYS='alpha=" "$rendered/install.sh" && grep -q "^MIN_SIGNATURES='2'" "$rendered/install.sh"; then
  pass "renders install.sh with single-quoted values"
else
  fail "render-installers"
fi
# shellcheck disable=SC2016 -- the backtick and dollar are literal test input
for bad in "a'b" 'a"b' 'a$b' 'a`b' 'a\b'; do
  if UPDATE_PUBLIC_KEYS="$bad" MIN_SIGNATURES=2 sh "$repo_dir/.github/scripts/render-installers.sh" "$root/render-bad" >/dev/null 2>&1; then
    fail "renderer accepted $bad"
  fi
done
if UPDATE_PUBLIC_KEYS="$(printf 'a=b\nc=d')" MIN_SIGNATURES=2 sh "$repo_dir/.github/scripts/render-installers.sh" "$root/render-bad" >/dev/null 2>&1; then
  fail "renderer accepted a newline"
else
  pass "renderer rejects quotes, backslashes, dollar, backtick and newlines"
fi

env -u INVEIL_INSTALL_TESTING INVEIL_UPDATE_PUBLIC_KEYS="$keys_two" INVEIL_INSTALL_BASE_URL="$base" INVEIL_INSTALL_DIR="$root/ignored/bin" \
  sh "$rendered/install.sh" --dry-run >"$root/ignored.out" 2>&1 || true
if grep -q 'download https://github.com/' "$root/ignored.out" && ! grep -q "$fixture" "$root/ignored.out"; then
  pass "ignores INVEIL_INSTALL_BASE_URL unless INVEIL_INSTALL_TESTING=1"
else
  fail "base url override leaked into a production run"
  cat "$root/ignored.out"
fi
env -u INVEIL_INSTALL_TESTING INVEIL_UPDATE_PUBLIC_KEYS="evil=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" INVEIL_INSTALL_DIR="$root/ignored/bin" \
  sh "$rendered/install.sh" --dry-run >"$root/ignored-keys.out" 2>&1 || true
if grep -q "alpha " "$root/ignored-keys.out" && ! grep -q 'evil' "$root/ignored-keys.out"; then
  pass "ignores INVEIL_UPDATE_PUBLIC_KEYS unless INVEIL_INSTALL_TESTING=1"
else
  fail "key override leaked into a production run"
fi

install_dir="$root/enroll/bin"
: >"$root/log"
token=tok_ABC-123_secret
if with_env INVEIL_ENROLL_TOKEN=$token run_installer --enroll --backend-url https://backend.example.com \
  --pinned-key "policy=$(pub gamma)" >"$root/enroll.out" 2>&1 &&
  grep -q -- 'enroll --bundle /dev/stdin' "$root/log" &&
  grep -q "\"enrollment_token\":\"$token\"" "$root/log" &&
  grep -q '^install' "$root/log"; then
  pass "enrolls with the token on a pipe, then installs the service"
else
  fail "enroll"
  cat "$root/enroll.out"
fi
if grep -q -- "$token" "$FAKE_MARKER" || grep -- 'enroll' "$root/log" | grep -v 'bundle-body' | grep -q -- "$token"; then
  fail "token appeared on a command line"
else
  pass "the token never appears in any argv"
fi
if grep -rl -- "$token" "$root/tmp" 2>/dev/null | grep -q .; then
  fail "token written to a temp file"
else
  pass "the token is not written to any file in the temp dir"
fi
if [ -z "$(find "$root/tmp" -mindepth 1 2>/dev/null)" ]; then
  pass "the temp dir is removed afterwards"
else
  fail "temp dir left behind"
fi
if with_env INVEIL_ENROLL_TOKEN=$token run_installer --enroll --backend-url https://backend.example.com --pinned-key "policy=$(pub gamma)" 2>&1 |
  grep -q "$token"; then
  fail "installer printed the token"
else
  pass "the installer never prints the token"
fi
if run_installer --enroll >"$root/notoken.out" 2>&1; then
  fail "--enroll without a token accepted"
else
  pass "--enroll needs INVEIL_ENROLL_TOKEN"
fi
if run_installer --enroll "$token" >"$root/argv.out" 2>&1; then
  fail "token as an argument accepted"
elif grep -q -- "$token" "$root/argv.out"; then
  fail "token echoed back from argv"
else
  pass "refuses a token given as an argument without echoing it"
fi

printf '{"backend_url":"https://b.example","pinned_keys":[],"enrollment_token":"filetoken"}\n' >"$root/bundle.json"
: >"$root/log"
install_dir="$root/bundle/bin"
if run_installer --bundle "$root/bundle.json" >/dev/null 2>&1 && grep -q -- "enroll --bundle $root/bundle.json" "$root/log"; then
  pass "--bundle passes the file through"
else
  fail "--bundle"
fi

: >"$root/log"
install_dir="$root/bundle-trust/bin"
with_env INVEIL_ENROLL_TOKEN=$token run_installer --enroll --backend-url https://backend.example.com \
  --pinned-key "policy=$(pub gamma)" >/dev/null 2>&1 || true
bundle_body=$(sed -n 's/^bundle-body //p' "$root/log")
bundle_minimum=$(printf '%s' "$bundle_body" | sed -n 's/.*"min_signatures":\([0-9][0-9]*\).*/\1/p')
if [ -n "$bundle_minimum" ] && [ "$bundle_minimum" -ge 2 ]; then
  pass "the enrollment bundle carries min_signatures >= 2 by default"
else
  fail "bundle min_signatures: $bundle_body"
fi
if printf '%s' "$bundle_body" | grep -q '"feed_url":"https://[^"]*\.json\.sig"'; then
  pass "the enrollment bundle carries the signed feed_url (.json.sig)"
else
  fail "bundle feed_url: $bundle_body"
fi
if printf '%s' "$bundle_body" | grep -q '"update":{"keys":\[{"key_id":"alpha"'; then
  pass "the enrollment bundle still pins the update keys"
else
  fail "bundle update keys: $bundle_body"
fi

expect_backend_url() {
  # expect_backend_url <accept|reject> <url>
  if with_env INVEIL_ENROLL_TOKEN=tok run_installer --enroll --dry-run --backend-url "$2" --pinned-key "policy=$(pub gamma)" >"$root/url.out" 2>&1; then
    outcome=accept
  else
    outcome=reject
  fi
  if [ "$outcome" = "$1" ]; then pass "backend url $2 is ${1}ed"; else fail "backend url $2 was ${outcome}ed, expected $1"; fi
}
install_dir="$root/url/bin"
expect_backend_url accept https://backend.example.com
expect_backend_url accept http://localhost
expect_backend_url accept http://localhost:8080/base
expect_backend_url accept http://127.0.0.1:9000
expect_backend_url accept 'http://[::1]:9000'
expect_backend_url reject http://localhost:1@evil.com
expect_backend_url reject http://localhost@evil.com/
expect_backend_url reject http://127.0.0.1:80@evil.com
expect_backend_url reject https://user:pass@backend.example.com
expect_backend_url reject http://localhost.evil.com
expect_backend_url reject http://evil.com/localhost
expect_backend_url reject http://localhost:80a
expect_backend_url reject http://backend.example.com
expect_backend_url reject ftp://localhost

older_min="$root/older-min"
make_release "$older_min" 9.0.0 stable "$far_future" 2 alpha=alpha beta=beta
expect_rejected "refuses a manifest older than --min-version on a fresh install" "older than --min-version" "$older_min" --min-version 9.5.0
install_dir="$root/min-version/bin"
if INVEIL_INSTALL_BASE_URL="file://$older_min" INVEIL_INSTALL_DIR="$install_dir" sh "$installer" --min-version 9.0.0 >/dev/null 2>&1 && [ -x "$install_dir/inveil" ]; then
  pass "accepts a manifest at --min-version"
else
  fail "--min-version equal"
fi
expect_rejected "rejects an invalid --min-version" "invalid --min-version" "$fixture" --min-version latest

install_dir="$root/noenroll/bin"
: >"$root/log"
if with_env INVEIL_ENROLL_TOKEN=tok run_installer --enroll --no-enroll >/dev/null 2>&1 && ! grep -q enroll "$root/log"; then
  pass "--no-enroll skips enrollment"
else
  fail "--no-enroll"
fi

: >"$root/log"
if run_installer --uninstall >/dev/null 2>&1 && [ ! -e "$install_dir/inveil" ] && grep -q uninstall "$root/log"; then
  pass "--uninstall removes the binary"
else
  fail "--uninstall"
fi

install_dir="$root/refuse/bin"
if env -u INVEIL_INSTALL_TESTING INVEIL_INSTALL_BASE_URL="$base" INVEIL_INSTALL_DIR="$install_dir" sh "$rendered/install.sh" >/dev/null 2>&1; then
  fail "file:// accepted without testing mode"
else
  pass "refuses file:// outside testing mode"
fi
if INVEIL_INSTALL_BASE_URL=http://example.com/releases INVEIL_INSTALL_DIR="$install_dir" sh "$installer" >/dev/null 2>&1; then
  fail "plain http accepted"
else
  pass "refuses plain http"
fi
if INVEIL_UPDATE_PUBLIC_KEYS='' INVEIL_INSTALL_BASE_URL="$base" INVEIL_INSTALL_DIR="$install_dir" sh "$installer" >/dev/null 2>&1; then
  fail "installed without pinned update keys"
else
  pass "refuses to run without pinned update keys"
fi
if with_env INVEIL_ENROLL_TOKEN='bad token";' run_installer --enroll --backend-url https://b.example.com --pinned-key "k=$(pub gamma)" >/dev/null 2>&1; then
  fail "malformed token accepted"
else
  pass "rejects a token that could break the bundle JSON"
fi
if run_installer --channel beta >/dev/null 2>&1; then
  fail "beta without --version accepted"
else
  pass "beta channel requires --version"
fi
if run_installer --bogus >/dev/null 2>&1; then
  fail "unknown option accepted"
else
  pass "rejects unknown options"
fi

sed '$d' "$installer" >"$root/truncated.sh"
if [ -z "$(sh "$root/truncated.sh" 2>&1)" ]; then
  pass "a truncated download runs nothing"
else
  fail "truncated script"
fi

sign_script="$repo_dir/.github/scripts/sign-manifest.sh"
manifest_script="$repo_dir/.github/scripts/update_manifest.py"
alpha_key_b64=$("$openssl_bin" pkey -in "$root/alpha.pem" -outform DER | "$openssl_bin" base64 -A)
beta_key_b64=$("$openssl_bin" pkey -in "$root/beta.pem" -outform DER | "$openssl_bin" base64 -A)
if command -v python3 >/dev/null 2>&1; then
  # A packaged release as the sign job sees it: all six raw binaries, then the generated unsigned manifest.
  dist="$root/sign-dist"
  mkdir -p "$dist"
  write_binary "$dist" signed
  for other in macos-x86_64 macos-aarch64 linux-x86_64 linux-aarch64 windows-x86_64 windows-aarch64; do
    case $other in windows-*) other_name="inveil-$other.exe" ;; *) other_name="inveil-$other" ;; esac
    [ -e "$dist/$other_name" ] || printf 'binary for %s\n' "$other" >"$dist/$other_name"
  done
  (cd "$dist" && for file in inveil-*; do printf '%s  %s\n' "$(hash_file "$file")" "$file"; done >SHA256SUMS)
  signed="$root/signed"
  mkdir -p "$signed"
  python3 "$manifest_script" generate --dist "$dist" --version 9.9.9 --tag v9.9.9 --channel stable \
    --repo example/inveil-app --threshold 2 --output "$signed/update-manifest.json"
  cp "$dist/$binary_name" "$signed/$binary_name"

  run_sign() {
    # run_sign <tag> <payload> <output> <key spec>...  (environment: extra variables set by the caller)
    sign_tag=$1 sign_payload=$2 sign_output=$3
    shift 3
    PATH="$(dirname "$openssl_bin"):$PATH" UPDATE_PUBLIC_KEYS="$keys_two" SIGN_KEY_ALPHA=$alpha_key_b64 SIGN_KEY_BETA=$beta_key_b64 \
      EXPECTED_TAG=$sign_tag GITHUB_REPOSITORY=example/inveil-app DIST_DIR=$dist \
      sh "$sign_script" "$sign_payload" "$sign_output" "$@"
  }
  mutated_manifest() {
    # mutated_manifest <name> <python statements editing the dict m>: writes $root/mutated/<name>/update-manifest.json
    mutation_dir="$root/mutated/$1"
    mkdir -p "$mutation_dir"
    python3 - "$signed/update-manifest.json" "$mutation_dir/update-manifest.json" "$2" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
exec(sys.argv[3])
open(sys.argv[2], "w").write(json.dumps(m, indent=2, sort_keys=True) + "\n")
PY
  }
  expect_sign_refused() {
    refused_name=$1 refused_message=$2 refused_tag=$3 refused_payload=$4
    if run_sign "$refused_tag" "$refused_payload" "$root/refused.sig" alpha:SIGN_KEY_ALPHA >"$root/refused.out" 2>&1; then
      fail "sign-manifest.sh signed: $refused_name"
    elif [ -e "$root/refused.sig" ] || ! grep -q "$refused_message" "$root/refused.out"; then
      fail "sign-manifest.sh: $refused_name (expected '$refused_message')"
      cat "$root/refused.out"
    else
      pass "sign-manifest.sh refuses: $refused_name"
    fi
    rm -f "$root/refused.sig"
  }

  if run_sign v9.9.9 "$signed/update-manifest.json" "$signed/one-key.sig" alpha:SIGN_KEY_ALPHA >/dev/null 2>"$root/sign.err"; then
    pass "sign-manifest.sh signs a valid manifest with the single CI key"
  else
    fail "sign-manifest.sh single key"
    cat "$root/sign.err"
  fi
  if with_env ALLOW_UNOFFICIAL_RELEASE=true run_sign v9.9.9 "$signed/update-manifest.json" "$signed/update-manifest.json.sig" \
    alpha:SIGN_KEY_ALPHA beta:SIGN_KEY_BETA >/dev/null 2>"$root/sign.err" &&
    INVEIL_INSTALL_BASE_URL="file://$signed" INVEIL_INSTALL_DIR="$root/signed-install/bin" sh "$installer" >/dev/null 2>&1; then
    pass "installs a manifest produced by sign-manifest.sh (OpenSSL-only signing)"
  else
    fail "sign-manifest.sh round trip"
    cat "$root/sign.err"
    INVEIL_INSTALL_BASE_URL="file://$signed" INVEIL_INSTALL_DIR="$root/signed-install/bin" sh "$installer" 2>&1 | tail -5
  fi
  if run_sign v9.9.9 "$signed/update-manifest.json" "$root/two-keys.sig" alpha:SIGN_KEY_ALPHA beta:SIGN_KEY_BETA >/dev/null 2>&1; then
    fail "official release signed with two keys in CI"
  else
    pass "sign-manifest.sh refuses to hold two update keys in an official release"
  fi
  if run_sign v9.9.9 "$signed/update-manifest.json" "$root/mislabelled.sig" alpha:SIGN_KEY_BETA >/dev/null 2>&1; then
    fail "sign-manifest.sh accepted a key that does not match the pinned id"
  else
    pass "sign-manifest.sh refuses a key that does not match the pinned public key"
  fi

  expect_sign_refused "a version that is not the tag" "version is 9.9.9, the tag says 9.9.8" v9.9.8 "$signed/update-manifest.json"
  expect_sign_refused "a stable manifest for an rc tag" "channel is stable" v9.9.9-rc.1 "$signed/update-manifest.json"
  mutated_manifest threshold1 'm["threshold"] = 1'
  expect_sign_refused "a threshold of 1" "threshold is 1" v9.9.9 "$root/mutated/threshold1/update-manifest.json"
  mutated_manifest foreign-url 'm["artifacts"]["linux-x86_64"]["url"] = "https://github.com/evil/inveil-app/releases/download/v9.9.9/inveil-linux-x86_64"'
  expect_sign_refused "an artifact url outside this repository" "linux-x86_64: url" v9.9.9 "$root/mutated/foreign-url/update-manifest.json"
  mutated_manifest other-host 'm["artifacts"]["macos-aarch64"]["url"] = "https://example.invalid/inveil-macos-aarch64"'
  expect_sign_refused "an artifact url on another host" "macos-aarch64: url" v9.9.9 "$root/mutated/other-host/update-manifest.json"
  mutated_manifest bad-hash 'm["artifacts"]["windows-x86_64"]["sha256"] = "0" * 64'
  expect_sign_refused "a sha256 that does not match the packaged binary" "windows-x86_64: sha256" v9.9.9 "$root/mutated/bad-hash/update-manifest.json"
  mutated_manifest bad-size 'm["artifacts"]["linux-aarch64"]["size"] += 1'
  expect_sign_refused "a size that does not match the packaged binary" "linux-aarch64: size" v9.9.9 "$root/mutated/bad-size/update-manifest.json"
  mutated_manifest missing-target 'del m["artifacts"]["windows-aarch64"]'
  expect_sign_refused "a manifest missing a target" "targets are" v9.9.9 "$root/mutated/missing-target/update-manifest.json"
  mutated_manifest expired 'm["expires_at"] = 1000000000'
  expect_sign_refused "an expired manifest" "expires_at" v9.9.9 "$root/mutated/expired/update-manifest.json"
  mutated_manifest forever 'm["expires_at"] += 10 * 365 * 86400'
  expect_sign_refused "a manifest valid for years" "expires_at" v9.9.9 "$root/mutated/forever/update-manifest.json"
  mutated_manifest revocation 'm["revoked_key_ids"] = ["alpha"]'
  expect_sign_refused "a surprise key revocation" "revoked_key_ids" v9.9.9 "$root/mutated/revocation/update-manifest.json"
  mutated_manifest extra-field 'm["extra"] = 1'
  expect_sign_refused "an unknown field" "unknown fields" v9.9.9 "$root/mutated/extra-field/update-manifest.json"
  printf 'tampered after packaging\n' >>"$dist/inveil-linux-x86_64"
  expect_sign_refused "a binary changed after the manifest was generated" "linux-x86_64: sha256" v9.9.9 "$signed/update-manifest.json"
else
  echo "skip sign-manifest.sh tests (python3 not found)"
fi

policy_script="$repo_dir/.github/scripts/check-signing-policy.sh"
check_policy() {
  ( UPDATE_MANIFEST_THRESHOLD=$1 UPDATE_PUBLIC_KEYS=$2 ALLOW_UNOFFICIAL_RELEASE=${3:-} sh "$policy_script" ) >/dev/null 2>&1
}
if check_policy 2 "$keys_two"; then pass "signing policy accepts threshold 2 with two distinct keys"; else fail "signing policy happy path"; fi
if check_policy 1 "$keys_two"; then fail "threshold 1 accepted"; else pass "signing policy refuses a threshold of 1"; fi
if check_policy 2 "alpha=$(pub alpha)"; then fail "one key accepted"; else pass "signing policy refuses a single pinned key"; fi
if check_policy 2 "alpha=$(pub alpha) other=$(pub alpha)"; then fail "duplicate key accepted"; else pass "signing policy refuses two ids for one public key"; fi
if check_policy 1 "alpha=$(pub alpha)" true; then pass "signing policy lets a fork opt out explicitly"; else fail "fork override"; fi

inveil_binary="$repo_dir/target/debug/inveil"
if [ -x "$inveil_binary" ]; then
  interop="$root/interop"
  mkdir -p "$interop"
  write_binary "$interop" real
  write_payload "$interop/payload.json" 9.9.9 stable "$far_future" 2 "$(hash_file "$interop/$binary_name")" "$(file_size "$interop/$binary_name")"
  "$inveil_binary" keygen --out "$root/real-a.key" >"$root/real-a.out"
  "$inveil_binary" keygen --out "$root/real-b.key" >"$root/real-b.out"
  real_a=$(sed -n 's/^public_key: //p' "$root/real-a.out")
  real_b=$(sed -n 's/^public_key: //p' "$root/real-b.out")
  if "$inveil_binary" sign --role update --key "$root/real-a.key" --key-id ra "$interop/payload.json" >"$interop/first.json" 2>/dev/null &&
    "$inveil_binary" sign --role update --co-sign --key "$root/real-b.key" --key-id rb "$interop/first.json" >"$interop/update-manifest.json.sig" 2>/dev/null; then
    install_dir="$root/interop-install/bin"
    if INVEIL_UPDATE_PUBLIC_KEYS="ra=$real_a rb=$real_b" INVEIL_INSTALL_BASE_URL="file://$interop" INVEIL_INSTALL_DIR="$install_dir" \
      sh "$installer" >"$root/interop.out" 2>&1; then
      pass "installs a manifest signed by the real inveil sign command"
    else
      fail "interop with the real inveil sign output"
      cat "$root/interop.out"
    fi
  else
    fail "could not produce a signed envelope with $inveil_binary (stale debug build?)"
  fi
else
  echo "skip interop with the real inveil binary (build target/debug/inveil to enable)"
fi

if [ "$failures" -gt 0 ]; then
  printf '%s test(s) failed\n' "$failures"
  exit 1
fi
echo "all install.sh tests passed"
