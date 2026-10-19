#!/bin/sh
# inveil installer for macOS and Linux.
#
#   curl -fsSL https://github.com/sansjack/inveil-app/releases/latest/download/install.sh | sh -s -- --no-enroll
#   curl -fsSL <your-host>/install.sh | INVEIL_ENROLL_TOKEN=<token> sh -s -- --enroll
#
# Verification order (nothing downloaded is executed until step 4 has passed):
#   1. Download the signed manifest (`update-manifest.json.sig`, an envelope of payload + signatures).
#   2. Verify each Ed25519 signature over "inveil-update-v1\0" || payload with OpenSSL 3 (`openssl pkeyutl
#      -verify -rawin`) against the public keys pinned in this script. At least MIN_SIGNATURES distinct pinned
#      keys must have signed. Then check expiry, channel and that the version is not older than the installed one.
#   3. Download the binary and compare its SHA-256 and size with the signed manifest entry for this machine.
#   4. Only now run `inveil verify` from the downloaded binary as a second, independent check, then install.
#
# Limits, stated plainly:
#   * The verifier is OpenSSL, not the downloaded binary. Stock macOS ships LibreSSL 3.3, which cannot verify
#     Ed25519 through `pkeyutl -rawin`. The script self-tests every candidate openssl against an RFC 8032 vector
#     and uses the first that works (PATH, then Homebrew openssl@3, or $INVEIL_OPENSSL). If none works it
#     refuses to install; run `brew install openssl@3` and retry. It never falls back to executing unverified code.
#   * The pinned keys come from this script. If the host that served this script is compromised, so are the keys;
#     compare the fingerprints printed below (sha256 of the raw 32-byte public key) with the release notes.
#   * Revoked key ids in the manifest are not evaluated here; the threshold of distinct keys is the protection.
#   * Expiry is checked against the local clock, and an older manifest that has not expired yet is a valid
#     signed manifest, so a fresh install (nothing installed to compare with) can be served an older release by
#     whoever controls the download path. The installer cannot know the newest release by itself. Pass
#     --min-version <x.y.z> (the newest version you know of, e.g. from the release notes or your MDM policy) to
#     refuse anything older. Once installed, the updater's persisted high-water mark closes this gap.
#   * --bundle <file> hands the file to `inveil enroll` as is. The file contains the one-time enrollment token and
#     is left on disk where you put it; delete it after enrolling. The token path (INVEIL_ENROLL_TOKEN) uses a pipe.
#
# Hosting this script (templated by .github/scripts/render-installers.sh; values are single-quoted and may not
# contain quotes, backslashes, `$`, backticks or newlines):
#   UPDATE_PUBLIC_KEYS   required. Whitespace-separated "<key_id>=<base64 Ed25519 public key>" entries.
#   MIN_SIGNATURES       optional, default 2. A value below 2 is refused unless --allow-single-signature is
#                        given, which exists for self-hosters with a single update key.
#   DEFAULT_BACKEND_URL / DEFAULT_BACKEND_PINNED_KEYS  optional, used when --backend-url / --pinned-key are absent.
# Unfilled placeholders are ignored.
#
# Options:
#   --enroll               enroll this device; the one-time token is read from INVEIL_ENROLL_TOKEN (never argv)
#   --bundle <file>        enroll from an enrollment.json file instead of a token
#   --backend-url <url>    backend for --enroll (https, or loopback http)
#   --pinned-key <id=b64>  policy public key for --enroll; repeatable
#   --no-enroll            install the binary only, ignore any enrollment options
#   --version <x.y.z>      install exactly this release (also permits installing an older version)
#   --min-version <x.y.z>  refuse a signed manifest older than this version (a "latest known version" hint)
#   --channel <name>       stable (default) or beta; beta requires --version
#   --allow-single-signature  accept a script templated with MIN_SIGNATURES below 2 (self-hosters)
#   --uninstall            run `inveil uninstall` and remove the installed binary
#   --dry-run              print what would happen without downloading or changing anything
#   -h, --help             show this help
#
# Environment: INVEIL_ENROLL_TOKEN, INVEIL_INSTALL_DIR (default $XDG_BIN_HOME or ~/.local/bin), INVEIL_OPENSSL
# (path of an OpenSSL 3 binary). INVEIL_INSTALL_TESTING=1 (tests only) additionally enables
# INVEIL_UPDATE_PUBLIC_KEYS, INVEIL_INSTALL_BASE_URL, INVEIL_MIN_SIGNATURES and file:// URLs; they are ignored
# otherwise so a stray variable cannot replace the pinned keys.
#
# Everything lives in functions and the last line calls main, so a truncated download runs nothing.

set -eu

UPDATE_PUBLIC_KEYS='@@UPDATE_PUBLIC_KEYS@@'
MIN_SIGNATURES='@@MIN_SIGNATURES@@'
DEFAULT_BACKEND_URL='@@BACKEND_URL@@'
DEFAULT_BACKEND_PINNED_KEYS='@@BACKEND_PINNED_KEYS@@'
GITHUB_RELEASES_URL="https://github.com/sansjack/inveil-app/releases"

DEFAULT_MIN_SIGNATURES=2
MAX_SIGNATURES=16
MANIFEST_SCHEMA=1
MAX_MANIFEST_BYTES=1048576
MAX_BINARY_BYTES=268435456
UPDATE_DOMAIN='inveil-update-v1'

# RFC 8032 test vector 2 (the one-byte message "r"), used to prove a candidate openssl really verifies Ed25519.
SELFTEST_KEY='PUAXw+hDiVqStwqnTRt+vJyYLM8uxJaMwM1V8Sr0Zgw='
SELFTEST_SIGNATURE='kqAJqfDUyrhyDoILX2QlQKKye1QWUD+Ps3YiI+vbadoIWsHkPhWZbkWPNhPQ8R2MOHsurrQwKu6wDSkWErsMAA=='

WORK_DIR=""
OPENSSL=""

say() {
  printf '%s\n' "$*"
}

die() {
  printf 'install.sh: error: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  if [ -n "$WORK_DIR" ] && [ -d "$WORK_DIR" ]; then
    rm -rf "$WORK_DIR"
  fi
}

usage() {
  if [ -f "$0" ]; then
    sed -n '2,/^# Everything lives/p' "$0" | sed 's/^# \{0,1\}//'
  else
    say "Usage: install.sh [--enroll] [--bundle <file>] [--version <x.y.z>] [--channel stable|beta] [--dry-run] [--uninstall]"
  fi
}

is_placeholder() {
  case $1 in
    @@*@@) return 0 ;;
    *) return 1 ;;
  esac
}

need_value() {
  [ "$2" -ge 2 ] || die "$1 needs a value"
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | cut -d' ' -f1
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "$1" | sed 's/^.*= //'
  else
    die "no SHA-256 tool found (need sha256sum, shasum or openssl)"
  fi
}

file_size() {
  wc -c <"$1" | tr -d ' '
}

hex_of() {
  od -An -tx1 "$1" | tr -d ' \n'
}

base64_decode() {
  printf '%s' "$1" | "${OPENSSL:-openssl}" base64 -d -A >"$2" 2>/dev/null || return 1
}

fetch() {
  url=$1
  destination=$2
  max_bytes=$3
  case $url in
    file://*)
      [ "${INVEIL_INSTALL_TESTING:-}" = 1 ] || die "file:// URLs are only allowed when INVEIL_INSTALL_TESTING=1"
      cp "${url#file://}" "$destination" || die "cannot read $url"
      ;;
    https://*)
      if command -v curl >/dev/null 2>&1; then
        curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
          --tlsv1.2 --max-filesize "$max_bytes" --output "$destination" "$url" </dev/null || die "download failed: $url"
      elif command -v wget >/dev/null 2>&1; then
        wget --https-only --quiet --output-document "$destination" "$url" </dev/null || die "download failed: $url"
      else
        die "need curl or wget"
      fi
      ;;
    *)
      die "only https:// URLs are allowed: $url"
      ;;
  esac
  [ "$(file_size "$destination")" -le "$max_bytes" ] || die "$url is larger than $max_bytes bytes"
}

detect_os() {
  case $(uname -s) in
    Darwin) echo macos ;;
    Linux) echo linux ;;
    *) die "unsupported operating system: $(uname -s) (supported: macOS, Linux; Windows uses install.ps1)" ;;
  esac
}

detect_arch() {
  case $(uname -m) in
    x86_64 | amd64) architecture=x86_64 ;;
    arm64 | aarch64) architecture=aarch64 ;;
    *) die "unsupported CPU architecture: $(uname -m) (supported: x86_64, aarch64)" ;;
  esac
  # A shell running under Rosetta reports x86_64 on Apple silicon; install the native build.
  if [ "$1" = macos ] && [ "$architecture" = x86_64 ] &&
    [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)" = 1 ]; then
    architecture=aarch64
  fi
  echo "$architecture"
}

# Accepts https://host..., or http:// only for localhost, 127.0.0.1 or [::1] (optional port). The authority is split
# by hand: anything with userinfo ("@") or an odd port is refused, so http://localhost:1@evil.com cannot pass.
check_backend_url() {
  case $1 in
    https://*) rest=${1#https://} ;;
    http://*) rest=${1#http://} ;;
    *) die "--backend-url must be https:// (or loopback http://)" ;;
  esac
  authority=${rest%%[/?#]*}
  case $authority in
    '' | *@* | *' '*) die "--backend-url must not contain userinfo or be empty" ;;
  esac
  case $authority in
    \[*\]*) host=${authority%%\]*}; host="$host]"; port=${authority#"$host"} ;;
    *) host=${authority%%:*}; port=${authority#"$host"} ;;
  esac
  case $port in
    '') ;;
    :*[!0-9]* | :) die "--backend-url has an invalid port" ;;
  esac
  case $1 in
    https://*) return 0 ;;
  esac
  case $host in
    localhost | 127.0.0.1 | '[::1]') ;;
    *) die "--backend-url must be https:// (or loopback http://)" ;;
  esac
}

validate_key_list() {
  [ -n "$2" ] || die "$1 is empty"
  for entry in $2; do
    case $entry in
      *=*) ;;
      *) die "$1: '$entry' is not <key_id>=<base64 public key>" ;;
    esac
    key_id=${entry%%=*}
    public_key=${entry#*=}
    case $key_id in
      '' | *[!A-Za-z0-9._-]*) die "$1: invalid key id '$key_id'" ;;
    esac
    case $public_key in
      '' | *[!A-Za-z0-9+/=]*) die "$1: invalid public key for '$key_id'" ;;
    esac
  done
}

key_list_to_json() {
  json=""
  separator=""
  for entry in $1; do
    json="$json$separator{\"key_id\":\"${entry%%=*}\",\"public_key\":\"${entry#*=}\"}"
    separator=","
  done
  printf '[%s]' "$json"
}

# Writes "<key_id> <raw key hex>" lines to $WORK_DIR/pinned-keys and prints the fingerprint of every key.
load_pinned_keys() {
  : >"$WORK_DIR/pinned-keys"
  say "Pinned update keys (SHA-256 of the raw 32-byte public key; compare with the release notes or MDM policy):"
  for entry in $1; do
    base64_decode "${entry#*=}" "$WORK_DIR/raw-key" || die "public key for '${entry%%=*}' is not valid base64"
    [ "$(file_size "$WORK_DIR/raw-key")" -eq 32 ] || die "public key for '${entry%%=*}' is not 32 bytes"
    printf '%s %s\n' "${entry%%=*}" "$(hex_of "$WORK_DIR/raw-key")" >>"$WORK_DIR/pinned-keys"
    say "  ${entry%%=*}  sha256:$(sha256_of "$WORK_DIR/raw-key")"
  done
  distinct_pinned_keys=$(awk '{ print $2 }' "$WORK_DIR/pinned-keys" | sort -u | wc -l | tr -d ' ')
}

ed25519_verify() {
  verifier=$1
  base64_decode "$2" "$WORK_DIR/verify.key" || return 1
  base64_decode "$3" "$WORK_DIR/verify.sig" || return 1
  [ "$(file_size "$WORK_DIR/verify.key")" -eq 32 ] || return 1
  [ "$(file_size "$WORK_DIR/verify.sig")" -eq 64 ] || return 1
  # SubjectPublicKeyInfo header for Ed25519 (RFC 8410) followed by the raw key.
  {
    printf '\060\052\060\005\006\003\053\145\160\003\041\000'
    cat "$WORK_DIR/verify.key"
  } >"$WORK_DIR/verify.der"
  "$verifier" pkeyutl -verify -pubin -inkey "$WORK_DIR/verify.der" -keyform DER -rawin \
    -in "$4" -sigfile "$WORK_DIR/verify.sig" >/dev/null 2>&1
}

openssl_verifies_ed25519() {
  candidate=$1
  { command -v "$candidate" >/dev/null 2>&1 || [ -x "$candidate" ]; } || return 1
  printf 'r' >"$WORK_DIR/selftest-message"
  printf 'x' >"$WORK_DIR/selftest-wrong-message"
  OPENSSL=$candidate
  if ed25519_verify "$candidate" "$SELFTEST_KEY" "$SELFTEST_SIGNATURE" "$WORK_DIR/selftest-message" &&
    ! ed25519_verify "$candidate" "$SELFTEST_KEY" "$SELFTEST_SIGNATURE" "$WORK_DIR/selftest-wrong-message"; then
    return 0
  fi
  OPENSSL=""
  return 1
}

find_openssl() {
  for candidate in "${INVEIL_OPENSSL:-}" openssl /opt/homebrew/opt/openssl@3/bin/openssl \
    /usr/local/opt/openssl@3/bin/openssl /opt/homebrew/bin/openssl /usr/local/bin/openssl; do
    [ -n "$candidate" ] || continue
    openssl_verifies_ed25519 "$candidate" && return 0
  done
  return 1
}

require_openssl() {
  find_openssl && return 0
  die "no OpenSSL 3 that can verify Ed25519 signatures was found, so the signed manifest cannot be checked before
running anything. Stock macOS ships LibreSSL, which cannot. Install one (macOS: brew install openssl@3; Debian/
Ubuntu: apt install openssl) or set INVEIL_OPENSSL to its path, then re-run. Nothing was downloaded or installed."
}

# Reads a JSON document and prints one "<path><TAB><value>" line per scalar (arrays use indices). The value of
# the top-level "payload" key goes byte-exact into $2 instead, so it can be verified and then parsed.
flatten_json() {
  LC_ALL=C awk -v payload_file="${2:-}" '
    function fail(message) {
      print "install.sh: error: malformed JSON: " message > "/dev/stderr"
      exit 1
    }
    function skip_space() {
      while (pos <= len && index(" \t\n\r", substr(text, pos, 1)) > 0) pos++
    }
    function hex_value(digit) {
      return index("0123456789abcdef", tolower(digit)) - 1
    }
    function parse_string(   out, ch, esc, code, i, digit) {
      pos++
      out = ""
      while (pos <= len) {
        ch = substr(text, pos, 1)
        if (ch == "\"") { pos++; return out }
        if (ch != "\\") { out = out ch; pos++; continue }
        esc = substr(text, pos + 1, 1)
        pos += 2
        if (esc == "n") out = out "\n"
        else if (esc == "t") out = out "\t"
        else if (esc == "r") out = out "\r"
        else if (esc == "b") out = out sprintf("%c", 8)
        else if (esc == "f") out = out sprintf("%c", 12)
        else if (esc == "/" || esc == "\\" || esc == "\"") out = out esc
        else if (esc == "u") {
          code = 0
          for (i = 0; i < 4; i++) {
            digit = hex_value(substr(text, pos + i, 1))
            if (digit < 0) fail("bad unicode escape")
            code = code * 16 + digit
          }
          pos += 4
          if (code == 0 || code >= 128) fail("unsupported unicode escape")
          out = out sprintf("%c", code)
        } else fail("unknown escape")
      }
      fail("unterminated string")
    }
    function emit(path, value) {
      if (path == "payload" && payload_file != "") {
        printf "%s", value > payload_file
        close(payload_file)
        return
      }
      if (index(value, "\n") > 0 || index(value, "\t") > 0 || index(value, "\r") > 0) fail("control character in " path)
      print path "\t" value
    }
    function parse_value(path, depth,   ch, key, n, start) {
      if (depth > 16) fail("nested too deeply")
      skip_space()
      if (pos > len) fail("unexpected end")
      ch = substr(text, pos, 1)
      if (ch == "{") {
        pos++
        skip_space()
        if (substr(text, pos, 1) == "}") { pos++; return }
        while (1) {
          skip_space()
          if (substr(text, pos, 1) != "\"") fail("expected a key")
          key = parse_string()
          skip_space()
          if (substr(text, pos, 1) != ":") fail("expected a colon")
          pos++
          parse_value(path == "" ? key : path "." key, depth + 1)
          skip_space()
          ch = substr(text, pos, 1)
          pos++
          if (ch == "}") return
          if (ch != ",") fail("expected a comma")
        }
      }
      if (ch == "[") {
        pos++
        skip_space()
        if (substr(text, pos, 1) == "]") { pos++; return }
        n = 0
        while (1) {
          parse_value(path "." n, depth + 1)
          n++
          skip_space()
          ch = substr(text, pos, 1)
          pos++
          if (ch == "]") return
          if (ch != ",") fail("expected a comma")
        }
      }
      if (ch == "\"") { emit(path, parse_string()); return }
      start = pos
      while (pos <= len && index(",}] \t\n\r", substr(text, pos, 1)) == 0) pos++
      if (pos == start) fail("unexpected character")
      emit(path, substr(text, start, pos - start))
    }
    { text = text $0 "\n" }
    END {
      len = length(text)
      pos = 1
      parse_value("", 0)
      skip_space()
      if (pos <= len) fail("trailing data")
    }
  ' "$1"
}

json_field() {
  awk -F '\t' -v name="$2" '$1 == name { print substr($0, length($1) + 2); exit }' "$1"
}

# Prints -1, 0 or 1 comparing two semantic versions (prerelease sorts below the release).
version_compare() {
  awk -v a="$1" -v b="$2" '
    function split_version(text, parts,   dash) {
      dash = index(text, "-")
      parts["pre"] = dash > 0 ? substr(text, dash + 1) : ""
      parts["count"] = split(dash > 0 ? substr(text, 1, dash - 1) : text, core, ".")
      for (i = 1; i <= 3; i++) parts[i] = core[i] + 0
    }
    function compare_identifiers(x, y,   xs, ys, xn, yn, k, limit) {
      xn = split(x, xs, ".")
      yn = split(y, ys, ".")
      limit = xn > yn ? xn : yn
      for (k = 1; k <= limit; k++) {
        if (k > xn) return -1
        if (k > yn) return 1
        if (xs[k] == ys[k]) continue
        if (xs[k] ~ /^[0-9]+$/ && ys[k] ~ /^[0-9]+$/) return (xs[k] + 0 < ys[k] + 0) ? -1 : 1
        if (xs[k] ~ /^[0-9]+$/) return -1
        if (ys[k] ~ /^[0-9]+$/) return 1
        return (xs[k] < ys[k]) ? -1 : 1
      }
      return 0
    }
    BEGIN {
      split_version(a, left)
      split_version(b, right)
      for (i = 1; i <= 3; i++) {
        if (left[i] != right[i]) { print (left[i] < right[i]) ? -1 : 1; exit }
      }
      if (left["pre"] == right["pre"]) { print 0; exit }
      if (left["pre"] == "") { print 1; exit }
      if (right["pre"] == "") { print -1; exit }
      print compare_identifiers(left["pre"], right["pre"])
    }'
}

is_version() {
  printf '%s' "$1" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'
}

installed_version() {
  [ -x "$INSTALL_DIR/inveil" ] || return 0
  "$INSTALL_DIR/inveil" --version </dev/null 2>/dev/null | sed -n 's/^inveil \([0-9][0-9A-Za-z.+-]*\).*/\1/p' | head -n 1
}

# Checks the signed manifest with OpenSSL only. Sets MANIFEST_VERSION, ARTIFACT_SHA256 and ARTIFACT_SIZE.
verify_manifest() {
  flatten_json "$WORK_DIR/$MANIFEST_NAME" "$WORK_DIR/payload" >"$WORK_DIR/envelope.flat"
  [ -f "$WORK_DIR/payload" ] || die "the manifest envelope has no payload"
  { printf '%s\0' "$UPDATE_DOMAIN"; cat "$WORK_DIR/payload"; } >"$WORK_DIR/signed-message"

  : >"$WORK_DIR/valid-keys"
  index=0
  while [ "$index" -lt "$MAX_SIGNATURES" ]; do
    signer_id=$(json_field "$WORK_DIR/envelope.flat" "signatures.$index.key_id")
    signature=$(json_field "$WORK_DIR/envelope.flat" "signatures.$index.signature")
    index=$((index + 1))
    [ -n "$signer_id" ] && [ -n "$signature" ] || continue
    case $signature in *[!A-Za-z0-9+/=]*) continue ;; esac
    for entry in $UPDATE_KEYS; do
      [ "${entry%%=*}" = "$signer_id" ] || continue
      if ed25519_verify "$OPENSSL" "${entry#*=}" "$signature" "$WORK_DIR/signed-message"; then
        base64_decode "${entry#*=}" "$WORK_DIR/raw-key"
        hex_of "$WORK_DIR/raw-key" >>"$WORK_DIR/valid-keys"
        echo >>"$WORK_DIR/valid-keys"
      fi
    done
  done
  valid_signatures=$(sort -u "$WORK_DIR/valid-keys" | grep -c . || true)

  flatten_json "$WORK_DIR/payload" >"$WORK_DIR/payload.flat"
  manifest_threshold=$(json_field "$WORK_DIR/payload.flat" threshold)
  case $manifest_threshold in '' | *[!0-9]*) die "the signed manifest has no valid threshold" ;; esac
  required=$MIN_SIGNATURES_EFFECTIVE
  if [ "$manifest_threshold" -gt "$required" ]; then
    required=$manifest_threshold
  fi
  [ "$valid_signatures" -ge "$required" ] ||
    die "manifest has $valid_signatures valid signature(s) from distinct pinned keys, $required required; nothing was installed"
  say "Manifest signature check passed: $valid_signatures distinct pinned key(s) signed (required $required)."

  [ "$(json_field "$WORK_DIR/payload.flat" schema)" = "$MANIFEST_SCHEMA" ] || die "unsupported manifest schema"
  [ "$(json_field "$WORK_DIR/payload.flat" channel)" = "$channel" ] ||
    die "the manifest is for channel '$(json_field "$WORK_DIR/payload.flat" channel)', not '$channel'"
  expires_at=$(json_field "$WORK_DIR/payload.flat" expires_at)
  case $expires_at in '' | *[!0-9]*) die "the signed manifest has no valid expires_at" ;; esac
  [ "$expires_at" -gt "$(date +%s)" ] || die "the signed manifest has expired; ask the publisher for a new release"

  MANIFEST_VERSION=$(json_field "$WORK_DIR/payload.flat" version)
  is_version "$MANIFEST_VERSION" || die "the signed manifest has an invalid version"
  if [ -n "$min_version" ] && [ "$(version_compare "$MANIFEST_VERSION" "$min_version")" = -1 ]; then
    die "the signed manifest is for $MANIFEST_VERSION, older than --min-version $min_version; nothing was installed"
  fi
  if [ -n "$release_version" ]; then
    [ "$MANIFEST_VERSION" = "$release_version" ] || die "asked for $release_version but the manifest is for $MANIFEST_VERSION"
  else
    current=$(installed_version)
    if [ -n "$current" ] && [ "$(version_compare "$MANIFEST_VERSION" "$current")" = -1 ]; then
      die "refusing to downgrade from $current to $MANIFEST_VERSION; pass --version $MANIFEST_VERSION to do it deliberately"
    fi
  fi

  ARTIFACT_SHA256=$(json_field "$WORK_DIR/payload.flat" "artifacts.$TARGET.sha256")
  ARTIFACT_SIZE=$(json_field "$WORK_DIR/payload.flat" "artifacts.$TARGET.size")
  printf '%s' "$ARTIFACT_SHA256" | grep -Eq '^[0-9a-f]{64}$' || die "the signed manifest has no SHA-256 for $TARGET"
  case $ARTIFACT_SIZE in '' | *[!0-9]*) die "the signed manifest has no size for $TARGET" ;; esac
  [ "$ARTIFACT_SIZE" -le "$MAX_BINARY_BYTES" ] || die "the signed size for $TARGET is implausibly large"
}

verify_download() {
  [ "$(file_size "$WORK_DIR/$BINARY_NAME")" = "$ARTIFACT_SIZE" ] ||
    die "size mismatch for $BINARY_NAME (signed manifest says $ARTIFACT_SIZE bytes); nothing was installed"
  actual=$(sha256_of "$WORK_DIR/$BINARY_NAME")
  [ "$actual" = "$ARTIFACT_SHA256" ] ||
    die "SHA-256 mismatch for $BINARY_NAME (signed manifest says $ARTIFACT_SHA256, got $actual); nothing was installed"
  say "Binary matches the signed manifest: sha256 $actual, $ARTIFACT_SIZE bytes."

  chmod 700 "$WORK_DIR/$BINARY_NAME"
  pinned_args=""
  for entry in $UPDATE_KEYS; do
    pinned_args="$pinned_args --pinned-key $entry"
  done
  # The key list was validated to contain no whitespace or shell metacharacters, so splitting is safe.
  # shellcheck disable=SC2086
  "$WORK_DIR/$BINARY_NAME" verify --role update $pinned_args --artifact "$WORK_DIR/$BINARY_NAME" \
    "$WORK_DIR/$MANIFEST_NAME" </dev/null || die "inveil verify rejected the manifest; nothing was installed"
  say "inveil verify agrees (second check)."
}

install_binary() {
  target="$INSTALL_DIR/inveil"
  mkdir -p "$INSTALL_DIR"
  if [ -f "$target" ] && [ "$(sha256_of "$target")" = "$actual" ]; then
    say "inveil $target is already up to date."
    return 0
  fi
  cp "$WORK_DIR/$BINARY_NAME" "$INSTALL_DIR/inveil.new"
  chmod 755 "$INSTALL_DIR/inveil.new"
  if [ -f "$target" ]; then
    mv -f "$target" "$INSTALL_DIR/inveil.prev"
    say "Kept the previous binary as $INSTALL_DIR/inveil.prev"
  fi
  mv -f "$INSTALL_DIR/inveil.new" "$target"
  [ "$(sha256_of "$target")" = "$actual" ] || die "installed file does not match the verified download"
  say "Installed $target"
}

# The update section carries the same trust settings the installer just enforced, so the 2-of-N rule also holds for
# the in-app updater: the pinned keys, the minimum signatures and the signed feed (never an unsigned payload).
bundle_json() {
  printf '{"backend_url":"%s","pinned_keys":%s,"enrollment_token":"%s","auth":{"mode":"enrolled"},"update":{"keys":%s,"min_signatures":%s,"feed_url":"%s"}}\n' \
    "$BACKEND_URL" "$(key_list_to_json "$BACKEND_KEYS")" "$ENROLL_TOKEN" "$(key_list_to_json "$UPDATE_KEYS")" \
    "$MIN_SIGNATURES_EFFECTIVE" "$FEED_URL"
}

enroll_device() {
  if [ -n "$BUNDLE_FILE" ]; then
    "$INSTALL_DIR/inveil" enroll --bundle "$BUNDLE_FILE" </dev/null
  else
    bundle_json | "$INSTALL_DIR/inveil" enroll --bundle /dev/stdin
  fi
  "$INSTALL_DIR/inveil" install </dev/null
  say "Enrolled this device and installed the background service."
  if [ -n "$BUNDLE_FILE" ]; then
    say "Note: $BUNDLE_FILE still contains the one-time enrollment token. Delete it now."
  else
    say "The one-time enrollment token went to inveil on a pipe: it was never on a command line or written to disk by this script."
  fi
}

uninstall() {
  if [ -x "$INSTALL_DIR/inveil" ]; then
    "$INSTALL_DIR/inveil" uninstall </dev/null
  else
    say "No inveil binary at $INSTALL_DIR/inveil; skipping service removal."
  fi
  rm -f "$INSTALL_DIR/inveil" "$INSTALL_DIR/inveil.prev" "$INSTALL_DIR/inveil.new"
  say "Removed $INSTALL_DIR/inveil. Enrollment data and keychain entries are removed by 'inveil uninstall'."
}

main() {
  enroll_requested=0
  bundle_file=""
  backend_url=""
  backend_keys=""
  skip_enroll=0
  release_version=""
  min_version=""
  channel=stable
  do_uninstall=0
  dry_run=0
  allow_single_signature=0

  while [ $# -gt 0 ]; do
    case $1 in
      --enroll) enroll_requested=1; shift ;;
      --bundle) need_value "$1" $#; bundle_file=$2; shift 2 ;;
      --backend-url) need_value "$1" $#; backend_url=$2; shift 2 ;;
      --pinned-key) need_value "$1" $#; backend_keys="$backend_keys $2"; shift 2 ;;
      --no-enroll) skip_enroll=1; shift ;;
      --version) need_value "$1" $#; release_version=${2#v}; shift 2 ;;
      --min-version) need_value "$1" $#; min_version=${2#v}; shift 2 ;;
      --channel) need_value "$1" $#; channel=$2; shift 2 ;;
      --allow-single-signature) allow_single_signature=1; shift ;;
      --uninstall) do_uninstall=1; shift ;;
      --dry-run) dry_run=1; shift ;;
      -h | --help) usage; exit 0 ;;
      -*) die "unknown option (try --help)" ;;
      *) die "unexpected argument; an enrollment token must be passed in INVEIL_ENROLL_TOKEN, never as an argument" ;;
    esac
  done

  ENROLL_TOKEN=${INVEIL_ENROLL_TOKEN:-}
  unset INVEIL_ENROLL_TOKEN

  case $channel in
    stable | beta) ;;
    *) die "--channel must be stable or beta" ;;
  esac
  if [ -n "$release_version" ]; then
    is_version "$release_version" || die "invalid --version"
  fi
  if [ -n "$min_version" ]; then
    is_version "$min_version" || die "invalid --min-version"
  fi
  [ -z "$ENROLL_TOKEN" ] || [ -z "$bundle_file" ] || die "use either INVEIL_ENROLL_TOKEN or --bundle, not both"
  if [ "$enroll_requested" = 1 ] && [ -z "$ENROLL_TOKEN" ] && [ -z "$bundle_file" ]; then
    die "--enroll needs the token in the INVEIL_ENROLL_TOKEN environment variable (or use --bundle <file>)"
  fi

  UPDATE_KEYS=$UPDATE_PUBLIC_KEYS
  min_signatures=$MIN_SIGNATURES
  base_url=""
  if [ "${INVEIL_INSTALL_TESTING:-}" = 1 ]; then
    say "WARNING: INVEIL_INSTALL_TESTING=1, pinned keys and download location may be overridden. Never use this for a real install."
    UPDATE_KEYS=${INVEIL_UPDATE_PUBLIC_KEYS:-$UPDATE_KEYS}
    min_signatures=${INVEIL_MIN_SIGNATURES:-$min_signatures}
    base_url=${INVEIL_INSTALL_BASE_URL:-}
  fi
  if is_placeholder "$UPDATE_KEYS"; then
    die "no update public keys are pinned in this script (UPDATE_PUBLIC_KEYS); refusing to install unverified software"
  fi
  validate_key_list UPDATE_PUBLIC_KEYS "$UPDATE_KEYS"
  if is_placeholder "$min_signatures"; then
    min_signatures=$DEFAULT_MIN_SIGNATURES
  fi
  case $min_signatures in
    '' | *[!0-9]*) die "MIN_SIGNATURES must be a number" ;;
  esac
  [ "$min_signatures" -ge 1 ] || die "MIN_SIGNATURES must be at least 1"
  if [ "$min_signatures" -lt "$DEFAULT_MIN_SIGNATURES" ] && [ "$allow_single_signature" = 0 ]; then
    die "this script accepts a manifest with fewer than $DEFAULT_MIN_SIGNATURES signatures; that is only for self-hosters with one update key. Pass --allow-single-signature if that is what you intend"
  fi
  MIN_SIGNATURES_EFFECTIVE=$min_signatures

  os=$(detect_os)
  architecture=$(detect_arch "$os")
  TARGET="$os-$architecture"
  BINARY_NAME="inveil-$TARGET"
  MANIFEST_NAME=update-manifest.json.sig
  if [ "$channel" = beta ]; then
    MANIFEST_NAME=update-manifest-beta.json.sig
  fi

  INSTALL_DIR=${INVEIL_INSTALL_DIR:-${XDG_BIN_HOME:-$HOME/.local/bin}}

  if [ -z "$base_url" ]; then
    if [ -n "$release_version" ]; then
      base_url="$GITHUB_RELEASES_URL/download/v$release_version"
    elif [ "$channel" = beta ]; then
      die "the beta channel is published on pre-releases; pass --version <x.y.z-rc.N>"
    else
      base_url="$GITHUB_RELEASES_URL/latest/download"
    fi
  fi
  base_url=${base_url%/}
  # The updater's feed is always the https GitHub URL, even when tests redirect the download location.
  if [ "$channel" = beta ]; then
    FEED_URL="$GITHUB_RELEASES_URL/download/v$release_version/$MANIFEST_NAME"
  else
    FEED_URL="$GITHUB_RELEASES_URL/latest/download/$MANIFEST_NAME"
  fi

  BUNDLE_FILE=$bundle_file
  BACKEND_URL=$backend_url
  BACKEND_KEYS=$backend_keys
  if [ -z "$BACKEND_URL" ] && ! is_placeholder "$DEFAULT_BACKEND_URL"; then
    BACKEND_URL=$DEFAULT_BACKEND_URL
  fi
  if [ -z "$BACKEND_KEYS" ] && ! is_placeholder "$DEFAULT_BACKEND_PINNED_KEYS"; then
    BACKEND_KEYS=$DEFAULT_BACKEND_PINNED_KEYS
  fi

  enrolling=0
  if [ "$skip_enroll" = 0 ] && { [ -n "$ENROLL_TOKEN" ] || [ -n "$BUNDLE_FILE" ]; }; then
    enrolling=1
  fi
  if [ "$enrolling" = 1 ] && [ -n "$ENROLL_TOKEN" ]; then
    [ -n "$BACKEND_URL" ] || die "--enroll needs --backend-url"
    [ -n "$BACKEND_KEYS" ] || die "--enroll needs at least one --pinned-key"
    validate_key_list "--pinned-key" "$BACKEND_KEYS"
    check_backend_url "$BACKEND_URL"
    case $BACKEND_URL in
      *[!][A-Za-z0-9:/._~%?=@+'&'-]*) die "--backend-url contains unsupported characters" ;;
    esac
    case $ENROLL_TOKEN in
      *[!A-Za-z0-9_-]*) die "the enrollment token must contain only letters, digits, '-' and '_'" ;;
    esac
  fi
  if [ "$enrolling" = 1 ] && [ -n "$BUNDLE_FILE" ] && [ ! -f "$BUNDLE_FILE" ]; then
    die "bundle file not found: $BUNDLE_FILE"
  fi

  trap cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM HUP
  WORK_DIR=$(umask 077 && mktemp -d "${TMPDIR:-/tmp}/inveil-install.XXXXXX")
  chmod 700 "$WORK_DIR"

  if [ "$dry_run" = 1 ]; then
    find_openssl || true
  else
    require_openssl
  fi

  say "inveil installer: $os/$architecture, channel $channel, install dir $INSTALL_DIR"
  load_pinned_keys "$UPDATE_KEYS"
  say "Signatures required: at least $MIN_SIGNATURES_EFFECTIVE distinct pinned keys (the manifest may raise this)."
  [ "$distinct_pinned_keys" -ge "$MIN_SIGNATURES_EFFECTIVE" ] ||
    die "only $distinct_pinned_keys distinct key(s) are pinned but $MIN_SIGNATURES_EFFECTIVE signatures are required"

  if [ "$do_uninstall" = 1 ]; then
    if [ "$dry_run" = 1 ]; then
      say "[dry-run] would run '$INSTALL_DIR/inveil uninstall' and remove $INSTALL_DIR/inveil"
      return 0
    fi
    uninstall
    return 0
  fi

  if [ "$dry_run" = 1 ]; then
    say "[dry-run] verifier: ${OPENSSL:-none found (a real run would refuse)}"
    say "[dry-run] would download $base_url/$MANIFEST_NAME and verify its signatures before anything else"
    say "[dry-run] would download $base_url/$BINARY_NAME and check its SHA-256 and size against the signed manifest"
    say "[dry-run] would then run 'inveil verify --role update' from the checked binary and install $INSTALL_DIR/inveil"
    if [ "$enrolling" = 1 ]; then
      say "[dry-run] would run 'inveil enroll --bundle' (token on a pipe) then 'inveil install'"
    else
      say "[dry-run] would not enroll"
    fi
    return 0
  fi

  fetch "$base_url/$MANIFEST_NAME" "$WORK_DIR/$MANIFEST_NAME" "$MAX_MANIFEST_BYTES"
  verify_manifest
  fetch "$base_url/$BINARY_NAME" "$WORK_DIR/$BINARY_NAME" "$MAX_BINARY_BYTES"
  verify_download
  install_binary

  if [ "$enrolling" = 1 ]; then
    enroll_device
  else
    say "Not enrolled. Next: run 'inveil init' then 'inveil install', or re-run this script with --enroll."
  fi

  case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *) say "Note: $INSTALL_DIR is not on your PATH." ;;
  esac
  say "To uninstall: sh install.sh --uninstall"
}

main "$@"
