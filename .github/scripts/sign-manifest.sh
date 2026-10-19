#!/bin/sh
# Usage: sign-manifest.sh <payload.json> <output.sig> <key_id>:<ENV_VAR_WITH_KEY>...
# Signs an update manifest with OpenSSL only, so no repository-built code runs next to the signing key. Each key is
# base64 PKCS#8 (what `inveil keygen` writes) read from the named environment variable and piped straight into
# openssl; it never touches the disk. The output is the envelope `inveil verify` and install.sh expect.
# Needs UPDATE_PUBLIC_KEYS: every key_id given must be pinned there and the key must match, which catches a
# mislabelled secret before a signature is published.
#
# Before any key is read the payload is validated against what this run produced (update_manifest.py validate):
# version equals the tag, channel matches the tag kind, threshold is at least 2, expiry is in a sane window, every
# artifact URL is https://github.com/$GITHUB_REPOSITORY/releases/download/$EXPECTED_TAG/<name>, every target is
# present and sha256/size match the packaged binaries in $DIST_DIR. Needs EXPECTED_TAG, GITHUB_REPOSITORY and
# DIST_DIR. ALLOW_UNOFFICIAL_RELEASE=true (forks) permits a threshold of 1 and more than one key in this job.
# Official releases sign with one key per job: sign-manifest and cosign-manifest each hold one, in separate
# protected environments, and update_manifest.py merge combines the two envelopes.
set -eu

payload=${1:?usage: sign-manifest.sh <payload.json> <output.sig> <key_id>:<ENV_VAR>...}
output=${2:?missing output path}
shift 2
[ $# -gt 0 ] || { echo "sign-manifest.sh: no keys given" >&2; exit 1; }
: "${UPDATE_PUBLIC_KEYS:?UPDATE_PUBLIC_KEYS is not set}"
: "${EXPECTED_TAG:?EXPECTED_TAG is not set}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is not set}"
: "${DIST_DIR:?DIST_DIR is not set}"

die() {
  echo "sign-manifest.sh: $*" >&2
  exit 1
}

validate_flags=""
if [ "${ALLOW_UNOFFICIAL_RELEASE:-}" = true ]; then
  validate_flags="--allow-unofficial"
elif [ $# -gt 1 ]; then
  die "official releases sign with one key per job; the second key signs in cosign-manifest (ALLOW_UNOFFICIAL_RELEASE=true for forks)"
fi

# The validator never sees the signing keys: they are removed from its environment.
unset_flags=""
for spec in "$@"; do
  unset_flags="$unset_flags -u ${spec#*:}"
done
# shellcheck disable=SC2086
env $unset_flags python3 "$(dirname "$0")/update_manifest.py" validate --payload "$payload" --dist "$DIST_DIR" \
  --tag "$EXPECTED_TAG" --repo "$GITHUB_REPOSITORY" $validate_flags || die "payload validation failed; nothing was signed"

[ "$(tail -c 1 "$payload" | od -An -c | tr -d ' ')" = '\n' ] || die "the payload must end with a newline"
grep -q "$(printf '\r')" "$payload" && die "the payload must not contain carriage returns"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
{ printf 'inveil-update-v1\0'; cat "$payload"; } >"$work/message"

{
  printf '{\n  "payload": "'
  awk 'BEGIN { ORS = "" } { gsub(/\\/, "\\\\"); gsub(/"/, "\\\""); gsub(/\t/, "\\t"); print $0 "\\n" }' "$payload"
  printf '",\n  "signatures": ['
} >"$output"

separator=""
for spec in "$@"; do
  key_id=${spec%%:*}
  variable=${spec#*:}
  [ -n "$(printenv "$variable")" ] || die "environment variable $variable is empty"

  pinned=""
  for entry in $UPDATE_PUBLIC_KEYS; do
    [ "${entry%%=*}" = "$key_id" ] && pinned=${entry#*=}
  done
  [ -n "$pinned" ] || die "key id $key_id is not in UPDATE_PUBLIC_KEYS"

  actual=$(printenv "$variable" | openssl base64 -d -A | openssl pkey -inform DER -pubout -outform DER | tail -c 32 | openssl base64 -A)
  [ "$actual" = "$pinned" ] || die "the key in $variable does not match the pinned public key for $key_id"

  printenv "$variable" | openssl base64 -d -A | openssl pkeyutl -sign -rawin -inkey /dev/stdin -keyform DER \
    -in "$work/message" -out "$work/signature"
  printf '%s\n    {\n      "key_id": "%s",\n      "signature": "%s"\n    }' "$separator" "$key_id" \
    "$(openssl base64 -A <"$work/signature")" >>"$output"
  separator=","
done
printf '\n  ]\n}' >>"$output"
