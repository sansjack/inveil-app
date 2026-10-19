#!/usr/bin/env bash
# Usage: verify-manifest.sh <inveil-binary> <dist-dir> <version> <manifest-envelope>
# Needs UPDATE_PUBLIC_KEYS: whitespace-separated "<key_id>=<base64 public key>" entries.
#
# Always checks that the signed payload matches the files on disk. Runs `inveil verify`
# (signatures and threshold) only when the envelope already carries enough signatures;
# a manifest missing its co-signature cannot meet a threshold of 2.
# Only run this in a job that holds no token or secret: it executes the downloaded binary.
# When it did verify, it writes "verified=true" to $GITHUB_OUTPUT.
set -euo pipefail

inveil_binary=$1
dist_dir=$2
version=$3
envelope=$4
script_dir=$(cd "$(dirname "$0")" && pwd)

report=$(python3 "$script_dir/update_manifest.py" check --dist "$dist_dir" --version "$version" --envelope "$envelope")
echo "$report"
signatures=$(echo "$report" | sed -n 's/^signatures=//p')
threshold=$(echo "$report" | sed -n 's/^threshold=//p')

if [ -z "${UPDATE_PUBLIC_KEYS:-}" ]; then
  echo "::warning::UPDATE_PUBLIC_KEYS is not set; skipping signature verification"
  exit 0
fi

if [ "$signatures" -lt "$threshold" ]; then
  echo "::notice::manifest has $signatures of $threshold required signatures; signature verification needs the co-signature from cosign-manifest"
  exit 0
fi

key_args=()
for entry in $UPDATE_PUBLIC_KEYS; do
  key_args+=(--pinned-key "$entry")
done

"$inveil_binary" verify --role update "${key_args[@]}" "$envelope"

echo "verified=true" >> "${GITHUB_OUTPUT:-/dev/null}"
