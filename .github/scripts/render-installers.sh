#!/bin/sh
# Usage: render-installers.sh <output-dir>
# Copies scripts/install.sh and scripts/install.ps1 with their @@PLACEHOLDERS@@ filled in from the environment:
#   UPDATE_PUBLIC_KEYS (required), MIN_SIGNATURES, BACKEND_URL, BACKEND_PINNED_KEYS (optional).
# Values end up inside single-quoted strings, so anything outside a strict allow-list is refused.
set -eu

output_dir=${1:?usage: render-installers.sh <output-dir>}
script_dir=$(cd "$(dirname "$0")" && pwd)
source_dir="$script_dir/../../scripts"

die() {
  printf 'render-installers.sh: error: %s\n' "$*" >&2
  exit 1
}

: "${UPDATE_PUBLIC_KEYS:?UPDATE_PUBLIC_KEYS is not set}"
MIN_SIGNATURES=${MIN_SIGNATURES:-2}
BACKEND_URL=${BACKEND_URL:-}
BACKEND_PINNED_KEYS=${BACKEND_PINNED_KEYS:-}

case $UPDATE_PUBLIC_KEYS in
  *[!A-Za-z0-9+/=._\ -]*) die "UPDATE_PUBLIC_KEYS contains characters outside A-Za-z0-9+/=._- and space" ;;
esac
case $BACKEND_PINNED_KEYS in
  *[!A-Za-z0-9+/=._\ -]*) die "BACKEND_PINNED_KEYS contains characters outside A-Za-z0-9+/=._- and space" ;;
esac
case $MIN_SIGNATURES in
  '' | *[!0-9]*) die "MIN_SIGNATURES must be a number" ;;
esac
case $BACKEND_URL in
  *[!A-Za-z0-9:/._~%?=@+\&-]*) die "BACKEND_URL contains unsupported characters" ;;
esac

mkdir -p "$output_dir"
export UPDATE_PUBLIC_KEYS MIN_SIGNATURES BACKEND_URL BACKEND_PINNED_KEYS

for name in install.sh install.ps1; do
  awk '
    function fill(line, placeholder, value,   at) {
      at = index(line, placeholder)
      if (at == 0 || value == "") return line
      return substr(line, 1, at - 1) value substr(line, at + length(placeholder))
    }
    {
      $0 = fill($0, "@@UPDATE_PUBLIC_KEYS@@", ENVIRON["UPDATE_PUBLIC_KEYS"])
      $0 = fill($0, "@@MIN_SIGNATURES@@", ENVIRON["MIN_SIGNATURES"])
      $0 = fill($0, "@@BACKEND_URL@@", ENVIRON["BACKEND_URL"])
      $0 = fill($0, "@@BACKEND_PINNED_KEYS@@", ENVIRON["BACKEND_PINNED_KEYS"])
      print
    }' "$source_dir/$name" >"$output_dir/$name"
done
chmod 755 "$output_dir/install.sh"
