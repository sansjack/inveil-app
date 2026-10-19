#!/bin/sh
# Fails an official release whose update-signing setup is weaker than the trust model requires:
# a manifest threshold of at least 2, and at least two distinct pinned update keys to meet it.
# Needs UPDATE_PUBLIC_KEYS ("<key_id>=<base64>" entries) and UPDATE_MANIFEST_THRESHOLD.
# UPDATE_KEY_ID, when set, must be one of the pinned ids.
# Forks that cannot meet this set the repository variable ALLOW_UNOFFICIAL_RELEASE=true; the release is then
# warned about instead of refused (see docs/RELEASING.md).
set -eu

MINIMUM_THRESHOLD=2

fail() {
  if [ "${ALLOW_UNOFFICIAL_RELEASE:-}" = true ]; then
    echo "::warning::$* (allowed because ALLOW_UNOFFICIAL_RELEASE=true; this is not an official release)"
    exit 0
  fi
  echo "::error::$* Set the repository variables described in docs/RELEASING.md, or ALLOW_UNOFFICIAL_RELEASE=true for a fork."
  exit 1
}

threshold=${UPDATE_MANIFEST_THRESHOLD:-}
case $threshold in
  '' | *[!0-9]*) fail "UPDATE_MANIFEST_THRESHOLD must be a number, got '${threshold}'." ;;
esac
[ "$threshold" -ge "$MINIMUM_THRESHOLD" ] || fail "UPDATE_MANIFEST_THRESHOLD is $threshold; official releases need at least $MINIMUM_THRESHOLD."

keys=${UPDATE_PUBLIC_KEYS:-}
[ -n "$keys" ] || fail "UPDATE_PUBLIC_KEYS is empty."

seen_ids=" "
seen_keys=" "
distinct=0
for entry in $keys; do
  case $entry in
    *=*) ;;
    *) fail "UPDATE_PUBLIC_KEYS entry '$entry' is not <key_id>=<base64 public key>." ;;
  esac
  key_id=${entry%%=*}
  public_key=${entry#*=}
  case $key_id in '' | *[!A-Za-z0-9._-]*) fail "invalid key id '$key_id' in UPDATE_PUBLIC_KEYS." ;; esac
  case $public_key in '' | *[!A-Za-z0-9+/=]*) fail "invalid public key for '$key_id' in UPDATE_PUBLIC_KEYS." ;; esac
  case $seen_ids in *" $key_id "*) fail "key id '$key_id' appears twice in UPDATE_PUBLIC_KEYS." ;; esac
  case $seen_keys in *" $public_key "*) fail "key '$key_id' repeats another key's public key; two key ids for one key do not give two signers." ;; esac
  seen_ids="$seen_ids$key_id "
  seen_keys="$seen_keys$public_key "
  distinct=$((distinct + 1))
done

[ "$distinct" -ge "$threshold" ] || fail "only $distinct distinct update key(s) are pinned but the threshold is $threshold."

if [ -n "${UPDATE_KEY_ID:-}" ]; then
  case $seen_ids in *" $UPDATE_KEY_ID "*) ;; *) fail "UPDATE_KEY_ID '$UPDATE_KEY_ID' is not in UPDATE_PUBLIC_KEYS." ;; esac
fi
echo "Signing policy ok: threshold $threshold, $distinct distinct pinned update keys."
