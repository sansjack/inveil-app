#!/bin/sh
# Prepares a release: bumps the workspace version, moves the CHANGELOG "Unreleased" entries under the new version
# (stable releases only), runs the tests, then commits and creates the annotated tag locally. Nothing is pushed: the
# script prints the push command, and pushing the tag starts release.yml (see docs/RELEASING.md).
#
# Usage: scripts/release.sh patch|minor|major   bump the current version, stable channel
#        scripts/release.sh X.Y.Z               stable channel
#        scripts/release.sh X.Y.Z-rc.N          beta channel (CHANGELOG left as is)

set -eu

die() {
  printf 'release: %s\n' "$1" >&2
  exit 1
}

[ "$#" -eq 1 ] || die "usage: scripts/release.sh patch|minor|major|X.Y.Z|X.Y.Z-rc.N"

cd "$(git rev-parse --show-toplevel)"

# patch/minor/major bump the current workspace version, ignoring any -rc suffix.
current=$(sed -n 's/^version = "\([0-9]*\.[0-9]*\.[0-9]*\).*"$/\1/p' Cargo.toml | head -n 1)
[ -n "$current" ] || die "could not read the version from Cargo.toml"
major=${current%%.*}
rest=${current#*.}
minor=${rest%%.*}
patch=${rest#*.}
case $1 in
  patch) version="$major.$minor.$((patch + 1))" ;;
  minor) version="$major.$((minor + 1)).0" ;;
  major) version="$((major + 1)).0.0" ;;
  *) version=$1 ;;
esac
tag="v$version"
printf '%s\n' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$' ||
  die "'$version' is not X.Y.Z or X.Y.Z-rc.N"
printf 'release: %s -> %s\n' "$current" "$version"

# release.yml only accepts a tag at the tip of main, so check that here rather than after the push.
[ "$(git branch --show-current)" = main ] || die "switch to main first"
[ -z "$(git status --porcelain)" ] || die "the working tree has uncommitted changes"
git fetch --quiet origin main --tags
[ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ] || die "main is not in sync with origin/main"
if git rev-parse --quiet --verify "refs/tags/$tag" >/dev/null; then
  die "tag $tag already exists"
fi

restore_hint() {
  printf 'release: stopped; undo the edits with: git checkout -- Cargo.toml Cargo.lock CHANGELOG.md\n' >&2
}
trap restore_hint EXIT

# The first `version = ` line in the root Cargo.toml is [workspace.package]; every crate inherits it.
awk -v version="$version" '
  !done && /^version = "/ { print "version = \"" version "\""; done = 1; next }
  { print }
' Cargo.toml >Cargo.toml.tmp && mv Cargo.toml.tmp Cargo.toml
grep -q "^version = \"$version\"$" Cargo.toml || die "could not set the version in Cargo.toml"

case $version in
  *-rc.*) ;;
  *)
    # Unreleased must have entries: a stable release with nothing to announce is a mistake.
    awk '/^## \[Unreleased\]/ { inside = 1; next } /^## \[/ { inside = 0 } inside && /^- / { found = 1 } END { exit !found }' \
      CHANGELOG.md || die "CHANGELOG.md has no entries under [Unreleased]"
    today=$(date -u +%Y-%m-%d)
    repo_url=https://github.com/sansjack/inveil-app
    awk -v version="$version" -v today="$today" -v url="$repo_url" '
      /^## \[Unreleased\]$/ { print; print ""; print "## [" version "] - " today; next }
      /^\[Unreleased\]: / {
        print "[Unreleased]: " url "/compare/v" version "...main"
        print "[" version "]: " url "/releases/tag/v" version
        next
      }
      { print }
    ' CHANGELOG.md >CHANGELOG.md.tmp && mv CHANGELOG.md.tmp CHANGELOG.md
    ;;
esac

# Refreshes Cargo.lock for the new version, then the same --locked build CI runs.
cargo check --workspace --quiet
cargo test --workspace --locked --quiet

git add Cargo.toml Cargo.lock CHANGELOG.md
git commit --quiet -m "chore: release $tag"
git tag -a "$tag" -m "$tag"
trap - EXIT

printf 'Created commit and tag %s locally. Review with: git show %s\n' "$tag" "$tag"
printf 'To release, push both: git push origin main && git push origin %s\n' "$tag"
printf 'Then follow docs/RELEASING.md from step 4 (approve the signing environments, co-sign, publish).\n'
