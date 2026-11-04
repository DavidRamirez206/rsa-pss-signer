#!/usr/bin/env bash
# Prints the next release tag from the Conventional Commits since the latest
# release tag, or nothing if those commits do not change the program.
#
#   breaking change (feat!: or a BREAKING CHANGE: footer) -> major
#   feat                                                  -> minor
#   fix, perf                                             -> patch
#   anything else (docs, ci, chore, test, build...)       -> no release
#
# The first release is always v0.1.0.
#
# Usage: scripts/next-version.sh
set -euo pipefail

latest="$(git tag --merged HEAD --list 'v[0-9]*.[0-9]*.[0-9]*' --sort=-v:refname | sed -n 1p)"
if [[ -n "$latest" ]]; then
    range="$latest..HEAD"
else
    range="HEAD"
fi

subjects="$(git log --format=%s "$range")"
bodies="$(git log --format=%b "$range")"

types='[a-z]+(\([^)]*\))?'
if grep -qiE "^[[:space:]]*$types!:" <<< "$subjects" || grep -qE '^BREAKING[ -]CHANGE:' <<< "$bodies"; then
    bump=major
elif grep -qiE '^[[:space:]]*feat(\([^)]*\))?:' <<< "$subjects"; then
    bump=minor
elif grep -qiE '^[[:space:]]*(fix|perf)(\([^)]*\))?:' <<< "$subjects"; then
    bump=patch
else
    exit 0
fi

if [[ -z "$latest" ]]; then
    echo "v0.1.0"
    exit 0
fi

IFS=. read -r major minor patch <<< "${latest#v}"
case "$bump" in
    major) echo "v$((major + 1)).0.0" ;;
    minor) echo "v$major.$((minor + 1)).0" ;;
    patch) echo "v$major.$minor.$((patch + 1))" ;;
esac
