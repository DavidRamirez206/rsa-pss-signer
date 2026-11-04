#!/usr/bin/env bash
# Prints the next release tag from the Conventional Commits since the latest
# stable release tag, or nothing if those commits do not change the program.
#
#   breaking change (feat!: or a BREAKING CHANGE: footer) -> major
#   feat                                                  -> minor
#   fix, perf                                             -> patch
#   anything else (docs, ci, chore, test, build...)       -> no release
#
# The first release is always v0.1.0.
#
# With --beta it prints the beta of that version, numbered after the betas already
# tagged (v0.3.0-beta.2), or nothing if no program change landed since the last one.
#
# Usage: scripts/next-version.sh [--beta]
set -euo pipefail

beta=false
if [[ "${1:-}" == "--beta" ]]; then
    beta=true
fi

# Prints major, minor or patch for a range of commits, or nothing.
bump_in() {
    local subjects bodies types
    subjects="$(git log --format=%s "$1")"
    bodies="$(git log --format=%b "$1")"
    types='[a-z]+(\([^)]*\))?'
    if grep -qiE "^[[:space:]]*$types!:" <<< "$subjects" || grep -qE '^BREAKING[ -]CHANGE:' <<< "$bodies"; then
        echo major
    elif grep -qiE '^[[:space:]]*feat(\([^)]*\))?:' <<< "$subjects"; then
        echo minor
    elif grep -qiE '^[[:space:]]*(fix|perf)(\([^)]*\))?:' <<< "$subjects"; then
        echo patch
    fi
}

# All tags, not only those reachable from HEAD: releases are tagged on main's merge
# commits, which develop does not contain. Betas never count as a release.
latest="$(git tag --list | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -V | tail -n 1 || true)"
if [[ -n "$latest" ]]; then
    range="$latest..HEAD"
else
    range="HEAD"
fi

bump="$(bump_in "$range")"
if [[ -z "$bump" ]]; then
    exit 0
fi

if [[ -z "$latest" ]]; then
    next="v0.1.0"
else
    IFS=. read -r major minor patch <<< "${latest#v}"
    case "$bump" in
        major) next="v$((major + 1)).0.0" ;;
        minor) next="v$major.$((minor + 1)).0" ;;
        patch) next="v$major.$minor.$((patch + 1))" ;;
    esac
fi

if [[ "$beta" == false ]]; then
    echo "$next"
    exit 0
fi

last_beta="$(git tag --list "$next-beta.*" | grep -E '\-beta\.[0-9]+$' | sort -V | tail -n 1 || true)"
if [[ -z "$last_beta" ]]; then
    echo "$next-beta.1"
elif [[ -n "$(bump_in "$last_beta..HEAD")" ]]; then
    echo "$next-beta.$((${last_beta##*.} + 1))"
fi
