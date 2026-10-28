#!/usr/bin/env bash
# Checks the lines added between two commits for Spanish text.
#
# Usage: scripts/check-diff-english.sh <base> <head>
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
base="$1"
head="$2"

# Test fixtures are raw data; the word list and allowlist contain Spanish on purpose
excludes=(
    ':(exclude)src/test/resources'
    ':(exclude).github/english-allowlist.txt'
    ':(exclude)scripts/check-english.sh'
)

status=0
while IFS= read -r file; do
    added="$(git diff --unified=0 "$base...$head" -- "$file" | grep '^+' | grep -v '^+++' | cut -c2- || true)"
    [[ -z "$added" ]] && continue
    "$root/scripts/check-english.sh" "$file" <<< "$added" || status=1
done < <(git diff --name-only --diff-filter=AMR "$base...$head" -- . "${excludes[@]}")

exit $status
