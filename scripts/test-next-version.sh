#!/usr/bin/env bash
# Tests next-version.sh against a throwaway repository shaped like this one:
# squash commits on develop, and releases tagged on main's merge commits.
#
# Usage: scripts/test-next-version.sh
set -euo pipefail

script="$(cd "$(dirname "$0")" && pwd)/next-version.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cd "$work"

export GIT_AUTHOR_NAME=test GIT_AUTHOR_EMAIL=test@example.com
export GIT_COMMITTER_NAME=test GIT_COMMITTER_EMAIL=test@example.com
git init -q -b main
git commit -q --allow-empty -m "chore: start"
git switch -q -c develop

failures=0
commit() { git commit -q --allow-empty -m "$1"; }
expect() { # description, expected, arguments...
    local actual
    actual="$("$script" "${@:3}")"
    if [[ "$actual" != "$2" ]]; then
        echo "FAIL: $1: expected '$2', got '$actual'"
        failures=$((failures + 1))
    fi
}
release() { # merge develop into main and tag it, like the release workflow
    git switch -q main
    git merge -q --no-ff --no-edit -m "chore: merge develop into main" develop
    git tag "$1"
    git switch -q develop
}

expect "only chores publish nothing" "" 
expect "only chores publish no beta" "" --beta

commit "feat: first"
expect "first release" "v0.1.0"
expect "first beta" "v0.1.0-beta.1" --beta

release v0.1.0
expect "nothing since the release" "" --beta

# The tag sits on main's merge commit, which develop does not contain
commit "docs: notes"
expect "docs publish no beta" "" --beta
commit "fix: bug"
expect "fix is a patch" "v0.1.1"
expect "fix gives a patch beta" "v0.1.1-beta.1" --beta
commit "feat: more"
expect "feat is a minor" "v0.2.0"
expect "feat gives a minor beta" "v0.2.0-beta.1" --beta

git tag v0.2.0-beta.1
expect "a beta is not a release" "v0.2.0"
expect "same commit gives no second beta" "" --beta
commit "docs: more notes"
expect "docs after a beta give no beta" "" --beta
commit "build(deps): bump"
expect "deps after a beta give no beta" "" --beta
commit "fix: another"
expect "a fix after a beta gives the next one" "v0.2.0-beta.2" --beta

git tag v0.2.0-beta.9
commit "fix: again"
git tag v0.2.0-beta.10
commit "fix: and again"
expect "betas sort as numbers" "v0.2.0-beta.11" --beta

release v0.2.0
expect "main after the release publishes nothing" ""
git tag v0.9.0
git tag v0.10.0
commit "fix: after many"
expect "versions sort as numbers" "v0.10.1"
commit "feat!: breaking"
expect "breaking is a major" "v1.0.0"
expect "breaking gives a major beta, numbered anew" "v1.0.0-beta.1" --beta

if [[ "$failures" -gt 0 ]]; then
    echo "$failures failed"
    exit 1
fi
echo "next-version: all passed"
