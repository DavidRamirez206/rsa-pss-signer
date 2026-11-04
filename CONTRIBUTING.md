# Contributing

## One-time setup

Enable the repository's git hooks after cloning:

```bash
git config core.hooksPath .githooks
```

The `commit-msg` hook rejects commits that break the conventions below before they
are created. CI runs the same checks on every pull request, so skipping the hook
only delays the failure.

## Branches

| Branch      | Purpose                                                  |
|-------------|----------------------------------------------------------|
| `main`      | Stable, deliverable code. Protected: changes only via PR. |
| `develop`   | Integration branch. Feature branches are merged here.     |
| `<type>/<short-description>` | One branch per task, created from `develop`. |

Flow:

1. `git switch develop && git pull`
2. `git switch -c feat/rsa-pss-signing` (the prefix matches the commit type)
3. Commit, push, and open a pull request into **`develop`**.
4. Another team member reviews it; CI must pass.
5. When a phase is complete, open a pull request from `develop` into **`main`**.

## Commit messages

[Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<optional scope>): <description>
```

- **Types:** `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `revert`, case-insensitive (`Feat:` is accepted)
- **Scopes:** usually the package: `cli`, `core`, `crypto`, `format`, `keystore`, `io`
- Subject in the imperative mood, at most 72 characters, no trailing period.
- Add `!` after the type for breaking changes: `feat(format)!: change .sig header layout`

Examples:

```
feat(crypto): add RSA-PSS signing service
fix(format): reject duplicate JSON keys in .sig files
test(keystore): cover wrong-password handling
```

Pull request titles follow the same format, since squash merges use them as the commit message.

## Releases

Merging `develop` into `main` publishes a release on its own. The version comes from
the commits since the last release:

| Commits include                                | Version bump          |
|------------------------------------------------|-----------------------|
| `feat!:` or a `BREAKING CHANGE:` footer        | major (`1.2.3` to `2.0.0`) |
| `feat:`                                        | minor (`1.2.3` to `1.3.0`) |
| `fix:` or `perf:`                              | patch (`1.2.3` to `1.2.4`) |
| Only `docs`, `ci`, `chore`, `test`, `build`... | no release            |

The first release is `v0.1.0`.

Use **Create a merge commit** for `develop` into `main`. A squash merge would hide the
individual commits behind the PR title, and a title like `chore: merge develop into main`
publishes nothing.

Running the **Release** workflow manually builds the executables as downloadable
artifacts without publishing anything.

## Language

Everything in the repository is written in **English**: code, identifiers, comments,
documentation, commit messages and PR titles.

CI flags added lines that contain Spanish-only characters (accented vowels, the letter n with tilde, inverted question and exclamation marks) or
common Spanish words. It is a heuristic, not a language detector. If a proper name
triggers it, add the name to `.github/english-allowlist.txt`.

The one exception is the Spanish text of the graphical interface, kept in
`src/main/resources/i18n/messages_es.properties`. Interface text always goes through the
message files, and both files must have the same keys (a test checks this).
