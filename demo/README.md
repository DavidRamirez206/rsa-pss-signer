# Demo

Scripts for the live presentation. Section h) of [docs/design.md](../docs/design.md) has what to
say at each step.

| File | What it is |
|---|---|
| `commands.sh` | Every demo on Linux or macOS: `demo/commands.sh setup`, then `demo/commands.sh 1` to `9` or `all` |
| `commands.ps1` | The same on Windows: `.\demo\commands.ps1 setup`, then `.\demo\commands.ps1 1` |
| `DemoTools.java` | Helpers the program does not offer: keys with a chosen iteration count, brute force, and the export for OpenSSL |

Run them from the repository root after `mvn package`, in a real terminal. `setup` asks for a
password many times: use the same long demo password every time, never a real one.

Everything they generate goes to `demo/work/`, which git ignores: keys and signatures are never
committed. Each demo uses its own trust store and version history inside it, as if it ran on its
own machine, so the demos can be repeated in any order. To start again, delete `demo/work/`.

| Demo | Shows |
|---|---|
| 1 | Public key substitution: Mallory's signature is VALID with her key; only the fingerprint tells |
| 2 | One changed character gives INVALID |
| 3 | Editing the signer name in the `.sig` gives INVALID |
| 4 | Brute force: attempts per second with 1,000 and 600,000 iterations |
| 5 | OpenSSL verifies the same signature |
| 6 | Replay of an old version detected, and the limit on another machine |
| 7 | Trust on first use flags Mallory, the expected fingerprint, and the limit if she comes first |
| 8 | Certificate authority, time stamp, and a real RFC 3161 time stamp (needs internet) |
| 9 | The format warning before signing a PDF |

Plan B if something fails live: the output of a previous `demo/commands.sh all` run, saved as
screenshots, and `mvn test` for the suite.
