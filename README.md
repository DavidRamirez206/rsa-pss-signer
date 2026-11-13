# RSA-PSS file signer and verifier

University project (ICESI, Cybersecurity). A Java command-line tool with three operations:

1. **Generate an RSA key pair**: public and private keys in separate files, with the private key password-protected.
2. **Sign a file** with the private key, after checking the password.
3. **Verify a signature** against the original file and the public key.

RSA-PSS done right is not broken by attacking the math. Real attacks target trust in
the public key, unsigned metadata, error handling and the password, so those are
where the defenses and the tests are focused.

Full design document: [docs/design.md](docs/design.md).

## Authors

- Luis López
- Catalina Bernal
- Ismael Barrionuevo

## Design highlights

- **RSASSA-PSS** only, with explicit parameters (never the SHA-1 defaults), no PKCS#1 v1.5 fallback.
- **Strict allowlists**: 2048/3072/4096-bit keys, e = 65537, SHA-256/512 and SHA3-256/512.
- **Three verification outcomes**: `VALID` / `INVALID` / `ERROR`, mapped to exit codes **0 / 1 / 2**. No exception ever becomes `VALID`.
- **Signed canonical header** in the `.sig` file (version, hash, PSS params, key fingerprint, file name, signer, date).
- **SHA-256 fingerprint** of the public key, always displayed.
- **Hardened private key**: encrypted PKCS#8 (PBKDF2-HMAC-SHA256, 600,000 iterations + AES-256-CBC), owner-only permissions, password handled as `char[]`.
- **Streaming hash**: constant memory for multi-GB files.
- **Beyond a plain signature**: document versions against replay, trust on first use of each
  signer's key, an expected-fingerprint check, a minimal certificate authority and a time-stamping
  authority. Each one is explained with what it does not solve in
  [docs/design.md, section i](docs/design.md#i-breaking-the-limits-of-signatures).

## Package layout

```
co.edu.icesi.signer
├── cli       Main, Cli (run(args) -> exit code), PasswordProvider
├── core      VerificationResult, VerificationOutcome, Message, FileReview
├── crypto    KeyPairService, SigningService, VerificationService, HashAlg, PssParams
├── gui       GuiMain, AppShell, the three views, GuiActions, Theme
├── format    SigFile, CanonicalHeader, SigValidationException
├── keystore  PrivateKeyStore, PublicKeyStore, WrongPasswordException
├── io        AtomicFileWriter, FileHasher, SafeFileReader
├── policy    PolicyVerifier, TrustStore, VersionStore, LocalState
├── pki       MiniCa
└── timestamp TimeAuthority, TimeToken, TimeServer, TimeClient
```

## Usage

```bash
rsa-pss-signer keygen --out ana [--bits 2048|3072|4096]
rsa-pss-signer sign contract.txt --key ana.key --signer "Ana Perez" [--hash SHA-256] [--out contract.txt.sig]
rsa-pss-signer verify contract.txt --sig contract.txt.sig --pub ana.pub
```

`verify` exits with **0** (`VALID`), **1** (`INVALID`) or **2** (`ERROR`). Always compare the
displayed fingerprint with the signer through an independent channel: a valid signature
proves who holds the key, not who that person is.

Passwords are read from the console without echo and are never command-line arguments, so
run the program from a real terminal rather than an IDE.

From a source build, run `java -jar target/rsa-pss-signer.jar ...` after `mvn package`.

### Beyond a plain signature

```bash
# Document versions: sign the next version, chained to the previous signature
rsa-pss-signer sign contract.txt --key ana.key --signer "Ana Perez" --out v2.sig --previous v1.sig
rsa-pss-signer verify contract.txt --sig v2.sig --pub ana.pub [--previous v1.sig]

# The fingerprint the signer gave you through another channel
rsa-pss-signer verify contract.txt --sig contract.txt.sig --pub ana.pub --expect-fingerprint "3A:7F:..."

# Keys pinned on first use
rsa-pss-signer trust list
rsa-pss-signer trust remove "Ana Perez"

# A minimal certificate authority
rsa-pss-signer ca init --out ca --name "ICESI Demo CA"
rsa-pss-signer ca issue --ca ca --pub ana.pub --name "Ana Perez" --out ana.crt
rsa-pss-signer verify contract.txt --sig contract.txt.sig --cert ana.crt --ca ca.crt

# Revoking a certificate: the authority signs a revocation list, ca.crl, valid for 30 days
rsa-pss-signer ca revoke --ca ca --cert ana.crt
rsa-pss-signer ca crl --ca ca     # renews the list without revoking anything
rsa-pss-signer verify contract.txt --sig contract.txt.sig --cert ana.crt --ca ca.crt --crl ca.crl

# A time stamp from a time authority's key and clock
rsa-pss-signer tsa stamp contract.txt.sig --key tsa.key
rsa-pss-signer verify contract.txt --sig contract.txt.sig --pub ana.pub --timestamp contract.txt.sig.tst --tsa-pub tsa.pub

# The same time authority as an HTTP service; requests send only the hash of the .sig
rsa-pss-signer tsa serve --key tsa.key            # http://127.0.0.1:8318 until Ctrl+C
rsa-pss-signer tsa request contract.txt.sig --url http://127.0.0.1:8318
```

Verifying remembers, on this machine, the key of each signer name and the highest version of each
document, in `~/.rsa-pss-signer` (or the directory in `RSA_PSS_SIGNER_HOME`). A different key under
a known name, or an older version than one already verified, gives `INVALID`. That memory is local:
another machine has not seen what this one has. In the interface, a changed key offers a button
to forget the pinned one, after confirming the new fingerprint with the signer.

Renaming a signed file keeps it `VALID`: the signature protects the content. The name used when
signing is signed too and shown in the `.sig`.

`sign` shows the file's size and SHA-256 before asking for the password, and warns for formats
that can hide content, such as PDF or Office files.

Signatures made by v0.1.0 to v0.3.0 (format 1) keep verifying; they have no document version.

### Graphical interface

`rsa-pss-signer-gui` offers the same three operations in a window, on the same services and
with the same checks. The password field never shows what is typed, and files can be dropped
onto the path fields.

The first time it opens, a short user guide walks through the three operations. It can be
skipped, and reopened at any time from **User guide** in the sidebar.

The interface is available in English and Spanish, from the **EN / ES** selector. It starts in
Spanish on Spanish systems and remembers the choice. The command line stays in English.

Verifying in the interface applies the same trust store and version checks. Signing a file
again and replacing its signature signs the next version of the document, when the previous
signature was made with the same key.

From a source build: `java -cp target/rsa-pss-signer.jar co.edu.icesi.signer.gui.GuiMain`.

## Requirements

- JDK 17 or later
- Maven 3.9+
- OpenSSL (only for the interop tests and demo)

## Build and test

```bash
mvn verify                                                  # build + fast test suite
mvn test -Dgroups=slow,external -DexcludedGroups=           # slow and OpenSSL interop tests
```

Coverage report: `target/site/jacoco/index.html`.

## Executables

Native executables for Windows and Linux are produced by the **Release** workflow
(`jlink` + `jpackage`, with a bundled Java runtime, so no Java install needed).
Merging `develop` into `main` publishes a release automatically; see
[CONTRIBUTING.md](CONTRIBUTING.md#releases) for how the version is chosen.

Each file is published with its `.sha256` checksum.

Windows also gets `rsa-pss-signer-windows-x64-setup.exe`: an installer that adds the
program with its icon and shortcuts, without administrator rights.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the branch flow, commit conventions and the English-only rule.

## Third-party assets

The interface bundles the [Plus Jakarta Sans](https://github.com/tokotype/PlusJakartaSans) font under the
[SIL Open Font License](src/main/resources/fonts/OFL.txt), and uses [FlatLaf](https://www.formdev.com/flatlaf/) (Apache 2.0).

## License

[MIT](LICENSE)
