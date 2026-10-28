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

- **RSASSA-PSS** only (`SHA256withRSAandMGF1` / `SHA512withRSAandMGF1`), no PKCS#1 v1.5 fallback.
- **Strict allowlists**: 2048/3072/4096-bit keys, e = 65537, SHA-256/512 and SHA3-256/512.
- **Three verification outcomes**: `VALID` / `INVALID` / `ERROR`, mapped to exit codes **0 / 1 / 2**. No exception ever becomes `VALID`.
- **Signed canonical header** in the `.sig` file (version, hash, PSS params, key fingerprint, file name, signer, date).
- **SHA-256 fingerprint** of the public key, always displayed.
- **Hardened private key**: encrypted PKCS#8 (PBKDF2-HMAC-SHA256, 600,000 iterations + AES-256-CBC), owner-only permissions, password handled as `char[]`.
- **Streaming hash**: constant memory for multi-GB files.

## Package layout

```
co.edu.icesi.signer
├── cli       Main, Cli (run(args) -> exit code), PasswordProvider
├── core      VerificationResult
├── crypto    KeyPairService, SigningService, VerificationService, HashAlg, PssParams
├── format    SigFile, CanonicalHeader, SigValidationException
├── keystore  PrivateKeyStore, PublicKeyStore, WrongPasswordException
└── io        AtomicFileWriter, FileHasher
```

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
Push a tag to build them:

```bash
git tag v1.0.0 && git push origin v1.0.0
```

Each archive is published with its `.sha256` checksum.

## License

[MIT](LICENSE)
