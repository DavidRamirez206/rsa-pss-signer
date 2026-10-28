# RSA-PSS signer and verifier — Project design document

2026-10-28 · University project · Java

**Authors:** Luis López, Catalina Bernal, Ismael Barrionuevo

## a) Summary and scope

The project implements a **file signer and verifier** using RSA, in Java, with three console operations: generate a key pair (password-protected private key), sign a file, and verify a signature. The design thesis is that **a correctly implemented RSA-PSS is not broken by attacking the math**: real attacks target trust in the public key, unsigned metadata, error handling, and the password. That is why those four things are the focus of the defenses and the tests.

### What the assignment requires (mandatory baseline)

1.  **RSA key pair generation** into two separate files (public and private); the private key file is password-protected.

2.  **Sign a file**: takes any file and the private key file; after checking the password, it generates the signature and stores it in a separate file.

3.  **Signature verification**: takes the original file, the signature file, and the public key file; verifies that the signature is correct.

### What we add and why

| Addition                                                                                       | Why                                                                                         |
|------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------|
| **RSASSA-PSS** signatures (not PKCS#1 v1.5)                                                    | Scheme with a modern security proof; avoids ambiguous policy decisions.                     |
| **Allowlists** for key size, exponent, hash, and PSS parameters                                | Closes off downgrade and algorithm-confusion attacks.                                       |
| **Signed canonical header** inside the `.sig`                                                  | Prevents tampering with metadata (signer, date, name) without invalidating the signature.   |
| **SHA-256 fingerprint of the public key**, always displayed                                    | Hands the trust decision to the user through an independent channel.                        |
| **Three verification states** (VALID / INVALID / ERROR) with exit codes 0 / 1 / 2              | Eliminates the class of false-positive bugs caused by a misplaced catch.                    |
| **Private key hardening** (high PBKDF2, random salt, 600 permissions, `char[]`)                | The `.key` can be attacked offline; real security depends on making each guess expensive.   |
| **Streaming** file hash                                                                        | Signs and verifies multi-GB files with constant memory.                                     |
| **Type 1 and 2** limits (signed name, version, trust store, time server)                       | Reduce informational limits honestly, showing who the trust is shifted to.                  |

### What is out of scope (explicitly)

- **X.509 certificates / full PKI.** A toy mini-PKI is included only as an optional Phase 5 extension, not as part of the baseline.

- **Real RFC 3161 timestamping against a public TSA** as a requirement. It is documented and, if time allows, a proof of concept is built.

- **File encryption.** The project signs and verifies; it does not encrypt the document's content.

- **Guaranteed memory wiping.** Java cannot guarantee it; the exposure window is reduced and we say so.

- **Defense against hidden content in the document (WYSIWYS).** Partial mitigations only; there is no cryptographic defense.

- **TOCTOU, spy FileOpener, ArchUnit, dependency-check** as delivered code: mentioned in the presentation as known limitations or future work.

> **Rigor convention for this document:** every external technical fact is verified and labeled. Those that depend on a library version or the environment are marked **to verify** in the appendix; the rest are **confirmed**. No class or API names are invented; where there is doubt, it is stated.

## b) Design decisions and rationale

All of these decisions are fixed **from the start**, before writing the core, because they shape the `.sig` format, the API, and the tests.

### 1. Verification with three outcomes

The verifier returns an `enum VerificationResult { VALID, INVALID, ERROR }`, **never a `boolean`**. The CLI delegates to `run(String[] args) -> int` and maps the states to exit codes **0 (VALID), 1 (INVALID), 2 (ERROR)**.

- **VALID**: the signature matches the file under that public key, and all format checks passed.

- **INVALID**: correct format, but the signature does not verify (modified file, wrong key, signature of a different file).

- **ERROR**: no decision could be made (missing file, malformed `.sig`, algorithm outside the allowlist, wrong key type).

*Rejected alternative:* return `boolean` and throw exceptions for errors. Rejected because it invites a generic `catch` to collapse ERROR into `true` or `false`, which is exactly the most dangerous bug (section 4.3 of the audit). Distinguishing INVALID from ERROR also gives honest messages: "the signature does not match" is not the same as "the file is broken".

### 2. RSASSA-PSS signatures, not PKCS#1 v1.5

*Rejected alternative:* PKCS#1 v1.5 (`SHA256withRSA`). It works, but PSS has a formal security proof (a reduction to the RSA problem in the random oracle model) and avoids the Bleichenbacher family of lax-parsing attacks. No "if PSS fails, try v1.5" *fallback* is implemented: accepting undecided schemes is the risk.

**Implementation decision (important):** use `Signature.getInstance("RSASSA-PSS")` and **always** call `setParameter(...)` with an explicit `PSSParameterSpec` bound to the message hash. Without it a `SignatureException("Parameters required for RSASSA-PSS signature")` is thrown, and `PSSParameterSpec.DEFAULT` uses **SHA-1**, not the intended hash. The JDK has **no** composite names such as `SHA256withRSAandMGF1` (those come from Bouncy Castle and throw `NoSuchAlgorithmException` on the JDK). To remove the footgun, the only way to obtain a `Signature` is `PssParams.newSignature(HashAlg)`, which sets the parameters every time. *(See appendix, PSS parameters.)*

### 3. Strict allowlists

| Parameter       | Allowed values                       | Anything else |
|-----------------|--------------------------------------|---------------|
| Key size        | 2048, 3072, 4096 bits                | ERROR         |
| Public exponent | 65537 (F4)                           | ERROR         |
| Hash            | SHA-256, SHA-512, SHA3-256, SHA3-512 | ERROR         |
| PSS salt        | = hash length                        | ERROR         |
| MGF             | MGF1 with the same hash as the message | ERROR       |
| PSS trailer     | 1 (`TRAILER_FIELD_BC`)               | ERROR         |

The hash is modeled as an `enum HashAlg`, never as free text. The algorithm name is **never** built by concatenating what comes from the `.sig` (`hash + "withRSA"`): that would allow `NONEwithRSA` and others. It is mapped `enum -> constant`.

*Rejected alternative:* accept any hash the JCE recognizes. Rejected because it opens a *downgrade* to MD5/SHA-1; SHA-1 has practical chosen-prefix collisions (SHAttered 2017).

### 4. Private key in encrypted PKCS#8 (PBES2)

Format: **encrypted PKCS#8, PBES2 = PBKDF2-HMAC-SHA256 + AES-256-CBC**, with the current recommended iteration count (**600,000**, see appendix). It must open with `openssl pkey`.

**Pure JDK vs. Bouncy Castle decision:** **Bouncy Castle** is used to *write* the encrypted key. Verified rationale:

- The JDK can **read** encrypted PKCS#8 with `EncryptedPrivateKeyInfo`, but *generating* a PBES2 with PBKDF2-HMAC-SHA256 + AES-256 and an iteration count of our choosing is awkward with the standard API before JDK 25: the PBES2 `AlgorithmParameters` have to be assembled by hand.

- Starting with **JDK 25** there is a PEM API (`PEMEncoder.withEncryption`, JEP 470, in *preview*) that simplifies this, but it is a preview and requires `--enable-preview`. **To verify** depending on the JDK version used by the course.

- Bouncy Castle does it directly and stably with `JcePKCSPBEOutputEncryptorBuilder(PBKDF2Config, AES_256_CBC).setIterationCount(...).setPRF(HmacSHA256)` or `JceOpenSSLPKCS8EncryptorBuilder`. It produces an encrypted PKCS#8 that OpenSSL opens without trouble. *(Class names verified in the BC Javadoc; see appendix.)*

*Conclusion:* for generation, **Bouncy Castle** gives control over the parameters with less risk. For reading, the JDK is enough. BC must be **≥ 1.78** (see appendix, CVE).

### 5. Password as `char[]`

Always `char[]`, cleared with `Arrays.fill(pwd, '\0')` in a `finally`, **never as a command-line argument** (it would end up in `ps`, the shell history, and logs). Input via `System.console().readPassword()`. **If `System.console()` is `null`** (running from an IDE), the program **refuses to continue** in console mode and, if there is a GUI, uses `JPasswordField`; it never falls back to a `Scanner` that echoes the password.

*Honesty:* Java cannot *guarantee* wiping — the GC may have copied the array, and the key's `BigInteger`s are immutable. Clearing reduces the window; it does not eliminate it. That is how it is presented.

### 6. Safe output files

- Permissions **600 from creation** (`Files.createFile` with `PosixFilePermissions.asFileAttribute(...)`), not create-then-`chmod` (race window).

- **Atomic write**: temp file in the same directory + `Files.move(..., ATOMIC_MOVE)`. A partial `.sig` is never left behind if something fails halfway.

- **No overwriting** without confirmation: outputs use `CREATE_NEW`.

### 7. Public key fingerprint always visible

The **SHA-256 fingerprint of the public key** (over its DER `SubjectPublicKeyInfo` encoding) is shown both when generating and when verifying, formatted as hex groups (`AB:CD:...`). It is what lets the user decide on trust through an independent channel.

### 8. Streaming hash

The file is hashed by reading in blocks with `DigestInputStream` or a `read(buffer)` loop that honors the return value. Constant memory; never `Files.readAllBytes` (fails above ~2 GB and throws `OutOfMemoryError` on huge files).

## c) Architecture

Separation of responsibilities: cryptography knows nothing about files, I/O knows nothing about cryptography, and the CLI only orchestrates and translates results into exit codes.

### Package structure

Base package: `co.edu.icesi.signer`.

| Package    | Class                       | Responsibility                                                                                         |
|------------|-----------------------------|--------------------------------------------------------------------------------------------------------|
| `cli`      | `Main`                      | `main(args)` → delegates to `run(args)`; catches the unexpected and returns 2.                         |
| `cli`      | `Cli`                       | `run(String[]) -> int`; parses the sub-option (1/2/3), calls the service, prints, and maps to an exit code. |
| `cli`      | `PasswordProvider`          | Interface for reading `char[]`; real implementation with `System.console()`, injectable test implementation. |
| `crypto`   | `KeyPairService`            | Generates the RSA pair with explicit parameters; computes the fingerprint.                             |
| `crypto`   | `SigningService`            | Signs: builds the canonical message and produces the signature bytes.                                  |
| `crypto`   | `VerificationService`       | Verifies: returns `VerificationResult`. It is the heart of the system.                                 |
| `crypto`   | `HashAlg` (enum)            | SHA-256 / SHA-512 / SHA3-256 / SHA3-512; maps to JCA names and lengths.                                |
| `crypto`   | `PssParams`                 | Encapsulates the fixed PSS parameters and builds the `PSSParameterSpec`.                               |
| `format`   | `SigFile`                   | `.sig` model: fields, canonical serialization, parsing with up-front validation.                       |
| `format`   | `CanonicalHeader`           | Deterministic serialization of the signed header.                                                      |
| `format`   | `SigValidationException`    | Signals an invalid format → maps to ERROR.                                                             |
| `keystore` | `PrivateKeyStore`           | Writes/reads encrypted PKCS#8 (Bouncy Castle); checks the password.                                    |
| `keystore` | `PublicKeyStore`            | Writes/reads the public key (X.509 SubjectPublicKeyInfo, PEM).                                         |
| `keystore` | `WrongPasswordException`    | Wrong password → controlled message, never a stack trace.                                              |
| `io`       | `AtomicFileWriter`          | Atomic write (temp file + `ATOMIC_MOVE`), 600 permissions.                                             |
| `io`       | `FileHasher`                | Streaming hash of an `InputStream`.                                                                    |
| `core`     | `VerificationResult` (enum) | `VALID(0)`, `INVALID(1)`, `ERROR(2)`.                                                                  |

### The result enum

``` java
public enum VerificationResult {
    VALID(0), INVALID(1), ERROR(2);
    private final int exitCode;
    VerificationResult(int c) { this.exitCode = c; }
    public int exitCode() { return exitCode; }
}
```

### Mapping exceptions to states

This is the contract that prevents false positives. The golden rule: **no exception ever turns into VALID.**

| Situation                                  | Typical exception                    | State                                                                     |
|--------------------------------------------|--------------------------------------|---------------------------------------------------------------------------|
| Signature does not match                   | `Signature.verify()` returns `false` | **INVALID**                                                               |
| Structurally broken signature              | `SignatureException`                 | **INVALID**                                                               |
| Malformed `.sig` (JSON/Base64)             | `SigValidationException`             | **ERROR**                                                                 |
| Hash/algorithm outside the allowlist       | `SigValidationException`             | **ERROR**                                                                 |
| Key of a disallowed type or size           | `InvalidKeyException`                | **ERROR**                                                                 |
| Missing file or key / no permissions       | `IOException`, `NoSuchFileException` | **ERROR**                                                                 |
| Declared fingerprint ≠ supplied key        | (own check)                          | **ERROR** with a specific message                                         |
| Programming bug                            | `NullPointerException`, etc.         | **allowed to propagate** (code 2 via `Main`), not disguised as INVALID    |

Only **specific** exceptions are caught, never a `catch (Exception e)` that would hide a real bug as "invalid signature".

### Flow of the three operations

**Operation 1 — Generate key pair**

1.  Validate the requested size against the allowlist {2048, 3072, 4096}.

2.  `KeyPairGenerator` with `RSAKeyGenParameterSpec(bits, F4)` and `SecureRandom`.

3.  Ask for the password (`char[]`), apply the minimum policy (≥ 12).

4.  Write the public key (PEM X.509) and the private key (encrypted PKCS#8, PBKDF2 600k + AES-256) with `AtomicFileWriter`, 600 permissions on the private key.

5.  Display the **SHA-256 fingerprint** of the public key.

6.  Clear the `char[]` in `finally`.

**Operation 2 — Sign**

1.  Load the private key: decrypt PKCS#8 with the password; on failure → `WrongPasswordException` → ERROR, without re-prompting in an infinite loop.

2.  Key consistency check (that it is RSA, allowed size).

3.  Hash the file by streaming → `digest`.

4.  Build the **canonical header** (version, hash, PSS params, public key fingerprint, base name, signer, date).

5.  PSS `Signature`: `update(header)` + `update(digest)` + `sign()`.

6.  Serialize the `.sig` (header + Base64 signature) and write it atomically.

**Operation 3 — Verify** (see the following diagram)

1.  **Up-front validation, before touching the cryptography:** `.sig` size ≤ 64 KB, well-formed JSON, no duplicate keys, required fields present, hash and params within the allowlists, Base64 signature of length = `modulusBytes`.

2.  Load the public key; compare its fingerprint with the one declared in the header → if they differ, ERROR with a clear message.

3.  Rebuild the canonical header from the fields and recompute the file `digest` by streaming.

4.  PSS `Signature`: `update(header)` + `update(digest)` + `verify(signature)`.

5.  `true` → VALID; `false` → INVALID; any exception from the tables → ERROR.

*\[Diagram: verification flow · 6 steps and the three states — see the PDF\]*

Any up-front validation failure or any exception falls to the right, into ERROR or INVALID; only a `verify()` that returns `true` reaches VALID.

## d) `.sig` file specification

The `.sig` is UTF-8 JSON. **All fields except `signature` form the canonical header, and that header is part of the signed data.** Changing any of them invalidates the signature.

### Fields

| Field            | Type               | Required | Description                                                           |
|------------------|--------------------|----------|-----------------------------------------------------------------------|
| `version`        | integer            | yes      | `.sig` format version. Currently: `1`.                                |
| `hashAlg`        | string (allowlist) | yes      | `SHA-256`, `SHA-512`, `SHA3-256`, `SHA3-512`.                         |
| `pss`            | object             | yes      | `{ "saltLen": int, "mgf": "MGF1", "mgfHash": string, "trailer": 1 }`. |
| `keyFingerprint` | hex string         | yes      | SHA-256 of the public key's DER `SubjectPublicKeyInfo`, as `AB:CD:...`. |
| `fileName`       | string             | yes      | Only the file's **base name** (no path).                              |
| `signerName`     | string             | yes      | Name declared by the signer (informational, but signed).              |
| `signedAt`       | ISO-8601 string    | yes      | Signing date declared by the signer (not trusted time).               |
| `signature`      | Base64 string      | yes      | **Not** part of the header. Length = `modulusBytes`.                  |

### Canonical serialization of the signed header

The problem: if the JSON were signed as-is, field order or whitespace could differ between signer and verifier (Jackson does not guarantee stable ordering with maps). That is why **the JSON is not signed**; instead a **canonical string built in a fixed order** is signed, independent of the serializer:

    CANON = "sigv1\n"
          + "version=" + version + "\n"
          + "hashAlg=" + hashAlg + "\n"
          + "pss.saltLen=" + saltLen + "\n"
          + "pss.mgf=" + mgf + "\n"
          + "pss.mgfHash=" + mgfHash + "\n"
          + "pss.trailer=" + trailer + "\n"
          + "keyFingerprint=" + keyFingerprint + "\n"
          + "fileName=" + fileName + "\n"
          + "signerName=" + signerName + "\n"
          + "signedAt=" + signedAt + "\n"

The `CANON` string is encoded as UTF-8. The signed message is `M = CANON_bytes || digest(file)`, applied with **a single** `Signature` object: `update(CANON_bytes)`, `update(digest)`, `sign()`. On verification, `CANON` is rebuilt **from the already-validated `.sig` fields** and the file `digest` is recomputed. If someone edited a field, the rebuilt string differs and the signature does not verify.

> **Note on `signerName` and `fileName`:** since they are signed free text, they are rejected if they contain `\n` or control characters (they would break the line-by-line format of `CANON`). That check is part of the up-front validation.

### Format version

The `sigv1` prefix and `version=1` allow the format to evolve without breaking old signatures: a future verifier can recognize `version=2` and apply a different canonical construction. Today only version 1 exists.

### Full example

``` json
{
  "version": 1,
  "hashAlg": "SHA-256",
  "pss": { "saltLen": 32, "mgf": "MGF1", "mgfHash": "SHA-256", "trailer": 1 },
  "keyFingerprint": "3A:7F:0C:91:...:DE",
  "fileName": "contract.pdf",
  "signerName": "Ana Perez",
  "signedAt": "2026-10-28T11:30:00-05:00",
  "signature": "Qm9ndXNCYXNlNjRTaWduYXR1cmVCeXRlcy4uLg=="
}
```

### What is validated BEFORE touching the cryptography

In this order; any failure → **ERROR**:

1.  **`.sig` file size ≤ 64 KB** (`Files.size` before reading). Rejects the DoS of a huge `.sig`.

2.  **Well-formed JSON**, with `STRICT_DUPLICATE_DETECTION` enabled → duplicate keys give ERROR.

3.  **All required fields present** and of the correct type.

4.  **`hashAlg` and `pss.mgfHash` in the allowlist**; `pss.mgf == "MGF1"`; `pss.trailer == 1`; `pss.saltLen == length(hashAlg)`.

5.  **`keyFingerprint`** in valid hex format.

6.  **`signerName` / `fileName`** with no line breaks or control characters.

7.  **`signature`** is valid Base64 and, once decoded, its length == `modulusBytes` of the supplied public key.

Only if all of the above passes do we rebuild the header, recompute the digest, and call `verify`.

## e) Key file specification

### Public key (`.pub`)

- **Format:** X.509 `SubjectPublicKeyInfo` in PEM (`-----BEGIN PUBLIC KEY-----`). Readable by `openssl pkey -pubin`.

- **Loading:** `X509EncodedKeySpec` + `KeyFactory.getInstance("RSA")`. If the DER is not RSA (for example an EC key) → ERROR.

- **Validation:** size ∈ {2048, 3072, 4096}; exponent == 65537. Any other value → ERROR.

- **Never** loaded with `ObjectInputStream` (Java serialization), to avoid insecure deserialization.

### Private key (`.key`)

- **Format:** encrypted PKCS#8, PBES2, in PEM (`-----BEGIN ENCRYPTED PRIVATE KEY-----`). Opens with `openssl pkey`.

- **KDF:** PBKDF2-HMAC-SHA256, **600,000 iterations** (production value; configurable downward only in tests).

- **Cipher:** AES-256-CBC.

- **Salt:** random, ≥ 16 bytes, new on every encryption. Random **IV**, new on every encryption.

- **Writing:** with Bouncy Castle (`JcePKCSPBEOutputEncryptorBuilder` with `PBKDF2Config` and `AES_256_CBC`, PRF HMAC-SHA256, iterationCount 600000). Names verified in the BC Javadoc.

- **Reading:** the JDK's `EncryptedPrivateKeyInfo` or BC's PKCS#8 reader; decrypted with the password; then parsed into `RSAPrivateCrtKey`.

- **Password check:** it is not enough that no `BadPaddingException` is thrown. After decrypting and parsing, key consistency is validated (that it is CRT, that `n` and `e` exist) by signing a test message and verifying it with the derived public key. If it does not match → `WrongPasswordException`.

### `.key` parameters: defensive validation

Before deriving the key from the password, the ASN.1 parameters are read and validated:

- `iterationCount` within a reasonable range (e.g. ≥ 100,000 and ≤ 10,000,000). A huge value could hang the program → rejected, tested with `assertTimeoutPreemptively`.

- PRF ∈ allowlist (HMAC-SHA256 or stronger). A weak PRF (e.g. DES-based) → ERROR.

- Cipher = AES. Anything else → ERROR.

### Permissions

- The `.key` is created with **600** permissions from the start (`PosixFilePermissions.asFileAttribute`), never create-then-`chmod`. On Windows, an owner-only ACL is used instead (`AclFileAttributeView`).

- The `.pub` may be world-readable (644); it contains no secrets.

### Fingerprint

- **SHA-256 fingerprint** of the public key's DER `SubjectPublicKeyInfo`, displayed as `AB:CD:...`.

- Shown when **generating** (so the signer can communicate it) and when **verifying** (so the verifier can compare it through an independent channel).

- The same fingerprint is stored, signed, in the `.sig` (`keyFingerprint`), so a verifier can state precisely *"this signature was made with key AB:CD:…"*.

## f) Phased plan

Each phase has a verifiable "done" criterion. Effort is relative (points), not hours. Dependencies indicate what must exist beforehand.

| Phase                           | Content                                                                                                                                                                  | Done when…                                                                                       | Effort        | Depends on |
|---------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|---------------|------------|
| **0. Structure**                | Maven project; packages `cli/crypto/format/keystore/io/core`; dependencies (BC ≥ 1.78, JSON parser, JUnit 5); `.gitignore` with `*.key`; CI and release workflows.      | Compiles empty; `mvn test` runs 0 tests; BC loaded.                                              | 1             | —          |
| **1. Core**                     | Generate pair (explicit parameters), sign (canonical header + PSS), verify (returns enum). Fingerprint displayed.                                                         | The 3 options work on the happy path; a valid signature verifies; `openssl pkey` opens the `.key`. | 5             | 0          |
| **2. Hardening**                | Allowlists; three states + exit codes; `run(args)->int`; up-front `.sig` validation; exception mapping; 600 permissions (ACL on Windows); atomic write; `char[]` with clearing. | Every bad input gives ERROR/INVALID (never VALID nor a crash); the CLI returns 0/1/2.            | 5             | 1          |
| **3. Test suite**               | All tests from section g (unit, integration, CLI). Fixtures and `@MethodSource`.                                                                                          | Green suite on Linux and Windows; reasonable coverage of the error paths.                       | 5             | 2          |
| **4. Type 1 limits**            | Signed name (with rename→warning policy); version number and previous-signature hash in the header.                                                                      | Editing name/version gives the documented result; tests for 2.3′ and replay pass.               | 3             | 2, 3       |
| **5. Type 2 extensions (opt.)** | \(a\) fingerprint comparison; (b) `known_hosts`-style trust store; (c) X.509 mini-PKI with BC; toy time server; RFC 3161 PoC.                                             | Each sub-extension with its 3-step demo and its test.                                           | 2–8 (modular) | 4          |
| **6. GUI (opt.)**               | Graphical interface (Swing/JavaFX) on top of the same services; `JPasswordField`.                                                                                         | The 3 operations from the GUI; the password is never visible.                                   | 3             | 2          |

### Dependency notes

- The **GUI (6)** depends only on the hardened core (2), not on the tests or the limits: it can be done in parallel with 3–5 if another person is available.

- The **extensions (5)** are independent of each other; one or two can be taken without the others. The recommended order is fingerprint → trust store → mini-PKI, from least to most effort.

- The **cut-off criterion**: if time is tight, delivering up to Phase 3 already more than satisfies the assignment and carries the whole security story. Phases 4–6 are what impresses in the presentation.

### Testing conventions (common to all phases)

- `@TempDir` for every test file.

- Key pair generated once per class in `@BeforeAll`.

- **Configurable PBKDF2 iterations** in tests (e.g. 1,000) so they run fast.

- A separate test that checks the **production default** is still high (≥ 600,000).

## g) Full test plan

All tests from the audit that are still valid are kept, and those that change when limits are broken are updated. **Expected result** uses VALID/INVALID/ERROR with its exit code. **Type**: U = unit, I = integration, C = CLI (checks the exit code of `run(args)`).

### Updates from breaking limits (important)

- **T-2.3 changes.** Before: "renaming the file stays VALID". Now the base name is signed, so **renaming → INVALID** when compared against the `.sig`. Since renaming can be legitimate, the decision (see section i, Type 1) is: INVALID with a message that distinguishes "name does not match" from "content modified". The test reflects that.

- **T-2.6 (replay)** goes from "cannot be detected" to "detected if there is a version number in the header and the verifier knows the current version".

- **T-3.1** is no longer "unsigned metadata": every field is now signed, so mutating them gives INVALID.

- **T-4.1** gains the trust-store sub-case (VALID_UNTRUSTED_KEY).

### Test table

| ID        | Attack / case               | Input                                                      | Expected (code)                                                               | Test class                                 | Type |
|-----------|-----------------------------|------------------------------------------------------------|-------------------------------------------------------------------------------|--------------------------------------------|------|
| T-1.1     | Offline dictionary          | `.key` + list of 1000 passwords                            | ASN.1 params: iter ≥ 600k, PRF SHA256, AES-256                                | `KeyKdfParamsTest`                         | U    |
| T-1.1b    | Password policy             | 8-char password                                            | rejected at generation                                                        | `PasswordPolicyTest`                       | U    |
| T-1.2     | Reused salt/IV              | encrypt the same key twice                                 | different salts and IVs; salt ≥ 16 B                                          | `KeyEncryptionTest`                        | U    |
| T-1.3     | Huge iteration count        | `.key` with iter = 2e9                                     | ERROR \< 2s (`assertTimeoutPreemptively`)                                     | `KeyKdfParamsTest`                         | U    |
| T-1.4     | Wrong password              | 2000 bad passwords                                         | 2000× `WrongPasswordException`                                                | `WrongPasswordTest`                        | U    |
| T-1.5     | `char[]` cleared            | spy `PasswordProvider`                                     | array is `\0` after the operation; log without password                       | `PasswordHandlingTest`                     | U    |
| T-1.6     | `.key` permissions          | generate in `@TempDir`                                     | permissions = 600 on POSIX; owner-only ACL on Windows                         | `KeyFilePermsTest`                         | I    |
| T-2.1     | Flip one bit                | sign, flip 1 byte (start/middle/end)                       | INVALID (1)                                                                   | `TamperTest` (`@ParameterizedTest`)        | I    |
| T-2.2     | Truncate / append bytes     | sizes 0,1,8191,8192,8193,3×8192+7; +`\0`, +`\n`, −1 byte   | hash == reference; mutations → INVALID                                        | `StreamingHashTest`                        | U/I  |
| T-2.3′    | Rename the file             | sign `contract.txt`, verify as `contract_final.txt`        | INVALID (1) with "name does not match" message                                | `SignedNameTest`                           | I    |
| T-2.4     | Malformed signature         | signatures of 0B, 255B, 1MB, zeros, 0xFF, random           | not VALID; no exception escapes the API                                       | `GarbageSignatureTest`                     | U    |
| T-2.5     | Signature of another file   | sign A, verify B with A's sig                              | INVALID (1)                                                                   | `WrongFileTest`                            | I    |
| T-2.6′    | Replay of an old version    | v1 sig presented when v2 is current                        | detected if the header carries a version (see i)                              | `ReplayVersionTest`                        | I    |
| T-2.7     | Hash downgrade              | `hashAlg` = MD5, SHA-1, NONE, `sha-256`, `SHA-256 `        | ERROR (2)                                                                     | `HashAllowlistTest` (`@ParameterizedTest`) | U    |
| T-2.7b    | Label ≠ actual signature    | `.sig` says SHA-512, signature made with SHA-256           | INVALID (1)                                                                   | `HashMismatchTest`                         | I    |
| T-2.8     | v1.5 vs PSS                 | `SHA256withRSA` signature verified by the program          | INVALID (1)                                                                   | `PkcsVsPssTest`                            | I    |
| T-2.9     | Altered PSS parameters      | `saltLen` 0/222, `mgf1`=SHA-1 with SHA-512 msg             | ERROR or INVALID depending on the case                                        | `PssParamsTest`                            | U    |
| T-3.1′    | Mutate a signed field       | edit `signerName`, `fileName`, `signedAt`                  | INVALID (1) for each field                                                    | `SignedHeaderTest` (`@ParameterizedTest`)  | I    |
| T-3.2     | Malformed JSON/Base64       | 15–20 files in `resources/malformed/`                      | ERROR (2)                                                                     | `MalformedSigTest` (`@ParameterizedTest`)  | U    |
| T-3.3     | Duplicate fields            | `.sig` with `hashAlg` twice                                | ERROR (2)                                                                     | `DuplicateKeyTest`                         | U    |
| T-3.4     | Huge `.sig`                 | 100 MB file                                                | ERROR (2) \< 1s                                                               | `SigSizeLimitTest`                         | U    |
| T-3.6     | Declared fingerprint ≠ key  | altered `keyFingerprint`                                   | ERROR (2), specific message                                                   | `FingerprintMismatchTest`                  | I    |
| T-3.7     | Wrong key type              | EC `.pub`; `.key` as `.pub`; corrupt PEM                   | ERROR (2)                                                                     | `WrongKeyTypeTest` (`@ParameterizedTest`)  | U    |
| T-4.1     | Public key substitution     | Mallory signs, hands over her `.pub`                       | VALID (0) + fingerprint in output; fingerprints differ                        | `KeySubstitutionTest`                      | I    |
| T-4.1b    | Trust store                 | unpinned key / changed fingerprint                         | VALID_UNTRUSTED_KEY / alert                                                   | `TrustStoreTest`                           | I    |
| T-4.2     | Weak key                    | `.pub` of 512, 1024, 1536 bits                             | ERROR (2); 2048 → accepted                                                    | `WeakKeyTest` (`@ParameterizedTest`)       | U    |
| T-4.2b    | Invalid exponent            | e = 1, 3, even                                             | ERROR (2)                                                                     | `BadExponentTest`                          | U    |
| T-4.3     | Three states / codes        | battery of good and bad inputs                             | correct 0/1/2; nothing is VALID by mistake                                    | `ExitCodeTest`                             | C    |
| T-5.1     | Empty file                  | sign 0 bytes                                               | VALID (0); +1 byte → INVALID                                                  | `EmptyFileTest`                            | I    |
| T-5.2     | Large file                  | 3 GB sparse file, `-Xmx256m`                               | signs and verifies OK                                                         | `LargeFileTest` (`@Tag("slow")`)           | I    |
| T-5.3     | Symlink as output           | output points to a symlink                                 | target untouched (`@DisabledOnOs WINDOWS`)                                    | `SymlinkOutputTest`                        | I    |
| T-5.6     | Hostile inputs              | missing, `chmod 000`, directory, FIFO                      | ERROR (2); FIFO with timeout                                                  | `HostileInputTest` (`@ParameterizedTest`)  | I    |
| T-5.7     | Same input/output path      | input == output                                            | ERROR (2)                                                                     | `SamePathTest`                             | I    |
| T-6.1     | OpenSSL interop             | rebuild M, `openssl pkeyutl -verify`                       | OpenSSL accepts the signature                                                 | `OpenSslInteropTest` (`@Tag("external")`)  | I    |
| T-6.2     | RNG                         | 2 generations, 2 signatures of the same file               | different moduli; different PSS signatures, both verify; 100 distinct salts   | `SecureRandomTest`                         | U    |
| T-6.3     | Generation parameters       | generate 2048/3072/4096                                    | correct `bitLength`; e == 65537                                               | `KeyGenParamsTest` (`@ParameterizedTest`)  | U    |
| T-KDF-def | Production default          | read the production iteration constant                     | ≥ 600,000                                                                     | `ProdDefaultsTest`                         | U    |

The section i extensions add `MiniPkiTest`, `DeclaredTimeTest` and `ToyTimeServerTest`.

### Common convention (reminder)

`@TempDir` everywhere; keys per class in `@BeforeAll`; configurable PBKDF2 iterations in tests (low for speed); `T-KDF-def` guards the production value. Tests tagged `@Tag("slow")` and `@Tag("external")` are excluded from the fast cycle and run separately (the OpenSSL one requires the binary to be installed). CI runs the suite on Linux and Windows.

## h) Presentation-day tests

Two separate blocks: (1) the JUnit suite that runs on its own, and (2) the scripted manual demos.

### (1) Live JUnit suite

**Single command** (Maven; slow and external tests are excluded by default so it finishes quickly):

``` bash
mvn test
```

**Expected output:** the list of test classes, all green, and at the end:

    [INFO] Tests run: NN, Failures: 0, Errors: 0, Skipped: 0
    [INFO] BUILD SUCCESS

To show coverage, open `target/site/jacoco/index.html` (JaCoCo is already configured). Optional: run the slow and OpenSSL tests separately with `mvn test -Dgroups=slow,external -DexcludedGroups=` if the binary is installed.

### (2) Manual demos — step-by-step script

Prepare **in advance** (see checklist): a `demo/` directory with `contract.txt` (one paragraph), Ana's and Mallory's keys already generated, and a real terminal (not the IDE).

**Demo 1 — Public key substitution (≈2 min). The key moment.**

1.  Show that Ana signed `contract.txt` → `contract.sig`, and verify with `ana.pub`: **VALID**, with Ana's fingerprint on screen.

2.  Mallory edits `contract.txt`, signs it with **her** key, and hands over `mallory.pub`. Verify: **VALID**. Dramatic pause.

3.  Say: *"The cryptography did its job: it proved this was signed by the owner of this key. It did not prove it was Ana."* Show that the fingerprint on screen is **not** Ana's. That is the defense: compare the fingerprint through a separate channel.

- *What to say:* the signature proves integrity and possession of the key, not identity; identity is anchored by the fingerprint.

**Demo 2 — One changed bit (≈1 min).**

1.  Open `contract.txt` in a hex editor, change one byte, save.

2.  Verify with the original signature: **INVALID (code 1)**.

- *What to say:* a single bit breaks the hash, and PSS detects it.

**Demo 3 — Edit the `signerName` field (≈1 min).**

1.  Open `contract.sig` in a text editor, change `"signerName": "Ana Perez"` to `"Professor X"`.

2.  Verify: **INVALID**.

- *What to say:* the name is part of the signed data; the signature cannot be reattributed.

**Demo 4 — Measured brute force (≈2 min).**

1.  Run a small harness that tries 1000 passwords against a `.key` with **1,000** iterations, and show attempts/second (high).

2.  Repeat against a `.key` with **600,000** iterations, and show attempts/second (low).

- *What to say:* the real security of the `.key` is the password × the cost per attempt; PBKDF2 raises that cost ~600×.

- *Important:* use a genuinely long password in the demo, in case someone asks to attack it live.

**Demo 5 — OpenSSL interoperability (≈2 min).**

1.  The program writes the rebuilt canonical message `m.bin` and the raw signature `signature.bin`.

2.  Run: `openssl pkeyutl -verify -pubin -inkey ana.pub -sigfile signature.bin -in m.hash -pkeyopt digest:sha256 -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:-1` (with `m.hash` = `openssl dgst -sha256 -binary m.bin`).

3.  Output: `Signature Verified Successfully`.

- *What to say, without overclaiming:* "OpenSSL verifies **our canonical message**, not the .txt directly. This proves we implemented standard, interoperable PSS, not a homemade scheme."

**Demo 6 (optional) — Rename / replay, before and after (≈2 min).**

- *Before:* without a signed name, renaming stayed VALID. *After:* with the name in the signed header, renaming gives **INVALID** with the message "name does not match". Also show the replay of an old version detected through the version number.

### Plan B (if something fails live)

| If this fails…                               | Plan B                                                                                                  |
|----------------------------------------------|---------------------------------------------------------------------------------------------------------|
| The IDE gives no console for the password    | Always run from the real terminal already open; keep the command in the history.                       |
| Brute force takes too long                   | Reduce to 200 passwords; or show a pre-recorded result (screenshot/asciinema) and explain the numbers. |
| OpenSSL is not installed or fails            | Show the already-run (green) `OpenSslInteropTest` in a screenshot; explain the command.                |
| The hex editor is not at hand                | Have an already-modified `contract_tampered.txt` ready in `demo/`.                                      |
| A command is mistyped                        | Have `demo/commands.sh` (and `commands.ps1` on Windows) with all exact commands to copy and paste.     |
| Time runs out                                | Prioritize Demos 1, 2 and 5; the rest are extras.                                                       |

### Preparation checklist

- `demo/` with `contract.txt`, `contract_tampered.txt`, `ana.key/ana.pub`, `mallory.key/mallory.pub`.

- Keys with 1,000 and 600,000 iterations ready for Demo 4.

- `demo/commands.sh` / `commands.ps1` with all exact commands (including the OpenSSL one).

- Real terminal open in `demo/`, large font, good contrast for the projector.

- **Long** demo password memorized (not `1234`).

- Hex editor open or `xxd` available (on Windows, rely on `contract_tampered.txt`).

- OpenSSL installed and tested; backup screenshot of the external test passing.

- Fast suite already run once (`mvn test`) to warm up and confirm green.

- Packaged executable from the Release workflow ready, so nothing is compiled live.

## i) Breaking the limits of signatures

Three types: (1) broken by changing the design; (2) mitigated by shifting trust to a third party; (3) not breakable. For Types 1 and 2, each comes with its three-step demo: attack without defense, defense applied, and what it does **not** solve.

### Type 1 — Broken by changing the program's design

**1A. Signed file name**

- **Decision:** the base name goes into the signed header (`fileName`). Renaming → **INVALID**, not just a warning.

- **Rationale:** renaming *can* be legitimate, but mixing "name changed" with "valid" forces the interface to display a name the signature does not back. We prefer an unambiguous result (INVALID) **with a message that distinguishes** "the content is intact but the name does not match (expected `X`)" from "the content was modified". That way the user knows they can verify again with the correct name, without believing the document is corrupt.

- **Implementation note:** the canonical header is rebuilt from the `.sig` fields, so renaming the file on disk does not by itself break the cryptographic check. The verifier must explicitly compare the signed `fileName` with the actual base name of the file being verified; that comparison is what produces INVALID.

- **3-step demo:**

  1.  *Without defense:* signature without the name in the header; renaming `contract.txt`→`contract_final.txt` stays **VALID**. The interface shows the new name as if it were endorsed.

  2.  *With defense:* name in the signed header; renaming gives **INVALID** with "name does not match, expected contract.txt".

  3.  *Does not solve:* it does not stop someone with the private key from signing the file under another name in the first place. It binds the name to *this* signature; it does not prohibit new signatures.

- **Test:** `SignedNameTest` — rename → INVALID with the "name" message; intact content distinguished from modified content.

**1B. Replay of old versions**

- **Design:** add a `docVersion` (integer) to the signed header and, optionally, `prevSigHash` (SHA-256 of the previous signature), chaining versions.

- **What can be detected without a server or shared history:** that **this** `.sig` declares version N. The verifier can reject a version lower than one it already knows **if** it is told which one is current (via a parameter or a small local "last seen version" file). The `prevSigHash` chain makes it possible to check that a chain of versions is consistent *if the previous signatures are available*.

- **What CANNOT be detected without that:** if the verifier has no state and is not told the current version, an old, valid `.sig` remains valid. A signature has no notion of "currency" on its own. That requires shared state or a third party.

- **3-step demo:**

  1.  *Without defense:* resend `contract_v1` + its signature when v2 already exists → **VALID**.

  2.  *With defense:* with a signed `docVersion` and a local file `last_version=2`, verifying v1 gives **INVALID / "outdated version" alert**.

  3.  *Does not solve:* without that local state (or on another machine), v1 is valid again. Currency does not live in the signature.

- **Test:** `ReplayVersionTest` — v1 with local state of v2 → alert; without state → VALID (documenting the limit).

### Type 2 — Mitigated by shifting trust to a third party

**2A. Key owner — three levels of effort**

| Level                                       | Mechanism                                                                          | Who the trust is shifted to                                         |
|---------------------------------------------|------------------------------------------------------------------------------------|---------------------------------------------------------------------|
| \(a\) Fingerprint through another channel   | Show the SHA-256 fingerprint and compare it in person / by phone / on paper        | **The human channel** and whoever communicates the fingerprint      |
| \(b\) `known_hosts`-style store (TOFU)      | Trust on first use, pin the key, alert if the fingerprint changes later            | **The first-use decision** (and that nobody fooled you then)        |
| \(c\) Mini-PKI                              | Our own authority (CA) signs users' X.509 certificates; the chain is validated     | **The certificate authority**                                       |

- **3-step demo (level b, the most visual):**

  1.  *Without defense:* Mallory substitutes the key (Demo 1) → VALID, nobody notices.

  2.  *With defense:* `ana.pub` is pinned on first use; when `mallory.pub` shows up with a different fingerprint, the program **alerts: "Ana's key changed"** (like SSH).

  3.  *Does not solve:* if Mallory fools you **on first use**, you pin her key as "Ana's" and never find out. TOFU trusts that the first contact was legitimate.

- **Mini-PKI (c):** feasible with Bouncy Castle (X.509 certificate generation and chain validation). Trust is shifted **to the CA**: if the CA signs a fake certificate, everything falls. It is not "the definitive solution"; it just moves the problem to a central point that must be protected.

- **Tests:** `TrustStoreTest` (TOFU: pin, alert on change), `MiniPkiTest` (valid chain → VALID; certificate not issued by the CA → ERROR).

**2B. Signing time**

| Level             | Mechanism                                                            | Trust                                        |
|-------------------|----------------------------------------------------------------------|----------------------------------------------|
| Declared date     | `signedAt` in the signed header                                      | **The signer** (who can lie)                 |
| Toy time server   | A second key pair signs `hash ‖ date`                                | **The time server** (its clock and its key)  |
| Real RFC 3161     | Timestamp from a public TSA                                          | **The TSA** and its certificate chain        |

- **Declared date:** it is already signed, but it is set by the signer; it is not trusted time. Say so explicitly.

- **Toy server:** a process with its own key pair receives the hash, adds its date, and signs `hash || date`. It adds a third party, but trust is shifted **to that server**: its clock and its key.

- **Real RFC 3161 (verified):** public TSAs exist (e.g. FreeTSA and others) and Bouncy Castle supports them in `org.bouncycastle.tsp` (`TimeStampRequestGenerator`, `TimeStampResponse.validate(...)`, `TimeStampToken`). Also verifiable with `openssl ts -verify`. A realistic PoC if time allows (Phase 5). Trust is shifted **to the TSA**.

- **3-step demo (toy server):**

  1.  *Without defense:* `signedAt` is set by Ana; she can put any date.

  2.  *With defense:* the time server signs `hash || date`; the date is no longer controlled by Ana alone.

  3.  *Does not solve:* if the server lies or its key is stolen, the date is false. We only shift trust from the signer to the server.

- **Tests:** `DeclaredTimeTest` (the date is signed but comes from the signer), `ToyTimeServerTest` (the time token verifies against the server's key).

### Type 3 — Not breakable

**3A. What the user thought they saw when signing (WYSIWYS).** A `.docx`/`.pdf` can contain hidden text, fields, or macros. The signature guarantees the **bytes**, not the visual interpretation. **Partial mitigations, not a defense:** show size and SHA-256 before signing; warn on complex formats ("this format can hide content"). There is no cryptographic solution.

**3B. Forging without the private key.** Not possible by attacking RSA-PSS; only possible through an **implementation flaw** (those in section g). That is why the tests focus there.

## j) Limitations and honesty

Key distinction for the whole presentation: **"no practical method is known" ≠ "impossible"**. The former is the honest statement for RSA/SHA; the latter applies only to logical impossibilities.

### Limits table

| Limit                      | Type | Mitigated by                                       | Not mitigated / honesty                                     |
|----------------------------|------|----------------------------------------------------|-------------------------------------------------------------|
| File name                  | 1    | Signing the name → renaming gives INVALID          | Does not stop signing under another name from the start     |
| Replay of an old version   | 1    | Signed version + local "current" state             | Without shared state, an old `.sig` stays valid             |
| Key owner                  | 2    | Fingerprint / TOFU / mini-PKI                      | Trust is shifted (channel, first use, or the CA)            |
| Signing time               | 2    | Time server / RFC 3161                             | Trust is shifted to the server or the TSA                   |
| Hidden content (WYSIWYS)   | 3    | Show hash/size; warn on complex formats            | No cryptographic defense                                    |
| Forging without the key    | 3    | —                                                  | Only possible through an implementation flaw, not by breaking PSS |

### What is NOT possible (and how to say it)

- **Forging an RSA-PSS signature without the private key.** PSS reduces forgery to the RSA problem (random oracle model). Breaking RSA-2048 amounts to factoring a ~617-digit modulus; the number field sieve is very far from that. Phrase: *"no practical method is known"*, not *"impossible"*.

- **Recovering the private key from the public key or from many signatures.** PSS signatures do not leak useful information about the private key.

- **Decrypting the `.key` without guessing the password.** AES-256 has no known shortcuts; the only attack is trying passwords, and PBKDF2 makes that expensive. **That is why real security depends on the password.**

- **Second preimage of SHA-256/512/SHA-3.** On the order of 2^256; no known attacks. **SHA-1 does have practical collisions (SHAttered 2017)** — that is why it is outside the allowlist; it is the best example of "why the allowlist exists".

- **Changing the hash label in the `.sig` to make a signature pass.** The hash is bound inside PSS; changing the label only breaks verification.

- **Reusing A's signature for B.** Fails barring a hash collision.

- **Length-extension attack.** Affects `H(secret || message)`; in signatures the hash carries no secret, and SHA-3 is not even vulnerable. Does not apply.

- **Timing / padding oracles in verification.** Verification uses only public data; there is no secret to leak. For the `.key`, whoever has the file can already brute-force it offline; an oracle adds nothing. Note: using `MessageDigest.isEqual` is good hygiene, but **it is not a defense against an existing attack here** — do not present it as one.

- **Bleichenbacher 2006 (e=3) and Bellcore-style faults on RSA-CRT.** The former affects poorly written v1.5 verifiers, not PSS with the JDK verifier. The latter requires injecting physical faults during signing; outside the threat model of a desktop app.

- **Quantum computing.** Shor would break RSA, but no quantum computer comes close to 2048 bits. As future work: post-quantum **ML-DSA** signatures, standardized by NIST (FIPS 204) and available in the JDK since **version 24** (JEP 497).

### Recommended closing line

> *"The attacks that work against this program do not break RSA: they break trust in the public key, the metadata, error handling, and the password. That is why those are our defenses and our tests. When something cannot be forged, we say 'no practical method is known', not 'it is impossible'."*

## k) Project risks and mitigations

| Risk                                                                | Impact                                     | Mitigation                                                                                                                                                                         |
|---------------------------------------------------------------------|--------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Getting stuck on Bouncy Castle** (dense API, PKCS#8 encryption)   | Eats days in Phase 1/2                     | Isolate BC in `keystore` behind a small interface; first try generating/reading a `.key` and opening it with `openssl pkey` before moving on. Class names already verified in the appendix. |
| **Wrongly set PSS parameters** (SHA-1 left as default)              | Non-interoperable or insecure signatures   | Obtain every `Signature` through `PssParams.newSignature`; unit test that the parameters are not the SHA-1 default; interop test with OpenSSL (T-6.1).                            |
| **Not enough time**                                                 | Extensions are not reached                 | Cut at Phase 3: it already satisfies the assignment with the full security story. Phases 4–6 are optional and independent.                                                         |
| **Scope creep** (mini-PKI, RFC 3161, GUI grow unchecked)            | The core is neglected                      | Rule: nothing from Phase 5/6 starts until Phase 3 is green. Each extension is a module with its own "done" criterion.                                                              |
| **`System.console()` null in the IDE** ruins the demo               | Visible password or program that won't run | Always run from a real terminal; the demo uses the terminal, not the IDE (checklist). On Windows, the executable is packaged with `--win-console`.                                  |
| **Slow live brute force**                                           | Demo 4 drags on                            | Reduce to 200 passwords or use a pre-recorded capture (plan B).                                                                                                                     |
| **False sense of security** (overclaiming in the presentation)      | Loss of credibility under questioning      | Honesty script from section j; distinguish "not practical" from "impossible".                                                                                                      |
| **Vulnerable dependencies**                                         | Remark from the professor                  | BC ≥ 1.78 (avoids CVE-2024-30171); pinned versions; Dependabot enabled; mention that it was reviewed.                                                                              |
| **Slow tests due to real PBKDF2**                                   | The suite is slow and discourages running it | Low configurable iterations in tests + a single test of the production default.                                                                                                  |
| **Loss/leak of the `.key`** (the project's own, in Git)             | Exposure of the demo key                   | `.gitignore` with `*.key`; demo keys generated separately, never committed.                                                                                                       |

## l) Likely questions from the professor

**What is the difference between signing and encrypting?** Encrypting protects **confidentiality**: only whoever has the key can read. Signing protects **integrity and authenticity**: anyone with the public key can check that the content did not change and that it was signed by whoever holds the private key. It encrypts nothing; the file remains readable. RSA uses inverse operations (private to sign, public to verify), but the purpose is opposite.

**Why PSS and not PKCS#1 v1.5?** PSS has a formal security proof (a reduction to the RSA problem) and is randomized. v1.5 works, but its deterministic scheme has led to lax-parsing attacks (Bleichenbacher) in poorly written implementations. Choosing PSS avoids ambiguous policy decisions and is the modern recommendation.

**Why is the public key fingerprint displayed?** Because cryptography proves "this was signed by the owner of **this** key", not "Ana signed it". The fingerprint lets you check through an independent channel that *this* key really is Ana's. Without it, an attacker who substitutes the key passes verification (our Demo 1).

**What happens if the `.key` is stolen?** It is encrypted with PKCS#8 (PBKDF2 600k + AES-256). The attacker can only try passwords offline, and PBKDF2 makes each attempt ~600× more expensive. **Security comes down to the strength of the password.** With a long password it is infeasible in practice; with `1234` it falls in seconds. That is why we enforce a minimum policy and say so.

**Why three states instead of a boolean?** To avoid collapsing "could not decide" (ERROR) into "the signature does not match" (INVALID) or, worse, into "valid". A generic `catch` that returns `true` is the most dangerous bug; with the enum and exit codes 0/1/2, any exception lands in ERROR or INVALID, never in VALID.

**Can a signature be forged without the private key?** No practical method is known: it would require breaking RSA-2048 (factoring ~617 digits) or finding a second preimage of SHA-256. The only thing that would actually forge a signature is a **flaw in our implementation**, which is why half of the tests attack those flaws.

**Why not accept SHA-1 or MD5?** SHA-1 has practical chosen-prefix collisions (SHAttered 2017); MD5 has been broken for years. If the verifier accepted them, a downgrade would make sense. That is why there is an `enum` allowlist and everything else gives ERROR.

**What exactly does the signature protect: the name, the date?** By design, the signature covers the content **and** the canonical header (base name, declared date, parameters, key fingerprint). The date is declared by the signer, so it is not trusted time — that would require a TSA (RFC 3161). We say so explicitly to avoid overclaiming.

**Why Bouncy Castle and not just the JDK?** The JDK reads encrypted PKCS#8 without trouble, but generating a PBES2 with PBKDF2-HMAC-SHA256 + AES-256 and our iteration count is awkward with the standard API before JDK 25. BC does it directly and stably, and `openssl pkey` opens the result. We use BC ≥ 1.78 (because of CVE-2024-30171, which in any case affects PKCS#1 v1.5 in TLS, not our PSS signature).

**Does the verifier need the password?** No. Verifying uses only public data: the file, the `.sig`, and the `.pub`. The password is used only when **signing**, to open the private key.

**What happens if the user verifies with the wrong key?** It gives not-valid with a precise message: "this signature was made with key AB:CD:…, not with the one you supplied", thanks to `keyFingerprint`. We do not say "the file was modified", which would be false in that case.

## m) Distribution

The program is delivered as native executables for Windows and Linux, produced by the `Release` workflow on every `v*` tag.

- **Tooling:** `jdeps` (detects the required JDK modules) → `jlink` (minimal runtime) → `jpackage --type app-image` (executable with a bundled runtime; no Java install needed).

- **No cross-compilation:** `jpackage` builds only for the OS it runs on, so the workflow uses one runner per OS (`ubuntu-latest`, `windows-latest`).

- **No fat JAR:** the Bouncy Castle JAR is signed; merging it into a single JAR breaks its signature (`Invalid signature file digest`). Dependencies stay as separate JARs.

- **Windows specifics:**
  - `--win-console` is mandatory; without it, `System.console()` is `null` and the program refuses to read the password.
  - POSIX permissions do not exist on NTFS; `AtomicFileWriter` uses an owner-only ACL (`AclFileAttributeView`) instead.
  - `ATOMIC_MOVE` can fail with `AccessDeniedException` if another process holds the target open; that maps to ERROR.
  - Console output is forced to UTF-8 (`-Dstdout.encoding=UTF-8`).
  - The file system is case-insensitive: whether a case-only rename counts as a name mismatch must be decided and documented.

- **Integrity of the release:** each archive is published with its SHA-256 checksum. Unsigned Windows executables trigger a SmartScreen warning — the same trust problem this project is about.

## Appendix — Verification of technical facts

Each fact is marked **Confirmed** (verified against a source) or **To verify** (depends on your version/environment; confirm it at delivery).

### OWASP PBKDF2 — **Confirmed**

The OWASP Password Storage Cheat Sheet recommends **600,000 iterations** for PBKDF2-HMAC-SHA256 (and ~210,000 for SHA-512). The 310,000 figure that circulates is an earlier recommendation; the current one is 600,000. [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

### ML-DSA in the JDK — **Confirmed**

ML-DSA (FIPS 204) arrived in the JDK in **version 24** (March 2025) via **JEP 497**, with `ML-DSA-44/65/87`. Not version 25. [JEP 497](https://openjdk.org/jeps/497)

### Jackson and duplicate fields — **Confirmed**

The exact name is `StreamReadFeature.STRICT_DUPLICATE_DETECTION` (since Jackson 2.10), **disabled by default**; when enabled, it throws on duplicate keys and adds ~20–30% to parsing time. [Jackson StreamReadFeatures](https://github.com/FasterXML/jackson-core/wiki/StreamReadFeatures)

### Bouncy Castle CVE — **Confirmed (corrected from the audit)**

The relevant CVE is **CVE-2024-30171** (Marvin attack, timing side channel in **RSA PKCS#1 v1.5** within the TLS/JSSE APIs), medium severity (CVSS 5.9), **fixed in BC 1.78**. **It does not affect this project's PSS signatures**, but **BC ≥ 1.78** is advisable as hygiene. [GHSA-v435-xc8x-wvr9](https://github.com/advisories/GHSA-v435-xc8x-wvr9) · [BC wiki](https://github.com/bcgit/bc-java/wiki/CVE%E2%80%902024%E2%80%9030171)

### JDK default PSS parameters — **Confirmed (with an operational caveat)**

`PSSParameterSpec.DEFAULT` uses **SHA-1 / MGF1-SHA1 / salt 20 / trailer 1**. With `Signature.getInstance("RSASSA-PSS")` you must call `setParameter(new PSSParameterSpec(...))` or a `SignatureException("Parameters required for RSASSA-PSS signature")` is thrown. **Recommendation:** always set the parameters explicitly through `PssParams`. [PSSParameterSpec (Javadoc)](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/security/spec/PSSParameterSpec.html)

### No composite PSS names in the JDK — **Confirmed (corrected from an earlier draft)**

An earlier draft recommended `SHA256withRSAandMGF1` / `SHA512withRSAandMGF1`. Tested on OpenJDK 17: all four composite names (`SHA256`, `SHA512`, `SHA3-256`, `SHA3-512` + `withRSAandMGF1`) throw `NoSuchAlgorithmException`; they are Bouncy Castle names. Plain `RSASSA-PSS` (provider `SunRsaSign`) with an explicit `PSSParameterSpec` signs and verifies with all four allowed hashes, **including SHA3-256 and SHA3-512**, so SHA-3 stays in the allowlist. Covered by `PssParamsTest`.

### Bouncy Castle class names used — **Confirmed**

Verified in the official BC Javadoc: `JcePKCSPBEOutputEncryptorBuilder` (with a constructor taking a `PBKDFConfig` for PBKDF2, `setIterationCount`, `setPRF`), `JceOpenSSLPKCS8EncryptorBuilder` (with `AES_256_CBC`, `setIterationCount`, `setPassword`), and in TSP: `TimeStampRequestGenerator`, `TimeStampResponse.validate(...)`, `TimeStampToken`. [bcpkix Javadoc](https://downloads.bouncycastle.org/java/docs/bcpkix-jdk18on-javadoc/)

### OpenSSL + PSS when the message is not the file — **Confirmed (important for the demo)**

`openssl dgst -sigopt rsa_padding_mode:pss` **re-hashes the file you pass it**, so it does not work if the signed message is `header || digest` rather than the original file. For the demo, the canonical message must be rebuilt in a temporary file and verified with `openssl pkeyutl -verify ... -pkeyopt rsa_padding_mode:pss`, which operates on an already computed hash. This proves interoperability of the scheme; it does not "verify the .txt directly". (Standard `openssl dgst`/`pkeyutl` mechanics.)

### JDK PEM API (alternative to BC for the key) — **To verify**

The `PEMEncoder.withEncryption(...)` API that simplifies writing encrypted keys arrived as a **preview in JDK 25** (JEP 470) and remains in preview (JEP 524, second preview); finalization is planned for JDK 27. If your course uses JDK 25+, you can consider it, but it requires `--enable-preview`. Confirm your JDK version before depending on it. For stability, the plan uses Bouncy Castle. [JEP 470](https://openjdk.org/jeps/470)

### Public RFC 3161 TSA services — **To verify (availability)**

Public TSAs exist (e.g. FreeTSA and others cited by RFC 3161 clients), verifiable with `openssl ts -verify`. Availability and policies of each service change over time; if you build the PoC, confirm that the chosen service is still up on the day of the test. [openssl ts (manual)](https://manpages.ubuntu.com/manpages/trusty/man1/ts.1ssl.html)

### Provider divergence when rejecting malformed signatures — **Confirmed (context)**

It has been documented that, for structurally invalid signatures, the JDK's SUN provider throws `SignatureException` while BC returns `false` (observed with ML-DSA, but it illustrates the general point). That is why the design maps **both** — exception and `false` — to not-valid. [bc-java issue 2367](https://github.com/bcgit/bc-java/issues/2367)

*Date this appendix was verified: October 28, 2026.*
