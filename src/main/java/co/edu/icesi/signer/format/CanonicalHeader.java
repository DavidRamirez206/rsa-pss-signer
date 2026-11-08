package co.edu.icesi.signer.format;

import co.edu.icesi.signer.crypto.HashAlg;
import co.edu.icesi.signer.crypto.PssParams;
import java.nio.charset.StandardCharsets;

/**
 * The signed metadata of a {@code .sig} file.
 *
 * <p>The JSON itself is never signed, because field order and whitespace may differ
 * between serializers. What gets signed is {@link #toBytes()}: a fixed-order,
 * line-based string. Free-text fields may not contain control characters, otherwise
 * a crafted value could imitate the following lines.
 *
 * <p>Format version 2 adds the document version and the hash of the previous signature,
 * which chain the versions of a document against replay. Version 1, written by v0.1.0
 * to v0.3.0, has neither: {@code docVersion} is 0 and {@code prevSigHash} is empty.
 *
 * @param docVersion version of the signed document, from 1; 0 in format version 1
 * @param prevSigHash lowercase hex SHA-256 of the previous version's {@code .sig}; empty for the first
 */
public record CanonicalHeader(
        int version,
        HashAlg hashAlg,
        int saltLen,
        String mgf,
        String mgfHash,
        int trailer,
        String keyFingerprint,
        String fileName,
        String signerName,
        String signedAt,
        int docVersion,
        String prevSigHash) {

    public static final int CURRENT_VERSION = 2;

    /** Format version without document versions, still accepted when verifying. */
    public static final int LEGACY_VERSION = 1;

    /**
     * @throws IllegalArgumentException if a text field is null or contains control characters
     */
    public CanonicalHeader {
        requireSafeText("mgf", mgf);
        requireSafeText("mgfHash", mgfHash);
        requireSafeText("keyFingerprint", keyFingerprint);
        requireSafeText("fileName", fileName);
        requireSafeText("signerName", signerName);
        requireSafeText("signedAt", signedAt);
        requireSafeText("prevSigHash", prevSigHash);
    }

    /** Builds the header for the first version of a document. */
    public static CanonicalHeader forSigning(
            HashAlg hashAlg, String keyFingerprint, String fileName, String signerName, String signedAt) {
        return forSigning(hashAlg, keyFingerprint, fileName, signerName, signedAt, 1, "");
    }

    /** Builds the header for a new signature with the project's PSS parameters. */
    public static CanonicalHeader forSigning(HashAlg hashAlg, String keyFingerprint, String fileName,
            String signerName, String signedAt, int docVersion, String prevSigHash) {
        return new CanonicalHeader(
                CURRENT_VERSION,
                hashAlg,
                hashAlg.digestLength(),
                PssParams.MGF,
                hashAlg.jcaName(),
                PssParams.TRAILER_FIELD,
                keyFingerprint,
                fileName,
                signerName,
                signedAt,
                docVersion,
                prevSigHash);
    }

    /** Whether this header carries a document version, that is, format version 2 or later. */
    public boolean hasDocVersion() {
        return version >= CURRENT_VERSION;
    }

    /** The canonical string, one {@code name=value} per line, in a fixed order. */
    public String toCanonicalString() {
        String common = "version=" + version + "\n"
                + "hashAlg=" + hashAlg.jcaName() + "\n"
                + "pss.saltLen=" + saltLen + "\n"
                + "pss.mgf=" + mgf + "\n"
                + "pss.mgfHash=" + mgfHash + "\n"
                + "pss.trailer=" + trailer + "\n"
                + "keyFingerprint=" + keyFingerprint + "\n"
                + "fileName=" + fileName + "\n"
                + "signerName=" + signerName + "\n"
                + "signedAt=" + signedAt + "\n";
        if (!hasDocVersion()) {
            return "sigv1\n" + common;
        }
        return "sigv2\n" + common
                + "docVersion=" + docVersion + "\n"
                + "prevSigHash=" + prevSigHash + "\n";
    }

    /** The UTF-8 bytes that go into the signature, followed by the file digest. */
    public byte[] toBytes() {
        return toCanonicalString().getBytes(StandardCharsets.UTF_8);
    }

    private static void requireSafeText(String field, String value) {
        if (value == null) {
            throw new IllegalArgumentException(field + " is required");
        }
        if (value.codePoints().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException(field + " must not contain control characters");
        }
    }
}
