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
        String signedAt) {

    public static final int CURRENT_VERSION = 1;

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
    }

    /** Builds the header for a new signature with the project's PSS parameters. */
    public static CanonicalHeader forSigning(
            HashAlg hashAlg, String keyFingerprint, String fileName, String signerName, String signedAt) {
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
                signedAt);
    }

    /** The canonical string, one {@code name=value} per line, in a fixed order. */
    public String toCanonicalString() {
        return "sigv1\n"
                + "version=" + version + "\n"
                + "hashAlg=" + hashAlg.jcaName() + "\n"
                + "pss.saltLen=" + saltLen + "\n"
                + "pss.mgf=" + mgf + "\n"
                + "pss.mgfHash=" + mgfHash + "\n"
                + "pss.trailer=" + trailer + "\n"
                + "keyFingerprint=" + keyFingerprint + "\n"
                + "fileName=" + fileName + "\n"
                + "signerName=" + signerName + "\n"
                + "signedAt=" + signedAt + "\n";
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
