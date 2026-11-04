package co.edu.icesi.signer.format;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import co.edu.icesi.signer.crypto.HashAlg;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;

class CanonicalHeaderTest {

    private static final String FINGERPRINT = "3A:7F:0C";
    private static final String SIGNED_AT = "2026-10-28T11:30:00-05:00";

    private static CanonicalHeader header(String fileName, String signerName) {
        return CanonicalHeader.forSigning(HashAlg.SHA_256, FINGERPRINT, fileName, signerName, SIGNED_AT);
    }

    // The exact bytes are the signature format: changing them breaks every existing signature
    @Test
    void canonicalStringHasTheExactSpecifiedFormat() {
        String expected = """
                sigv1
                version=1
                hashAlg=SHA-256
                pss.saltLen=32
                pss.mgf=MGF1
                pss.mgfHash=SHA-256
                pss.trailer=1
                keyFingerprint=3A:7F:0C
                fileName=contract.pdf
                signerName=Ana Perez
                signedAt=2026-10-28T11:30:00-05:00
                """;

        assertEquals(expected, header("contract.pdf", "Ana Perez").toCanonicalString());
    }

    @ParameterizedTest
    @EnumSource(HashAlg.class)
    void forSigningBindsThePssParametersToTheHash(HashAlg alg) {
        CanonicalHeader header = CanonicalHeader.forSigning(alg, FINGERPRINT, "a.txt", "Ana", SIGNED_AT);

        assertEquals(alg.digestLength(), header.saltLen());
        assertEquals("MGF1", header.mgf());
        assertEquals(alg.jcaName(), header.mgfHash());
        assertEquals(1, header.trailer());
    }

    @Test
    void bytesAreUtf8() {
        CanonicalHeader header = header("contract.txt", "Zoë Müller");

        assertArrayEquals(header.toCanonicalString().getBytes(StandardCharsets.UTF_8), header.toBytes());
    }

    @Test
    void anyFieldChangesTheBytes() {
        byte[] original = header("contract.txt", "Ana").toBytes();

        assertFalse(Arrays.equals(original, header("other.txt", "Ana").toBytes()));
        assertFalse(Arrays.equals(original, header("contract.txt", "Mallory").toBytes()));
    }

    // Without this, signerName "Ana\nsignedAt=..." could imitate the following lines
    @ParameterizedTest
    @ValueSource(strings = {"Ana\nsignedAt=2000-01-01", "Ana\r", "tab\there", "nul\0", "del\u007f", "c1\u0085"})
    void rejectsControlCharactersInFreeText(String value) {
        assertThrows(IllegalArgumentException.class, () -> header(value, "Ana"));
        assertThrows(IllegalArgumentException.class, () -> header("a.txt", value));
    }

    @Test
    void rejectsNullText() {
        assertThrows(IllegalArgumentException.class, () -> header(null, "Ana"));
        assertThrows(IllegalArgumentException.class, () -> header("a.txt", null));
    }
}
