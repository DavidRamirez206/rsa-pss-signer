package co.edu.icesi.signer.format;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/** T-2.9: values the format fixes are checked before any cryptography. */
class SigExpectedValuesTest {

    private static final String FINGERPRINT = "3A:7F:0C:91:3A:7F:0C:91:3A:7F:0C:91:3A:7F:0C:91:3A:7F:0C:91:3A:7F:0C:91:3A:7F:0C:91:3A:7F:0C:91";

    private static String sig(String hash, String salt, String mgf, String mgfHash, String trailer,
            String version, String fingerprint, String fileName) {
        return """
                { "version": %s, "hashAlg": "%s",
                  "pss": { "saltLen": %s, "mgf": "%s", "mgfHash": "%s", "trailer": %s },
                  "keyFingerprint": "%s", "fileName": "%s", "signerName": "Ana Perez",
                  "signedAt": "2026-10-28T11:30:00-05:00", "signature": "AQID" }
                """.formatted(version, hash, salt, mgf, mgfHash, trailer, fingerprint, fileName);
    }

    private static SigFile parse(String json) throws SigValidationException {
        return SigFile.parse(json.getBytes(StandardCharsets.UTF_8));
    }

    private static void assertRejected(String json, String expectedMessage) {
        SigValidationException e = assertThrows(SigValidationException.class, () -> parse(json));
        assertTrue(e.getMessage().contains(expectedMessage), e.getMessage());
    }

    @ParameterizedTest
    @CsvSource({"SHA-256, 32", "SHA-512, 64", "SHA3-256, 32", "SHA3-512, 64"})
    void acceptsTheParametersOfEveryAllowedHash(String hash, String salt) throws SigValidationException {
        parse(sig(hash, salt, "MGF1", hash, "1", "1", FINGERPRINT, "a.txt"));
    }

    @ParameterizedTest
    @CsvSource({"SHA-256, 0", "SHA-256, 20", "SHA-256, 64", "SHA-256, 222", "SHA-256, -1", "SHA-512, 32"})
    void rejectsASaltThatIsNotTheHashLength(String hash, String salt) {
        assertRejected(sig(hash, salt, "MGF1", hash, "1", "1", FINGERPRINT, "a.txt"), "saltLen");
    }

    @ParameterizedTest
    @CsvSource({"SHA-256, SHA-1", "SHA-512, SHA-1", "SHA-512, SHA-256", "SHA-256, MD5", "SHA-256, sha-256"})
    void rejectsAnMgfHashThatIsNotTheMessageHash(String hash, String mgfHash) {
        assertRejected(sig(hash, "256".equals(hash.substring(4)) ? "32" : "64", "MGF1", mgfHash, "1", "1",
                FINGERPRINT, "a.txt"), "mgfHash");
    }

    @Test
    void rejectsAnotherMaskFunction() {
        assertRejected(sig("SHA-256", "32", "MGF2", "SHA-256", "1", "1", FINGERPRINT, "a.txt"), "mgf");
    }

    @ParameterizedTest
    @CsvSource({"0", "2", "188"})
    void rejectsAnotherTrailer(String trailer) {
        assertRejected(sig("SHA-256", "32", "MGF1", "SHA-256", trailer, "1", FINGERPRINT, "a.txt"), "trailer");
    }

    @ParameterizedTest
    @CsvSource({"0", "2", "-1"})
    void rejectsAnUnsupportedVersion(String version) {
        assertRejected(sig("SHA-256", "32", "MGF1", "SHA-256", "1", version, FINGERPRINT, "a.txt"), "version");
    }

    @ParameterizedTest
    @CsvSource({"3A:7F", "not a fingerprint", "''"})
    void rejectsAMalformedFingerprint(String fingerprint) {
        assertRejected(sig("SHA-256", "32", "MGF1", "SHA-256", "1", "1", fingerprint, "a.txt"), "keyFingerprint");
    }

    @Test
    void rejectsALowerCaseFingerprint() {
        assertRejected(sig("SHA-256", "32", "MGF1", "SHA-256", "1", "1", FINGERPRINT.toLowerCase(), "a.txt"),
                "keyFingerprint");
    }

    @ParameterizedTest
    @CsvSource({"dir/a.txt", "../a.txt", "/etc/passwd", "''"})
    void rejectsAFileNameThatIsNotABaseName(String fileName) {
        assertRejected(sig("SHA-256", "32", "MGF1", "SHA-256", "1", "1", FINGERPRINT, fileName), "fileName");
    }

    @Test
    void rejectsABackslashInTheFileName() {
        assertRejected(sig("SHA-256", "32", "MGF1", "SHA-256", "1", "1", FINGERPRINT, "dir\\\\a.txt"), "fileName");
    }
}
