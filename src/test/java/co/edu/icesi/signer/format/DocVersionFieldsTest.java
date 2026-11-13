package co.edu.icesi.signer.format;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import co.edu.icesi.signer.crypto.HashAlg;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/** Format version 2: the document version and the chain to the previous signature. */
class DocVersionFieldsTest {

    private static final String FINGERPRINT = "3A:7F:0C:91:3A:7F:0C:91:3A:7F:0C:91:3A:7F:0C:91:3A:7F:0C:91:3A:7F:0C:91:3A:7F:0C:91:3A:7F:0C:91";
    private static final String HASH = "0123456789abcdef".repeat(4);

    private static String sig(int version, String extra) {
        return """
                { "version": %d, "hashAlg": "SHA-256",
                  "pss": { "saltLen": 32, "mgf": "MGF1", "mgfHash": "SHA-256", "trailer": 1 },
                  "keyFingerprint": "%s", "fileName": "a.txt", "signerName": "Ana Perez",
                  "signedAt": "2026-10-28T11:30:00-05:00", %s "signature": "AQID" }
                """.formatted(version, FINGERPRINT, extra);
    }

    private static SigFile parse(String json) throws SigValidationException {
        return SigFile.parse(json.getBytes(StandardCharsets.UTF_8));
    }

    private static void assertRejected(String json, String expectedMessage) {
        SigValidationException e = assertThrows(SigValidationException.class, () -> parse(json));
        assertTrue(e.getMessage().contains(expectedMessage), e.getMessage());
    }

    @Test
    void acceptsAFirstVersionAndAChainedOne() throws SigValidationException {
        assertEquals(1, parse(sig(2, "\"docVersion\": 1, \"prevSigHash\": \"\",")).header().docVersion());

        SigFile chained = parse(sig(2, "\"docVersion\": 4, \"prevSigHash\": \"" + HASH + "\","));
        assertEquals(4, chained.header().docVersion());
        assertEquals(HASH, chained.header().prevSigHash());
    }

    @Test
    void theLegacyFormatHasNoVersion() throws SigValidationException {
        SigFile legacy = parse(sig(1, ""));

        assertEquals(0, legacy.header().docVersion());
        assertTrue(legacy.header().toCanonicalString().startsWith("sigv1\n"));
    }

    @Test
    void theLegacyFormatRejectsTheNewFields() {
        assertRejected(sig(1, "\"docVersion\": 1, \"prevSigHash\": \"\","), "Unknown field: docVersion");
    }

    @Test
    void formatTwoRequiresTheNewFields() {
        assertRejected(sig(2, ""), "Missing field: ");
        assertRejected(sig(2, "\"docVersion\": 1,"), "Missing field: prevSigHash");
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
        "0 | ''         | docVersion must be 1 or more",
        "-3 | ''        | docVersion must be 1 or more",
        "1 | HASH       | must be empty for version 1",
        "2 | ''         | must chain to the previous version",
        "2 | UPPER      | not a lowercase hex",
        "2 | abc        | not a lowercase hex"})
    void rejectsAnInconsistentChain(int docVersion, String prevSigHash, String message) {
        String hash = switch (prevSigHash) {
            case "HASH" -> HASH;
            case "UPPER" -> HASH.toUpperCase();
            default -> prevSigHash;
        };
        assertRejected(sig(2, "\"docVersion\": " + docVersion + ", \"prevSigHash\": \"" + hash + "\","), message);
    }

    @Test
    void docVersionMustBeAnInteger() {
        assertRejected(sig(2, "\"docVersion\": \"2\", \"prevSigHash\": \"" + HASH + "\","), "docVersion must be an integer");
    }

    @Test
    void serializationRoundTrips() throws SigValidationException {
        CanonicalHeader header = CanonicalHeader.forSigning(HashAlg.SHA_256, FINGERPRINT, "a.txt", "Ana",
                "2026-10-28T11:30:00-05:00", 3, HASH);

        SigFile parsed = SigFile.parse(new SigFile(header, new byte[] {1, 2, 3}).toJson());

        assertEquals(header, parsed.header());
    }

    @Test
    void theChainHashIsTheSha256OfTheFileBytes() {
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                SigFile.hashOf("abc".getBytes(StandardCharsets.US_ASCII)));
    }
}
