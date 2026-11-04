package co.edu.icesi.signer.format;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import co.edu.icesi.signer.crypto.HashAlg;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;

class SigFileTest {

    private static final String VALID = """
            {
              "version": 1,
              "hashAlg": "SHA-256",
              "pss": { "saltLen": 32, "mgf": "MGF1", "mgfHash": "SHA-256", "trailer": 1 },
              "keyFingerprint": "3A:7F:0C:91:3A:7F:0C:91:3A:7F:0C:91:3A:7F:0C:91:3A:7F:0C:91:3A:7F:0C:91:3A:7F:0C:91:3A:7F:0C:91",
              "fileName": "contract.pdf",
              "signerName": "Ana Perez",
              "signedAt": "2026-10-28T11:30:00-05:00",
              "signature": "AQID"
            }
            """;

    private static SigFile parse(String json) throws SigValidationException {
        return SigFile.parse(json.getBytes(StandardCharsets.UTF_8));
    }

    private static void assertRejected(String json) {
        assertThrows(SigValidationException.class, () -> parse(json));
    }

    @Test
    void parsesAValidFile() throws Exception {
        SigFile sig = parse(VALID);

        assertEquals(1, sig.header().version());
        assertEquals(HashAlg.SHA_256, sig.header().hashAlg());
        assertEquals(32, sig.header().saltLen());
        assertEquals("MGF1", sig.header().mgf());
        assertEquals("SHA-256", sig.header().mgfHash());
        assertEquals(1, sig.header().trailer());
        assertEquals("3A:7F:0C:91:3A:7F:0C:91:3A:7F:0C:91:3A:7F:0C:91:3A:7F:0C:91:3A:7F:0C:91:3A:7F:0C:91:3A:7F:0C:91", sig.header().keyFingerprint());
        assertEquals("contract.pdf", sig.header().fileName());
        assertEquals("Ana Perez", sig.header().signerName());
        assertEquals("2026-10-28T11:30:00-05:00", sig.header().signedAt());
        assertArrayEquals(new byte[] {1, 2, 3}, sig.signature());
    }

    @ParameterizedTest
    @EnumSource(HashAlg.class)
    void jsonRoundTripPreservesEverything(HashAlg alg) throws Exception {
        CanonicalHeader header = CanonicalHeader.forSigning(
                alg, "3A:7F:0C:91:3A:7F:0C:91:3A:7F:0C:91:3A:7F:0C:91:3A:7F:0C:91:3A:7F:0C:91:3A:7F:0C:91:3A:7F:0C:91", "Müller report.txt", "Zoë \"Quote\" Müller", "2026-10-28T11:30:00Z");
        SigFile original = new SigFile(header, new byte[] {0, -1, 127, -128});

        SigFile parsed = SigFile.parse(original.toJson());

        assertEquals(header, parsed.header());
        assertArrayEquals(original.signature(), parsed.signature());
    }

    // The signed bytes must not depend on how the JSON was formatted
    @Test
    void canonicalBytesDoNotDependOnJsonLayout() throws Exception {
        String reordered = """
                {"signature":"AQID","signedAt":"2026-10-28T11:30:00-05:00","signerName":"Ana Perez",
                "fileName":"contract.pdf","keyFingerprint":"3A:7F:0C:91:3A:7F:0C:91:3A:7F:0C:91:3A:7F:0C:91:3A:7F:0C:91:3A:7F:0C:91:3A:7F:0C:91:3A:7F:0C:91",
                "pss":{"trailer":1,"mgfHash":"SHA-256","mgf":"MGF1","saltLen":32},
                "hashAlg":"SHA-256","version":1}
                """;

        assertArrayEquals(parse(VALID).header().toBytes(), parse(reordered).header().toBytes());
    }

    @Test
    void toJsonWritesTheDocumentedFieldNames() {
        String json = new String(new SigFile(
                CanonicalHeader.forSigning(HashAlg.SHA_256, "3A:7F:0C:91:3A:7F:0C:91:3A:7F:0C:91:3A:7F:0C:91:3A:7F:0C:91:3A:7F:0C:91:3A:7F:0C:91:3A:7F:0C:91", "a.txt", "Ana", "2026-10-28T11:30:00Z"),
                new byte[] {1}).toJson(), StandardCharsets.UTF_8);

        for (String field : new String[] {"version", "hashAlg", "pss", "saltLen", "mgf", "mgfHash", "trailer",
            "keyFingerprint", "fileName", "signerName", "signedAt", "signature"}) {
            assertTrue(json.contains("\"" + field + "\""), field);
        }
    }

    // T-3.2: malformed JSON
    @ParameterizedTest
    @ValueSource(strings = {"", "   ", "not json", "{", "[]", "1", "null", "\"text\""})
    void rejectsContentThatIsNotAJsonObject(String content) {
        assertRejected(content);
    }

    @Test
    void rejectsBinaryContent() {
        assertThrows(SigValidationException.class, () -> SigFile.parse(new byte[] {(byte) 0xFF, (byte) 0xFE, 0, 1}));
    }

    @Test
    void rejectsTrailingContent() {
        assertRejected(VALID + "{}");
    }

    // T-3.3: duplicate fields
    @Test
    void rejectsDuplicateKeys() {
        assertRejected(VALID.replace("\"version\": 1,", "\"version\": 1, \"hashAlg\": \"MD5\","));
        assertRejected(VALID.replace("\"saltLen\": 32,", "\"saltLen\": 32, \"saltLen\": 0,"));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "\"version\": 1,", "\"hashAlg\": \"SHA-256\",", "\"keyFingerprint\": \"3A:7F:0C:91:3A:7F:0C:91:3A:7F:0C:91:3A:7F:0C:91:3A:7F:0C:91:3A:7F:0C:91:3A:7F:0C:91:3A:7F:0C:91\",",
        "\"fileName\": \"contract.pdf\",", "\"signerName\": \"Ana Perez\",",
        "\"signedAt\": \"2026-10-28T11:30:00-05:00\",", "\"saltLen\": 32,", "\"mgf\": \"MGF1\",",
        "\"mgfHash\": \"SHA-256\","
    })
    void rejectsMissingFields(String field) {
        assertTrue(VALID.contains(field), field);
        assertRejected(VALID.replace(field, ""));
    }

    @Test
    void rejectsMissingSignature() {
        assertRejected(VALID.replace(",\n  \"signature\": \"AQID\"", ""));
    }

    // Anything outside the signed fields would be metadata an attacker could edit freely
    @Test
    void rejectsUnknownFields() {
        assertRejected(VALID.replace("\"version\": 1,", "\"version\": 1, \"note\": \"unsigned\","));
        assertRejected(VALID.replace("\"saltLen\": 32,", "\"saltLen\": 32, \"extra\": 1,"));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "\"version\": \"1\"", "\"version\": 1.5", "\"version\": null", "\"version\": 99999999999",
        "\"hashAlg\": 1", "\"fileName\": 1", "\"signerName\": null", "\"signedAt\": []",
        "\"pss\": 1", "\"signature\": 1"
    })
    void rejectsWrongTypes(String replacement) {
        String field = replacement.substring(0, replacement.indexOf(':') + 1);
        String json = VALID.replaceFirst("(?s)" + field + " (\\{.*?\\}|[^,\\n]*)", replacement);

        assertRejected(json);
    }

    // T-2.7: hash downgrade
    @ParameterizedTest
    @ValueSource(strings = {"MD5", "SHA-1", "NONE", "sha-256", "SHA-256 "})
    void rejectsHashesOutsideTheAllowlist(String hash) {
        assertRejected(VALID.replace("\"hashAlg\": \"SHA-256\"", "\"hashAlg\": \"" + hash + "\""));
    }

    @ParameterizedTest
    @ValueSource(strings = {"not base64!", "AQI", "AQJ=", "AQID==", "AQ ID"})
    void rejectsInvalidBase64(String signature) {
        assertRejected(VALID.replace("\"signature\": \"AQID\"", "\"signature\": \"" + signature + "\""));
    }

    @Test
    void rejectsControlCharactersInFreeText() {
        assertRejected(VALID.replace("Ana Perez", "Ana\\nsignedAt=2000-01-01"));
    }
}
