package co.edu.icesi.signer.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.Optional;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

class HashAlgTest {

    @ParameterizedTest
    @EnumSource(HashAlg.class)
    void digestLengthMatchesJcaDigest(HashAlg alg) {
        assertEquals(alg.digestLength(), alg.newDigest().getDigestLength());
    }

    @ParameterizedTest
    @EnumSource(HashAlg.class)
    void fromJcaNameAcceptsEveryAllowedAlgorithm(HashAlg alg) {
        assertEquals(Optional.of(alg), HashAlg.fromJcaName(alg.jcaName()));
    }

    // T-2.7: hash downgrade and label confusion
    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {
        "MD5", "SHA-1", "SHA1", "NONE", "SHA-384",
        "sha-256", "SHA256", "SHA-256 ", " SHA-256", "SHA_256", "SHA3_256"
    })
    void fromJcaNameRejectsAnythingOutsideTheAllowlist(String name) {
        assertTrue(HashAlg.fromJcaName(name).isEmpty());
    }

    // FIPS 180-4 and FIPS 202 test vectors for the message "abc"
    @ParameterizedTest
    @CsvSource({
        "SHA_256,  ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "SHA_512,  ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
            + "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        "SHA3_256, 3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
        "SHA3_512, b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
            + "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
    })
    void newDigestProducesKnownTestVectors(HashAlg alg, String expectedHex) {
        byte[] digest = alg.newDigest().digest("abc".getBytes(StandardCharsets.US_ASCII));
        assertEquals(expectedHex, HexFormat.of().formatHex(digest));
    }
}
