package co.edu.icesi.signer.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class KeyPairServiceTest {

    private static KeyPair keyPair;

    @BeforeAll
    static void generateKeyPair() {
        keyPair = KeyPairService.generate(2048);
    }

    // T-6.3: generation parameters
    @ParameterizedTest
    @ValueSource(ints = {2048, 3072, 4096})
    void generatesRequestedSizeWithExponentF4(int bits) {
        RSAPublicKey publicKey = (RSAPublicKey) KeyPairService.generate(bits).getPublic();

        assertEquals(bits, publicKey.getModulus().bitLength());
        assertEquals(BigInteger.valueOf(65537), publicKey.getPublicExponent());
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 512, 1024, 2047, 2049, 8192})
    void rejectsDisallowedKeySizes(int bits) {
        assertThrows(IllegalArgumentException.class, () -> KeyPairService.generate(bits));
    }

    // T-6.2: the generator is not deterministic
    @Test
    void twoGenerationsProduceDifferentModuli() {
        RSAPublicKey other = (RSAPublicKey) KeyPairService.generate(2048).getPublic();

        assertFalse(((RSAPublicKey) keyPair.getPublic()).getModulus().equals(other.getModulus()));
    }

    @Test
    void fingerprintIsFormattedSha256() {
        String fingerprint = KeyPairService.fingerprint(keyPair.getPublic());

        assertTrue(fingerprint.matches("[0-9A-F]{2}(:[0-9A-F]{2}){31}"), fingerprint);
    }

    @Test
    void fingerprintIsStableAndDependsOnTheKey() {
        assertEquals(KeyPairService.fingerprint(keyPair.getPublic()), KeyPairService.fingerprint(keyPair.getPublic()));
        assertFalse(KeyPairService.fingerprint(keyPair.getPublic())
                .equals(KeyPairService.fingerprint(KeyPairService.generate(2048).getPublic())));
    }

    @Test
    void derivedPublicKeyMatchesTheGeneratedOne() throws GeneralSecurityException {
        RSAPublicKey derived = KeyPairService.publicKeyOf((RSAPrivateCrtKey) keyPair.getPrivate());

        assertEquals(KeyPairService.fingerprint(keyPair.getPublic()), KeyPairService.fingerprint(derived));
    }
}
