package co.edu.icesi.signer.keystore;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import co.edu.icesi.signer.core.VerificationOutcome;
import co.edu.icesi.signer.core.VerificationResult;
import co.edu.icesi.signer.crypto.HashAlg;
import co.edu.icesi.signer.crypto.KeyPairService;
import co.edu.icesi.signer.crypto.SigningService;
import co.edu.icesi.signer.crypto.VerificationService;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

/** T-4.2 and T-4.2b: keys outside the size and exponent allowlists never verify or sign. */
class WeakKeyTest {

    private static final char[] PASSWORD = "correct horse battery".toCharArray();

    @TempDir
    Path dir;

    private static KeyPair generate(int bits, BigInteger exponent) throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(new RSAKeyGenParameterSpec(bits, exponent));
        return generator.generateKeyPair();
    }

    static Stream<Arguments> forbiddenKeys() {
        return Stream.of(
                Arguments.of(512, RSAKeyGenParameterSpec.F4),
                Arguments.of(1024, RSAKeyGenParameterSpec.F4),
                Arguments.of(1536, RSAKeyGenParameterSpec.F4),
                Arguments.of(2048, BigInteger.valueOf(3)),
                Arguments.of(2048, BigInteger.valueOf(17)));
    }

    @ParameterizedTest
    @MethodSource("forbiddenKeys")
    void publicKeyStoreRejectsForbiddenKeys(int bits, BigInteger exponent) throws Exception {
        Path pub = dir.resolve("weak.pub");
        PublicKeyStore.write(generate(bits, exponent).getPublic(), pub);

        assertThrows(InvalidKeyException.class, () -> PublicKeyStore.read(pub));
    }

    @ParameterizedTest
    @MethodSource("forbiddenKeys")
    void privateKeyStoreRejectsForbiddenKeys(int bits, BigInteger exponent) throws Exception {
        PrivateKeyStore store = new PrivateKeyStore(1000);
        Path key = dir.resolve("weak.key");
        store.write(generate(bits, exponent).getPrivate(), PASSWORD, key);

        assertThrows(InvalidKeyException.class, () -> store.read(key, PASSWORD));
    }

    // A correct signature made with a weak key must still not be VALID
    @ParameterizedTest
    @MethodSource("forbiddenKeys")
    void verificationGivesErrorEvenWithCorrectSignature(int bits, BigInteger exponent) throws Exception {
        KeyPair weak = generate(bits, exponent);
        KeyPair good = KeyPairService.generate(2048);
        Path file = Files.writeString(dir.resolve("contract.txt"), "content");
        var sig = SigningService.sign(file, (RSAPrivateCrtKey) good.getPrivate(), HashAlg.SHA_256, "Ana", "2026-01-01T00:00:00Z");

        VerificationOutcome outcome = VerificationService.verify(file, sig, (RSAPublicKey) weak.getPublic());

        assertEquals(VerificationResult.ERROR, outcome.result());
        assertTrue(outcome.detail().contains("not allowed"), outcome.detail());
    }

    @ParameterizedTest
    @MethodSource("forbiddenKeys")
    void signingRejectsForbiddenKeys(int bits, BigInteger exponent) throws Exception {
        KeyPair weak = generate(bits, exponent);
        Path file = Files.writeString(dir.resolve("contract.txt"), "content");

        assertThrows(InvalidKeyException.class, () -> SigningService.sign(
                file, (RSAPrivateCrtKey) weak.getPrivate(), HashAlg.SHA_256, "Ana", "2026-01-01T00:00:00Z"));
    }

    @ParameterizedTest
    @ValueSource(ints = {2048, 3072, 4096})
    void allowedKeysAreAccepted(int bits) throws IOException, GeneralSecurityException {
        Path pub = dir.resolve("good.pub");
        PublicKeyStore.write(KeyPairService.generate(bits).getPublic(), pub);

        assertEquals(bits, PublicKeyStore.read(pub).getModulus().bitLength());
    }

    @Test
    void messageNamesTheProblem() throws Exception {
        Path pub = dir.resolve("weak.pub");
        PublicKeyStore.write(generate(1024, RSAKeyGenParameterSpec.F4).getPublic(), pub);

        InvalidKeyException e = assertThrows(InvalidKeyException.class, () -> PublicKeyStore.read(pub));
        assertTrue(e.getMessage().contains("1024"), e.getMessage());
    }
}
