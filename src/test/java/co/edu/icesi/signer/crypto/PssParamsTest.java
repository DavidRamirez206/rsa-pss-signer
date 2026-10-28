package co.edu.icesi.signer.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Arrays;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

class PssParamsTest {

    private static final byte[] MESSAGE = "contract contents".getBytes(StandardCharsets.UTF_8);

    private static KeyPair keyPair;

    @BeforeAll
    static void generateKeyPair() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        keyPair = generator.generateKeyPair();
    }

    @ParameterizedTest
    @EnumSource(HashAlg.class)
    void parametersAreBoundToTheMessageHash(HashAlg alg) {
        PSSParameterSpec spec = PssParams.forHash(alg);

        assertEquals(alg.jcaName(), spec.getDigestAlgorithm());
        assertEquals("MGF1", spec.getMGFAlgorithm());
        assertEquals(alg.jcaName(), ((MGF1ParameterSpec) spec.getMGFParameters()).getDigestAlgorithm());
        assertEquals(alg.digestLength(), spec.getSaltLength());
        assertEquals(1, spec.getTrailerField());
    }

    @ParameterizedTest
    @EnumSource(HashAlg.class)
    void signatureCarriesExplicitParametersNotTheSha1Default(HashAlg alg) throws GeneralSecurityException {
        PSSParameterSpec actual = PssParams.newSignature(alg).getParameters().getParameterSpec(PSSParameterSpec.class);

        assertEquals(alg.jcaName(), actual.getDigestAlgorithm());
        assertEquals(alg.jcaName(), ((MGF1ParameterSpec) actual.getMGFParameters()).getDigestAlgorithm());
        assertEquals(alg.digestLength(), actual.getSaltLength());
    }

    @ParameterizedTest
    @EnumSource(HashAlg.class)
    void signThenVerifyRoundTrip(HashAlg alg) throws GeneralSecurityException {
        byte[] signature = sign(alg, MESSAGE);

        assertEquals(256, signature.length);
        assertTrue(verify(alg, MESSAGE, signature));
    }

    @ParameterizedTest
    @EnumSource(HashAlg.class)
    void modifiedMessageDoesNotVerify(HashAlg alg) throws GeneralSecurityException {
        byte[] signature = sign(alg, MESSAGE);
        byte[] tampered = MESSAGE.clone();
        tampered[0] ^= 1;

        assertFalse(verify(alg, tampered, signature));
    }

    @Test
    void signaturesAreRandomizedBySalt() throws GeneralSecurityException {
        byte[] first = sign(HashAlg.SHA_256, MESSAGE);
        byte[] second = sign(HashAlg.SHA_256, MESSAGE);

        assertFalse(Arrays.equals(first, second));
        assertTrue(verify(HashAlg.SHA_256, MESSAGE, first));
        assertTrue(verify(HashAlg.SHA_256, MESSAGE, second));
    }

    @Test
    void signatureDoesNotVerifyUnderADifferentHash() throws GeneralSecurityException {
        byte[] signature = sign(HashAlg.SHA_256, MESSAGE);

        assertFalse(verify(HashAlg.SHA_512, MESSAGE, signature));
    }

    private static byte[] sign(HashAlg alg, byte[] message) throws GeneralSecurityException {
        Signature signer = PssParams.newSignature(alg);
        signer.initSign(keyPair.getPrivate());
        signer.update(message);
        return signer.sign();
    }

    private static boolean verify(HashAlg alg, byte[] message, byte[] signature) throws GeneralSecurityException {
        Signature verifier = PssParams.newSignature(alg);
        verifier.initVerify(keyPair.getPublic());
        verifier.update(message);
        return verifier.verify(signature);
    }
}
