package co.edu.icesi.signer.keystore;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import co.edu.icesi.signer.crypto.KeyPairService;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.time.Duration;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.EncryptionScheme;
import org.bouncycastle.asn1.pkcs.KeyDerivationFunc;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * T-1.3: the encryption parameters of a {@code .key} are checked before deriving
 * anything from the password. The crafted files hold no real key, so a test that
 * passes shows the file was rejected by its parameters alone.
 */
class KeyKdfParamsTest {

    private static final char[] PASSWORD = "correct horse battery".toCharArray();
    private static final ASN1ObjectIdentifier HMAC_SHA256 = PKCSObjectIdentifiers.id_hmacWithSHA256;
    private static final ASN1ObjectIdentifier AES_256 = NISTObjectIdentifiers.id_aes256_CBC;

    @TempDir
    Path dir;

    private Path crafted(ASN1ObjectIdentifier scheme, int iterations, ASN1ObjectIdentifier prf, ASN1ObjectIdentifier cipher)
            throws Exception {
        PBKDF2Params kdf = new PBKDF2Params(new byte[16], iterations, new AlgorithmIdentifier(prf, DERNull.INSTANCE));
        PBES2Parameters pbes2 = new PBES2Parameters(
                new KeyDerivationFunc(PKCSObjectIdentifiers.id_PBKDF2, kdf),
                new EncryptionScheme(cipher, new DEROctetString(new byte[16])));
        EncryptedPrivateKeyInfo info = new EncryptedPrivateKeyInfo(new AlgorithmIdentifier(scheme, pbes2), new byte[64]);

        StringWriter pem = new StringWriter();
        try (PemWriter writer = new PemWriter(pem)) {
            writer.writeObject(new PemObject("ENCRYPTED PRIVATE KEY", info.getEncoded()));
        }
        return Files.writeString(dir.resolve("crafted.key"), pem.toString());
    }

    private static void assertRejected(PrivateKeyStore store, Path key, String expectedMessage) {
        InvalidKeyException e = assertThrows(InvalidKeyException.class, () -> store.read(key, PASSWORD));
        assertTrue(e.getMessage().contains(expectedMessage), e.getMessage());
    }

    // T-1.3: at 2e9 iterations, deriving the key would take far longer than the limit
    @Test
    void hugeIterationCountIsRejectedQuickly() throws Exception {
        Path key = crafted(PKCSObjectIdentifiers.id_PBES2, 2_000_000_000, HMAC_SHA256, AES_256);

        assertTimeoutPreemptively(Duration.ofSeconds(2),
                () -> assertRejected(new PrivateKeyStore(), key, "Iteration count"));
    }

    @Test
    void lowStoreStillRejectsHugeIterationCount() throws Exception {
        Path key = crafted(PKCSObjectIdentifiers.id_PBES2, PrivateKeyStore.MAX_ITERATIONS + 1, HMAC_SHA256, AES_256);

        assertRejected(new PrivateKeyStore(1000), key, "Iteration count");
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 1000, PrivateKeyStore.MIN_ITERATIONS - 1})
    void lowIterationCountIsRejectedInProduction(int iterations) throws Exception {
        Path key = crafted(PKCSObjectIdentifiers.id_PBES2, iterations, HMAC_SHA256, AES_256);

        assertRejected(new PrivateKeyStore(), key, "Iteration count");
    }

    @Test
    void productionBoundsAreAccepted() throws Exception {
        KeyPair keyPair = KeyPairService.generate(2048);
        Path key = dir.resolve("real.key");
        new PrivateKeyStore(PrivateKeyStore.MIN_ITERATIONS).write(keyPair.getPrivate(), PASSWORD, key);

        assertDoesNotThrow(() -> new PrivateKeyStore().read(key, PASSWORD));
    }

    @Test
    void lowIterationStoreReadsItsOwnKeys() throws Exception {
        KeyPair keyPair = KeyPairService.generate(2048);
        PrivateKeyStore store = new PrivateKeyStore(1000);
        Path key = dir.resolve("real.key");
        store.write(keyPair.getPrivate(), PASSWORD, key);

        assertDoesNotThrow(() -> store.read(key, PASSWORD));
    }

    @Test
    void weakPrfIsRejected() throws Exception {
        Path key = crafted(PKCSObjectIdentifiers.id_PBES2, 600_000, PKCSObjectIdentifiers.id_hmacWithSHA1, AES_256);

        assertRejected(new PrivateKeyStore(), key, "PBKDF2 hash");
    }

    @Test
    void nonAesCipherIsRejected() throws Exception {
        Path key = crafted(PKCSObjectIdentifiers.id_PBES2, 600_000, HMAC_SHA256, PKCSObjectIdentifiers.des_EDE3_CBC);

        assertRejected(new PrivateKeyStore(), key, "Cipher");
    }

    @Test
    void nonPbes2SchemeIsRejected() throws Exception {
        Path key = crafted(PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC, 600_000, HMAC_SHA256, AES_256);

        assertRejected(new PrivateKeyStore(), key, "PBES2");
    }
}
