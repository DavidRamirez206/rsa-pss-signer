package co.edu.icesi.signer.keystore;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import co.edu.icesi.signer.crypto.KeyPairService;
import java.io.IOException;
import java.io.StringReader;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.util.Arrays;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.EncryptionScheme;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.util.io.pem.PemReader;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PrivateKeyStoreTest {

    private static final int TEST_ITERATIONS = 1000;
    private static final char[] PASSWORD = "a long test password".toCharArray();

    private static KeyPair keyPair;

    private final PrivateKeyStore store = new PrivateKeyStore(TEST_ITERATIONS);

    @TempDir
    Path dir;

    @BeforeAll
    static void generateKeyPair() {
        keyPair = KeyPairService.generate(2048);
    }

    @Test
    void writeThenReadRoundTrip() throws Exception {
        Path file = dir.resolve("ana.key");

        store.write(keyPair.getPrivate(), PASSWORD, file);

        assertTrue(Files.readString(file).startsWith("-----BEGIN ENCRYPTED PRIVATE KEY-----"));
        assertEquals(keyPair.getPrivate(), store.read(file, PASSWORD));
    }

    @Test
    void passwordIsNotModifiedByTheStore() throws Exception {
        char[] password = PASSWORD.clone();
        Path file = dir.resolve("ana.key");

        store.write(keyPair.getPrivate(), password, file);
        store.read(file, password);

        assertArrayEquals(PASSWORD, password);
    }

    @Test
    void keyMaterialIsNotStoredInTheClear() throws Exception {
        Path file = dir.resolve("ana.key");
        store.write(keyPair.getPrivate(), PASSWORD, file);

        byte[] encrypted = readEncrypted(file).getEncoded();
        byte[] modulus = ((RSAPrivateKey) keyPair.getPrivate()).getModulus().toByteArray();

        assertFalse(contains(encrypted, Arrays.copyOfRange(modulus, 1, 33)));
    }

    // T-1.1: KDF parameters
    @Test
    void usesPbes2WithPbkdf2HmacSha256AndAes256Cbc() throws Exception {
        Path file = dir.resolve("ana.key");
        store.write(keyPair.getPrivate(), PASSWORD, file);

        AlgorithmIdentifier algorithm = readEncrypted(file).getEncryptionAlgorithm();
        assertEquals(PKCSObjectIdentifiers.id_PBES2, algorithm.getAlgorithm());

        PBES2Parameters pbes2 = PBES2Parameters.getInstance(algorithm.getParameters());
        PBKDF2Params kdf = PBKDF2Params.getInstance(pbes2.getKeyDerivationFunc().getParameters());
        assertEquals(TEST_ITERATIONS, kdf.getIterationCount().intValue());
        assertEquals(PKCSObjectIdentifiers.id_hmacWithSHA256, kdf.getPrf().getAlgorithm());
        assertEquals(NISTObjectIdentifiers.id_aes256_CBC, pbes2.getEncryptionScheme().getAlgorithm());
    }

    // T-KDF-def: the production default stays high
    @Test
    void productionIterationCountStaysHigh() {
        assertTrue(PrivateKeyStore.DEFAULT_ITERATIONS >= 600_000);
    }

    // T-1.2: salt and IV are fresh on every encryption
    @Test
    void saltAndIvDifferBetweenEncryptions() throws Exception {
        Path first = dir.resolve("first.key");
        Path second = dir.resolve("second.key");
        store.write(keyPair.getPrivate(), PASSWORD, first);
        store.write(keyPair.getPrivate(), PASSWORD, second);

        byte[] firstSalt = salt(first);

        assertTrue(firstSalt.length >= 16);
        assertFalse(Arrays.equals(firstSalt, salt(second)));
        assertFalse(Arrays.equals(iv(first), iv(second)));
    }

    // T-1.4: a wrong password always ends in WrongPasswordException, whatever the
    // decryption happens to produce (about 1 in 256 attempts passes the CBC padding)
    @Test
    void wrongPasswordsAlwaysThrowWrongPasswordException() throws Exception {
        PrivateKeyStore fastStore = new PrivateKeyStore(10);
        Path file = dir.resolve("ana.key");
        fastStore.write(keyPair.getPrivate(), PASSWORD, file);

        for (int i = 0; i < 2000; i++) {
            char[] wrong = ("wrong password " + i).toCharArray();
            assertThrows(WrongPasswordException.class, () -> fastStore.read(file, wrong));
        }
    }

    @Test
    void doesNotOverwriteAnExistingFile() throws IOException {
        Path file = Files.writeString(dir.resolve("ana.key"), "existing");

        assertThrows(FileAlreadyExistsException.class, () -> store.write(keyPair.getPrivate(), PASSWORD, file));
        assertEquals("existing", Files.readString(file));
    }

    @Test
    void missingFileIsAnIoError() {
        assertThrows(NoSuchFileException.class, () -> store.read(dir.resolve("missing.key"), PASSWORD));
    }

    @Test
    void rejectsFilesThatAreNotEncryptedPrivateKeys() throws IOException {
        Path publicKey = dir.resolve("ana.pub");
        PublicKeyStore.write(keyPair.getPublic(), publicKey);
        Path corrupt = Files.writeString(dir.resolve("corrupt.key"),
                "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n");
        Path text = Files.writeString(dir.resolve("text.key"), "not a key");

        assertThrows(InvalidKeyException.class, () -> store.read(publicKey, PASSWORD));
        assertThrows(InvalidKeyException.class, () -> store.read(corrupt, PASSWORD));
        assertThrows(InvalidKeyException.class, () -> store.read(text, PASSWORD));
    }

    @Test
    void rejectsEncryptedKeyThatIsNotRsa() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(256);
        Path file = dir.resolve("ec.key");
        store.write(generator.generateKeyPair().getPrivate(), PASSWORD, file);

        assertThrows(InvalidKeyException.class, () -> store.read(file, PASSWORD));
    }

    private static PKCS8EncryptedPrivateKeyInfo readEncrypted(Path file) throws IOException {
        try (PemReader reader = new PemReader(new StringReader(Files.readString(file)))) {
            return new PKCS8EncryptedPrivateKeyInfo(reader.readPemObject().getContent());
        }
    }

    private static PBES2Parameters pbes2(Path file) throws IOException {
        return PBES2Parameters.getInstance(readEncrypted(file).getEncryptionAlgorithm().getParameters());
    }

    private static byte[] salt(Path file) throws IOException {
        return PBKDF2Params.getInstance(pbes2(file).getKeyDerivationFunc().getParameters()).getSalt();
    }

    private static byte[] iv(Path file) throws IOException {
        EncryptionScheme scheme = pbes2(file).getEncryptionScheme();
        return ASN1OctetString.getInstance(scheme.getParameters()).getOctets();
    }

    private static boolean contains(byte[] haystack, byte[] needle) {
        for (int i = 0; i <= haystack.length - needle.length; i++) {
            if (Arrays.equals(haystack, i, i + needle.length, needle, 0, needle.length)) {
                return true;
            }
        }
        return false;
    }
}
