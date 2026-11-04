package co.edu.icesi.signer.keystore;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import co.edu.icesi.signer.crypto.KeyPairService;
import java.io.IOException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PublicKeyStoreTest {

    private static KeyPair keyPair;

    @TempDir
    Path dir;

    @BeforeAll
    static void generateKeyPair() {
        keyPair = KeyPairService.generate(2048);
    }

    @Test
    void writeThenReadRoundTrip() throws Exception {
        Path file = dir.resolve("ana.pub");

        PublicKeyStore.write(keyPair.getPublic(), file);

        assertTrue(Files.readString(file).startsWith("-----BEGIN PUBLIC KEY-----"));
        assertEquals(keyPair.getPublic(), PublicKeyStore.read(file));
    }

    @Test
    void doesNotOverwriteAnExistingFile() throws IOException {
        Path file = Files.writeString(dir.resolve("ana.pub"), "existing");

        assertThrows(FileAlreadyExistsException.class, () -> PublicKeyStore.write(keyPair.getPublic(), file));
        assertEquals("existing", Files.readString(file));
    }

    @Test
    void missingFileIsAnIoError() {
        assertThrows(NoSuchFileException.class, () -> PublicKeyStore.read(dir.resolve("missing.pub")));
    }

    // T-3.7: wrong key type and corrupt PEM
    @Test
    void rejectsEcKey() throws IOException, GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(256);
        Path file = dir.resolve("ec.pub");
        PublicKeyStore.write(generator.generateKeyPair().getPublic(), file);

        assertThrows(InvalidKeyException.class, () -> PublicKeyStore.read(file));
    }

    @Test
    void rejectsPrivateKeyFileUsedAsPublicKey() throws IOException {
        Path file = dir.resolve("ana.key");
        new PrivateKeyStore(1000).write(keyPair.getPrivate(), "a long test password".toCharArray(), file);

        assertThrows(InvalidKeyException.class, () -> PublicKeyStore.read(file));
    }

    @Test
    void rejectsCorruptPem() throws IOException {
        Path corrupt = Files.writeString(dir.resolve("corrupt.pub"),
                "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n");
        Path text = Files.writeString(dir.resolve("text.pub"), "not a key");
        Path binary = Files.write(dir.resolve("binary.pub"), new byte[] {(byte) 0xFF, (byte) 0xFE, 0, 1});

        assertThrows(InvalidKeyException.class, () -> PublicKeyStore.read(corrupt));
        assertThrows(InvalidKeyException.class, () -> PublicKeyStore.read(text));
        assertThrows(InvalidKeyException.class, () -> PublicKeyStore.read(binary));
    }
}
