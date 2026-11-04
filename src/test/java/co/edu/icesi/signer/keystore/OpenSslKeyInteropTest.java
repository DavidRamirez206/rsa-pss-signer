package co.edu.icesi.signer.keystore;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import co.edu.icesi.signer.crypto.KeyPairService;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

@Tag("external")
class OpenSslKeyInteropTest {

    private static final String PASSWORD = "a long test password";

    private static KeyPair keyPair;

    @TempDir
    Path dir;

    @BeforeAll
    static void generateKeyPair() {
        keyPair = KeyPairService.generate(2048);
    }

    @Test
    void opensslOpensOurEncryptedPrivateKey() throws Exception {
        Path key = dir.resolve("ana.key");
        new PrivateKeyStore().write(keyPair.getPrivate(), PASSWORD.toCharArray(), key);

        Result result = openssl("pkey", "-in", key.toString(), "-passin", "file:" + passwordFile(), "-noout");

        assertEquals(0, result.exitCode, result.output);
    }

    @Test
    void opensslRejectsAWrongPassword() throws Exception {
        Path key = dir.resolve("ana.key");
        new PrivateKeyStore(1000).write(keyPair.getPrivate(), PASSWORD.toCharArray(), key);
        Path wrong = Files.writeString(dir.resolve("wrong.txt"), "wrong password");

        Result result = openssl("pkey", "-in", key.toString(), "-passin", "file:" + wrong, "-noout");

        assertNotEquals(0, result.exitCode);
    }

    @Test
    void opensslReadsOurPublicKey() throws Exception {
        Path pub = dir.resolve("ana.pub");
        PublicKeyStore.write(keyPair.getPublic(), pub);
        Path der = dir.resolve("ana.der");

        Result result = openssl("pkey", "-pubin", "-in", pub.toString(), "-outform", "DER", "-out", der.toString());

        assertEquals(0, result.exitCode, result.output);
        assertArrayEquals(keyPair.getPublic().getEncoded(), Files.readAllBytes(der));
    }

    @Test
    void weReadAPrivateKeyEncryptedByOpenssl() throws Exception {
        Path plain = dir.resolve("plain.pem");
        Path encrypted = dir.resolve("encrypted.key");
        assertEquals(0, openssl("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
                "-out", plain.toString()).exitCode);
        Result result = openssl("pkcs8", "-topk8", "-in", plain.toString(), "-out", encrypted.toString(),
                "-v2", "aes-256-cbc", "-v2prf", "hmacWithSHA256", "-iter", "1000",
                "-passout", "file:" + passwordFile());
        assertEquals(0, result.exitCode, result.output);

        assertEquals("RSA", new PrivateKeyStore().read(encrypted, PASSWORD.toCharArray()).getAlgorithm());
    }

    private Path passwordFile() throws IOException {
        Path file = dir.resolve("password.txt");
        return Files.exists(file) ? file : Files.writeString(file, PASSWORD);
    }

    private static Result openssl(String... args) throws IOException, InterruptedException {
        List<String> command = new ArrayList<>(List.of("openssl"));
        command.addAll(List.of(args));
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        String output = new String(process.getInputStream().readAllBytes());
        return new Result(process.waitFor(), output);
    }

    private static final class Result {
        final int exitCode;
        final String output;

        Result(int exitCode, String output) {
            this.exitCode = exitCode;
            this.output = output;
        }
    }
}
