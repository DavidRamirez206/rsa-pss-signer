package co.edu.icesi.signer.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import co.edu.icesi.signer.format.SigFile;
import co.edu.icesi.signer.io.FileHasher;
import co.edu.icesi.signer.keystore.PublicKeyStore;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * T-6.1: OpenSSL accepts our signatures. It verifies the rebuilt canonical message,
 * not the file itself, which proves the scheme is standard PSS rather than a homemade one.
 */
@Tag("external")
class OpenSslInteropTest {

    private static KeyPair keyPair;

    @TempDir
    Path dir;

    @BeforeAll
    static void generateKeyPair() {
        keyPair = KeyPairService.generate(2048);
    }

    @ParameterizedTest
    @CsvSource({"SHA_256, sha256", "SHA_512, sha512", "SHA3_256, sha3-256", "SHA3_512, sha3-512"})
    void opensslVerifiesOurSignature(HashAlg alg, String opensslDigest) throws Exception {
        assertEquals(0, verifyWithOpenssl(alg, opensslDigest, false).exitCode);
    }

    @Test
    void opensslRejectsASignatureOverADifferentMessage() throws Exception {
        assertNotEquals(0, verifyWithOpenssl(HashAlg.SHA_256, "sha256", true).exitCode);
    }

    private Result verifyWithOpenssl(HashAlg alg, String opensslDigest, boolean tamperMessage) throws Exception {
        Path file = Files.writeString(dir.resolve("contract.txt"), "The parties agree to the terms.");
        Path pub = dir.resolve("ana.pub");
        PublicKeyStore.write(keyPair.getPublic(), pub);

        SigFile sig = SigningService.sign(
                file, (RSAPrivateCrtKey) keyPair.getPrivate(), alg, "Ana Perez", "2026-10-28T11:30:00Z");

        ByteArrayOutputStream message = new ByteArrayOutputStream();
        message.write(sig.header().toBytes());
        message.write(FileHasher.hash(file, alg.newDigest()));
        if (tamperMessage) {
            message.write(0);
        }
        Path messageFile = Files.write(dir.resolve("m.bin"), message.toByteArray());
        Path signatureFile = Files.write(dir.resolve("signature.bin"), sig.signature());
        Path hashFile = dir.resolve("m.hash");
        assertEquals(0, run("dgst", "-" + opensslDigest, "-binary", "-out", hashFile.toString(),
                messageFile.toString()).exitCode);

        return run("pkeyutl", "-verify", "-pubin", "-inkey", pub.toString(),
                "-sigfile", signatureFile.toString(), "-in", hashFile.toString(),
                "-pkeyopt", "digest:" + opensslDigest,
                "-pkeyopt", "rsa_padding_mode:pss",
                "-pkeyopt", "rsa_pss_saltlen:digest",
                "-pkeyopt", "rsa_mgf1_md:" + opensslDigest);
    }

    private static Result run(String... args) throws IOException, InterruptedException {
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
