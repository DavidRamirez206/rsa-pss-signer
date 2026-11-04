package co.edu.icesi.signer.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

import co.edu.icesi.signer.core.VerificationOutcome;
import co.edu.icesi.signer.core.VerificationResult;
import co.edu.icesi.signer.format.SigFile;
import co.edu.icesi.signer.keystore.PrivateKeyStore;
import co.edu.icesi.signer.keystore.PublicKeyStore;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateCrtKey;
import java.time.Duration;
import java.util.Arrays;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** T-3.4 and T-5.6: unusual paths end in ERROR, quickly, and never hang the program. */
class HostileInputTest {

    private static final String SIGNED_AT = "2026-10-28T11:30:00-05:00";
    private static final char[] PASSWORD = "correct horse battery".toCharArray();

    private static KeyPair keyPair;

    @TempDir
    Path dir;

    private Path file;
    private Path sig;
    private Path pub;

    @BeforeAll
    static void generateKeys() {
        keyPair = KeyPairService.generate(2048);
    }

    @BeforeEach
    void createValidInputs() throws Exception {
        file = Files.writeString(dir.resolve("contract.txt"), "The parties agree to the terms.");
        sig = Files.write(dir.resolve("contract.sig"), SigningService.sign(
                file, (RSAPrivateCrtKey) keyPair.getPrivate(), HashAlg.SHA_256, "Ana Perez", SIGNED_AT).toJson());
        pub = dir.resolve("ana.pub");
        PublicKeyStore.write(keyPair.getPublic(), pub);
    }

    private void assertError(Path file, Path sig, Path pub) {
        VerificationOutcome outcome = VerificationService.verify(file, sig, pub);
        assertEquals(VerificationResult.ERROR, outcome.result(), outcome.detail());
    }


    private void assertErrorInEachRole(Path hostile) {
        assertError(hostile, sig, pub);
        assertError(file, hostile, pub);
        assertError(file, sig, hostile);
    }

    @Test
    void validInputsAreValid() {
        assertEquals(VerificationResult.VALID, VerificationService.verify(file, sig, pub).result());
    }

    @Test
    void missingPathIsAnError() {
        assertErrorInEachRole(dir.resolve("missing"));
    }

    @Test
    void directoryIsAnError() {
        assertErrorInEachRole(dir);
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void unreadableFileIsAnError() throws IOException {
        Path hidden = Files.writeString(dir.resolve("hidden"), "secret");
        Files.setPosixFilePermissions(hidden, PosixFilePermissions.fromString("---------"));
        assumeFalse(Files.isReadable(hidden), "running as root, which ignores permissions");

        assertErrorInEachRole(hidden);
    }

    // Opening a FIFO with no writer blocks forever, so these fail by timing out
    @Test
    @DisabledOnOs(OS.WINDOWS)
    void fifoIsAnErrorWithoutBlocking() throws Exception {
        Path fifo = dir.resolve("fifo");
        assertEquals(0, new ProcessBuilder("mkfifo", fifo.toString()).start().waitFor());

        assertTimeoutPreemptively(Duration.ofSeconds(10), () -> assertErrorInEachRole(fifo));
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void signingAFifoFailsWithoutBlocking() throws Exception {
        Path fifo = dir.resolve("fifo");
        assertEquals(0, new ProcessBuilder("mkfifo", fifo.toString()).start().waitFor());

        assertTimeoutPreemptively(Duration.ofSeconds(10), () -> assertThrows(IOException.class, () -> SigningService.sign(
                fifo, (RSAPrivateCrtKey) keyPair.getPrivate(), HashAlg.SHA_256, "Ana Perez", SIGNED_AT)));
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void readingAPrivateKeyFromAFifoFailsWithoutBlocking() throws Exception {
        Path fifo = dir.resolve("fifo");
        assertEquals(0, new ProcessBuilder("mkfifo", fifo.toString()).start().waitFor());

        assertTimeoutPreemptively(Duration.ofSeconds(10),
                () -> assertThrows(IOException.class, () -> new PrivateKeyStore().read(fifo, PASSWORD)));
    }

    // T-3.4: sparse, so the test itself is fast; reading it all would take far longer
    @ParameterizedTest
    @ValueSource(strings = {"sig", "pub"})
    void hugeFileIsRejectedWithoutReadingIt(String role) throws Exception {
        Path huge = dir.resolve("huge");
        try (RandomAccessFile out = new RandomAccessFile(huge.toFile(), "rw")) {
            out.setLength(100L * 1024 * 1024);
        }
        Path sigInput = role.equals("sig") ? huge : sig;
        Path pubInput = role.equals("pub") ? huge : pub;

        VerificationOutcome outcome = assertTimeoutPreemptively(Duration.ofSeconds(1),
                () -> VerificationService.verify(file, sigInput, pubInput));

        assertEquals(VerificationResult.ERROR, outcome.result());
        assertTrue(outcome.detail().contains("limit"), outcome.detail());
    }

    @Test
    void sigOfExactlyTheLimitIsRead() throws Exception {
        byte[] json = Files.readAllBytes(sig);
        Path padded = dir.resolve("padded.sig");
        // Trailing spaces are valid JSON, so only the size differs
        Files.write(padded, pad(json, Math.toIntExact(SigFile.MAX_FILE_SIZE)));

        assertEquals(VerificationResult.VALID, VerificationService.verify(file, padded, pub).result());
    }

    @Test
    void sigOneByteOverTheLimitIsRejected() throws Exception {
        byte[] json = Files.readAllBytes(sig);
        Path padded = dir.resolve("padded.sig");
        Files.write(padded, pad(json, Math.toIntExact(SigFile.MAX_FILE_SIZE) + 1));

        VerificationOutcome outcome = VerificationService.verify(file, padded, pub);
        assertEquals(VerificationResult.ERROR, outcome.result());
        assertTrue(outcome.detail().contains("limit"), outcome.detail());
    }

    private static byte[] pad(byte[] json, int size) {
        byte[] padded = new byte[size];
        Arrays.fill(padded, (byte) ' ');
        System.arraycopy(json, 0, padded, 0, json.length);
        return padded;
    }
}
