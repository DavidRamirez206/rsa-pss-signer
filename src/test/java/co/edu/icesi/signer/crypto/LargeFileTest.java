package co.edu.icesi.signer.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import co.edu.icesi.signer.core.VerificationOutcome;
import co.edu.icesi.signer.core.VerificationResult;
import co.edu.icesi.signer.format.SigFile;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * T-5.2: a 3 GB file signs and verifies with a 256 MB heap, which only works if the
 * file is streamed. The work runs in a separate JVM because a test cannot lower the
 * heap of the JVM it runs in.
 */
@Tag("slow")
class LargeFileTest {

    private static final long SIZE = 3L * 1024 * 1024 * 1024;

    @Test
    void largeFileSignsAndVerifiesWithASmallHeap(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("large.bin");
        try (RandomAccessFile out = new RandomAccessFile(file.toFile(), "rw")) {
            out.setLength(SIZE);
        }
        Path log = dir.resolve("child.log");

        Process child = new ProcessBuilder(
                Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "-Xmx256m",
                "-cp", System.getProperty("java.class.path"),
                Child.class.getName(),
                file.toString())
                .redirectErrorStream(true)
                .redirectOutput(log.toFile())
                .start();

        assertTrue(child.waitFor(10, TimeUnit.MINUTES), "timed out");
        String output = Files.readString(log, StandardCharsets.UTF_8);
        assertEquals(0, child.exitValue(), output);
        assertTrue(output.contains(VerificationResult.VALID.name()), output);
    }

    /** Runs in the small-heap JVM. */
    static final class Child {
        public static void main(String[] args) throws IOException, java.security.GeneralSecurityException {
            Path file = Path.of(args[0]);
            KeyPair keyPair = KeyPairService.generate(2048);
            SigFile sig = SigningService.sign(file, (RSAPrivateCrtKey) keyPair.getPrivate(), HashAlg.SHA_256,
                    "Ana Perez", "2026-10-28T11:30:00-05:00");
            VerificationOutcome outcome = VerificationService.verify(file, sig, (RSAPublicKey) keyPair.getPublic());
            System.out.println(outcome.result());
        }
    }
}
