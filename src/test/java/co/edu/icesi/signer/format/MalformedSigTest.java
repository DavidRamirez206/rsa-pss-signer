package co.edu.icesi.signer.format;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import co.edu.icesi.signer.core.VerificationOutcome;
import co.edu.icesi.signer.core.VerificationResult;
import co.edu.icesi.signer.crypto.KeyPairService;
import co.edu.icesi.signer.crypto.VerificationService;
import co.edu.icesi.signer.keystore.PublicKeyStore;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.List;
import java.util.Objects;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/** T-3.2: each file in {@code resources/malformed} breaks the format in one way. */
class MalformedSigTest {

    private static final KeyPair KEY = KeyPairService.generate(2048);

    @TempDir
    Path dir;

    static List<Path> malformedFiles() throws IOException, URISyntaxException {
        Path folder = Path.of(Objects.requireNonNull(MalformedSigTest.class.getResource("/malformed")).toURI());
        try (Stream<Path> files = Files.list(folder)) {
            return files.sorted().toList();
        }
    }

    @Test
    void thereAreEnoughFixtures() throws Exception {
        assertTrue(malformedFiles().size() >= 15, "found " + malformedFiles().size());
    }

    @ParameterizedTest
    @MethodSource("malformedFiles")
    void parsingRejectsTheFile(Path fixture) throws IOException {
        byte[] content = Files.readAllBytes(fixture);

        SigValidationException e = assertThrows(SigValidationException.class, () -> SigFile.parse(content));
        assertFalse(e.getMessage().isBlank());
    }

    @ParameterizedTest
    @MethodSource("malformedFiles")
    void verificationGivesError(Path fixture) throws Exception {
        Path file = Files.writeString(dir.resolve("contract.txt"), "content");
        Path pub = dir.resolve("ana.pub");
        PublicKeyStore.write(KEY.getPublic(), pub);

        VerificationOutcome outcome = VerificationService.verify(file, fixture, pub);

        assertEquals(VerificationResult.ERROR, outcome.result(), outcome.detail());
    }

}
