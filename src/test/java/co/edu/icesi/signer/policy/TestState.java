package co.edu.icesi.signer.policy;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;

/** Local state for tests, so they never touch the user's real trust store. */
public final class TestState {

    private TestState() {
    }

    /** A new, empty state directory under {@code target}, removed by {@code mvn clean}. */
    public static LocalState fresh() {
        try {
            Path base = Files.createDirectories(Path.of("target", "test-state"));
            return new LocalState(Files.createTempDirectory(base, "state-"));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
