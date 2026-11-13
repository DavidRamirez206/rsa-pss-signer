package co.edu.icesi.signer.policy;

import co.edu.icesi.signer.io.AtomicFileWriter;
import co.edu.icesi.signer.io.SafeFileReader;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.Properties;

/**
 * The directory where this machine remembers trusted keys and document versions:
 * {@code RSA_PSS_SIGNER_HOME} if set, otherwise {@code .rsa-pss-signer} in the user's home.
 * What it remembers holds only on this machine: that is the limit of local state.
 */
public final class LocalState {

    /** Far above any realistic number of signers and documents. */
    private static final long MAX_FILE_SIZE = 1024 * 1024;

    private final Path directory;

    public LocalState(Path directory) {
        this.directory = directory;
    }

    /** The directory from the environment, or the default one in the user's home. */
    public static LocalState fromEnvironment() {
        String override = System.getenv("RSA_PSS_SIGNER_HOME");
        if (override != null && !override.isBlank()) {
            return new LocalState(Path.of(override));
        }
        return new LocalState(Path.of(System.getProperty("user.home"), ".rsa-pss-signer"));
    }

    public Path directory() {
        return directory;
    }

    Properties load(String name) throws IOException {
        Properties properties = new Properties();
        Path file = directory.resolve(name);
        if (Files.exists(file, LinkOption.NOFOLLOW_LINKS)) {
            byte[] content = SafeFileReader.read(file, MAX_FILE_SIZE);
            properties.load(new StringReader(new String(content, StandardCharsets.UTF_8)));
        }
        return properties;
    }

    void save(String name, Properties properties, String comment) throws IOException {
        Files.createDirectories(directory);
        StringWriter text = new StringWriter();
        properties.store(text, comment);
        AtomicFileWriter.replacePublic(directory.resolve(name), text.toString().getBytes(StandardCharsets.UTF_8));
    }
}
