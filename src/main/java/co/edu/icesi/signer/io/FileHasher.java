package co.edu.icesi.signer.io;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;

/**
 * Hashes files by streaming them in fixed-size blocks, so memory use stays
 * constant regardless of file size (never {@code Files.readAllBytes}).
 *
 * <p>Takes a plain {@link MessageDigest} so that I/O stays independent of the
 * crypto package; callers choose the algorithm.
 */
public final class FileHasher {

    static final int BUFFER_SIZE = 8192;

    private FileHasher() {
    }

    /** Hashes the whole file. */
    public static byte[] hash(Path file, MessageDigest digest) throws IOException {
        try (InputStream in = Files.newInputStream(file)) {
            return hash(in, digest);
        }
    }

    /**
     * Hashes everything left in the stream. The stream is read to the end but not
     * closed; any previous state in {@code digest} is discarded.
     */
    public static byte[] hash(InputStream in, MessageDigest digest) throws IOException {
        digest.reset();
        byte[] buffer = new byte[BUFFER_SIZE];
        int read;
        while ((read = in.read(buffer)) != -1) {
            digest.update(buffer, 0, read);
        }
        return digest.digest();
    }
}
