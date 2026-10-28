package co.edu.icesi.signer.io;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Random;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class FileHasherTest {

    private static final int BLOCK = FileHasher.BUFFER_SIZE;

    @TempDir
    Path dir;

    // T-2.2: sizes around the buffer boundary hash exactly like an in-memory reference
    @ParameterizedTest
    @ValueSource(ints = {0, 1, BLOCK - 1, BLOCK, BLOCK + 1, 3 * BLOCK + 7})
    void fileHashMatchesInMemoryReference(int size) throws IOException {
        byte[] content = randomBytes(size);
        Path file = write(content);

        assertArrayEquals(sha256().digest(content), FileHasher.hash(file, sha256()));
    }

    @Test
    void emptyFileHasTheKnownSha256() throws IOException {
        Path file = write(new byte[0]);

        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                HexFormat.of().formatHex(FileHasher.hash(file, sha256())));
    }

    // T-2.2: appending or removing a single byte changes the hash
    @Test
    void appendedOrTruncatedBytesChangeTheHash() throws IOException {
        byte[] content = randomBytes(BLOCK + 1);
        byte[] original = FileHasher.hash(write(content), sha256());

        byte[] withNul = Arrays.copyOf(content, content.length + 1);
        byte[] withNewline = Arrays.copyOf(content, content.length + 1);
        withNewline[content.length] = '\n';
        byte[] truncated = Arrays.copyOf(content, content.length - 1);

        for (byte[] mutated : new byte[][] {withNul, withNewline, truncated}) {
            assertFalse(Arrays.equals(original, FileHasher.hash(write(mutated), sha256())));
        }
    }

    @Test
    void shortReadsAreHandledCorrectly() throws IOException {
        byte[] content = randomBytes(3 * BLOCK + 7);
        InputStream trickle = new TrickleInputStream(new ByteArrayInputStream(content));

        assertArrayEquals(sha256().digest(content), FileHasher.hash(trickle, sha256()));
    }

    @Test
    void previousDigestStateIsDiscarded() throws IOException {
        byte[] content = randomBytes(100);
        MessageDigest dirty = sha256();
        dirty.update(new byte[] {1, 2, 3});

        assertArrayEquals(sha256().digest(content), FileHasher.hash(new ByteArrayInputStream(content), dirty));
    }

    @Test
    void callerStreamIsNotClosed() throws IOException {
        CloseTrackingInputStream in = new CloseTrackingInputStream(new ByteArrayInputStream(randomBytes(10)));

        FileHasher.hash(in, sha256());

        assertFalse(in.closed);
    }

    @Test
    void missingFileThrows() {
        assertThrows(NoSuchFileException.class, () -> FileHasher.hash(dir.resolve("missing.txt"), sha256()));
    }

    private Path write(byte[] content) throws IOException {
        return Files.write(Files.createTempFile(dir, "input", ".bin"), content);
    }

    private static byte[] randomBytes(int size) {
        byte[] bytes = new byte[size];
        new Random(size).nextBytes(bytes);
        return bytes;
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Returns at most 3 bytes per read, like a slow pipe or network stream. */
    private static final class TrickleInputStream extends FilterInputStream {
        TrickleInputStream(InputStream in) {
            super(in);
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            return super.read(b, off, Math.min(len, 3));
        }
    }

    private static final class CloseTrackingInputStream extends FilterInputStream {
        boolean closed;

        CloseTrackingInputStream(InputStream in) {
            super(in);
        }

        @Override
        public void close() throws IOException {
            closed = true;
            super.close();
        }
    }
}
