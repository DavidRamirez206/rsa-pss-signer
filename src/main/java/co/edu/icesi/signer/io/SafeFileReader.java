package co.edu.icesi.signer.io;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;

/**
 * Reads files named on the command line, which may be anything. Only regular files
 * are opened, because opening a FIFO blocks forever and a device like
 * {@code /dev/zero} never ends. Small files have a size limit, checked before reading.
 */
public final class SafeFileReader {

    private SafeFileReader() {
    }

    /**
     * Reads a whole regular file of at most {@code maxBytes} bytes.
     *
     * @throws IOException if the file is missing, not a regular file or too large
     */
    public static byte[] read(Path file, long maxBytes) throws IOException {
        BasicFileAttributes attributes = requireRegularFile(file);
        if (attributes.size() > maxBytes) {
            throw tooLarge(file, maxBytes);
        }
        // The file may grow after the check: never read more than the limit
        try (InputStream in = Files.newInputStream(file)) {
            byte[] content = in.readNBytes(Math.toIntExact(maxBytes + 1));
            if (content.length > maxBytes) {
                throw tooLarge(file, maxBytes);
            }
            return content;
        }
    }

    /**
     * Checks that a path names a regular file, following symbolic links.
     *
     * @throws IOException if it is missing or anything else, such as a directory or FIFO
     */
    public static BasicFileAttributes requireRegularFile(Path file) throws IOException {
        BasicFileAttributes attributes = Files.readAttributes(file, BasicFileAttributes.class);
        if (!attributes.isRegularFile()) {
            throw new IOException(file + " is not a regular file");
        }
        return attributes;
    }

    private static IOException tooLarge(Path file, long maxBytes) {
        return new IOException(file + " is larger than the limit of " + maxBytes + " bytes");
    }
}
