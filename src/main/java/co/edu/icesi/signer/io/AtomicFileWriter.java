package co.edu.icesi.signer.io;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileSystemException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * Writes new files all at once: the content goes to a temporary file in the same
 * directory, which only takes the final name when it is complete. A failure halfway
 * never leaves a partial file under the final name, and an existing file or symbolic
 * link is never overwritten.
 *
 * <p>Permissions are set when the temporary file is created rather than changed
 * afterwards, so a private file is never readable by others, not even briefly.
 */
public final class AtomicFileWriter {

    private AtomicFileWriter() {
    }

    /** Writes a file only its owner can access: mode 600 on POSIX, an owner-only ACL on Windows. */
    public static void writePrivate(Path target, byte[] content) throws IOException {
        write(target, content, privateAttributes(target));
    }

    /** Writes a file holding no secrets: mode 644 on POSIX, default permissions elsewhere. */
    public static void writePublic(Path target, byte[] content) throws IOException {
        FileAttribute<?>[] attributes = supportsPosix(target)
                ? new FileAttribute<?>[] {PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-r--r--"))}
                : new FileAttribute<?>[0];
        write(target, content, attributes);
    }

    private static void write(Path target, byte[] content, FileAttribute<?>[] attributes) throws IOException {
        Path absolute = target.toAbsolutePath();
        Path directory = absolute.getParent();
        if (directory == null || !Files.isDirectory(directory)) {
            throw new NoSuchFileException(String.valueOf(directory));
        }
        requireAbsent(absolute, target);

        Path temp = directory.resolve("." + absolute.getFileName() + "." + UUID.randomUUID() + ".tmp");
        try {
            try (FileChannel channel = FileChannel.open(
                    temp, Set.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE), attributes)) {
                ByteBuffer buffer = ByteBuffer.wrap(content);
                while (buffer.hasRemaining()) {
                    channel.write(buffer);
                }
                channel.force(true);
            }
            publish(temp, absolute, target);
        } finally {
            Files.deleteIfExists(temp);
        }
    }

    /**
     * Gives the complete file its final name. {@code ATOMIC_MOVE} replaces an existing
     * target, so a hard link goes first: it is just as atomic but fails if the name is
     * taken. File systems without hard links fall back to the move.
     */
    private static void publish(Path temp, Path absolute, Path target) throws IOException {
        try {
            Files.createLink(absolute, temp);
        } catch (FileAlreadyExistsException e) {
            throw new FileAlreadyExistsException(target.toString());
        } catch (UnsupportedOperationException | FileSystemException e) {
            requireAbsent(absolute, target);
            Files.move(temp, absolute, StandardCopyOption.ATOMIC_MOVE);
        }
    }

    // NOFOLLOW_LINKS: a symbolic link counts as taken even if it points nowhere
    private static void requireAbsent(Path absolute, Path target) throws FileAlreadyExistsException {
        if (Files.exists(absolute, LinkOption.NOFOLLOW_LINKS)) {
            throw new FileAlreadyExistsException(target.toString());
        }
    }

    private static boolean supportsPosix(Path target) {
        return target.getFileSystem().supportedFileAttributeViews().contains("posix");
    }

    private static FileAttribute<?>[] privateAttributes(Path target) throws IOException {
        if (supportsPosix(target)) {
            Set<PosixFilePermission> ownerOnly = EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
            return new FileAttribute<?>[] {PosixFilePermissions.asFileAttribute(ownerOnly)};
        }
        if (target.getFileSystem().supportedFileAttributeViews().contains("acl")) {
            return new FileAttribute<?>[] {ownerOnlyAcl(target)};
        }
        throw new IOException("Cannot restrict file permissions on this file system");
    }

    private static FileAttribute<List<AclEntry>> ownerOnlyAcl(Path target) throws IOException {
        UserPrincipal owner = target.getFileSystem().getUserPrincipalLookupService()
                .lookupPrincipalByName(System.getProperty("user.name"));
        List<AclEntry> acl = List.of(AclEntry.newBuilder()
                .setType(AclEntryType.ALLOW)
                .setPrincipal(owner)
                .setPermissions(EnumSet.allOf(AclEntryPermission.class))
                .build());
        return new FileAttribute<>() {
            @Override
            public String name() {
                return "acl:acl";
            }

            @Override
            public List<AclEntry> value() {
                return acl;
            }
        };
    }
}
