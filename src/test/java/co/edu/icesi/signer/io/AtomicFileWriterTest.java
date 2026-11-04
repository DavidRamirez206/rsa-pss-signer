package co.edu.icesi.signer.io;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

class AtomicFileWriterTest {

    private static final byte[] CONTENT = "content".getBytes(StandardCharsets.UTF_8);

    @TempDir
    Path dir;

    private List<String> names() throws IOException {
        try (Stream<Path> files = Files.list(dir)) {
            return files.map(file -> file.getFileName().toString()).sorted().toList();
        }
    }

    @Test
    void writesTheContentAndLeavesNoTemporaryFile() throws IOException {
        Path target = dir.resolve("out.bin");

        AtomicFileWriter.writePublic(target, CONTENT);

        assertArrayEquals(CONTENT, Files.readAllBytes(target));
        assertEquals(List.of("out.bin"), names());
    }

    @Test
    void writesEmptyAndLargeContent() throws IOException {
        byte[] large = new byte[3 * 1024 * 1024];
        large[large.length - 1] = 7;
        AtomicFileWriter.writePublic(dir.resolve("empty"), new byte[0]);
        AtomicFileWriter.writePrivate(dir.resolve("large"), large);

        assertEquals(0, Files.size(dir.resolve("empty")));
        assertArrayEquals(large, Files.readAllBytes(dir.resolve("large")));
    }

    @Test
    void relativePathsWork() throws IOException {
        // Inside the working directory: on Windows the temp folder may be on another drive
        Path target = Path.of("target", "relative-" + UUID.randomUUID() + ".bin");
        Files.createDirectories(target.getParent());
        try {
            AtomicFileWriter.writePublic(target, CONTENT);

            assertArrayEquals(CONTENT, Files.readAllBytes(target));
        } finally {
            Files.deleteIfExists(target);
        }
    }

    // T-5.7: an existing file, such as the input itself, is never replaced
    @Test
    void refusesToOverwriteAndKeepsTheOriginal() throws IOException {
        Path target = Files.writeString(dir.resolve("out.bin"), "original");

        assertThrows(FileAlreadyExistsException.class, () -> AtomicFileWriter.writePublic(target, CONTENT));
        assertThrows(FileAlreadyExistsException.class, () -> AtomicFileWriter.writePrivate(target, CONTENT));

        assertEquals("original", Files.readString(target));
        assertEquals(List.of("out.bin"), names());
    }

    @Test
    void missingDirectoryNamesTheDirectory() {
        Path missing = dir.resolve("missing");

        NoSuchFileException e = assertThrows(NoSuchFileException.class,
                () -> AtomicFileWriter.writePublic(missing.resolve("out.bin"), CONTENT));
        assertEquals(missing.toString(), e.getFile());
    }

    @Test
    void replaceSwapsTheContentAndLeavesNoTemporaryFile() throws IOException {
        Path target = Files.writeString(dir.resolve("out.sig"), "original");

        AtomicFileWriter.replacePublic(target, CONTENT);

        assertArrayEquals(CONTENT, Files.readAllBytes(target));
        assertEquals(List.of("out.sig"), names());
    }

    @Test
    void replaceAlsoCreatesAMissingFile() throws IOException {
        Path target = dir.resolve("out.sig");

        AtomicFileWriter.replacePublic(target, CONTENT);

        assertArrayEquals(CONTENT, Files.readAllBytes(target));
    }

    @Test
    void replaceRefusesADirectory() throws IOException {
        Path target = Files.createDirectory(dir.resolve("folder"));

        assertThrows(IOException.class, () -> AtomicFileWriter.replacePublic(target, CONTENT));

        assertTrue(Files.isDirectory(target));
    }

    // T-5.3
    @Test
    @DisabledOnOs(OS.WINDOWS)
    void replaceRefusesASymbolicLinkAndLeavesItsDestinationUntouched() throws IOException {
        Path victim = Files.writeString(dir.resolve("victim"), "original");
        Path link = Files.createSymbolicLink(dir.resolve("link"), victim);

        assertThrows(IOException.class, () -> AtomicFileWriter.replacePublic(link, CONTENT));

        assertEquals("original", Files.readString(victim));
        assertTrue(Files.isSymbolicLink(link));
    }

    // T-1.6
    @Test
    @DisabledOnOs(OS.WINDOWS)
    void privateFilesAreOwnerOnlyOnPosix() throws IOException {
        Path target = dir.resolve("secret");

        AtomicFileWriter.writePrivate(target, CONTENT);

        assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(target)));
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void publicFilesAreWorldReadableOnPosix() throws IOException {
        Path target = dir.resolve("public");

        AtomicFileWriter.writePublic(target, CONTENT);

        assertTrue(PosixFilePermissions.toString(Files.getPosixFilePermissions(target)).startsWith("rw-r--"));
    }

    // T-1.6
    @Test
    @EnabledOnOs(OS.WINDOWS)
    void privateFilesAreOwnerOnlyOnWindows() throws IOException {
        Path target = dir.resolve("secret");

        AtomicFileWriter.writePrivate(target, CONTENT);

        AclFileAttributeView view = Files.getFileAttributeView(target, AclFileAttributeView.class);
        List<AclEntry> acl = view.getAcl();
        assertEquals(1, acl.size(), acl.toString());
        assertEquals(view.getOwner(), acl.get(0).principal());
    }

    // T-5.3: writing through the link would change the file it points to
    @Test
    @DisabledOnOs(OS.WINDOWS)
    void symbolicLinkAsTargetLeavesItsDestinationUntouched() throws IOException {
        Path victim = Files.writeString(dir.resolve("victim"), "original");
        Path link = Files.createSymbolicLink(dir.resolve("link"), victim);

        assertThrows(FileAlreadyExistsException.class, () -> AtomicFileWriter.writePublic(link, CONTENT));

        assertEquals("original", Files.readString(victim));
        assertTrue(Files.isSymbolicLink(link));
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void danglingSymbolicLinkIsNotReplaced() throws IOException {
        Path victim = dir.resolve("not-created-yet");
        Path link = Files.createSymbolicLink(dir.resolve("link"), victim);

        assertThrows(FileAlreadyExistsException.class, () -> AtomicFileWriter.writePrivate(link, CONTENT));

        assertTrue(Files.notExists(victim));
    }
}
