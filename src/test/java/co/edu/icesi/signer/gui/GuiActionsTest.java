package co.edu.icesi.signer.gui;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import co.edu.icesi.signer.core.VerificationResult;
import co.edu.icesi.signer.crypto.HashAlg;
import co.edu.icesi.signer.gui.GuiActions.ActionFailure;
import co.edu.icesi.signer.gui.GuiActions.GeneratedKeys;
import co.edu.icesi.signer.keystore.PrivateKeyStore;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class GuiActionsTest {

    private static final String PASSWORD = "correct horse battery";
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-10-28T11:30:00Z"), ZoneOffset.UTC);

    private final GuiActions actions = new GuiActions(new PrivateKeyStore(1000), CLOCK);

    @TempDir
    Path dir;

    @BeforeEach
    void startInEnglish() {
        I18n.use(I18n.Language.ENGLISH);
    }

    private char[] password() {
        return PASSWORD.toCharArray();
    }

    private String path(String name) {
        return dir.resolve(name).toString();
    }

    private GeneratedKeys generate(String name) throws ActionFailure {
        return actions.generateKeys(path(name), 2048, password(), password());
    }

    private void assertFails(String expected, org.junit.jupiter.api.function.Executable action) {
        ActionFailure e = assertThrows(ActionFailure.class, action);
        assertTrue(e.getMessage().contains(expected), e.getMessage());
    }

    @Test
    void generatesSignsAndVerifies() throws Exception {
        GeneratedKeys keys = generate("ana");
        Path file = Files.writeString(dir.resolve("contract.txt"), "content");

        GuiActions.Signature signature = actions.sign(
                file.toString(), keys.privateKey().toString(), "Ana Perez", HashAlg.SHA_256, password());

        assertEquals(dir.resolve("contract.txt.sig"), signature.file());
        assertEquals(keys.fingerprint(), signature.fingerprint());
        assertEquals(VerificationResult.VALID, actions.verify(
                file.toString(), signature.file().toString(), keys.publicKey().toString()).result());
    }

    @Test
    void modifiedFileIsInvalid() throws Exception {
        GeneratedKeys keys = generate("ana");
        Path file = Files.writeString(dir.resolve("contract.txt"), "content");
        GuiActions.Signature signature = actions.sign(
                file.toString(), keys.privateKey().toString(), "Ana Perez", HashAlg.SHA_256, password());
        Files.writeString(file, "changed");

        assertEquals(VerificationResult.INVALID, actions.verify(
                file.toString(), signature.file().toString(), keys.publicKey().toString()).result());
    }

    // Only the bytes count: undoing a change exactly makes the signature valid again
    @Test
    void undoingAChangeExactlyIsValidAgain() throws Exception {
        GeneratedKeys keys = generate("ana");
        Path file = Files.writeString(dir.resolve("contract.txt"), "content");
        GuiActions.Signature signature = actions.sign(
                file.toString(), keys.privateKey().toString(), "Ana Perez", HashAlg.SHA_256, password());
        String sig = signature.file().toString();
        String pub = keys.publicKey().toString();

        Files.writeString(file, "contents");
        assertEquals(VerificationResult.INVALID, actions.verify(file.toString(), sig, pub).result());

        Files.writeString(file, "content");
        assertEquals(VerificationResult.VALID, actions.verify(file.toString(), sig, pub).result());
    }

    // What an editor may do on save, without showing it
    @ParameterizedTest
    @ValueSource(strings = {"content\n", "content\r\n", "\uFEFFcontent"})
    void invisibleChangesAreChangesToo(String saved) throws Exception {
        GeneratedKeys keys = generate("ana");
        Path file = Files.writeString(dir.resolve("contract.txt"), "content");
        GuiActions.Signature signature = actions.sign(
                file.toString(), keys.privateKey().toString(), "Ana Perez", HashAlg.SHA_256, password());

        Files.writeString(file, saved);

        assertEquals(VerificationResult.INVALID, actions.verify(
                file.toString(), signature.file().toString(), keys.publicKey().toString()).result());
    }

    // T-1.5: passwords are cleared on success and on failure
    @Test
    void generatingClearsBothPasswords() throws Exception {
        char[] first = password();
        char[] second = password();

        actions.generateKeys(path("ana"), 2048, first, second);

        assertArrayEquals(new char[first.length], first);
        assertArrayEquals(new char[second.length], second);
    }

    @Test
    void rejectedPasswordsAreClearedToo() {
        char[] first = password();
        char[] second = "something else entirely".toCharArray();

        assertFails("do not match", () -> actions.generateKeys(path("ana"), 2048, first, second));

        assertArrayEquals(new char[first.length], first);
        assertArrayEquals(new char[second.length], second);
    }

    @Test
    void signingClearsThePasswordEvenWhenItIsWrong() throws Exception {
        GeneratedKeys keys = generate("ana");
        Path file = Files.writeString(dir.resolve("contract.txt"), "content");
        char[] wrong = "not the right password".toCharArray();

        assertFails("Wrong password", () -> actions.sign(
                file.toString(), keys.privateKey().toString(), "Ana", HashAlg.SHA_256, wrong));

        assertArrayEquals(new char[wrong.length], wrong);
        assertTrue(Files.notExists(dir.resolve("contract.txt.sig")));
    }

    // T-1.1b
    @Test
    void shortPasswordIsRejectedAndNothingIsWritten() {
        assertFails("at least 12", () -> actions.generateKeys(
                path("ana"), 2048, "elevenchars".toCharArray(), "elevenchars".toCharArray()));

        assertTrue(Files.notExists(dir.resolve("ana.key")));
    }

    @Test
    void existingKeysAreNeverOverwritten() throws Exception {
        generate("ana");
        byte[] before = Files.readAllBytes(dir.resolve("ana.key"));

        assertFails("Nothing was overwritten", () -> generate("ana"));

        assertArrayEquals(before, Files.readAllBytes(dir.resolve("ana.key")));
    }

    @Test
    void existingPublicKeyLeavesNoPrivateKeyBehind() throws Exception {
        Files.writeString(dir.resolve("ana.pub"), "taken");

        assertFails("Nothing was overwritten", () -> generate("ana"));

        assertTrue(Files.notExists(dir.resolve("ana.key")));
    }

    @Test
    void existingSignatureIsNeverOverwritten() throws Exception {
        GeneratedKeys keys = generate("ana");
        Path file = Files.writeString(dir.resolve("contract.txt"), "content");
        Files.writeString(dir.resolve("contract.txt.sig"), "original");

        assertFails("Nothing was overwritten", () -> actions.sign(
                file.toString(), keys.privateKey().toString(), "Ana", HashAlg.SHA_256, password()));

        assertEquals("original", Files.readString(dir.resolve("contract.txt.sig")));
    }

    @Test
    void agreedOverwriteReplacesTheSignatureWithAWorkingOne() throws Exception {
        GeneratedKeys keys = generate("ana");
        Path file = Files.writeString(dir.resolve("contract.txt"), "content");
        Path sig = Files.writeString(dir.resolve("contract.txt.sig"), "old");
        assertTrue(actions.signatureExists(file.toString()));

        actions.sign(file.toString(), keys.privateKey().toString(), "Ana", HashAlg.SHA_256, password(), true);

        assertEquals(VerificationResult.VALID, actions.verify(
                file.toString(), sig.toString(), keys.publicKey().toString()).result());
    }

    @Test
    void signatureExistsIsFalseWithoutOne() throws Exception {
        Path file = Files.writeString(dir.resolve("contract.txt"), "content");

        assertFalse(actions.signatureExists(file.toString()));
        assertFalse(actions.signatureExists(" "));
    }

    // Signing "ana" with the key "ana.sig" would otherwise destroy the key
    @Test
    void overwriteNeverDestroysThePrivateKey() throws Exception {
        GeneratedKeys keys = generate("ana");
        Path file = Files.writeString(dir.resolve("doc"), "content");
        Path key = Files.move(keys.privateKey(), dir.resolve("doc.sig"));
        byte[] before = Files.readAllBytes(key);

        assertFails("private key", () -> actions.sign(
                file.toString(), key.toString(), "Ana", HashAlg.SHA_256, password(), true));

        assertArrayEquals(before, Files.readAllBytes(key));
    }

    @Test
    void failedSigningKeepsTheOldSignature() throws Exception {
        GeneratedKeys keys = generate("ana");
        Path file = Files.writeString(dir.resolve("contract.txt"), "content");
        Path sig = Files.writeString(dir.resolve("contract.txt.sig"), "old");

        assertFails("Wrong password", () -> actions.sign(file.toString(), keys.privateKey().toString(), "Ana",
                HashAlg.SHA_256, "not the right password".toCharArray(), true));

        assertEquals("old", Files.readString(sig));
    }

    @Test
    void emptyFieldsAskForWhatIsMissing() {
        assertFails("Choose where", () -> actions.generateKeys(" ", 2048, password(), password()));
        assertFails("Choose the file", () -> actions.sign("", "key", "Ana", HashAlg.SHA_256, password()));
        assertFails("signer", () -> actions.sign("file", "key", " ", HashAlg.SHA_256, password()));
        assertFails("Choose the file", () -> actions.verify("", "sig", "pub"));
    }

    @Test
    void missingFileNamesIt() throws Exception {
        GeneratedKeys keys = generate("ana");

        assertFails("File not found", () -> actions.sign(
                path("missing.txt"), keys.privateKey().toString(), "Ana", HashAlg.SHA_256, password()));
    }

    @Test
    void signerWithAControlCharacterIsRejected() throws Exception {
        GeneratedKeys keys = generate("ana");
        Path file = Files.writeString(dir.resolve("contract.txt"), "content");

        assertFails("control characters", () -> actions.sign(
                file.toString(), keys.privateKey().toString(), "Ana\nhashAlg=MD5", HashAlg.SHA_256, password()));
    }

    @Test
    void verifyingMissingFilesIsAnErrorNotAFailure() throws Exception {
        assertEquals(VerificationResult.ERROR,
                actions.verify(path("a"), path("b"), path("c")).result());
    }
}
