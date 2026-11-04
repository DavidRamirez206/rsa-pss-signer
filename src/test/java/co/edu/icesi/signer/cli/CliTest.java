package co.edu.icesi.signer.cli;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import co.edu.icesi.signer.format.SigFile;
import co.edu.icesi.signer.keystore.PrivateKeyStore;
import co.edu.icesi.signer.keystore.PublicKeyStore;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class CliTest {

    private static final String PASSWORD = "a long test password";
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-10-28T16:30:00Z"), ZoneOffset.ofHours(-5));

    private final Deque<String> typedPasswords = new ArrayDeque<>();
    private final List<char[]> handedOutPasswords = new ArrayList<>();
    private final ByteArrayOutputStream stdout = new ByteArrayOutputStream();
    private final ByteArrayOutputStream stderr = new ByteArrayOutputStream();

    @TempDir
    Path dir;

    private Cli cli;
    private Path contract;

    @BeforeEach
    void setUp() throws IOException {
        contract = Files.writeString(dir.resolve("contract.txt"), "The parties agree to the terms.");
        PasswordProvider spy = prompt -> {
            if (typedPasswords.isEmpty()) {
                throw new IOException("No password was entered");
            }
            char[] password = typedPasswords.pop().toCharArray();
            handedOutPasswords.add(password);
            return password;
        };
        cli = new Cli(spy, new PrintStream(stdout, true, StandardCharsets.UTF_8),
                new PrintStream(stderr, true, StandardCharsets.UTF_8), new PrivateKeyStore(1000), CLOCK);
    }

    private int run(String... args) {
        return cli.run(args);
    }

    private String out() {
        return stdout.toString(StandardCharsets.UTF_8);
    }

    private String err() {
        return stderr.toString(StandardCharsets.UTF_8);
    }

    private String path(String name) {
        return dir.resolve(name).toString();
    }

    private void generateKeys(String base) {
        typedPasswords.add(PASSWORD);
        typedPasswords.add(PASSWORD);
        assertEquals(0, run("keygen", "--out", path(base), "--bits", "2048"), err());
    }

    private void signContract() {
        typedPasswords.add(PASSWORD);
        assertEquals(0, run("sign", contract.toString(), "--key", path("ana.key"), "--signer", "Ana Perez"), err());
    }

    private int verifyContract(String pub) {
        return run("verify", contract.toString(), "--sig", contract + ".sig", "--pub", path(pub));
    }

    @Test
    void keygenWritesBothFilesAndShowsTheFingerprint() throws Exception {
        generateKeys("ana");

        assertTrue(Files.readString(dir.resolve("ana.key")).startsWith("-----BEGIN ENCRYPTED PRIVATE KEY-----"));
        assertTrue(Files.readString(dir.resolve("ana.pub")).startsWith("-----BEGIN PUBLIC KEY-----"));
        assertTrue(out().matches("(?s).*Fingerprint: [0-9A-F]{2}(:[0-9A-F]{2}){31}.*"), out());
        assertEquals(2048, PublicKeyStore.read(dir.resolve("ana.pub")).getModulus().bitLength());
    }

    @Test
    void keygenDefaultsTo3072Bits() throws Exception {
        typedPasswords.add(PASSWORD);
        typedPasswords.add(PASSWORD);

        assertEquals(0, run("keygen", "--out", path("ana")), err());

        RSAPublicKey key = PublicKeyStore.read(dir.resolve("ana.pub"));
        assertEquals(3072, key.getModulus().bitLength());
    }

    // T-1.1b: password policy
    @Test
    void keygenRejectsAShortPassword() {
        typedPasswords.add("short");

        assertEquals(2, run("keygen", "--out", path("ana"), "--bits", "2048"));

        assertTrue(err().contains("at least 12"), err());
        assertFalse(Files.exists(dir.resolve("ana.key")));
        assertFalse(Files.exists(dir.resolve("ana.pub")));
    }

    @Test
    void keygenRejectsAMismatchedConfirmation() {
        typedPasswords.add(PASSWORD);
        typedPasswords.add(PASSWORD + "x");

        assertEquals(2, run("keygen", "--out", path("ana"), "--bits", "2048"));

        assertFalse(Files.exists(dir.resolve("ana.key")));
    }

    @ParameterizedTest
    @ValueSource(strings = {"1024", "2047", "abc", ""})
    void keygenRejectsDisallowedSizes(String bits) {
        assertEquals(2, run("keygen", "--out", path("ana"), "--bits", bits));

        assertFalse(Files.exists(dir.resolve("ana.key")));
    }

    @Test
    void keygenNeverOverwritesAndLeavesNoHalfPair() throws IOException {
        Path existingPub = Files.writeString(dir.resolve("ana.pub"), "existing");

        assertEquals(2, run("keygen", "--out", path("ana"), "--bits", "2048"));

        assertEquals("existing", Files.readString(existingPub));
        assertFalse(Files.exists(dir.resolve("ana.key")));
        assertTrue(handedOutPasswords.isEmpty(), "should fail before asking for a password");
    }

    @Test
    void signThenVerifyIsValid() throws Exception {
        generateKeys("ana");
        signContract();

        assertEquals(0, verifyContract("ana.pub"), out() + err());

        assertTrue(out().contains("VALID"), out());
        assertTrue(out().contains("Key fingerprint:"), out());
    }

    @Test
    void signRecordsTheDeclaredDateWithSecondsAndOffset() throws Exception {
        generateKeys("ana");
        signContract();

        SigFile sig = SigFile.parse(Files.readAllBytes(Path.of(contract + ".sig")));

        assertEquals("2026-10-28T11:30:00-05:00", sig.header().signedAt());
        assertEquals("contract.txt", sig.header().fileName());
        assertEquals("Ana Perez", sig.header().signerName());
    }

    @ParameterizedTest
    @ValueSource(strings = {"SHA-256", "SHA-512", "SHA3-256", "SHA3-512"})
    void signAcceptsEveryAllowedHash(String hash) throws Exception {
        generateKeys("ana");
        typedPasswords.add(PASSWORD);

        assertEquals(0, run("sign", contract.toString(), "--key", path("ana.key"), "--signer", "Ana",
                "--hash", hash, "--out", path("custom.sig")), err());

        assertEquals(0, run("verify", contract.toString(), "--sig", path("custom.sig"), "--pub", path("ana.pub")));
    }

    // T-2.7: downgrade from the command line
    @ParameterizedTest
    @ValueSource(strings = {"MD5", "SHA-1", "NONE", "sha-256"})
    void signRejectsHashesOutsideTheAllowlist(String hash) {
        generateKeys("ana");

        assertEquals(2, run("sign", contract.toString(), "--key", path("ana.key"), "--signer", "Ana", "--hash", hash));

        assertFalse(Files.exists(Path.of(contract + ".sig")));
    }

    @Test
    void signWithTheWrongPasswordIsAControlledError() {
        generateKeys("ana");
        typedPasswords.add("wrong password here");

        assertEquals(2, run("sign", contract.toString(), "--key", path("ana.key"), "--signer", "Ana"));

        assertTrue(err().contains("Wrong password"), err());
        assertFalse(err().contains("Exception"), err());
        assertFalse(Files.exists(Path.of(contract + ".sig")));
    }

    @Test
    void signRejectsControlCharactersInTheSignerName() {
        generateKeys("ana");
        typedPasswords.add(PASSWORD);

        assertEquals(2, run("sign", contract.toString(), "--key", path("ana.key"), "--signer", "Ana\nX"));

        assertFalse(Files.exists(Path.of(contract + ".sig")));
    }

    @Test
    void signDoesNotOverwriteAnExistingSignature() throws IOException {
        generateKeys("ana");
        Path existing = Files.writeString(Path.of(contract + ".sig"), "existing");
        typedPasswords.add(PASSWORD);

        assertEquals(2, run("sign", contract.toString(), "--key", path("ana.key"), "--signer", "Ana"));

        assertEquals("existing", Files.readString(existing));
    }

    // T-4.3: exit codes across good and bad input
    @Test
    void modifiedFileExitsWithOne() throws IOException {
        generateKeys("ana");
        signContract();
        Files.writeString(contract, "Altered terms.");

        assertEquals(1, verifyContract("ana.pub"));
        assertTrue(out().contains("INVALID"), out());
    }

    @Test
    void editedSignerNameExitsWithOne() throws IOException {
        generateKeys("ana");
        signContract();
        Path sig = Path.of(contract + ".sig");
        Files.writeString(sig, Files.readString(sig).replace("Ana Perez", "Professor X"));

        assertEquals(1, verifyContract("ana.pub"));
    }

    @Test
    void otherKeyExitsWithTwoAndNamesTheSigningKey() {
        generateKeys("ana");
        generateKeys("mallory");
        signContract();

        assertEquals(2, verifyContract("mallory.pub"));
        assertTrue(out().contains("This signature was made with key"), out());
    }

    @Test
    void malformedSignatureFileExitsWithTwo() throws IOException {
        generateKeys("ana");
        Files.writeString(Path.of(contract + ".sig"), "not json");

        assertEquals(2, verifyContract("ana.pub"));
    }

    @Test
    void missingInputsExitWithTwo() {
        generateKeys("ana");

        assertEquals(2, verifyContract("ana.pub"));
        assertEquals(2, run("verify", path("missing.txt"), "--sig", path("x.sig"), "--pub", path("ana.pub")));
        typedPasswords.add(PASSWORD);
        assertEquals(2, run("sign", path("missing.txt"), "--key", path("ana.key"), "--signer", "Ana"));
        typedPasswords.add(PASSWORD);
        assertEquals(2, run("sign", contract.toString(), "--key", path("missing.key"), "--signer", "Ana"));
    }

    @Test
    void passwordUnavailableExitsWithTwo() {
        assertEquals(2, run("keygen", "--out", path("ana"), "--bits", "2048"));
        assertTrue(err().contains("No password"), err());
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "", "unknown", "keygen", "sign", "verify", "keygen --bogus 1", "keygen --out", "keygen extra --out x",
        "sign a.txt", "sign a.txt --key k", "verify a.txt", "verify a.txt --sig s", "verify a.txt b.txt --sig s --pub p",
        "verify a.txt --sig s --sig t --pub p"
    })
    void usageErrorsExitWithTwo(String commandLine) {
        String[] args = commandLine.isEmpty() ? new String[0] : commandLine.split(" ");

        assertEquals(2, cli.run(args));

        assertTrue(err().contains("Usage:"), err());
    }

    @Test
    void helpExitsWithZero() {
        assertEquals(0, run("--help"));
        assertTrue(out().contains("Usage:"));
    }

    // T-1.5: every password array is cleared and the password is never printed
    @Test
    void passwordsAreClearedAndNeverPrinted() {
        generateKeys("ana");
        signContract();
        typedPasswords.add("wrong password here");
        run("sign", contract.toString(), "--key", path("ana.key"), "--signer", "Ana", "--out", path("other.sig"));
        typedPasswords.add("short");
        run("keygen", "--out", path("b"), "--bits", "2048");

        assertEquals(5, handedOutPasswords.size());
        for (char[] password : handedOutPasswords) {
            char[] cleared = new char[password.length];
            Arrays.fill(cleared, '\0');
            assertArrayEquals(cleared, password);
        }
        assertFalse(out().contains(PASSWORD));
        assertFalse(err().contains(PASSWORD));
        assertFalse(err().contains("wrong password here"));
    }
}
