import co.edu.icesi.signer.crypto.KeyPairService;
import co.edu.icesi.signer.format.CanonicalHeader;
import co.edu.icesi.signer.format.SigFile;
import co.edu.icesi.signer.io.FileHasher;
import co.edu.icesi.signer.keystore.PrivateKeyStore;
import co.edu.icesi.signer.keystore.PublicKeyStore;
import co.edu.icesi.signer.keystore.WrongPasswordException;
import java.io.ByteArrayOutputStream;
import java.io.Console;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.Arrays;

/**
 * Helpers for the live demos that the program itself does not offer. Run from the
 * repository root, after mvn package (on Windows, use ; instead of : in the class path):
 *
 *   java -cp "target/rsa-pss-signer.jar:target/lib/*" demo/DemoTools.java keys <base> <iterations>
 *   java -cp "target/rsa-pss-signer.jar:target/lib/*" demo/DemoTools.java bruteforce <file.key> [seconds]
 *   java -cp "target/rsa-pss-signer.jar:target/lib/*" demo/DemoTools.java export <file> <file.sig> <dir>
 */
public final class DemoTools {

    private DemoTools() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length >= 3 && args[0].equals("keys")) {
            keys(args[1], Integer.parseInt(args[2]));
        } else if (args.length >= 2 && args[0].equals("bruteforce")) {
            bruteForce(Path.of(args[1]), args.length > 2 ? Integer.parseInt(args[2]) : 10);
        } else if (args.length >= 4 && args[0].equals("export")) {
            export(Path.of(args[1]), Path.of(args[2]), Path.of(args[3]));
        } else {
            System.err.println("Usage: keys <base> <iterations> | bruteforce <file.key> [seconds]"
                    + " | export <file> <file.sig> <dir>");
            System.exit(2);
        }
    }

    /** Demo 4: a key pair whose private key uses the given PBKDF2 iteration count. */
    private static void keys(String base, int iterations) throws Exception {
        Console console = System.console();
        if (console == null) {
            throw new IllegalStateException("Run from a real terminal to type the password");
        }
        char[] password = console.readPassword("Password for %s.key: ", base);
        try {
            KeyPair pair = KeyPairService.generate(2048);
            new PrivateKeyStore(iterations).write(pair.getPrivate(), password, Path.of(base + ".key"));
            PublicKeyStore.write(pair.getPublic(), Path.of(base + ".pub"));
            System.out.printf("Wrote %s.key (%,d iterations) and %s.pub%n", base, iterations, base);
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    /** Demo 4: how many wrong passwords per second an attacker can try against this key. */
    private static void bruteForce(Path key, int seconds) throws Exception {
        // Reads keys down to 1,000 iterations, which the program itself rejects
        PrivateKeyStore store = new PrivateKeyStore(1000);
        long deadline = System.nanoTime() + seconds * 1_000_000_000L;
        long start = System.nanoTime();
        int attempts = 0;
        while (System.nanoTime() < deadline) {
            char[] guess = String.format("guess-%06d", attempts).toCharArray();
            try {
                store.read(key, guess);
                System.out.println("Found the password: " + new String(guess));
                return;
            } catch (WrongPasswordException e) {
                attempts++;
            }
        }
        double elapsed = (System.nanoTime() - start) / 1e9;
        double perSecond = attempts / elapsed;
        System.out.printf("%s: %,d wrong passwords in %.1f s = %,.1f attempts per second%n",
                key.getFileName(), attempts, elapsed, perSecond);
        System.out.printf("A list of 10 million common passwords would take %s%n", duration(10_000_000 / perSecond));
    }

    private static String duration(double seconds) {
        if (seconds < 120) {
            return String.format("%.0f seconds", seconds);
        }
        if (seconds < 2 * 3600) {
            return String.format("%.0f minutes", seconds / 60);
        }
        if (seconds < 2 * 86400) {
            return String.format("%.1f hours", seconds / 3600);
        }
        return String.format("%.1f days", seconds / 86400);
    }

    /** Demo 5: the message that was signed and the raw signature, for OpenSSL to verify. */
    private static void export(Path file, Path sigFile, Path dir) throws Exception {
        SigFile sig = SigFile.parse(Files.readAllBytes(sigFile));
        CanonicalHeader header = sig.header();
        ByteArrayOutputStream message = new ByteArrayOutputStream();
        message.write(header.toBytes());
        message.write(FileHasher.hash(file, header.hashAlg().newDigest()));
        Files.createDirectories(dir);
        Files.write(dir.resolve("m.bin"), message.toByteArray());
        Files.write(dir.resolve("signature.bin"), sig.signature());
        String digest = header.hashAlg().jcaName().replace("-", "").toLowerCase();
        System.out.println("Wrote m.bin (canonical header + digest of the file) and signature.bin in " + dir);
        System.out.println("Verify with OpenSSL:");
        System.out.printf("  openssl dgst -%s -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:%d"
                + " -sigopt rsa_mgf1_md:%s -verify <public key> -signature %s %s%n",
                digest, header.saltLen(), header.mgfHash().replace("-", "").toLowerCase(),
                dir.resolve("signature.bin"), dir.resolve("m.bin"));
    }
}
