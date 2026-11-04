package co.edu.icesi.signer.cli;

import co.edu.icesi.signer.core.VerificationOutcome;
import co.edu.icesi.signer.core.VerificationResult;
import co.edu.icesi.signer.crypto.HashAlg;
import co.edu.icesi.signer.crypto.KeyPairService;
import co.edu.icesi.signer.crypto.SigningService;
import co.edu.icesi.signer.crypto.VerificationService;
import co.edu.icesi.signer.format.SigFile;
import co.edu.icesi.signer.keystore.PrivateKeyStore;
import co.edu.icesi.signer.keystore.PublicKeyStore;
import co.edu.icesi.signer.keystore.WrongPasswordException;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateCrtKey;
import java.time.Clock;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The command-line interface: {@code keygen}, {@code sign} and {@code verify}.
 *
 * <p>{@link #run(String[])} returns the process exit code instead of exiting, so
 * tests can check it: 0 for success or VALID, 1 for INVALID, 2 for any error.
 */
public final class Cli {

    static final int MIN_PASSWORD_LENGTH = 12;

    private static final int EXIT_OK = VerificationResult.VALID.exitCode();
    private static final int EXIT_ERROR = VerificationResult.ERROR.exitCode();

    private static final String USAGE = """
            Usage:
              rsa-pss-signer keygen --out <base> [--bits 2048|3072|4096]
                  Writes <base>.key (encrypted private key) and <base>.pub. Default: 3072 bits.
              rsa-pss-signer sign <file> --key <file.key> --signer <name> [--hash <alg>] [--out <file.sig>]
                  Writes the signature to <file>.sig unless --out is given.
                  Hashes: SHA-256 (default), SHA-512, SHA3-256, SHA3-512.
              rsa-pss-signer verify <file> --sig <file.sig> --pub <file.pub>
                  Exit code: 0 VALID, 1 INVALID, 2 ERROR.
            """;

    private final PasswordProvider passwords;
    private final PrintStream out;
    private final PrintStream err;
    private final PrivateKeyStore privateKeys;
    private final Clock clock;

    public Cli(PasswordProvider passwords, PrintStream out, PrintStream err, PrivateKeyStore privateKeys, Clock clock) {
        this.passwords = passwords;
        this.out = out;
        this.err = err;
        this.privateKeys = privateKeys;
        this.clock = clock;
    }

    /** Runs a command and returns the exit code. */
    public int run(String[] args) {
        if (args.length == 0) {
            err.print(USAGE);
            return EXIT_ERROR;
        }
        List<String> rest = List.of(args).subList(1, args.length);
        try {
            switch (args[0]) {
                case "keygen":
                    return keygen(Arguments.parse(rest, 0, Set.of("--out", "--bits")));
                case "sign":
                    return sign(Arguments.parse(rest, 1, Set.of("--key", "--signer", "--hash", "--out")));
                case "verify":
                    return verify(Arguments.parse(rest, 1, Set.of("--sig", "--pub")));
                case "help":
                case "--help":
                case "-h":
                    out.print(USAGE);
                    return EXIT_OK;
                default:
                    throw new UsageException("Unknown command: " + args[0]);
            }
        } catch (UsageException e) {
            err.println("Error: " + e.getMessage());
            err.print(USAGE);
            return EXIT_ERROR;
        } catch (FileAlreadyExistsException e) {
            err.println("Error: refusing to overwrite existing file: " + e.getFile());
            return EXIT_ERROR;
        } catch (NoSuchFileException e) {
            err.println("Error: file not found: " + e.getFile());
            return EXIT_ERROR;
        } catch (IOException | GeneralSecurityException | WrongPasswordException e) {
            err.println("Error: " + e.getMessage());
            return EXIT_ERROR;
        }
    }

    private int keygen(Arguments arguments) throws UsageException, IOException {
        String base = arguments.required("--out");
        Path keyFile = arguments.path(base + ".key");
        Path pubFile = arguments.path(base + ".pub");
        int bits = arguments.bits();

        // Checked up front so that a conflict cannot leave half a key pair behind
        for (Path file : List.of(keyFile, pubFile)) {
            if (Files.exists(file)) {
                throw new FileAlreadyExistsException(file.toString());
            }
        }

        char[] password = readNewPassword();
        try {
            KeyPair keyPair = KeyPairService.generate(bits);
            privateKeys.write(keyPair.getPrivate(), password, keyFile);
            PublicKeyStore.write(keyPair.getPublic(), pubFile);
            out.println("Private key: " + keyFile);
            out.println("Public key:  " + pubFile);
            out.println("Fingerprint: " + KeyPairService.fingerprint(keyPair.getPublic()));
            out.println("Share this fingerprint through a channel independent from the public key file.");
            return EXIT_OK;
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private char[] readNewPassword() throws IOException {
        char[] password = passwords.readPassword("New password for the private key");
        char[] confirmation = null;
        boolean accepted = false;
        try {
            if (password.length < MIN_PASSWORD_LENGTH) {
                throw new IOException("The password must have at least " + MIN_PASSWORD_LENGTH + " characters");
            }
            confirmation = passwords.readPassword("Repeat the password");
            if (!Arrays.equals(password, confirmation)) {
                throw new IOException("The passwords do not match");
            }
            accepted = true;
            return password;
        } finally {
            if (confirmation != null) {
                Arrays.fill(confirmation, '\0');
            }
            if (!accepted) {
                Arrays.fill(password, '\0');
            }
        }
    }

    private int sign(Arguments arguments)
            throws UsageException, IOException, GeneralSecurityException, WrongPasswordException {
        Path file = arguments.path(arguments.positional());
        Path keyFile = arguments.path(arguments.required("--key"));
        String signer = arguments.required("--signer");
        HashAlg hash = arguments.hash();
        Path sigFile = arguments.path(arguments.optional("--out", arguments.positional() + ".sig"));

        char[] password = passwords.readPassword("Password for " + keyFile.getFileName());
        RSAPrivateCrtKey privateKey;
        try {
            privateKey = privateKeys.read(keyFile, password);
        } finally {
            Arrays.fill(password, '\0');
        }

        String signedAt = OffsetDateTime.now(clock)
                .truncatedTo(ChronoUnit.SECONDS)
                .format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);
        SigFile sig;
        try {
            sig = SigningService.sign(file, privateKey, hash, signer, signedAt);
        } catch (IllegalArgumentException e) {
            throw new UsageException(e.getMessage());
        }
        Files.write(sigFile, sig.toJson(), StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);

        out.println("Signature:   " + sigFile);
        out.println("Fingerprint: " + sig.header().keyFingerprint());
        return EXIT_OK;
    }

    private int verify(Arguments arguments) throws UsageException {
        VerificationOutcome outcome = VerificationService.verify(
                arguments.path(arguments.positional()),
                arguments.path(arguments.required("--sig")),
                arguments.path(arguments.required("--pub")));

        out.println(outcome.result() + ": " + outcome.detail());
        if (outcome.keyFingerprint() != null) {
            out.println("Key fingerprint: " + outcome.keyFingerprint());
            if (outcome.result() == VerificationResult.VALID) {
                out.println("This proves who holds this key, not who the person is: compare the"
                        + " fingerprint with the signer through an independent channel.");
            }
        }
        return outcome.result().exitCode();
    }

    private static final class UsageException extends Exception {
        private static final long serialVersionUID = 1L;

        UsageException(String message) {
            super(message);
        }
    }

    /** Positional arguments and {@code --name value} options. Each option may appear once. */
    private static final class Arguments {
        private final List<String> positionals;
        private final Map<String, String> options;

        private Arguments(List<String> positionals, Map<String, String> options) {
            this.positionals = positionals;
            this.options = options;
        }

        static Arguments parse(List<String> args, int expectedPositionals, Set<String> allowedOptions)
                throws UsageException {
            List<String> positionals = new ArrayList<>();
            Map<String, String> options = new HashMap<>();
            for (int i = 0; i < args.size(); i++) {
                String arg = args.get(i);
                if (!arg.startsWith("--")) {
                    positionals.add(arg);
                    continue;
                }
                if (!allowedOptions.contains(arg)) {
                    throw new UsageException("Unknown option: " + arg);
                }
                if (i + 1 == args.size()) {
                    throw new UsageException("Missing value for " + arg);
                }
                if (options.put(arg, args.get(++i)) != null) {
                    throw new UsageException("Repeated option: " + arg);
                }
            }
            if (positionals.size() != expectedPositionals) {
                throw new UsageException("Expected " + expectedPositionals + " file argument(s), got "
                        + positionals.size());
            }
            return new Arguments(positionals, options);
        }

        String positional() {
            return positionals.get(0);
        }

        String required(String option) throws UsageException {
            String value = options.get(option);
            if (value == null) {
                throw new UsageException("Missing option: " + option);
            }
            return value;
        }

        String optional(String option, String defaultValue) {
            return options.getOrDefault(option, defaultValue);
        }

        Path path(String value) throws UsageException {
            try {
                return Path.of(value);
            } catch (InvalidPathException e) {
                throw new UsageException("Invalid path: " + value);
            }
        }

        int bits() throws UsageException {
            String value = optional("--bits", String.valueOf(KeyPairService.DEFAULT_KEY_SIZE));
            try {
                int bits = Integer.parseInt(value);
                if (KeyPairService.ALLOWED_KEY_SIZES.contains(bits)) {
                    return bits;
                }
            } catch (NumberFormatException e) {
                // Reported below, like any other value outside the allowlist
            }
            throw new UsageException("Key size not allowed: " + value);
        }

        HashAlg hash() throws UsageException {
            String value = optional("--hash", HashAlg.SHA_256.jcaName());
            return HashAlg.fromJcaName(value)
                    .orElseThrow(() -> new UsageException("Hash algorithm not allowed: " + value));
        }
    }
}
