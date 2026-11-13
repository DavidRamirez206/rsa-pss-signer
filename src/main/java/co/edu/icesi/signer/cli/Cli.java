package co.edu.icesi.signer.cli;

import co.edu.icesi.signer.core.FileReview;
import co.edu.icesi.signer.core.VerificationOutcome;
import co.edu.icesi.signer.core.VerificationResult;
import co.edu.icesi.signer.crypto.HashAlg;
import co.edu.icesi.signer.crypto.KeyPairService;
import co.edu.icesi.signer.crypto.SigningService;
import co.edu.icesi.signer.format.SigFile;
import co.edu.icesi.signer.format.SigValidationException;
import co.edu.icesi.signer.io.AtomicFileWriter;
import co.edu.icesi.signer.io.FileHasher;
import co.edu.icesi.signer.io.SafeFileReader;
import co.edu.icesi.signer.keystore.PrivateKeyStore;
import co.edu.icesi.signer.keystore.PublicKeyStore;
import co.edu.icesi.signer.keystore.WrongPasswordException;
import co.edu.icesi.signer.pki.MiniCa;
import co.edu.icesi.signer.policy.LocalState;
import co.edu.icesi.signer.policy.PolicyVerifier;
import co.edu.icesi.signer.policy.TrustStore;
import co.edu.icesi.signer.timestamp.TimeAuthority;
import co.edu.icesi.signer.timestamp.TimeToken;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.cert.X509CRL;
import java.util.concurrent.CountDownLatch;
import co.edu.icesi.signer.timestamp.TimeClient;
import co.edu.icesi.signer.timestamp.TimeServer;
import java.io.PrintStream;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The command-line interface: {@code keygen}, {@code sign} and {@code verify}, plus
 * {@code trust}, {@code ca} and {@code tsa} for the checks that go beyond a plain signature.
 *
 * <p>{@link #run(String[])} returns the process exit code instead of exiting, so
 * tests can check it: 0 for success or VALID, 1 for INVALID, 2 for any error.
 */
public final class Cli {

    public static final int MIN_PASSWORD_LENGTH = 12;

    private static final int EXIT_OK = VerificationResult.VALID.exitCode();
    private static final int EXIT_ERROR = VerificationResult.ERROR.exitCode();

    private static final String USAGE = """
            Usage:
              rsa-pss-signer keygen --out <base> [--bits 2048|3072|4096]
                  Writes <base>.key (encrypted private key) and <base>.pub. Default: 3072 bits.
              rsa-pss-signer sign <file> --key <file.key> --signer <name> [--hash <alg>] [--out <file.sig>]
                                  [--previous <old.sig>]
                  Writes the signature to <file>.sig unless --out is given.
                  Hashes: SHA-256 (default), SHA-512, SHA3-256, SHA3-512.
                  --previous signs the next version of a document, chained to its previous signature.
              rsa-pss-signer verify <file> --sig <file.sig>
                                    (--pub <file.pub> | --cert <file.crt> --ca <ca.crt> [--crl <ca.crl>])
                                    [--expect-fingerprint <fingerprint>] [--previous <old.sig>]
                                    [--timestamp <file.tst> --tsa-pub <tsa.pub>]
                  Exit code: 0 VALID, 1 INVALID, 2 ERROR.
                  With --pub, the first key seen for each signer name is pinned on this machine.
              rsa-pss-signer trust list
              rsa-pss-signer trust remove <signer name>
              rsa-pss-signer ca init --out <base> --name <authority name> [--days <n>]
                  Writes <base>.key (encrypted) and <base>.crt, a self-signed authority certificate.
              rsa-pss-signer ca issue --ca <base> --pub <signer.pub> --name <signer name> --out <file.crt> [--days <n>]
              rsa-pss-signer ca revoke --ca <base> --cert <file.crt> [--days <n>]
              rsa-pss-signer ca crl --ca <base> [--days <n>]
                  Revokes a certificate, or only renews, the revocation list <base>.crl. It must be renewed
                  before it expires (default: 30 days); verifiers reject an expired list.
              rsa-pss-signer tsa stamp <file.sig> --key <tsa.key> [--out <file.tst>]
                  Time-stamps a signature with the time authority's key and clock. Default: <file.sig>.tst.
              rsa-pss-signer tsa serve --key <tsa.key> [--host <address>] [--port <n>]
                  Runs the time authority as an HTTP service until stopped. Default: 127.0.0.1:8318.
              rsa-pss-signer tsa request <file.sig> --url <http://host:port> [--out <file.tst>]
                  Asks a running time authority for a time stamp, sending only the hash of <file.sig>.
            """;

    private static final int CA_DAYS = 1825;
    private static final int CERTIFICATE_DAYS = 365;
    private static final int CRL_DAYS = 30;
    private static final int TSA_PORT = 8318;

    private final PasswordProvider passwords;
    private final PrintStream out;
    private final PrintStream err;
    private final PrivateKeyStore privateKeys;
    private final Clock clock;
    private final LocalState state;

    public Cli(PasswordProvider passwords, PrintStream out, PrintStream err, PrivateKeyStore privateKeys, Clock clock,
            LocalState state) {
        this.passwords = passwords;
        this.out = out;
        this.err = err;
        this.privateKeys = privateKeys;
        this.clock = clock;
        this.state = state;
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
                    return sign(Arguments.parse(rest, 1, Set.of("--key", "--signer", "--hash", "--out", "--previous")));
                case "verify":
                    return verify(Arguments.parse(rest, 1, Set.of("--sig", "--pub", "--cert", "--ca",
                            "--crl", "--expect-fingerprint", "--previous", "--timestamp", "--tsa-pub")));
                case "trust":
                    return trust(rest);
                case "ca":
                    return ca(rest);
                case "tsa":
                    return tsa(rest);
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
        } catch (SigValidationException e) {
            err.println("Error: invalid signature file: " + e.getMessage());
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

    private int sign(Arguments arguments) throws UsageException, IOException, GeneralSecurityException,
            WrongPasswordException, SigValidationException {
        Path file = arguments.path(arguments.positional());
        Path keyFile = arguments.path(arguments.required("--key"));
        String signer = arguments.required("--signer");
        HashAlg hash = arguments.hash();
        Path sigFile = arguments.path(arguments.optional("--out", arguments.positional() + ".sig"));
        String previous = arguments.optional("--previous", null);
        SigningService.Chain chain = previous == null
                ? SigningService.Chain.FIRST
                : SigningService.Chain.after(SafeFileReader.read(arguments.path(previous), SigFile.MAX_FILE_SIZE));

        // What a signature cannot cover: show what is about to be signed, before the password
        long size = SafeFileReader.requireRegularFile(file).size();
        out.println("File:        " + file.getFileName() + " (" + size + " bytes)");
        out.println("SHA-256:     " + HexFormat.of().formatHex(FileHasher.hash(file, HashAlg.SHA_256.newDigest())));
        if (FileReview.canHideContent(file.getFileName().toString())) {
            out.println("Warning: " + FileReview.WARNING);
        }

        char[] password = passwords.readPassword("Password for " + keyFile.getFileName());
        RSAPrivateCrtKey privateKey;
        try {
            privateKey = privateKeys.read(keyFile, password);
        } finally {
            Arrays.fill(password, '\0');
        }

        String signedAt = SigningService.timestamp(clock);
        SigFile sig;
        try {
            sig = SigningService.sign(file, privateKey, hash, signer, signedAt, chain);
        } catch (IllegalArgumentException e) {
            throw new UsageException(e.getMessage());
        }
        AtomicFileWriter.writePublic(sigFile, sig.toJson());

        out.println("Signature:   " + sigFile);
        out.println("Fingerprint: " + sig.header().keyFingerprint());
        out.println("Version:     " + chain.docVersion());
        return EXIT_OK;
    }

    private int verify(Arguments arguments) throws UsageException {
        String pub = arguments.optional("--pub", null);
        String cert = arguments.optional("--cert", null);
        String ca = arguments.optional("--ca", null);
        if ((pub == null) == (cert == null) || (cert == null) != (ca == null)) {
            throw new UsageException("Give either --pub, or --cert with --ca");
        }
        String crl = arguments.optional("--crl", null);
        if (crl != null && cert == null) {
            throw new UsageException("--crl goes with --cert");
        }
        String timestamp = arguments.optional("--timestamp", null);
        String tsaPub = arguments.optional("--tsa-pub", null);
        if ((timestamp == null) != (tsaPub == null)) {
            throw new UsageException("--timestamp and --tsa-pub go together");
        }
        PolicyVerifier.KeySource key = pub != null
                ? new PolicyVerifier.PublicKeyFile(arguments.path(pub))
                : new PolicyVerifier.Certificate(arguments.path(cert), arguments.path(ca),
                        crl == null ? null : arguments.path(crl));
        String previous = arguments.optional("--previous", null);
        VerificationOutcome outcome = new PolicyVerifier(state, clock).verify(new PolicyVerifier.Request(
                arguments.path(arguments.positional()),
                arguments.path(arguments.required("--sig")),
                key,
                arguments.optional("--expect-fingerprint", null),
                previous == null ? null : arguments.path(previous),
                timestamp == null ? null : arguments.path(timestamp),
                tsaPub == null ? null : arguments.path(tsaPub)));

        out.println(outcome.result() + ": " + outcome.detail());
        if (outcome.keyFingerprint() != null) {
            out.println("Key fingerprint: " + outcome.keyFingerprint());
        }
        for (String note : outcome.notes()) {
            out.println("- " + note);
        }
        if (outcome.reason() != null && outcome.reason().key().equals("reason.key.changed")) {
            out.println("To forget the pinned key: rsa-pss-signer trust remove \""
                    + outcome.reason().args().get(0) + "\"");
        }
        if (outcome.result() == VerificationResult.VALID && cert == null) {
            out.println("This proves who holds this key, not who the person is: compare the"
                    + " fingerprint with the signer through an independent channel.");
        }
        return outcome.result().exitCode();
    }

    private int trust(List<String> args) throws UsageException, IOException {
        TrustStore store = new TrustStore(state);
        if (args.size() == 1 && args.get(0).equals("list")) {
            Map<String, String> pinned = store.all();
            if (pinned.isEmpty()) {
                out.println("No keys pinned yet in " + state.directory());
            }
            pinned.forEach((name, fingerprint) -> out.println(fingerprint + "  " + name));
            return EXIT_OK;
        }
        if (args.size() == 2 && args.get(0).equals("remove")) {
            if (!store.remove(args.get(1))) {
                err.println("Error: no key is pinned for \"" + args.get(1) + "\"");
                return EXIT_ERROR;
            }
            out.println("Forgot the key of \"" + args.get(1) + "\". Its next valid signature pins a new one.");
            return EXIT_OK;
        }
        throw new UsageException("Use: trust list, or trust remove <signer name>");
    }

    private int ca(List<String> args) throws UsageException, IOException, GeneralSecurityException,
            WrongPasswordException {
        if (args.isEmpty()) {
            throw new UsageException("Use: ca init, ca issue, ca revoke or ca crl");
        }
        List<String> rest = args.subList(1, args.size());
        switch (args.get(0)) {
            case "init": {
                Arguments arguments = Arguments.parse(rest, 0, Set.of("--out", "--name", "--days"));
                String base = arguments.required("--out");
                Path keyFile = arguments.path(base + ".key");
                Path certFile = arguments.path(base + ".crt");
                String name = arguments.required("--name");
                int days = arguments.days(CA_DAYS);
                for (Path file : List.of(keyFile, certFile)) {
                    if (Files.exists(file)) {
                        throw new FileAlreadyExistsException(file.toString());
                    }
                }
                char[] password = readNewPassword();
                try {
                    KeyPair keyPair = KeyPairService.generate(KeyPairService.DEFAULT_KEY_SIZE);
                    X509Certificate authority = MiniCa.createAuthority(name, keyPair.getPublic(),
                            keyPair.getPrivate(), Duration.ofDays(days), clock);
                    privateKeys.write(keyPair.getPrivate(), password, keyFile);
                    AtomicFileWriter.writePublic(certFile, MiniCa.toPem(authority));
                    out.println("Authority key:         " + keyFile);
                    out.println("Authority certificate: " + certFile);
                    out.println("Fingerprint: " + KeyPairService.fingerprint(keyPair.getPublic()));
                    out.println("Verifiers must get " + certFile.getFileName() + " through a trusted channel:"
                            + " whoever controls it decides who is who.");
                    return EXIT_OK;
                } catch (IllegalArgumentException e) {
                    throw new UsageException(e.getMessage());
                } finally {
                    Arrays.fill(password, '\0');
                }
            }
            case "issue": {
                Arguments arguments = Arguments.parse(rest, 0, Set.of("--ca", "--pub", "--name", "--out", "--days"));
                String base = arguments.required("--ca");
                X509Certificate authority = MiniCa.read(arguments.path(base + ".crt"));
                RSAPublicKey signerKey = PublicKeyStore.read(arguments.path(arguments.required("--pub")));
                String name = arguments.required("--name");
                Path certFile = arguments.path(arguments.required("--out"));
                int days = arguments.days(CERTIFICATE_DAYS);
                RSAPrivateCrtKey authorityKey = authorityKey(arguments, base, authority);
                X509Certificate certificate;
                try {
                    certificate = MiniCa.issue(authority, authorityKey, name, signerKey, Duration.ofDays(days), clock);
                } catch (IllegalArgumentException e) {
                    throw new UsageException(e.getMessage());
                }
                AtomicFileWriter.writePublic(certFile, MiniCa.toPem(certificate));
                out.println("Certificate: " + certFile);
                out.println("Binds \"" + name + "\" to key " + KeyPairService.fingerprint(signerKey)
                        + ", valid for " + days + " days.");
                return EXIT_OK;
            }
            case "revoke":
            case "crl": {
                boolean revoking = args.get(0).equals("revoke");
                Arguments arguments = Arguments.parse(rest, 0,
                        revoking ? Set.of("--ca", "--cert", "--days") : Set.of("--ca", "--days"));
                String base = arguments.required("--ca");
                X509Certificate authority = MiniCa.read(arguments.path(base + ".crt"));
                X509Certificate revoke = revoking ? MiniCa.read(arguments.path(arguments.required("--cert"))) : null;
                Path crlFile = arguments.path(base + ".crl");
                int days = arguments.days(CRL_DAYS);
                X509CRL previous = Files.exists(crlFile) ? MiniCa.readRevocationList(crlFile) : null;
                RSAPrivateCrtKey authorityKey = authorityKey(arguments, base, authority);
                X509CRL list = MiniCa.revocationList(authority, authorityKey, previous, revoke,
                        Duration.ofDays(days), clock);
                AtomicFileWriter.replacePublic(crlFile, MiniCa.toPem(list));
                out.println("Revocation list: " + crlFile);
                if (revoke != null) {
                    out.println("Revoked: \"" + MiniCa.commonName(revoke) + "\", serial " + revoke.getSerialNumber());
                }
                int count = list.getRevokedCertificates() == null ? 0 : list.getRevokedCertificates().size();
                out.println(count + " certificate(s) revoked; renew it with ca crl before "
                        + list.getNextUpdate().toInstant() + ".");
                out.println("Verifiers must use the latest list: an older copy does not show recent revocations.");
                return EXIT_OK;
            }
            default:
                throw new UsageException("Unknown ca command: " + args.get(0));
        }
    }

    private int tsa(List<String> args) throws UsageException, IOException, GeneralSecurityException,
            WrongPasswordException {
        String command = args.isEmpty() ? "" : args.get(0);
        if (command.equals("serve")) {
            return tsaServe(Arguments.parse(args.subList(1, args.size()), 0, Set.of("--key", "--host", "--port")));
        }
        if (command.equals("request")) {
            return tsaRequest(Arguments.parse(args.subList(1, args.size()), 1, Set.of("--url", "--out")));
        }
        if (!command.equals("stamp")) {
            throw new UsageException("Use: tsa stamp, tsa serve or tsa request");
        }
        Arguments arguments = Arguments.parse(args.subList(1, args.size()), 1, Set.of("--key", "--out"));
        Path sigFile = arguments.path(arguments.positional());
        Path keyFile = arguments.path(arguments.required("--key"));
        Path output = arguments.path(arguments.optional("--out", arguments.positional() + ".tst"));
        byte[] sigBytes = SafeFileReader.read(sigFile, SigFile.MAX_FILE_SIZE);

        char[] password = passwords.readPassword("Password for " + keyFile.getFileName());
        RSAPrivateCrtKey authorityKey;
        try {
            authorityKey = privateKeys.read(keyFile, password);
        } finally {
            Arrays.fill(password, '\0');
        }
        TimeToken token = TimeAuthority.stamp(sigBytes, authorityKey, clock);
        AtomicFileWriter.writePublic(output, token.toJson());
        out.println("Time stamp: " + output);
        out.println("Time:       " + token.time() + " (the authority's clock)");
        out.println("Authority:  " + token.authorityFingerprint());
        return EXIT_OK;
    }

    private int tsaServe(Arguments arguments) throws UsageException, IOException, GeneralSecurityException,
            WrongPasswordException {
        Path keyFile = arguments.path(arguments.required("--key"));
        String host = arguments.optional("--host", "127.0.0.1");
        int port = arguments.port(TSA_PORT);
        char[] password = passwords.readPassword("Password for " + keyFile.getFileName());
        RSAPrivateCrtKey authorityKey;
        try {
            authorityKey = privateKeys.read(keyFile, password);
        } finally {
            Arrays.fill(password, '\0');
        }
        KeyPairService.requireAllowed(KeyPairService.publicKeyOf(authorityKey));
        try (TimeServer server = TimeServer.start(new InetSocketAddress(host, port), authorityKey, clock)) {
            out.println("Time authority listening on http://" + host + ":" + server.port() + TimeServer.PATH);
            out.println("Authority: " + KeyPairService.fingerprint(KeyPairService.publicKeyOf(authorityKey)));
            out.println("Press Ctrl+C to stop.");
            out.flush();
            new CountDownLatch(1).await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        return EXIT_OK;
    }

    private int tsaRequest(Arguments arguments) throws UsageException, IOException {
        Path sigFile = arguments.path(arguments.positional());
        Path output = arguments.path(arguments.optional("--out", arguments.positional() + ".tst"));
        URI url;
        try {
            url = new URI(arguments.required("--url"));
        } catch (URISyntaxException e) {
            throw new UsageException("Invalid --url: " + e.getMessage());
        }
        TimeToken token = TimeClient.request(url, SafeFileReader.read(sigFile, SigFile.MAX_FILE_SIZE));
        AtomicFileWriter.writePublic(output, token.toJson());
        out.println("Time stamp: " + output);
        out.println("Time:       " + token.time() + " (the authority's clock)");
        out.println("Authority:  " + token.authorityFingerprint());
        out.println("Check it with verify --timestamp and the authority's public key.");
        return EXIT_OK;
    }

    /** Reads the authority's private key and checks that it matches its certificate. */
    private RSAPrivateCrtKey authorityKey(Arguments arguments, String base, X509Certificate authority)
            throws UsageException, IOException, GeneralSecurityException, WrongPasswordException {
        Path keyFile = arguments.path(base + ".key");
        char[] password = passwords.readPassword("Password for " + keyFile.getFileName());
        RSAPrivateCrtKey authorityKey;
        try {
            authorityKey = privateKeys.read(keyFile, password);
        } finally {
            Arrays.fill(password, '\0');
        }
        if (!KeyPairService.publicKeyOf(authorityKey).equals(authority.getPublicKey())) {
            throw new GeneralSecurityException(keyFile + " is not the key of " + base + ".crt");
        }
        return authorityKey;
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

        int port(int defaultPort) throws UsageException {
            String value = optional("--port", String.valueOf(defaultPort));
            try {
                int port = Integer.parseInt(value);
                if (port >= 0 && port <= 65535) {
                    return port;
                }
            } catch (NumberFormatException e) {
                // Reported below
            }
            throw new UsageException("--port must be between 0 and 65535: " + value);
        }

        int days(int defaultDays) throws UsageException {
            String value = optional("--days", String.valueOf(defaultDays));
            try {
                int days = Integer.parseInt(value);
                if (days >= 1 && days <= 36500) {
                    return days;
                }
            } catch (NumberFormatException e) {
                // Reported below
            }
            throw new UsageException("--days must be between 1 and 36500: " + value);
        }

        HashAlg hash() throws UsageException {
            String value = optional("--hash", HashAlg.SHA_256.jcaName());
            return HashAlg.fromJcaName(value)
                    .orElseThrow(() -> new UsageException("Hash algorithm not allowed: " + value));
        }
    }
}
