package co.edu.icesi.signer.gui;

import static co.edu.icesi.signer.gui.I18n.t;

import co.edu.icesi.signer.cli.Cli;
import co.edu.icesi.signer.core.VerificationOutcome;
import co.edu.icesi.signer.crypto.HashAlg;
import co.edu.icesi.signer.crypto.KeyPairService;
import co.edu.icesi.signer.crypto.SigningService;
import co.edu.icesi.signer.crypto.VerificationService;
import co.edu.icesi.signer.format.SigFile;
import co.edu.icesi.signer.io.AtomicFileWriter;
import co.edu.icesi.signer.keystore.PrivateKeyStore;
import co.edu.icesi.signer.keystore.PublicKeyStore;
import co.edu.icesi.signer.keystore.WrongPasswordException;
import java.io.IOException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateCrtKey;
import java.time.Clock;
import java.util.Arrays;
import java.util.List;

/**
 * The three operations as the interface needs them, free of Swing so they can be
 * tested without a display. Every password array passed in is cleared before returning,
 * and every expected failure becomes an {@link ActionFailure} with a readable message.
 */
final class GuiActions {

    /** An operation that failed for a reason the user can act on. */
    static final class ActionFailure extends Exception {
        private static final long serialVersionUID = 1L;

        ActionFailure(String message) {
            super(message);
        }
    }

    record GeneratedKeys(Path privateKey, Path publicKey, String fingerprint) {
    }

    record Signature(Path file, String fingerprint) {
    }

    private final PrivateKeyStore privateKeys;
    private final Clock clock;

    GuiActions(PrivateKeyStore privateKeys, Clock clock) {
        this.privateKeys = privateKeys;
        this.clock = clock;
    }

    GeneratedKeys generateKeys(String base, int bits, char[] password, char[] confirmation) throws ActionFailure {
        try {
            if (base.isBlank()) {
                throw new ActionFailure(t("failure.choose.base"));
            }
            if (password.length < Cli.MIN_PASSWORD_LENGTH) {
                throw new ActionFailure(t("failure.password.short", Cli.MIN_PASSWORD_LENGTH));
            }
            if (!Arrays.equals(password, confirmation)) {
                throw new ActionFailure(t("failure.password.mismatch"));
            }
            Path keyFile = path(base + ".key");
            Path pubFile = path(base + ".pub");
            // Checked up front so that a conflict cannot leave half a key pair behind
            for (Path file : List.of(keyFile, pubFile)) {
                if (Files.exists(file)) {
                    throw new FileAlreadyExistsException(file.toString());
                }
            }
            KeyPair keyPair = KeyPairService.generate(bits);
            privateKeys.write(keyPair.getPrivate(), password, keyFile);
            PublicKeyStore.write(keyPair.getPublic(), pubFile);
            return new GeneratedKeys(keyFile, pubFile, KeyPairService.fingerprint(keyPair.getPublic()));
        } catch (IOException e) {
            throw failure(e);
        } finally {
            Arrays.fill(password, '\0');
            Arrays.fill(confirmation, '\0');
        }
    }

    Signature sign(String file, String key, String signer, HashAlg hash, char[] password) throws ActionFailure {
        try {
            if (file.isBlank() || key.isBlank()) {
                throw new ActionFailure(t("failure.choose.sign"));
            }
            if (signer.isBlank()) {
                throw new ActionFailure(t("failure.signer"));
            }
            Path input = path(file);
            Path output = path(file + ".sig");
            RSAPrivateCrtKey privateKey = privateKeys.read(path(key), password);
            SigFile sig = SigningService.sign(input, privateKey, hash, signer.strip(), SigningService.timestamp(clock));
            AtomicFileWriter.writePublic(output, sig.toJson());
            return new Signature(output, sig.header().keyFingerprint());
        } catch (WrongPasswordException e) {
            throw new ActionFailure(t("failure.password.wrong"));
        } catch (IllegalArgumentException e) {
            throw new ActionFailure(t("failure.signer.control"));
        } catch (IOException | GeneralSecurityException e) {
            throw failure(e);
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    VerificationOutcome verify(String file, String sig, String publicKey) throws ActionFailure {
        if (file.isBlank() || sig.isBlank() || publicKey.isBlank()) {
            throw new ActionFailure(t("failure.choose.verify"));
        }
        return VerificationService.verify(path(file), path(sig), path(publicKey));
    }

    private static Path path(String value) throws ActionFailure {
        try {
            return Path.of(value.strip());
        } catch (InvalidPathException e) {
            throw new ActionFailure(t("failure.path", value));
        }
    }

    private static ActionFailure failure(Exception e) {
        if (e instanceof FileAlreadyExistsException) {
            return new ActionFailure(t("failure.exists", ((FileAlreadyExistsException) e).getFile()));
        }
        if (e instanceof NoSuchFileException) {
            return new ActionFailure(t("failure.missing", ((NoSuchFileException) e).getFile()));
        }
        return new ActionFailure(e.getMessage());
    }
}
