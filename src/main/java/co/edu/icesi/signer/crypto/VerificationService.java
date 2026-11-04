package co.edu.icesi.signer.crypto;

import co.edu.icesi.signer.core.VerificationOutcome;
import co.edu.icesi.signer.core.VerificationResult;
import co.edu.icesi.signer.format.CanonicalHeader;
import co.edu.icesi.signer.format.SigFile;
import co.edu.icesi.signer.format.SigValidationException;
import co.edu.icesi.signer.keystore.PublicKeyStore;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;

/**
 * Verifies signatures. Only a {@code verify()} that returns {@code true} produces
 * VALID. Expected failures map to INVALID or ERROR; only specific exceptions are
 * caught, so a programming bug propagates instead of looking like a bad signature.
 */
public final class VerificationService {

    private VerificationService() {
    }

    /** Reads the {@code .sig} and public key files, then verifies the file against them. */
    public static VerificationOutcome verify(Path file, Path sigFile, Path publicKeyFile) {
        RSAPublicKey publicKey;
        try {
            publicKey = PublicKeyStore.read(publicKeyFile);
        } catch (IOException | InvalidKeyException e) {
            return error("Could not read the public key: " + describe(e), null);
        }
        String fingerprint = KeyPairService.fingerprint(publicKey);

        SigFile sig;
        try {
            sig = SigFile.parse(Files.readAllBytes(sigFile));
        } catch (IOException | SigValidationException e) {
            return error("Could not read the signature file: " + describe(e), fingerprint);
        }
        return verify(file, sig, publicKey);
    }

    /** Verifies the file against an already parsed signature and public key. */
    public static VerificationOutcome verify(Path file, SigFile sig, RSAPublicKey publicKey) {
        String fingerprint = KeyPairService.fingerprint(publicKey);
        CanonicalHeader header = sig.header();

        try {
            KeyPairService.requireAllowed(publicKey);
        } catch (InvalidKeyException e) {
            return error("The public key cannot be used: " + e.getMessage(), fingerprint);
        }
        if (!fingerprint.equals(header.keyFingerprint())) {
            return error("This signature was made with key " + header.keyFingerprint()
                    + ", not with the key supplied", fingerprint);
        }
        int modulusBytes = (publicKey.getModulus().bitLength() + 7) / 8;
        if (sig.signature().length != modulusBytes) {
            return error("The signature has " + sig.signature().length + " bytes; expected " + modulusBytes,
                    fingerprint);
        }

        try {
            Signature verifier = PssParams.newSignature(header.hashAlg());
            verifier.initVerify(publicKey);
            SignedMessage.update(verifier, header, file);
            if (verifier.verify(sig.signature())) {
                return new VerificationOutcome(VerificationResult.VALID, "The signature is valid", fingerprint);
            }
            return invalid(fingerprint);
        } catch (SignatureException e) {
            return invalid(fingerprint);
        } catch (InvalidKeyException e) {
            return error("The public key cannot be used: " + describe(e), fingerprint);
        } catch (IOException e) {
            return error("Could not read the file: " + describe(e), fingerprint);
        }
    }

    private static VerificationOutcome invalid(String fingerprint) {
        return new VerificationOutcome(VerificationResult.INVALID,
                "The signature does not match the file and its signed metadata", fingerprint);
    }

    private static VerificationOutcome error(String detail, String fingerprint) {
        return new VerificationOutcome(VerificationResult.ERROR, detail, fingerprint);
    }

    private static String describe(Exception e) {
        return e.getClass().getSimpleName() + ": " + e.getMessage();
    }
}
