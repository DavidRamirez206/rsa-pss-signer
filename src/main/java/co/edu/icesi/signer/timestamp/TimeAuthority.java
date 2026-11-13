package co.edu.icesi.signer.timestamp;

import co.edu.icesi.signer.core.Message;
import co.edu.icesi.signer.crypto.HashAlg;
import co.edu.icesi.signer.crypto.KeyPairService;
import co.edu.icesi.signer.crypto.PssParams;
import co.edu.icesi.signer.crypto.SigningService;
import co.edu.icesi.signer.format.SigFile;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;

/** Issues and checks time stamps. The authority runs {@link #stamp} with its own key and clock. */
public final class TimeAuthority {

    private TimeAuthority() {
    }

    /** Lowercase hex SHA-256 of the stamped bytes. */
    public static String hash(byte[] content) {
        return SigFile.hashOf(content);
    }

    /** Stamps the bytes of a {@code .sig} file with the authority's current time. */
    public static TimeToken stamp(byte[] sigFile, RSAPrivateCrtKey authorityKey, Clock clock)
            throws GeneralSecurityException {
        return stampHash(hash(sigFile), authorityKey, clock);
    }

    /**
     * Stamps the hash of a {@code .sig} file: what a remote authority receives, so it never
     * sees the signature itself.
     *
     * @throws IllegalArgumentException if {@code sigHash} is not a lowercase hex SHA-256
     */
    public static TimeToken stampHash(String sigHash, RSAPrivateCrtKey authorityKey, Clock clock)
            throws GeneralSecurityException {
        if (!sigHash.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("Expected the lowercase hex SHA-256 of a signature file");
        }
        RSAPublicKey publicKey = KeyPairService.publicKeyOf(authorityKey);
        KeyPairService.requireAllowed(publicKey);
        TimeToken unsigned = new TimeToken(
                sigHash, SigningService.timestamp(clock), KeyPairService.fingerprint(publicKey), new byte[0]);
        Signature signer = PssParams.newSignature(HashAlg.SHA_256);
        signer.initSign(authorityKey);
        signer.update(unsigned.canonicalBytes());
        return new TimeToken(unsigned.sigHash(), unsigned.time(), unsigned.authorityFingerprint(), signer.sign());
    }

    /**
     * Checks a token against the stamped {@code .sig} and the authority's public key.
     *
     * @return null if the token is good, otherwise why it is not
     * @throws InvalidKeyException if the authority key is outside the allowlists
     */
    public static Message problem(TimeToken token, byte[] sigFile, RSAPublicKey authorityKey)
            throws GeneralSecurityException {
        KeyPairService.requireAllowed(authorityKey);
        if (!KeyPairService.fingerprint(authorityKey).equals(token.authorityFingerprint())) {
            return Message.of("reason.timestamp.authority", token.authorityFingerprint());
        }
        Signature verifier = PssParams.newSignature(HashAlg.SHA_256);
        verifier.initVerify(authorityKey);
        verifier.update(token.canonicalBytes());
        boolean valid;
        try {
            valid = verifier.verify(token.signature());
        } catch (java.security.SignatureException e) {
            valid = false;
        }
        if (!valid) {
            return Message.of("reason.timestamp.signature");
        }
        if (!MessageDigest.isEqual(hash(sigFile).getBytes(), token.sigHash().getBytes())) {
            return Message.of("reason.timestamp.other");
        }
        return null;
    }
}
