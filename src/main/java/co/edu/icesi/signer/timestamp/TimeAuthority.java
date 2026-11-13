package co.edu.icesi.signer.timestamp;

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
        RSAPublicKey publicKey = KeyPairService.publicKeyOf(authorityKey);
        KeyPairService.requireAllowed(publicKey);
        TimeToken unsigned = new TimeToken(
                hash(sigFile), SigningService.timestamp(clock), KeyPairService.fingerprint(publicKey), new byte[0]);
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
    public static String problem(TimeToken token, byte[] sigFile, RSAPublicKey authorityKey)
            throws GeneralSecurityException {
        KeyPairService.requireAllowed(authorityKey);
        if (!KeyPairService.fingerprint(authorityKey).equals(token.authorityFingerprint())) {
            return "The time stamp was issued by key " + token.authorityFingerprint()
                    + ", not by the authority key supplied";
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
            return "The time stamp's signature does not verify";
        }
        if (!MessageDigest.isEqual(hash(sigFile).getBytes(), token.sigHash().getBytes())) {
            return "The time stamp is for another signature file";
        }
        return null;
    }
}
