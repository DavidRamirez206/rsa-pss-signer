package co.edu.icesi.signer.crypto;

import co.edu.icesi.signer.format.CanonicalHeader;
import co.edu.icesi.signer.format.SigFile;
import java.io.IOException;
import java.nio.file.Path;
import co.edu.icesi.signer.format.SigValidationException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Signature;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;

/** Signs files with RSASSA-PSS over the canonical header and the file digest. */
public final class SigningService {

    private SigningService() {
    }

    /** The current time as the signer declares it: ISO-8601 with an offset, in whole seconds. */
    public static String timestamp(Clock clock) {
        return OffsetDateTime.now(clock)
                .truncatedTo(ChronoUnit.SECONDS)
                .format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);
    }

    /**
     * Where a new signature stands in the versions of a document.
     *
     * @param docVersion the version being signed, from 1
     * @param prevSigHash hash of the previous version's {@code .sig}; empty for the first
     * @param keyFingerprint key that signed the previous version; null for the first
     */
    public record Chain(int docVersion, String prevSigHash, String keyFingerprint) {

        /** The first version of a document. */
        public static final Chain FIRST = new Chain(1, "", null);

        /**
         * The version after the one whose {@code .sig} bytes are given.
         *
         * @throws SigValidationException if those bytes are not a valid {@code .sig}
         */
        public static Chain after(byte[] previousSig) throws SigValidationException {
            CanonicalHeader previous = SigFile.parse(previousSig).header();
            return new Chain(Math.max(previous.docVersion(), 1) + 1, SigFile.hashOf(previousSig),
                    previous.keyFingerprint());
        }
    }

    /** Signs the first version of a document. */
    public static SigFile sign(
            Path file, RSAPrivateCrtKey privateKey, HashAlg hashAlg, String signerName, String signedAt)
            throws IOException, GeneralSecurityException {
        return sign(file, privateKey, hashAlg, signerName, signedAt, Chain.FIRST);
    }

    /**
     * Signs a file. The header records its base name, the signer's declared name and
     * date, and the fingerprint of the public key derived from {@code privateKey}.
     *
     * @param signedAt ISO-8601 date declared by the signer; it is signed, but it is not trusted time
     * @throws IllegalArgumentException if a text field contains control characters
     * @param chain the document version, and the previous signature it follows
     * @throws java.security.InvalidKeyException if the key is outside the allowlists, or the
     *     previous version was signed with another key
     */
    public static SigFile sign(Path file, RSAPrivateCrtKey privateKey, HashAlg hashAlg, String signerName,
            String signedAt, Chain chain) throws IOException, GeneralSecurityException {
        RSAPublicKey publicKey = KeyPairService.publicKeyOf(privateKey);
        KeyPairService.requireAllowed(publicKey);
        String fingerprint = KeyPairService.fingerprint(publicKey);
        // Versions are tracked per key, so a chain across keys would protect nothing
        if (chain.keyFingerprint() != null && !chain.keyFingerprint().equals(fingerprint)) {
            throw new InvalidKeyException("The previous version was signed with another key ("
                    + chain.keyFingerprint() + ")");
        }
        CanonicalHeader header = CanonicalHeader.forSigning(
                hashAlg,
                fingerprint,
                file.getFileName().toString(),
                signerName,
                signedAt,
                chain.docVersion(),
                chain.prevSigHash());

        Signature signer = PssParams.newSignature(hashAlg);
        signer.initSign(privateKey);
        SignedMessage.update(signer, header, file);
        return new SigFile(header, signer.sign());
    }
}
