package co.edu.icesi.signer.crypto;

import co.edu.icesi.signer.format.CanonicalHeader;
import co.edu.icesi.signer.format.SigFile;
import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
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
     * Signs a file. The header records its base name, the signer's declared name and
     * date, and the fingerprint of the public key derived from {@code privateKey}.
     *
     * @param signedAt ISO-8601 date declared by the signer; it is signed, but it is not trusted time
     * @throws IllegalArgumentException if a text field contains control characters
     * @throws java.security.InvalidKeyException if the key is outside the allowlists
     */
    public static SigFile sign(
            Path file, RSAPrivateCrtKey privateKey, HashAlg hashAlg, String signerName, String signedAt)
            throws IOException, GeneralSecurityException {
        RSAPublicKey publicKey = KeyPairService.publicKeyOf(privateKey);
        KeyPairService.requireAllowed(publicKey);
        CanonicalHeader header = CanonicalHeader.forSigning(
                hashAlg,
                KeyPairService.fingerprint(publicKey),
                file.getFileName().toString(),
                signerName,
                signedAt);

        Signature signer = PssParams.newSignature(hashAlg);
        signer.initSign(privateKey);
        SignedMessage.update(signer, header, file);
        return new SigFile(header, signer.sign());
    }
}
