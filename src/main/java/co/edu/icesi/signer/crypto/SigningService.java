package co.edu.icesi.signer.crypto;

import co.edu.icesi.signer.format.CanonicalHeader;
import co.edu.icesi.signer.format.SigFile;
import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.interfaces.RSAPrivateCrtKey;

/** Signs files with RSASSA-PSS over the canonical header and the file digest. */
public final class SigningService {

    private SigningService() {
    }

    /**
     * Signs a file. The header records its base name, the signer's declared name and
     * date, and the fingerprint of the public key derived from {@code privateKey}.
     *
     * @param signedAt ISO-8601 date declared by the signer; it is signed, but it is not trusted time
     * @throws IllegalArgumentException if a text field contains control characters
     */
    public static SigFile sign(
            Path file, RSAPrivateCrtKey privateKey, HashAlg hashAlg, String signerName, String signedAt)
            throws IOException, GeneralSecurityException {
        CanonicalHeader header = CanonicalHeader.forSigning(
                hashAlg,
                KeyPairService.fingerprint(KeyPairService.publicKeyOf(privateKey)),
                file.getFileName().toString(),
                signerName,
                signedAt);

        Signature signer = PssParams.newSignature(hashAlg);
        signer.initSign(privateKey);
        SignedMessage.update(signer, header, file);
        return new SigFile(header, signer.sign());
    }
}
