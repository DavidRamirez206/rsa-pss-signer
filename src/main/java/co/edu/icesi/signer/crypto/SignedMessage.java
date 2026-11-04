package co.edu.icesi.signer.crypto;

import co.edu.icesi.signer.format.CanonicalHeader;
import co.edu.icesi.signer.io.FileHasher;
import java.io.IOException;
import java.nio.file.Path;
import java.security.Signature;
import java.security.SignatureException;

/** The signed message {@code M = canonical header || digest(file)}, shared by signing and verification. */
final class SignedMessage {

    private SignedMessage() {
    }

    /** Feeds M into a signature that has already been initialized. */
    static void update(Signature signature, CanonicalHeader header, Path file) throws IOException, SignatureException {
        byte[] digest = FileHasher.hash(file, header.hashAlg().newDigest());
        signature.update(header.toBytes());
        signature.update(digest);
    }
}
