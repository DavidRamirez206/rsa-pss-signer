package co.edu.icesi.signer.keystore;

import co.edu.icesi.signer.crypto.KeyPairService;
import co.edu.icesi.signer.io.AtomicFileWriter;
import co.edu.icesi.signer.io.SafeFileReader;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

/** Writes and reads public keys as X.509 SubjectPublicKeyInfo in PEM. */
public final class PublicKeyStore {

    private static final String PEM_TYPE = "PUBLIC KEY";

    /** Far above any allowed key: a 4096-bit public key takes under 1 KB of PEM. */
    private static final long MAX_FILE_SIZE = 64 * 1024;

    private PublicKeyStore() {
    }

    /** Writes the key to a new file; fails if the file already exists. */
    public static void write(PublicKey publicKey, Path file) throws IOException {
        StringWriter pem = new StringWriter();
        try (PemWriter writer = new PemWriter(pem)) {
            writer.writeObject(new PemObject(PEM_TYPE, publicKey.getEncoded()));
        }
        AtomicFileWriter.writePublic(file, pem.toString().getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Reads an RSA public key.
     *
     * @throws InvalidKeyException if the file is not a PEM-encoded RSA public key, or
     *     the key is outside the allowlists for size and exponent
     */
    public static RSAPublicKey read(Path file) throws IOException, InvalidKeyException {
        // Latin-1 never fails on binary input: such a file simply contains no PEM object
        String content = new String(SafeFileReader.read(file, MAX_FILE_SIZE), StandardCharsets.ISO_8859_1);
        PemObject pem;
        try (PemReader reader = new PemReader(new StringReader(content))) {
            pem = reader.readPemObject();
        } catch (IOException | IllegalArgumentException e) {
            throw new InvalidKeyException("Malformed PEM in " + file.getFileName(), e);
        }
        if (pem == null || !PEM_TYPE.equals(pem.getType())) {
            throw new InvalidKeyException(file.getFileName() + " is not a PEM public key");
        }
        RSAPublicKey publicKey;
        try {
            publicKey = (RSAPublicKey) KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(pem.getContent()));
        } catch (GeneralSecurityException e) {
            throw new InvalidKeyException(file.getFileName() + " is not an RSA public key", e);
        }
        KeyPairService.requireAllowed(publicKey);
        return publicKey;
    }
}
