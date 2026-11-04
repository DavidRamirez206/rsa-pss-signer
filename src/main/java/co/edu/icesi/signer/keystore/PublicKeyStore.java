package co.edu.icesi.signer.keystore;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
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

    private PublicKeyStore() {
    }

    /** Writes the key to a new file; fails if the file already exists. */
    public static void write(PublicKey publicKey, Path file) throws IOException {
        StringWriter pem = new StringWriter();
        try (PemWriter writer = new PemWriter(pem)) {
            writer.writeObject(new PemObject(PEM_TYPE, publicKey.getEncoded()));
        }
        Files.writeString(file, pem.toString(), StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW);
    }

    /**
     * Reads an RSA public key.
     *
     * @throws InvalidKeyException if the file is not a PEM-encoded RSA public key
     */
    public static RSAPublicKey read(Path file) throws IOException, InvalidKeyException {
        // Latin-1 never fails on binary input: such a file simply contains no PEM object
        String content = Files.readString(file, StandardCharsets.ISO_8859_1);
        PemObject pem;
        try (PemReader reader = new PemReader(new StringReader(content))) {
            pem = reader.readPemObject();
        } catch (IOException | IllegalArgumentException e) {
            throw new InvalidKeyException("Malformed PEM in " + file.getFileName(), e);
        }
        if (pem == null || !PEM_TYPE.equals(pem.getType())) {
            throw new InvalidKeyException(file.getFileName() + " is not a PEM public key");
        }
        try {
            return (RSAPublicKey) KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(pem.getContent()));
        } catch (GeneralSecurityException e) {
            throw new InvalidKeyException(file.getFileName() + " is not an RSA public key", e);
        }
    }
}
