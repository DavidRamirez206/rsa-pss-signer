package co.edu.icesi.signer.keystore;

import co.edu.icesi.signer.crypto.HashAlg;
import co.edu.icesi.signer.crypto.KeyPairService;
import co.edu.icesi.signer.crypto.PssParams;
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
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.PKCS8EncodedKeySpec;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.crypto.util.PBKDF2Config;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfoBuilder;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEOutputEncryptorBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

/**
 * Writes and reads private keys as encrypted PKCS#8 in PEM: PBES2 with
 * PBKDF2-HMAC-SHA256 and AES-256-CBC, which {@code openssl pkey} can open.
 *
 * <p>Bouncy Castle is passed explicitly as a provider instance and never registered
 * globally, so it cannot change which provider the rest of the program gets.
 */
public final class PrivateKeyStore {

    /** Production PBKDF2 iteration count (OWASP recommendation for HMAC-SHA256). */
    public static final int DEFAULT_ITERATIONS = 600_000;

    static final int SALT_LENGTH = 16;

    private static final String PEM_TYPE = "ENCRYPTED PRIVATE KEY";
    private static final Provider BOUNCY_CASTLE = new BouncyCastleProvider();
    private static final byte[] CONSISTENCY_PROBE = {0x70, 0x72, 0x6f, 0x62, 0x65};

    private final int iterations;

    public PrivateKeyStore() {
        this(DEFAULT_ITERATIONS);
    }

    /** Lower iteration counts are for tests and the brute-force demo only. */
    PrivateKeyStore(int iterations) {
        this.iterations = iterations;
    }

    /** Encrypts the key and writes it to a new file; fails if the file already exists. */
    public void write(PrivateKey privateKey, char[] password, Path file) throws IOException {
        byte[] encrypted;
        try {
            OutputEncryptor encryptor = new JcePKCSPBEOutputEncryptorBuilder(
                    new PBKDF2Config.Builder()
                            .withIterationCount(iterations)
                            .withPRF(PBKDF2Config.PRF_SHA256)
                            .withSaltLength(SALT_LENGTH)
                            .build(),
                    NISTObjectIdentifiers.id_aes256_CBC)
                    .setProvider(BOUNCY_CASTLE)
                    .build(password);
            encrypted = new PKCS8EncryptedPrivateKeyInfoBuilder(PrivateKeyInfo.getInstance(privateKey.getEncoded()))
                    .build(encryptor)
                    .getEncoded();
        } catch (OperatorCreationException e) {
            throw new IllegalStateException("Private key encryption is not available", e);
        }

        StringWriter pem = new StringWriter();
        try (PemWriter writer = new PemWriter(pem)) {
            writer.writeObject(new PemObject(PEM_TYPE, encrypted));
        }
        Files.writeString(file, pem.toString(), StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW);
    }

    /**
     * Decrypts an RSA private key and checks it is usable by signing a probe message
     * and verifying it with the derived public key.
     *
     * @throws WrongPasswordException if the password does not open the key
     * @throws InvalidKeyException if the file is not an encrypted PEM private key,
     *     or holds a key that is not RSA
     */
    public RSAPrivateCrtKey read(Path file, char[] password)
            throws IOException, InvalidKeyException, WrongPasswordException {
        PKCS8EncryptedPrivateKeyInfo encrypted = readEncrypted(file);

        byte[] decrypted;
        try {
            // A wrong password usually fails on the padding, but about 1 in 256 attempts
            // gets through and produces garbage, which fails while parsing it instead.
            decrypted = encrypted
                    .decryptPrivateKeyInfo(new JcePKCSPBEInputDecryptorProviderBuilder()
                            .setProvider(BOUNCY_CASTLE)
                            .build(password))
                    .getEncoded();
        } catch (PKCSException | IOException e) {
            throw new WrongPasswordException();
        }

        RSAPrivateCrtKey privateKey;
        try {
            PrivateKey parsed = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(decrypted));
            if (!(parsed instanceof RSAPrivateCrtKey)) {
                throw new InvalidKeyException(file.getFileName() + " does not hold an RSA CRT private key");
            }
            privateKey = (RSAPrivateCrtKey) parsed;
        } catch (GeneralSecurityException e) {
            throw new InvalidKeyException(file.getFileName() + " does not hold an RSA private key", e);
        }

        requireConsistent(privateKey);
        return privateKey;
    }

    private static PKCS8EncryptedPrivateKeyInfo readEncrypted(Path file) throws IOException, InvalidKeyException {
        // Latin-1 never fails on binary input: such a file simply contains no PEM object
        String content = Files.readString(file, StandardCharsets.ISO_8859_1);
        try (PemReader reader = new PemReader(new StringReader(content))) {
            PemObject pem = reader.readPemObject();
            if (pem == null || !PEM_TYPE.equals(pem.getType())) {
                throw new InvalidKeyException(file.getFileName() + " is not an encrypted PEM private key");
            }
            return new PKCS8EncryptedPrivateKeyInfo(pem.getContent());
        } catch (IOException | IllegalArgumentException e) {
            throw new InvalidKeyException("Malformed private key in " + file.getFileName(), e);
        }
    }

    private static void requireConsistent(RSAPrivateCrtKey privateKey) throws InvalidKeyException {
        try {
            Signature signer = PssParams.newSignature(HashAlg.SHA_256);
            signer.initSign(privateKey);
            signer.update(CONSISTENCY_PROBE);
            byte[] signature = signer.sign();

            Signature verifier = PssParams.newSignature(HashAlg.SHA_256);
            verifier.initVerify(KeyPairService.publicKeyOf(privateKey));
            verifier.update(CONSISTENCY_PROBE);
            if (!verifier.verify(signature)) {
                throw new InvalidKeyException("The private key is internally inconsistent");
            }
        } catch (InvalidKeyException e) {
            throw e;
        } catch (GeneralSecurityException e) {
            throw new InvalidKeyException("The private key is internally inconsistent", e);
        }
    }
}
