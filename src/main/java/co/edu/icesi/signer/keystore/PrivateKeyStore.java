package co.edu.icesi.signer.keystore;

import co.edu.icesi.signer.crypto.HashAlg;
import co.edu.icesi.signer.crypto.KeyPairService;
import co.edu.icesi.signer.crypto.PssParams;
import co.edu.icesi.signer.io.AtomicFileWriter;
import co.edu.icesi.signer.io.SafeFileReader;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Set;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
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

    /** Accepted when reading: below this a key is too cheap to attack. */
    static final int MIN_ITERATIONS = 100_000;

    /** Accepted when reading: above this a crafted key could hang the program. */
    static final int MAX_ITERATIONS = 10_000_000;

    static final int SALT_LENGTH = 16;

    /** Far above any allowed key: a 4096-bit private key takes about 4 KB of PEM. */
    private static final long MAX_FILE_SIZE = 64 * 1024;

    private static final String PEM_TYPE = "ENCRYPTED PRIVATE KEY";
    private static final Provider BOUNCY_CASTLE = new BouncyCastleProvider();
    private static final byte[] CONSISTENCY_PROBE = {0x70, 0x72, 0x6f, 0x62, 0x65};
    private static final Set<ASN1ObjectIdentifier> ALLOWED_PRFS = Set.of(
            PKCSObjectIdentifiers.id_hmacWithSHA256,
            PKCSObjectIdentifiers.id_hmacWithSHA384,
            PKCSObjectIdentifiers.id_hmacWithSHA512);
    private static final Set<ASN1ObjectIdentifier> ALLOWED_CIPHERS = Set.of(
            NISTObjectIdentifiers.id_aes128_CBC,
            NISTObjectIdentifiers.id_aes192_CBC,
            NISTObjectIdentifiers.id_aes256_CBC);

    private final int iterations;

    public PrivateKeyStore() {
        this(DEFAULT_ITERATIONS);
    }

    /**
     * Lower iteration counts are for tests and the brute-force demo only. Such a store
     * also reads keys down to that count, while the default store rejects them.
     */
    public PrivateKeyStore(int iterations) {
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
        AtomicFileWriter.writePrivate(file, pem.toString().getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Decrypts an RSA private key and checks it is usable by signing a probe message
     * and verifying it with the derived public key.
     *
     * @throws WrongPasswordException if the password does not open the key
     * @throws InvalidKeyException if the file is not an encrypted PEM private key, its
     *     encryption parameters are not acceptable, or it holds a key that is not RSA
     *     or is outside the allowlists for size and exponent
     */
    public RSAPrivateCrtKey read(Path file, char[] password)
            throws IOException, InvalidKeyException, WrongPasswordException {
        PKCS8EncryptedPrivateKeyInfo encrypted = readEncrypted(file);
        requireSafeEncryption(encrypted, file);

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

        requireAllowedKey(privateKey);
        requireConsistent(privateKey);
        return privateKey;
    }

    /**
     * Checks the file's parameters before anything is derived from the password: they
     * come from the file, so a crafted iteration count could otherwise hang the program.
     */
    private void requireSafeEncryption(PKCS8EncryptedPrivateKeyInfo encrypted, Path file) throws InvalidKeyException {
        PBKDF2Params kdf;
        ASN1ObjectIdentifier cipher;
        try {
            AlgorithmIdentifier scheme = encrypted.toASN1Structure().getEncryptionAlgorithm();
            if (!PKCSObjectIdentifiers.id_PBES2.equals(scheme.getAlgorithm())) {
                throw new InvalidKeyException(file.getFileName() + " is not encrypted with PBES2");
            }
            PBES2Parameters pbes2 = PBES2Parameters.getInstance(scheme.getParameters());
            if (!PKCSObjectIdentifiers.id_PBKDF2.equals(pbes2.getKeyDerivationFunc().getAlgorithm())) {
                throw new InvalidKeyException(file.getFileName() + " does not use PBKDF2");
            }
            kdf = PBKDF2Params.getInstance(pbes2.getKeyDerivationFunc().getParameters());
            cipher = pbes2.getEncryptionScheme().getAlgorithm();
        } catch (IllegalArgumentException e) {
            throw new InvalidKeyException("Malformed encryption parameters in " + file.getFileName(), e);
        }

        BigInteger count = kdf.getIterationCount();
        int minimum = Math.min(iterations, MIN_ITERATIONS);
        if (count.compareTo(BigInteger.valueOf(minimum)) < 0
                || count.compareTo(BigInteger.valueOf(MAX_ITERATIONS)) > 0) {
            throw new InvalidKeyException("Iteration count not allowed in " + file.getFileName() + ": " + count);
        }
        if (!ALLOWED_PRFS.contains(kdf.getPrf().getAlgorithm())) {
            throw new InvalidKeyException("PBKDF2 hash not allowed in " + file.getFileName());
        }
        if (!ALLOWED_CIPHERS.contains(cipher)) {
            throw new InvalidKeyException("Cipher not allowed in " + file.getFileName());
        }
    }

    private static void requireAllowedKey(RSAPrivateCrtKey privateKey) throws InvalidKeyException {
        try {
            KeyPairService.requireAllowed(KeyPairService.publicKeyOf(privateKey));
        } catch (InvalidKeyException e) {
            throw e;
        } catch (GeneralSecurityException e) {
            throw new InvalidKeyException("The private key is internally inconsistent", e);
        }
    }

    private static PKCS8EncryptedPrivateKeyInfo readEncrypted(Path file) throws IOException, InvalidKeyException {
        // Latin-1 never fails on binary input: such a file simply contains no PEM object
        String content = new String(SafeFileReader.read(file, MAX_FILE_SIZE), StandardCharsets.ISO_8859_1);
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
