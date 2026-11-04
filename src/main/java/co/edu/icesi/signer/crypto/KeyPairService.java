package co.edu.icesi.signer.crypto;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.HexFormat;
import java.util.Set;

/** Generates RSA key pairs with explicit parameters and computes key fingerprints. */
public final class KeyPairService {

    public static final Set<Integer> ALLOWED_KEY_SIZES = Set.of(2048, 3072, 4096);
    public static final int DEFAULT_KEY_SIZE = 3072;

    private static final HexFormat FINGERPRINT_FORMAT = HexFormat.ofDelimiter(":").withUpperCase();

    private KeyPairService() {
    }

    /**
     * Generates a key pair with public exponent 65537.
     *
     * @throws IllegalArgumentException if {@code bits} is not an allowed key size
     */
    public static KeyPair generate(int bits) {
        if (!ALLOWED_KEY_SIZES.contains(bits)) {
            throw new IllegalArgumentException("Key size not allowed: " + bits);
        }
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(new RSAKeyGenParameterSpec(bits, RSAKeyGenParameterSpec.F4), new SecureRandom());
            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new IllegalStateException("RSA key generation is not available in this Java runtime", e);
        }
    }

    /** SHA-256 of the key's DER SubjectPublicKeyInfo encoding, formatted as {@code AB:CD:...}. */
    public static String fingerprint(PublicKey publicKey) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(publicKey.getEncoded());
            return FINGERPRINT_FORMAT.formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available in this Java runtime", e);
        }
    }

    /** Derives the public key from the modulus and public exponent of a private key. */
    public static RSAPublicKey publicKeyOf(RSAPrivateCrtKey privateKey) throws GeneralSecurityException {
        RSAPublicKeySpec spec = new RSAPublicKeySpec(privateKey.getModulus(), privateKey.getPublicExponent());
        return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(spec);
    }
}
