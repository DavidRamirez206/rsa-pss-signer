package co.edu.icesi.signer.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Optional;

/**
 * Allowlist of hash algorithms accepted for signing and verification.
 *
 * <p>Algorithm names coming from a {@code .sig} file are only ever mapped to one of
 * these constants through {@link #fromJcaName(String)}; they are never concatenated
 * into a JCA algorithm name.
 */
public enum HashAlg {
    SHA_256("SHA-256", 32),
    SHA_512("SHA-512", 64),
    SHA3_256("SHA3-256", 32),
    SHA3_512("SHA3-512", 64);

    private final String jcaName;
    private final int digestLength;

    HashAlg(String jcaName, int digestLength) {
        this.jcaName = jcaName;
        this.digestLength = digestLength;
    }

    /** Standard JCA name, also used as the label in {@code .sig} files. */
    public String jcaName() {
        return jcaName;
    }

    /** Digest length in bytes. */
    public int digestLength() {
        return digestLength;
    }

    /** Returns a fresh {@link MessageDigest} for this algorithm. */
    public MessageDigest newDigest() {
        try {
            return MessageDigest.getInstance(jcaName);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(jcaName + " is not available in this Java runtime", e);
        }
    }

    /**
     * Maps a label to an allowed algorithm. The match is exact: no trimming and no
     * case folding, so {@code "sha-256"} or {@code "SHA-256 "} are rejected.
     */
    public static Optional<HashAlg> fromJcaName(String name) {
        for (HashAlg alg : values()) {
            if (alg.jcaName.equals(name)) {
                return Optional.of(alg);
            }
        }
        return Optional.empty();
    }
}
