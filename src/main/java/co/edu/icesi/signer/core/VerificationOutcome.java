package co.edu.icesi.signer.core;

/**
 * A verification result plus what the user needs to interpret it.
 *
 * @param result the outcome
 * @param detail human-readable explanation
 * @param keyFingerprint fingerprint of the supplied public key, or null if it could not be read
 */
public record VerificationOutcome(VerificationResult result, String detail, String keyFingerprint) {
}
