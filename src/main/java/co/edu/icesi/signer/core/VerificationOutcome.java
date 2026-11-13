package co.edu.icesi.signer.core;

import java.util.List;

/**
 * A verification result plus what the user needs to interpret it.
 *
 * @param result the outcome
 * @param detail human-readable explanation
 * @param keyFingerprint fingerprint of the supplied public key, or null if it could not be read
 * @param notes further facts the user should see, such as the document version or a time stamp
 */
public record VerificationOutcome(VerificationResult result, String detail, String keyFingerprint, List<String> notes) {

    public VerificationOutcome {
        notes = List.copyOf(notes);
    }

    public VerificationOutcome(VerificationResult result, String detail, String keyFingerprint) {
        this(result, detail, keyFingerprint, List.of());
    }
}
