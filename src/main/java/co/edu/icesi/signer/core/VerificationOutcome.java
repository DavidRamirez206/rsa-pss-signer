package co.edu.icesi.signer.core;

import java.util.List;

/**
 * A verification result plus what the user needs to interpret it.
 *
 * @param result the outcome
 * @param detail human-readable explanation, in English
 * @param keyFingerprint fingerprint of the supplied public key, or null if it could not be read
 * @param messages further facts the user should see, such as the document version or a time stamp
 * @param reason why a check beyond the cryptography failed, translatable; null otherwise
 */
public record VerificationOutcome(VerificationResult result, String detail, String keyFingerprint,
        List<Message> messages, Message reason) {

    public VerificationOutcome {
        messages = List.copyOf(messages);
    }

    public VerificationOutcome(VerificationResult result, String detail, String keyFingerprint) {
        this(result, detail, keyFingerprint, List.of(), null);
    }

    /** An outcome whose explanation is a translatable reason. */
    public static VerificationOutcome because(VerificationResult result, Message reason, String keyFingerprint) {
        return new VerificationOutcome(result, reason.english(), keyFingerprint, List.of(), reason);
    }

    /** The messages in English, as the command line shows them. */
    public List<String> notes() {
        return messages.stream().map(Message::english).toList();
    }
}
