package co.edu.icesi.signer.format;

/** The {@code .sig} content is not valid. Verification reports this as ERROR, not INVALID. */
public final class SigValidationException extends Exception {

    private static final long serialVersionUID = 1L;

    public SigValidationException(String message) {
        super(message);
    }

    public SigValidationException(String message, Throwable cause) {
        super(message, cause);
    }
}
