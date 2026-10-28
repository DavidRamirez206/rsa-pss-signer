package co.edu.icesi.signer.core;

/**
 * Outcome of a signature verification.
 *
 * <p>Never collapse it into a boolean: {@link #ERROR} (no decision could be made)
 * must stay distinct from {@link #INVALID} (the signature does not match), and no
 * failure may ever turn into {@link #VALID}.
 */
public enum VerificationResult {
    /** The signature matches the file under the given public key. */
    VALID(0),
    /** Well-formed input, but the signature does not match. */
    INVALID(1),
    /** No decision could be made: missing file, malformed input, disallowed algorithm. */
    ERROR(2);

    private final int exitCode;

    VerificationResult(int exitCode) {
        this.exitCode = exitCode;
    }

    /** Process exit code the CLI reports for this outcome. */
    public int exitCode() {
        return exitCode;
    }
}
