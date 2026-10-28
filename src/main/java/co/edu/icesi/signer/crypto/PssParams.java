package co.edu.icesi.signer.crypto;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

/**
 * The RSASSA-PSS parameters used by this project: MGF1 with the same hash as the
 * message, a salt as long as the digest, and trailer field 1.
 *
 * <p>The JDK only exposes PSS as the plain {@code "RSASSA-PSS"} algorithm, and
 * {@link PSSParameterSpec#DEFAULT} uses SHA-1. Every {@link Signature} must therefore
 * be obtained through {@link #newSignature(HashAlg)}, which always sets the
 * parameters explicitly.
 */
public final class PssParams {

    public static final String SIGNATURE_ALGORITHM = "RSASSA-PSS";
    public static final String MGF = "MGF1";
    public static final int TRAILER_FIELD = PSSParameterSpec.TRAILER_FIELD_BC;

    private PssParams() {
    }

    /** PSS parameters bound to the given hash. */
    public static PSSParameterSpec forHash(HashAlg hash) {
        return new PSSParameterSpec(
                hash.jcaName(),
                MGF,
                new MGF1ParameterSpec(hash.jcaName()),
                hash.digestLength(),
                TRAILER_FIELD);
    }

    /** A {@link Signature} already configured with the PSS parameters for the given hash. */
    public static Signature newSignature(HashAlg hash) {
        try {
            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
            signature.setParameter(forHash(hash));
            return signature;
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new IllegalStateException(
                    SIGNATURE_ALGORITHM + " with " + hash.jcaName() + " is not available in this Java runtime", e);
        }
    }
}
