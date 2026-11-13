package co.edu.icesi.signer.policy;

import co.edu.icesi.signer.core.VerificationOutcome;
import co.edu.icesi.signer.core.VerificationResult;
import co.edu.icesi.signer.crypto.KeyPairService;
import co.edu.icesi.signer.crypto.VerificationService;
import co.edu.icesi.signer.format.CanonicalHeader;
import co.edu.icesi.signer.format.SigFile;
import co.edu.icesi.signer.format.SigValidationException;
import co.edu.icesi.signer.io.SafeFileReader;
import co.edu.icesi.signer.keystore.PublicKeyStore;
import co.edu.icesi.signer.pki.MiniCa;
import co.edu.icesi.signer.timestamp.TimeAuthority;
import co.edu.icesi.signer.timestamp.TimeToken;
import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * Verifies a signature and then applies the checks that address the limits of a plain
 * signature. Each check can only turn VALID into INVALID or ERROR, never the reverse,
 * and local state is only updated when the final result is VALID.
 */
public final class PolicyVerifier {

    /** Where the signer's public key comes from. */
    public sealed interface KeySource permits PublicKeyFile, Certificate {
    }

    /** A {@code .pub} file, checked against the trust store. */
    public record PublicKeyFile(Path file) implements KeySource {
    }

    /** A certificate, validated against the authority that must have issued it. */
    public record Certificate(Path certificate, Path authority) implements KeySource {
    }

    /**
     * @param expectedFingerprint fingerprint the verifier was told through another channel, or null
     * @param previous the {@code .sig} of the previous version this one must follow, or null
     * @param timeStamp a time stamp of the {@code .sig}, or null
     * @param timeAuthority the public key of the time stamp's authority; required with {@code timeStamp}
     */
    public record Request(Path file, Path sigFile, KeySource key, String expectedFingerprint, Path previous,
            Path timeStamp, Path timeAuthority) {

        public static Request of(Path file, Path sigFile, Path publicKey) {
            return new Request(file, sigFile, new PublicKeyFile(publicKey), null, null, null, null);
        }
    }

    private final LocalState state;
    private final TrustStore trust;
    private final VersionStore versions;
    private final Clock clock;

    public PolicyVerifier(LocalState state, Clock clock) {
        this.state = state;
        this.trust = new TrustStore(state);
        this.versions = new VersionStore(state);
        this.clock = clock;
    }

    public VerificationOutcome verify(Request request) {
        byte[] sigBytes;
        SigFile sig;
        try {
            sigBytes = SafeFileReader.read(request.sigFile(), SigFile.MAX_FILE_SIZE);
            sig = SigFile.parse(sigBytes);
        } catch (IOException | SigValidationException e) {
            return error("Could not read the signature file: " + describe(e), null);
        }

        RSAPublicKey publicKey;
        X509Certificate certificate = null;
        X509Certificate authority = null;
        try {
            if (request.key() instanceof Certificate source) {
                certificate = MiniCa.read(source.certificate());
                authority = MiniCa.read(source.authority());
                MiniCa.validate(certificate, authority, clock);
                publicKey = (RSAPublicKey) certificate.getPublicKey();
            } else {
                publicKey = PublicKeyStore.read(((PublicKeyFile) request.key()).file());
            }
        } catch (IOException | GeneralSecurityException e) {
            return error("Could not use the signer's key: " + describe(e), null);
        }

        VerificationOutcome outcome = VerificationService.verify(request.file(), sig, publicKey);
        if (outcome.result() != VerificationResult.VALID) {
            return outcome;
        }
        String fingerprint = outcome.keyFingerprint();
        CanonicalHeader header = sig.header();
        List<String> notes = new ArrayList<>();

        try {
            if (request.expectedFingerprint() != null
                    && !normalize(request.expectedFingerprint()).equals(normalize(fingerprint))) {
                return invalid("The key is not the one you expected: expected " + request.expectedFingerprint()
                        + ", but the signature was made with " + fingerprint, fingerprint);
            }
            if (request.expectedFingerprint() != null) {
                notes.add("The key matches the fingerprint you expected.");
            }

            if (certificate != null) {
                String certified = MiniCa.commonName(certificate);
                if (!certified.equals(header.signerName())) {
                    return invalid("The certificate is for \"" + certified + "\", but the signature names \""
                            + header.signerName() + "\"", fingerprint);
                }
                notes.add("Certificate issued by \"" + MiniCa.commonName(authority) + "\": this key belongs to \""
                        + certified + "\", as far as that authority is trusted.");
            }

            if (request.previous() != null) {
                String problem = chainProblem(header, SafeFileReader.read(request.previous(), SigFile.MAX_FILE_SIZE),
                        request.previous());
                if (problem != null) {
                    return invalid(problem, fingerprint);
                }
                notes.add("Follows " + request.previous().getFileName() + " as its next version.");
            }

            if (request.timeStamp() != null) {
                if (request.timeAuthority() == null) {
                    return error("A time stamp needs the authority's public key to be checked", fingerprint);
                }
                TimeToken token = TimeToken.parse(SafeFileReader.read(request.timeStamp(), TimeToken.MAX_FILE_SIZE));
                String problem = TimeAuthority.problem(token, sigBytes, PublicKeyStore.read(request.timeAuthority()));
                if (problem != null) {
                    return invalid(problem, fingerprint);
                }
                notes.add("Time stamp: this signature existed at " + token.time()
                        + ", according to the authority " + token.authorityFingerprint() + ".");
            }

            boolean pinNow = false;
            if (certificate == null) {
                Optional<String> pinned = trust.pinned(header.signerName());
                if (pinned.isPresent() && !pinned.get().equals(fingerprint)) {
                    return invalid("The key for \"" + header.signerName() + "\" changed: this machine pinned "
                            + pinned.get() + ", but this signature was made with " + fingerprint
                            + ". If the change is legitimate, confirm the new fingerprint with the signer and run:"
                            + " rsa-pss-signer trust remove \"" + header.signerName() + "\"", fingerprint);
                }
                pinNow = pinned.isEmpty();
                notes.add(pinNow
                        ? "First signature from \"" + header.signerName() + "\" on this machine: its key is now"
                                + " pinned, and a different key under that name will be flagged."
                        : "Same key as the one pinned for \"" + header.signerName() + "\" on this machine.");
            }

            if (header.hasDocVersion()) {
                int seen = versions.highestSeen(fingerprint, header.fileName());
                if (header.docVersion() < seen) {
                    return invalid("Outdated version: this is version " + header.docVersion() + " of "
                            + header.fileName() + ", but version " + seen + " was already verified on this machine",
                            fingerprint);
                }
                notes.add("Document version " + header.docVersion() + " of " + header.fileName() + ".");
            } else {
                notes.add("Signature format 1 has no document version, so an old version presented as"
                        + " current cannot be detected.");
            }

            if (pinNow) {
                trust.pin(header.signerName(), fingerprint);
            }
            if (header.hasDocVersion()) {
                versions.record(fingerprint, header.fileName(), header.docVersion());
            }
        } catch (IOException | GeneralSecurityException e) {
            return error("Could not complete the checks: " + describe(e), fingerprint);
        }
        return new VerificationOutcome(VerificationResult.VALID, outcome.detail(), fingerprint, notes);
    }

    /** Why {@code header} is not the next version of the {@code .sig} in {@code previous}, or null. */
    static String chainProblem(CanonicalHeader header, byte[] previous, Path previousFile) throws IOException {
        CanonicalHeader before;
        try {
            before = SigFile.parse(previous).header();
        } catch (SigValidationException e) {
            throw new IOException("Could not read the previous signature: " + e.getMessage(), e);
        }
        if (!header.hasDocVersion() || !header.prevSigHash().equals(SigFile.hashOf(previous))) {
            return "This signature does not follow " + previousFile.getFileName() + ": it is not its next version";
        }
        int expected = Math.max(before.docVersion(), 1) + 1;
        if (header.docVersion() != expected) {
            return "This signature follows " + previousFile.getFileName() + " but claims version "
                    + header.docVersion() + " instead of " + expected;
        }
        return null;
    }

    public LocalState state() {
        return state;
    }

    private static String normalize(String fingerprint) {
        return fingerprint.replaceAll("[\\s:]", "").toUpperCase(Locale.ROOT);
    }

    private static String describe(Exception e) {
        return e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
    }

    private static VerificationOutcome invalid(String detail, String fingerprint) {
        return new VerificationOutcome(VerificationResult.INVALID, detail, fingerprint);
    }

    private static VerificationOutcome error(String detail, String fingerprint) {
        return new VerificationOutcome(VerificationResult.ERROR, detail, fingerprint);
    }
}
