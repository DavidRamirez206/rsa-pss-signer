package co.edu.icesi.signer.policy;

import co.edu.icesi.signer.core.Message;
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
import java.security.cert.X509CRL;
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

    /**
     * A certificate, validated against the authority that must have issued it and, when
     * {@code revocationList} is given, checked against that authority's revocation list.
     */
    public record Certificate(Path certificate, Path authority, Path revocationList) implements KeySource {

        public Certificate(Path certificate, Path authority) {
            this(certificate, authority, null);
        }
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
        X509CRL revocationList = null;
        try {
            if (request.key() instanceof Certificate source) {
                certificate = MiniCa.read(source.certificate());
                authority = MiniCa.read(source.authority());
                MiniCa.validate(certificate, authority, clock);
                if (source.revocationList() != null) {
                    revocationList = MiniCa.readRevocationList(source.revocationList());
                    MiniCa.checkRevocation(certificate, revocationList, authority, clock);
                }
                publicKey = (RSAPublicKey) certificate.getPublicKey();
            } else {
                publicKey = PublicKeyStore.read(((PublicKeyFile) request.key()).file());
            }
        } catch (MiniCa.RevokedException e) {
            String fingerprint = fingerprintOrNull(certificate);
            return VerificationOutcome.because(VerificationResult.INVALID,
                    Message.of("reason.certificate.revoked", e.revokedAt().toString()), fingerprint);
        } catch (IOException | GeneralSecurityException e) {
            return error("Could not use the signer's key: " + describe(e), null);
        }

        VerificationOutcome outcome = VerificationService.verify(request.file(), sig, publicKey);
        if (outcome.result() != VerificationResult.VALID) {
            return outcome;
        }
        String fingerprint = outcome.keyFingerprint();
        CanonicalHeader header = sig.header();
        List<Message> notes = new ArrayList<>();

        try {
            if (request.expectedFingerprint() != null
                    && !normalize(request.expectedFingerprint()).equals(normalize(fingerprint))) {
                return invalid(Message.of("reason.fingerprint.unexpected", request.expectedFingerprint(),
                        fingerprint), fingerprint);
            }
            if (request.expectedFingerprint() != null) {
                notes.add(Message.of("note.expected"));
            }

            if (certificate != null) {
                String certified = MiniCa.commonName(certificate);
                if (!certified.equals(header.signerName())) {
                    return invalid(Message.of("reason.certificate.name", certified, header.signerName()),
                            fingerprint);
                }
                notes.add(Message.of("note.certificate", MiniCa.commonName(authority), certified));
                notes.add(revocationList != null
                        ? Message.of("note.revocation.checked", revocationList.getThisUpdate().toInstant().toString())
                        : Message.of("note.revocation.unchecked"));
            }

            if (request.previous() != null) {
                Message problem = chainProblem(header,
                        SafeFileReader.read(request.previous(), SigFile.MAX_FILE_SIZE), request.previous());
                if (problem != null) {
                    return invalid(problem, fingerprint);
                }
                notes.add(Message.of("note.follows", request.previous().getFileName().toString()));
            }

            if (request.timeStamp() != null) {
                if (request.timeAuthority() == null) {
                    return VerificationOutcome.because(VerificationResult.ERROR,
                            Message.of("reason.timestamp.key.missing"), fingerprint);
                }
                TimeToken token = TimeToken.parse(SafeFileReader.read(request.timeStamp(), TimeToken.MAX_FILE_SIZE));
                Message problem = TimeAuthority.problem(token, sigBytes, PublicKeyStore.read(request.timeAuthority()));
                if (problem != null) {
                    return invalid(problem, fingerprint);
                }
                notes.add(Message.of("note.timestamp", token.time(), token.authorityFingerprint()));
            }

            boolean pinNow = false;
            if (certificate == null) {
                Optional<String> pinned = trust.pinned(header.signerName());
                if (pinned.isPresent() && !pinned.get().equals(fingerprint)) {
                    return invalid(Message.of("reason.key.changed", header.signerName(), pinned.get(), fingerprint),
                            fingerprint);
                }
                pinNow = pinned.isEmpty();
                notes.add(Message.of(pinNow ? "note.pinned.first" : "note.pinned.same", header.signerName()));
            }

            if (header.hasDocVersion()) {
                int seen = versions.highestSeen(fingerprint, header.fileName());
                if (header.docVersion() < seen) {
                    return invalid(Message.of("reason.outdated", header.docVersion(), header.fileName(), seen),
                            fingerprint);
                }
                notes.add(Message.of("note.version", header.docVersion(), header.fileName()));
            } else {
                notes.add(Message.of("note.legacy"));
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
        return new VerificationOutcome(VerificationResult.VALID, outcome.detail(), fingerprint, notes, null);
    }

    /** Why {@code header} is not the next version of the {@code .sig} in {@code previous}, or null. */
    static Message chainProblem(CanonicalHeader header, byte[] previous, Path previousFile) throws IOException {
        CanonicalHeader before;
        try {
            before = SigFile.parse(previous).header();
        } catch (SigValidationException e) {
            throw new IOException("Could not read the previous signature: " + e.getMessage(), e);
        }
        if (!header.hasDocVersion() || !header.prevSigHash().equals(SigFile.hashOf(previous))) {
            return Message.of("reason.chain.broken", previousFile.getFileName().toString());
        }
        int expected = Math.max(before.docVersion(), 1) + 1;
        if (header.docVersion() != expected) {
            return Message.of("reason.chain.version", previousFile.getFileName().toString(), header.docVersion(),
                    expected);
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

    private static VerificationOutcome invalid(Message reason, String fingerprint) {
        return VerificationOutcome.because(VerificationResult.INVALID, reason, fingerprint);
    }

    private static String fingerprintOrNull(X509Certificate certificate) {
        try {
            return KeyPairService.fingerprint((RSAPublicKey) certificate.getPublicKey());
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static VerificationOutcome error(String detail, String fingerprint) {
        return new VerificationOutcome(VerificationResult.ERROR, detail, fingerprint);
    }
}
