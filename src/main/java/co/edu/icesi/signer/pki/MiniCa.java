package co.edu.icesi.signer.pki;

import co.edu.icesi.signer.crypto.KeyPairService;
import co.edu.icesi.signer.io.SafeFileReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.SecureRandom;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Set;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/** Creates the authority, issues signer certificates and validates them against the authority. */
public final class MiniCa {

    /** Largest certificate accepted, checked before reading it. */
    public static final long MAX_FILE_SIZE = 64 * 1024;

    /** Certificates are signed with RSASSA-PSS too, like the signatures. */
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSAandMGF1";
    private static final String PEM_TYPE = "CERTIFICATE";
    private static final String CRL_PEM_TYPE = "X509 CRL";
    private static final Provider BOUNCY_CASTLE = new BouncyCastleProvider();

    private MiniCa() {
    }

    /** A self-signed authority certificate for the authority's key pair. */
    public static X509Certificate createAuthority(String name, PublicKey publicKey, PrivateKey privateKey,
            Duration validity, Clock clock) throws GeneralSecurityException {
        X500Name subject = name(name);
        return build(subject, subject, publicKey, privateKey, validity, clock, true);
    }

    /** A certificate, signed by the authority, that binds {@code signerName} to the signer's key. */
    public static X509Certificate issue(X509Certificate authority, PrivateKey authorityKey, String signerName,
            RSAPublicKey signerKey, Duration validity, Clock clock) throws GeneralSecurityException {
        KeyPairService.requireAllowed(signerKey);
        X500Name issuer = new JcaX509CertificateHolder(authority).getSubject();
        return build(issuer, name(signerName), signerKey, authorityKey, validity, clock, false);
    }

    private static X500Name name(String commonName) {
        if (commonName.isBlank() || commonName.codePoints().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException("The name must be non-empty and without control characters");
        }
        return new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, commonName).build();
    }

    private static X509Certificate build(X500Name issuer, X500Name subject, PublicKey subjectKey,
            PrivateKey issuerKey, Duration validity, Clock clock, boolean authority)
            throws GeneralSecurityException {
        Instant now = clock.instant();
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer,
                new BigInteger(127, new SecureRandom()).add(BigInteger.ONE),
                Date.from(now.minus(Duration.ofMinutes(5))),
                Date.from(now.plus(validity)),
                subject,
                subjectKey);
        try {
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(authority));
            builder.addExtension(Extension.keyUsage, true, authority
                    ? new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign)
                    : new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation));
            return new JcaX509CertificateConverter().getCertificate(
                    builder.build(new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(BOUNCY_CASTLE).build(issuerKey)));
        } catch (CertIOException | OperatorCreationException e) {
            throw new GeneralSecurityException("Could not build the certificate: " + e.getMessage(), e);
        }
    }

    /**
     * Validates a signer certificate against the authority: issued by it, within its
     * validity at the clock's time, and not itself an authority.
     *
     * @throws CertificateException with the reason if the certificate is not acceptable
     */
    public static void validate(X509Certificate certificate, X509Certificate authority, Clock clock)
            throws GeneralSecurityException {
        if (certificate.getBasicConstraints() != -1) {
            throw new CertificateException("The certificate belongs to an authority, not to a signer");
        }
        PKIXParameters parameters = new PKIXParameters(Set.of(new TrustAnchor(authority, null)));
        parameters.setRevocationEnabled(false);
        parameters.setDate(Date.from(clock.instant()));
        try {
            CertPathValidator.getInstance("PKIX").validate(
                    CertificateFactory.getInstance("X.509").generateCertPath(List.of(certificate)), parameters);
        } catch (CertPathValidatorException e) {
            throw new CertificateException("The certificate was not issued by this authority or is not valid now: "
                    + e.getMessage(), e);
        }
        if (!(certificate.getPublicKey() instanceof RSAPublicKey key)) {
            throw new CertificateException("The certificate does not hold an RSA key");
        }
        KeyPairService.requireAllowed(key);
    }

    /** The common name in the certificate's subject: the signer's name it vouches for. */
    public static String commonName(X509Certificate certificate) throws CertificateException {
        RDN[] names = new JcaX509CertificateHolder(certificate).getSubject().getRDNs(BCStyle.CN);
        if (names.length != 1) {
            throw new CertificateException("The certificate must name exactly one signer");
        }
        return IETFUtils.valueToString(names[0].getFirst().getValue());
    }

    /** Thrown when a certificate is on the authority's revocation list. */
    public static final class RevokedException extends CertificateException {
        private static final long serialVersionUID = 1L;
        private final transient Instant revokedAt;

        RevokedException(Instant revokedAt) {
            super("The certificate was revoked on " + revokedAt);
            this.revokedAt = revokedAt;
        }

        public Instant revokedAt() {
            return revokedAt;
        }
    }

    /**
     * A new revocation list from the authority: the entries of {@code previous}, if any,
     * plus {@code revoke}, if any. It is valid until {@code clock} + {@code validity}; after
     * that verifiers reject it, so the authority must publish a fresh one.
     */
    public static X509CRL revocationList(X509Certificate authority, PrivateKey authorityKey, X509CRL previous,
            X509Certificate revoke, Duration validity, Clock clock) throws GeneralSecurityException {
        Instant now = clock.instant();
        X509v2CRLBuilder builder = new X509v2CRLBuilder(new JcaX509CertificateHolder(authority).getSubject(),
                Date.from(now));
        builder.setNextUpdate(Date.from(now.plus(validity)));
        try {
            if (previous != null) {
                checkIssuedBy(previous, authority);
                builder.addCRL(new X509CRLHolder(previous.getEncoded()));
            }
            if (revoke != null) {
                validate(revoke, authority, clock);
                if (previous == null || previous.getRevokedCertificate(revoke) == null) {
                    builder.addCRLEntry(revoke.getSerialNumber(), Date.from(now), CRLReason.unspecified);
                }
            }
            return new JcaX509CRLConverter().getCRL(
                    builder.build(new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(BOUNCY_CASTLE)
                            .build(authorityKey)));
        } catch (IOException | OperatorCreationException e) {
            throw new GeneralSecurityException("Could not build the revocation list: " + e.getMessage(), e);
        }
    }

    /**
     * Checks a certificate against the authority's revocation list: the list must be signed
     * by the authority and current at the clock's time.
     *
     * @throws RevokedException if the certificate is on the list
     * @throws CertificateException if the list cannot be trusted
     */
    public static void checkRevocation(X509Certificate certificate, X509CRL list, X509Certificate authority,
            Clock clock) throws GeneralSecurityException {
        checkIssuedBy(list, authority);
        Date now = Date.from(clock.instant());
        if (now.before(list.getThisUpdate()) || list.getNextUpdate() == null || now.after(list.getNextUpdate())) {
            throw new CertificateException("The revocation list is not current: it is valid from "
                    + list.getThisUpdate().toInstant() + " to "
                    + (list.getNextUpdate() == null ? "an unknown date" : list.getNextUpdate().toInstant()));
        }
        X509CRLEntry entry = list.getRevokedCertificate(certificate);
        if (entry != null) {
            throw new RevokedException(entry.getRevocationDate().toInstant());
        }
    }

    private static void checkIssuedBy(X509CRL list, X509Certificate authority) throws GeneralSecurityException {
        if (!list.getIssuerX500Principal().equals(authority.getSubjectX500Principal())) {
            throw new CertificateException("The revocation list is from another authority");
        }
        try {
            list.verify(authority.getPublicKey());
        } catch (SignatureException | InvalidKeyException e) {
            throw new CertificateException("The revocation list was not signed by this authority", e);
        }
    }

    /** PEM text of a revocation list. */
    public static byte[] toPem(X509CRL list) throws CRLException {
        return pem(CRL_PEM_TYPE, list.getEncoded());
    }

    /** Reads a single PEM revocation list, with the same size limit as the other inputs. */
    public static X509CRL readRevocationList(Path file) throws IOException, GeneralSecurityException {
        return (X509CRL) CertificateFactory.getInstance("X.509")
                .generateCRL(new ByteArrayInputStream(fromPem(file, CRL_PEM_TYPE)));
    }

    private static byte[] pem(String type, byte[] der) {
        String body = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(der);
        return ("-----BEGIN " + type + "-----\n" + body + "\n-----END " + type + "-----\n")
                .getBytes(StandardCharsets.US_ASCII);
    }

    private static byte[] fromPem(Path file, String type) throws IOException, CertificateException {
        String text = new String(SafeFileReader.read(file, MAX_FILE_SIZE), StandardCharsets.US_ASCII).strip();
        String begin = "-----BEGIN " + type + "-----";
        String end = "-----END " + type + "-----";
        if (!text.startsWith(begin) || !text.endsWith(end) || text.indexOf(begin, 1) != -1) {
            throw new CertificateException(file + " is not a single PEM " + type.toLowerCase(java.util.Locale.ROOT));
        }
        try {
            return Base64.getMimeDecoder().decode(text.substring(begin.length(), text.length() - end.length()));
        } catch (IllegalArgumentException e) {
            throw new CertificateException(file + " is not valid PEM", e);
        }
    }

    /** PEM text of a certificate. */
    public static byte[] toPem(X509Certificate certificate) throws CertificateException {
        return pem(PEM_TYPE, certificate.getEncoded());
    }

    /** Reads a single PEM certificate, with the same size limit as the other inputs. */
    public static X509Certificate read(Path file) throws IOException, CertificateException {
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(fromPem(file, PEM_TYPE)));
    }
}
