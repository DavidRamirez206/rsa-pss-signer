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
import java.security.PublicKey;
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
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/** Creates the authority, issues signer certificates and validates them against the authority. */
public final class MiniCa {

    /** Largest certificate accepted, checked before reading it. */
    public static final long MAX_FILE_SIZE = 64 * 1024;

    /** Certificates are signed with RSASSA-PSS too, like the signatures. */
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSAandMGF1";
    private static final String PEM_TYPE = "CERTIFICATE";

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
                    builder.build(new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).build(issuerKey)));
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

    /** PEM text of a certificate. */
    public static byte[] toPem(X509Certificate certificate) throws CertificateException {
        String body = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                .encodeToString(certificate.getEncoded());
        return ("-----BEGIN " + PEM_TYPE + "-----\n" + body + "\n-----END " + PEM_TYPE + "-----\n")
                .getBytes(StandardCharsets.US_ASCII);
    }

    /** Reads a single PEM certificate, with the same size limit as the other inputs. */
    public static X509Certificate read(Path file) throws IOException, CertificateException {
        String text = new String(SafeFileReader.read(file, MAX_FILE_SIZE), StandardCharsets.US_ASCII).strip();
        String begin = "-----BEGIN " + PEM_TYPE + "-----";
        String end = "-----END " + PEM_TYPE + "-----";
        if (!text.startsWith(begin) || !text.endsWith(end) || text.indexOf(begin, 1) != -1) {
            throw new CertificateException(file + " is not a single PEM certificate");
        }
        byte[] der;
        try {
            der = Base64.getMimeDecoder().decode(text.substring(begin.length(), text.length() - end.length()));
        } catch (IllegalArgumentException e) {
            throw new CertificateException(file + " is not valid PEM", e);
        }
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(der));
    }
}
