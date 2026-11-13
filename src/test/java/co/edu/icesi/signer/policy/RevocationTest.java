package co.edu.icesi.signer.policy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import co.edu.icesi.signer.core.VerificationOutcome;
import co.edu.icesi.signer.core.VerificationResult;
import co.edu.icesi.signer.crypto.HashAlg;
import co.edu.icesi.signer.crypto.KeyPairService;
import co.edu.icesi.signer.crypto.SigningService;
import co.edu.icesi.signer.format.SigFile;
import co.edu.icesi.signer.pki.MiniCa;
import co.edu.icesi.signer.policy.PolicyVerifier.Certificate;
import co.edu.icesi.signer.policy.PolicyVerifier.Request;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.ZoneOffset;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** T-2.7: a certificate revoked by its authority stops vouching for its key. */
class RevocationTest {

    private static final Clock CLOCK = PolicyVerifierTest.CLOCK;
    private static final Clock LATER = Clock.offset(CLOCK, Duration.ofDays(31));

    private static KeyPair ana;
    private static KeyPair bob;
    private static KeyPair authorityKeys;
    private static KeyPair rogueKeys;
    private static X509Certificate authority;
    private static X509Certificate anaCertificate;
    private static X509Certificate bobCertificate;

    @TempDir
    Path dir;

    private Path contract;
    private Path sig;
    private Path caFile;
    private Path certFile;

    @BeforeAll
    static void keys() throws Exception {
        ana = KeyPairService.generate(2048);
        bob = KeyPairService.generate(2048);
        authorityKeys = KeyPairService.generate(2048);
        rogueKeys = KeyPairService.generate(2048);
        authority = MiniCa.createAuthority("Demo CA", authorityKeys.getPublic(), authorityKeys.getPrivate(),
                Duration.ofDays(365), CLOCK);
        anaCertificate = MiniCa.issue(authority, authorityKeys.getPrivate(), "Ana Perez",
                (RSAPublicKey) ana.getPublic(), Duration.ofDays(100), CLOCK);
        bobCertificate = MiniCa.issue(authority, authorityKeys.getPrivate(), "Bob",
                (RSAPublicKey) bob.getPublic(), Duration.ofDays(100), CLOCK);
    }

    @BeforeEach
    void setUp() throws Exception {
        contract = Files.writeString(dir.resolve("contract.txt"), "terms");
        SigFile signed = SigningService.sign(contract, (RSAPrivateCrtKey) ana.getPrivate(), HashAlg.SHA_256,
                "Ana Perez", SigningService.timestamp(CLOCK));
        sig = Files.write(dir.resolve("contract.txt.sig"), signed.toJson());
        caFile = Files.write(dir.resolve("ca.crt"), MiniCa.toPem(authority));
        certFile = Files.write(dir.resolve("ana.crt"), MiniCa.toPem(anaCertificate));
    }

    private static X509CRL list(X509CRL previous, X509Certificate revoke) throws Exception {
        return MiniCa.revocationList(authority, authorityKeys.getPrivate(), previous, revoke, Duration.ofDays(30),
                CLOCK);
    }

    private VerificationOutcome verify(X509CRL list, Clock clock) throws Exception {
        Path crl = list == null ? null : Files.write(dir.resolve("ca.crl"), MiniCa.toPem(list));
        return new PolicyVerifier(new LocalState(dir.resolve("state")), clock)
                .verify(new Request(contract, sig, new Certificate(certFile, caFile, crl), null, null, null, null));
    }

    @Test
    void aCertificateNotOnTheListIsValid() throws Exception {
        VerificationOutcome outcome = verify(list(null, bobCertificate), CLOCK);

        assertEquals(VerificationResult.VALID, outcome.result(), outcome.detail());
        assertTrue(outcome.notes().stream().anyMatch(n -> n.contains("not on the authority's revocation list")),
                outcome.notes().toString());
    }

    @Test
    void aRevokedCertificateIsInvalid() throws Exception {
        VerificationOutcome outcome = verify(list(list(null, bobCertificate), anaCertificate), CLOCK);

        assertEquals(VerificationResult.INVALID, outcome.result(), outcome.detail());
        assertEquals("reason.certificate.revoked", outcome.reason().key());
        assertEquals(KeyPairService.fingerprint(ana.getPublic()), outcome.keyFingerprint());
    }

    @Test
    void withoutAListRevocationIsNotChecked() throws Exception {
        VerificationOutcome outcome = verify(null, CLOCK);

        assertEquals(VerificationResult.VALID, outcome.result(), outcome.detail());
        assertTrue(outcome.notes().stream().anyMatch(n -> n.contains("Revocation was not checked")),
                outcome.notes().toString());
    }

    // Otherwise an attacker would keep serving the list from before the revocation
    @Test
    void anExpiredListIsAnError() throws Exception {
        VerificationOutcome outcome = verify(list(null, null), LATER);

        assertEquals(VerificationResult.ERROR, outcome.result(), outcome.detail());
        assertTrue(outcome.detail().contains("not current"), outcome.detail());
    }

    @Test
    void aListFromAnotherAuthorityIsAnError() throws Exception {
        X509Certificate rogue = MiniCa.createAuthority("Demo CA", rogueKeys.getPublic(), rogueKeys.getPrivate(),
                Duration.ofDays(30), CLOCK);
        X509CRL forged = MiniCa.revocationList(rogue, rogueKeys.getPrivate(), null, null, Duration.ofDays(30), CLOCK);

        VerificationOutcome outcome = verify(forged, CLOCK);

        assertEquals(VerificationResult.ERROR, outcome.result(), outcome.detail());
        assertTrue(outcome.detail().contains("not signed by this authority"), outcome.detail());
    }

    @Test
    void aListNamingAnotherIssuerIsAnError() throws Exception {
        X509Certificate renamed = MiniCa.createAuthority("Other CA", authorityKeys.getPublic(),
                authorityKeys.getPrivate(), Duration.ofDays(30), CLOCK);
        X509CRL list = MiniCa.revocationList(renamed, authorityKeys.getPrivate(), null, null, Duration.ofDays(30),
                CLOCK);

        VerificationOutcome outcome = verify(list, CLOCK);

        assertEquals(VerificationResult.ERROR, outcome.result(), outcome.detail());
        assertTrue(outcome.detail().contains("from another authority"), outcome.detail());
    }

    @Test
    void renewingKeepsTheRevokedEntriesOnce() throws Exception {
        X509CRL first = list(null, anaCertificate);
        X509CRL renewed = list(list(first, anaCertificate), null);

        assertEquals(1, renewed.getRevokedCertificates().size());
        assertTrue(renewed.isRevoked(anaCertificate));
        assertNull(renewed.getRevokedCertificate(bobCertificate));
    }

    @Test
    void onlyCertificatesOfTheAuthorityCanBeRevoked() throws Exception {
        X509Certificate rogue = MiniCa.createAuthority("Rogue", rogueKeys.getPublic(), rogueKeys.getPrivate(),
                Duration.ofDays(30), CLOCK);
        X509Certificate foreign = MiniCa.issue(rogue, rogueKeys.getPrivate(), "Ana Perez",
                (RSAPublicKey) ana.getPublic(), Duration.ofDays(10), CLOCK);

        assertThrows(CertificateException.class, () -> list(null, foreign));
    }

    @Test
    void revocationListsRoundTripThroughPem() throws Exception {
        Path file = Files.write(dir.resolve("x.crl"), MiniCa.toPem(list(null, anaCertificate)));

        assertTrue(MiniCa.readRevocationList(file).isRevoked(anaCertificate));
        assertThrows(CertificateException.class, () -> MiniCa.readRevocationList(caFile));
    }
}
