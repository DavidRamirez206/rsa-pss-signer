package co.edu.icesi.signer.policy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import co.edu.icesi.signer.core.VerificationOutcome;
import co.edu.icesi.signer.core.VerificationResult;
import co.edu.icesi.signer.crypto.HashAlg;
import co.edu.icesi.signer.crypto.KeyPairService;
import co.edu.icesi.signer.crypto.SigningService;
import co.edu.icesi.signer.format.SigFile;
import co.edu.icesi.signer.keystore.PublicKeyStore;
import co.edu.icesi.signer.pki.MiniCa;
import co.edu.icesi.signer.policy.PolicyVerifier.Certificate;
import co.edu.icesi.signer.policy.PolicyVerifier.PublicKeyFile;
import co.edu.icesi.signer.policy.PolicyVerifier.Request;
import co.edu.icesi.signer.timestamp.TimeAuthority;
import co.edu.icesi.signer.timestamp.TimeToken;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Type 2 limits: trust moved to a certificate authority or a time-stamping authority. */
class ThirdPartyChecksTest {

    private static final Clock CLOCK = PolicyVerifierTest.CLOCK;

    private static KeyPair ana;
    private static KeyPair authority;
    private static KeyPair rogue;
    private static KeyPair timeKeys;

    @TempDir
    Path dir;

    private PolicyVerifier verifier;
    private Path contract;
    private Path sig;
    private Path caFile;

    @BeforeAll
    static void keys() {
        ana = KeyPairService.generate(2048);
        authority = KeyPairService.generate(2048);
        rogue = KeyPairService.generate(2048);
        timeKeys = KeyPairService.generate(2048);
    }

    @BeforeEach
    void setUp() throws Exception {
        verifier = new PolicyVerifier(new LocalState(dir.resolve("state")), CLOCK);
        contract = Files.writeString(dir.resolve("contract.txt"), "terms");
        SigFile signed = SigningService.sign(contract, (RSAPrivateCrtKey) ana.getPrivate(), HashAlg.SHA_256,
                "Ana Perez", SigningService.timestamp(CLOCK));
        sig = Files.write(dir.resolve("contract.txt.sig"), signed.toJson());
        caFile = Files.write(dir.resolve("ca.crt"), MiniCa.toPem(ca(authority, "Demo CA")));
    }

    private static X509Certificate ca(KeyPair keys, String name) throws Exception {
        return MiniCa.createAuthority(name, keys.getPublic(), keys.getPrivate(), Duration.ofDays(30), CLOCK);
    }

    private Path issue(KeyPair issuerKeys, X509Certificate issuer, String name, KeyPair subject, Duration validity)
            throws Exception {
        X509Certificate certificate = MiniCa.issue(issuer, issuerKeys.getPrivate(), name,
                (RSAPublicKey) subject.getPublic(), validity, CLOCK);
        return Files.write(dir.resolve(name.replace(' ', '_') + ".crt"), MiniCa.toPem(certificate));
    }

    private VerificationOutcome verifyWithCertificate(Path certificate, Clock clock) {
        return new PolicyVerifier(new LocalState(dir.resolve("state")), clock)
                .verify(new Request(contract, sig, new Certificate(certificate, caFile), null, null, null, null));
    }

    private static void assertResult(VerificationResult expected, String detailPart, VerificationOutcome outcome) {
        assertEquals(expected, outcome.result(), outcome.detail());
        assertTrue(outcome.detail().contains(detailPart), outcome.detail());
    }

    // Type 2, level c: the authority vouches for the key
    @Test
    void aCertificateFromTheAuthorityVouchesForTheSigner() throws Exception {
        Path certificate = issue(authority, MiniCa.read(caFile), "Ana Perez", ana, Duration.ofDays(10));

        VerificationOutcome outcome = verifyWithCertificate(certificate, CLOCK);

        assertEquals(VerificationResult.VALID, outcome.result(), outcome.detail());
        assertTrue(outcome.notes().stream().anyMatch(n -> n.contains("issued by \"Demo CA\"")), outcome.notes().toString());
        // The authority, not first use, decides: nothing is pinned
        assertTrue(new TrustStore(new LocalState(dir.resolve("state"))).all().isEmpty());
    }

    @Test
    void aCertificateFromAnotherAuthorityIsAnError() throws Exception {
        Path certificate = issue(rogue, ca(rogue, "Demo CA"), "Ana Perez", ana, Duration.ofDays(10));

        assertResult(VerificationResult.ERROR, "not issued by this authority", verifyWithCertificate(certificate, CLOCK));
    }

    @Test
    void aCertificateForAnotherNameIsInvalid() throws Exception {
        Path certificate = issue(authority, MiniCa.read(caFile), "Bob", ana, Duration.ofDays(10));

        assertResult(VerificationResult.INVALID, "is for \"Bob\"", verifyWithCertificate(certificate, CLOCK));
    }

    @Test
    void anExpiredCertificateIsAnError() throws Exception {
        Path certificate = issue(authority, MiniCa.read(caFile), "Ana Perez", ana, Duration.ofDays(1));

        Clock later = Clock.offset(CLOCK, Duration.ofDays(2));
        assertResult(VerificationResult.ERROR, "not valid now", verifyWithCertificate(certificate, later));
    }

    @Test
    void theAuthorityCertificateIsNotASignerCertificate() {
        assertResult(VerificationResult.ERROR, "belongs to an authority", verifyWithCertificate(caFile, CLOCK));
    }

    @Test
    void aCertificateForAnotherKeyDoesNotVerifyTheSignature() throws Exception {
        Path certificate = issue(authority, MiniCa.read(caFile), "Ana Perez", rogue, Duration.ofDays(10));

        assertEquals(VerificationResult.ERROR, verifyWithCertificate(certificate, CLOCK).result());
    }

    private Path stamp(byte[] stamped, KeyPair keys) throws Exception {
        TimeToken token = TimeAuthority.stamp(stamped, (RSAPrivateCrtKey) keys.getPrivate(), Clock.offset(CLOCK,
                Duration.ofMinutes(3)));
        return Files.write(dir.resolve("contract.txt.sig.tst"), token.toJson());
    }

    private VerificationOutcome verifyWithStamp(Path token, KeyPair authorityKeys) throws Exception {
        Path tsaPub = dir.resolve("tsa-" + System.nanoTime() + ".pub");
        PublicKeyStore.write(authorityKeys.getPublic(), tsaPub);
        return verifier.verify(new Request(contract, sig, new PublicKeyFile(writeAnaPub()), null, null, token, tsaPub));
    }

    private Path writeAnaPub() throws Exception {
        Path pub = dir.resolve("ana.pub");
        if (!Files.exists(pub)) {
            PublicKeyStore.write(ana.getPublic(), pub);
        }
        return pub;
    }

    // Type 2, signing time: the date comes from the authority, not from the signer
    @Test
    void aTimeStampShowsTheAuthoritysTime() throws Exception {
        VerificationOutcome outcome = verifyWithStamp(stamp(Files.readAllBytes(sig), timeKeys), timeKeys);

        assertEquals(VerificationResult.VALID, outcome.result(), outcome.detail());
        assertTrue(outcome.notes().stream().anyMatch(n -> n.contains("existed at 2026-11-08T15:03:00Z")),
                outcome.notes().toString());
    }

    @Test
    void aTimeStampOfAnotherSignatureIsInvalid() throws Exception {
        Path token = stamp("another signature".getBytes(StandardCharsets.UTF_8), timeKeys);

        assertResult(VerificationResult.INVALID, "another signature file", verifyWithStamp(token, timeKeys));
    }

    @Test
    void aTimeStampFromAnotherAuthorityIsInvalid() throws Exception {
        Path token = stamp(Files.readAllBytes(sig), rogue);

        assertResult(VerificationResult.INVALID, "not by the authority key", verifyWithStamp(token, timeKeys));
    }

    @Test
    void aBackdatedTimeStampIsInvalid() throws Exception {
        Path token = stamp(Files.readAllBytes(sig), timeKeys);
        Files.writeString(token, Files.readString(token).replace("2026-11-08T15:03:00Z", "2020-01-01T00:00:00Z"));

        assertResult(VerificationResult.INVALID, "does not verify", verifyWithStamp(token, timeKeys));
    }

    @Test
    void aMalformedTimeStampIsAnError() throws Exception {
        Path token = Files.writeString(dir.resolve("bad.tst"), "{\"version\": 1}");

        assertResult(VerificationResult.ERROR, "Missing field", verifyWithStamp(token, timeKeys));
    }

    @Test
    void aTimeStampWithoutTheAuthorityKeyIsAnError() throws Exception {
        Path token = stamp(Files.readAllBytes(sig), timeKeys);

        assertResult(VerificationResult.ERROR, "authority's public key", verifier.verify(
                new Request(contract, sig, new PublicKeyFile(writeAnaPub()), null, null, token, null)));
    }

    @Test
    void certificatesRoundTripThroughPem() throws Exception {
        X509Certificate read = MiniCa.read(caFile);

        assertEquals("Demo CA", MiniCa.commonName(read));
        assertEquals(KeyPairService.fingerprint(authority.getPublic()), KeyPairService.fingerprint(read.getPublicKey()));
    }
}
