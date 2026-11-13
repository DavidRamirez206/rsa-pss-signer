package co.edu.icesi.signer.policy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import co.edu.icesi.signer.core.VerificationOutcome;
import co.edu.icesi.signer.core.VerificationResult;
import co.edu.icesi.signer.crypto.HashAlg;
import co.edu.icesi.signer.crypto.KeyPairService;
import co.edu.icesi.signer.crypto.SigningService;
import co.edu.icesi.signer.crypto.SigningService.Chain;
import co.edu.icesi.signer.format.SigFile;
import co.edu.icesi.signer.keystore.PublicKeyStore;
import co.edu.icesi.signer.policy.PolicyVerifier.Request;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateCrtKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PolicyVerifierTest {

    static final Clock CLOCK = Clock.fixed(Instant.parse("2026-11-08T15:00:00Z"), ZoneOffset.UTC);

    private static KeyPair ana;
    private static KeyPair mallory;

    @TempDir
    Path dir;

    private LocalState state;
    private PolicyVerifier verifier;
    private Path contract;
    private Path anaPub;
    private Path malloryPub;

    @BeforeAll
    static void keys() {
        ana = KeyPairService.generate(2048);
        mallory = KeyPairService.generate(2048);
    }

    @BeforeEach
    void setUp() throws Exception {
        state = new LocalState(dir.resolve("state"));
        verifier = new PolicyVerifier(state, CLOCK);
        contract = Files.writeString(dir.resolve("contract.txt"), "version one");
        anaPub = dir.resolve("ana.pub");
        malloryPub = dir.resolve("mallory.pub");
        PublicKeyStore.write(ana.getPublic(), anaPub);
        PublicKeyStore.write(mallory.getPublic(), malloryPub);
    }

    private Path sign(KeyPair keys, String signer, Chain chain, String sigName) throws Exception {
        SigFile sig = SigningService.sign(contract, (RSAPrivateCrtKey) keys.getPrivate(), HashAlg.SHA_256, signer,
                SigningService.timestamp(CLOCK), chain);
        return Files.write(dir.resolve(sigName), sig.toJson());
    }

    private Path sign(KeyPair keys, String signer, String sigName) throws Exception {
        return sign(keys, signer, Chain.FIRST, sigName);
    }

    private VerificationOutcome verify(Path sig, Path pub) {
        return verifier.verify(Request.of(contract, sig, pub));
    }

    private static void assertResult(VerificationResult expected, String detailPart, VerificationOutcome outcome) {
        assertEquals(expected, outcome.result(), outcome.detail());
        assertTrue(outcome.detail().contains(detailPart), outcome.detail());
    }

    private static boolean noted(VerificationOutcome outcome, String part) {
        return outcome.notes().stream().anyMatch(note -> note.contains(part));
    }

    // T-4.1b: trust on first use
    @Test
    void theFirstKeySeenForASignerIsPinned() throws Exception {
        VerificationOutcome outcome = verify(sign(ana, "Ana", "a.sig"), anaPub);

        assertEquals(VerificationResult.VALID, outcome.result(), outcome.detail());
        assertTrue(noted(outcome, "now pinned"), outcome.notes().toString());
        assertEquals(KeyPairService.fingerprint(ana.getPublic()), new TrustStore(state).pinned("Ana").orElseThrow());

        assertTrue(noted(verify(dir.resolve("a.sig"), anaPub), "Same key"));
    }

    // T-4.1b: Mallory signs as Ana and hands over her own key
    @Test
    void anotherKeyUnderAPinnedNameIsFlagged() throws Exception {
        verify(sign(ana, "Ana", "a.sig"), anaPub);

        VerificationOutcome outcome = verify(sign(mallory, "Ana", "m.sig"), malloryPub);

        assertResult(VerificationResult.INVALID, "changed", outcome);
        assertEquals(KeyPairService.fingerprint(ana.getPublic()), new TrustStore(state).pinned("Ana").orElseThrow());
    }

    @Test
    void removingAPinAcceptsTheNextKey() throws Exception {
        verify(sign(ana, "Ana", "a.sig"), anaPub);
        assertTrue(new TrustStore(state).remove("Ana"));
        assertFalse(new TrustStore(state).remove("Ana"));

        assertEquals(VerificationResult.VALID, verify(sign(mallory, "Ana", "m.sig"), malloryPub).result());
    }

    // The limit of trust on first use: whoever comes first is believed
    @Test
    void ifMalloryComesFirstHerKeyIsPinned() throws Exception {
        assertEquals(VerificationResult.VALID, verify(sign(mallory, "Ana", "m.sig"), malloryPub).result());

        assertResult(VerificationResult.INVALID, "changed", verify(sign(ana, "Ana", "a.sig"), anaPub));
    }

    @Test
    void aFailedSignatureChangesNoState() throws Exception {
        Path sig = sign(ana, "Ana", "a.sig");
        Files.writeString(contract, "tampered");

        assertEquals(VerificationResult.INVALID, verify(sig, anaPub).result());

        assertTrue(new TrustStore(state).all().isEmpty());
        assertEquals(0, new VersionStore(state).highestSeen(KeyPairService.fingerprint(ana.getPublic()), "contract.txt"));
    }

    // T-2.3': by decision only the content counts, so renaming stays valid; the signed name stays visible
    @Test
    void renamingTheFileStaysValid() throws Exception {
        Path sig = sign(ana, "Ana", "a.sig");
        Path renamed = Files.move(contract, dir.resolve("contract_final.txt"));

        VerificationOutcome outcome = verifier.verify(Request.of(renamed, sig, anaPub));

        assertEquals(VerificationResult.VALID, outcome.result(), outcome.detail());
        assertTrue(noted(outcome, "of contract.txt"), outcome.notes().toString());
    }

    // T-2.6': replay of an old version
    @Test
    void anOldVersionIsRejectedOnceANewerOneWasVerified() throws Exception {
        Path v1 = sign(ana, "Ana", "v1.sig");
        Files.writeString(contract, "version two");
        Path v2 = sign(ana, "Ana", Chain.after(Files.readAllBytes(v1)), "v2.sig");

        VerificationOutcome current = verify(v2, anaPub);
        assertEquals(VerificationResult.VALID, current.result(), current.detail());
        assertTrue(noted(current, "Document version 2"), current.notes().toString());

        Files.writeString(contract, "version one");
        assertResult(VerificationResult.INVALID, "Outdated version", verify(v1, anaPub));
    }

    // The limit: without that state, an old version is valid again
    @Test
    void withoutLocalStateAnOldVersionVerifiesAgain() throws Exception {
        Path v1 = sign(ana, "Ana", "v1.sig");
        Files.writeString(contract, "version two");
        verify(sign(ana, "Ana", Chain.after(Files.readAllBytes(v1)), "v2.sig"), anaPub);

        Files.writeString(contract, "version one");
        PolicyVerifier elsewhere = new PolicyVerifier(new LocalState(dir.resolve("other machine")), CLOCK);

        assertEquals(VerificationResult.VALID, elsewhere.verify(Request.of(contract, v1, anaPub)).result());
    }

    @Test
    void theNewestVersionKeepsVerifying() throws Exception {
        Path v1 = sign(ana, "Ana", "v1.sig");

        assertEquals(VerificationResult.VALID, verify(v1, anaPub).result());
        assertEquals(VerificationResult.VALID, verify(v1, anaPub).result());
    }

    @Test
    void theChainToThePreviousSignatureIsChecked() throws Exception {
        Path v1 = sign(ana, "Ana", "v1.sig");
        Path unrelated = sign(ana, "Ana", "unrelated.sig");
        Files.writeString(contract, "version two");
        Path v2 = sign(ana, "Ana", Chain.after(Files.readAllBytes(v1)), "v2.sig");

        VerificationOutcome follows = verifier.verify(new Request(contract, v2, new PolicyVerifier.PublicKeyFile(anaPub),
                null, v1, null, null));
        assertEquals(VerificationResult.VALID, follows.result(), follows.detail());
        assertTrue(noted(follows, "Follows v1.sig"));

        assertResult(VerificationResult.INVALID, "does not follow", verifier.verify(new Request(contract, v2,
                new PolicyVerifier.PublicKeyFile(anaPub), null, unrelated, null, null)));
    }

    @Test
    void aChainThatSkipsVersionsIsFlagged() throws Exception {
        Path v1 = sign(ana, "Ana", "v1.sig");
        Chain next = Chain.after(Files.readAllBytes(v1));
        Path skipped = sign(ana, "Ana", new Chain(5, next.prevSigHash(), next.keyFingerprint()), "v5.sig");

        assertResult(VerificationResult.INVALID, "instead of 2", verifier.verify(new Request(contract, skipped,
                new PolicyVerifier.PublicKeyFile(anaPub), null, v1, null, null)));
    }

    @Test
    void signingRefusesToChainToAnotherKeysSignature() throws Exception {
        Path v1 = sign(ana, "Ana", "v1.sig");

        Exception e = org.junit.jupiter.api.Assertions.assertThrows(java.security.InvalidKeyException.class,
                () -> sign(mallory, "Ana", Chain.after(Files.readAllBytes(v1)), "m.sig"));
        assertTrue(e.getMessage().contains("another key"), e.getMessage());
    }

    // Type 2, level a: the fingerprint received through another channel
    @Test
    void theExpectedFingerprintIsCompared() throws Exception {
        Path sig = sign(ana, "Ana", "a.sig");
        String spoken = KeyPairService.fingerprint(ana.getPublic()).replace(":", " ").toLowerCase();

        VerificationOutcome matching = verifier.verify(new Request(contract, sig,
                new PolicyVerifier.PublicKeyFile(anaPub), spoken, null, null, null));
        assertEquals(VerificationResult.VALID, matching.result(), matching.detail());

        Path forged = sign(mallory, "Ana", "m.sig");
        assertResult(VerificationResult.INVALID, "not the one you expected", verifier.verify(new Request(contract,
                forged, new PolicyVerifier.PublicKeyFile(malloryPub), spoken, null, null, null)));
    }

    @Test
    void unusableStateIsAnError() throws Exception {
        Path sig = sign(ana, "Ana", "a.sig");
        Files.writeString(dir.resolve("blocked"), "a file where the state directory should be");
        PolicyVerifier blocked = new PolicyVerifier(new LocalState(dir.resolve("blocked")), CLOCK);

        assertResult(VerificationResult.ERROR, "Could not complete the checks",
                blocked.verify(Request.of(contract, sig, anaPub)));
    }
}
