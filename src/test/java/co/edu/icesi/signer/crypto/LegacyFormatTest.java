package co.edu.icesi.signer.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import co.edu.icesi.signer.core.VerificationOutcome;
import co.edu.icesi.signer.core.VerificationResult;
import co.edu.icesi.signer.format.CanonicalHeader;
import co.edu.icesi.signer.format.SigFile;
import co.edu.icesi.signer.keystore.PublicKeyStore;
import co.edu.icesi.signer.policy.LocalState;
import co.edu.icesi.signer.policy.PolicyVerifier;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.Signature;
import java.time.Clock;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Signatures in format 1, made by v0.1.0 to v0.3.0, keep verifying. */
class LegacyFormatTest {

    @TempDir
    Path dir;

    @Test
    void aFormatOneSignatureStillVerifiesAndSaysItHasNoVersion() throws Exception {
        KeyPair keys = KeyPairService.generate(2048);
        Path file = Files.writeString(dir.resolve("old.txt"), "signed with v0.3.0");
        CanonicalHeader header = new CanonicalHeader(1, HashAlg.SHA_256, 32, "MGF1", "SHA-256", 1,
                KeyPairService.fingerprint(keys.getPublic()), "old.txt", "Ana", "2026-11-04T10:00:00-05:00", 0, "");
        Signature signer = PssParams.newSignature(HashAlg.SHA_256);
        signer.initSign(keys.getPrivate());
        SignedMessage.update(signer, header, file);
        byte[] json = new SigFile(header, signer.sign()).toJson();
        assertTrue(new String(json).contains("\"version\" : 1"));
        assertTrue(!new String(json).contains("docVersion"));
        Path sig = Files.write(dir.resolve("old.txt.sig"), json);
        Path pub = dir.resolve("ana.pub");
        PublicKeyStore.write(keys.getPublic(), pub);

        assertEquals(VerificationResult.VALID, VerificationService.verify(file, sig, pub).result());
        VerificationOutcome outcome = new PolicyVerifier(new LocalState(dir.resolve("state")), Clock.systemUTC())
                .verify(PolicyVerifier.Request.of(file, sig, pub));
        assertEquals(VerificationResult.VALID, outcome.result(), outcome.detail());
        assertTrue(outcome.notes().stream().anyMatch(n -> n.contains("format 1 has no document version")));
    }
}
