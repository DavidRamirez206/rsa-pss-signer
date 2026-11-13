package co.edu.icesi.signer.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import co.edu.icesi.signer.core.VerificationOutcome;
import co.edu.icesi.signer.core.VerificationResult;
import co.edu.icesi.signer.format.CanonicalHeader;
import co.edu.icesi.signer.format.SigFile;
import co.edu.icesi.signer.keystore.PublicKeyStore;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.Signature;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.List;
import java.util.function.UnaryOperator;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;

class SignVerifyTest {

    private static final String SIGNED_AT = "2026-10-28T11:30:00-05:00";

    private static KeyPair ana;
    private static KeyPair mallory;

    @TempDir
    Path dir;

    @BeforeAll
    static void generateKeys() {
        ana = KeyPairService.generate(2048);
        mallory = KeyPairService.generate(2048);
    }

    private static RSAPublicKey publicKey(KeyPair pair) {
        return (RSAPublicKey) pair.getPublic();
    }

    private static SigFile sign(Path file, KeyPair pair, HashAlg alg) throws IOException, GeneralSecurityException {
        return SigningService.sign(file, (RSAPrivateCrtKey) pair.getPrivate(), alg, "Ana Perez", SIGNED_AT);
    }

    private Path contract() throws IOException {
        return Files.writeString(dir.resolve("contract.txt"), "The parties agree to the terms.");
    }

    private static void assertResult(VerificationResult expected, VerificationOutcome outcome) {
        assertEquals(expected, outcome.result(), outcome.detail());
    }

    @ParameterizedTest
    @EnumSource(HashAlg.class)
    void validSignatureVerifies(HashAlg alg) throws Exception {
        Path file = contract();

        VerificationOutcome outcome = VerificationService.verify(file, sign(file, ana, alg), publicKey(ana));

        assertResult(VerificationResult.VALID, outcome);
        assertEquals(KeyPairService.fingerprint(ana.getPublic()), outcome.keyFingerprint());
    }

    @Test
    void headerRecordsTheSigningContext() throws Exception {
        CanonicalHeader header = sign(contract(), ana, HashAlg.SHA_256).header();

        assertEquals("contract.txt", header.fileName());
        assertEquals("Ana Perez", header.signerName());
        assertEquals(SIGNED_AT, header.signedAt());
        assertEquals(KeyPairService.fingerprint(ana.getPublic()), header.keyFingerprint());
    }

    @Test
    void fileNameInTheHeaderHasNoPath() throws Exception {
        Files.createDirectory(dir.resolve("nested"));
        Path file = Files.writeString(dir.resolve("nested").resolve("inner.txt"), "content");

        assertEquals("inner.txt", sign(file, ana, HashAlg.SHA_256).header().fileName());
    }

    @Test
    void signingRejectsControlCharactersInTheSignerName() throws Exception {
        Path file = contract();

        assertThrows(IllegalArgumentException.class, () -> SigningService.sign(
                file, (RSAPrivateCrtKey) ana.getPrivate(), HashAlg.SHA_256, "Ana\nsignedAt=2000", SIGNED_AT));
    }

    // T-2.1: one flipped bit at the start, middle and end
    @ParameterizedTest
    @ValueSource(strings = {"start", "middle", "end"})
    void flippedBitIsInvalid(String position) throws Exception {
        Path file = contract();
        SigFile sig = sign(file, ana, HashAlg.SHA_256);
        byte[] bytes = Files.readAllBytes(file);
        int index = position.equals("start") ? 0 : position.equals("middle") ? bytes.length / 2 : bytes.length - 1;
        bytes[index] ^= 1;
        Files.write(file, bytes);

        assertResult(VerificationResult.INVALID, VerificationService.verify(file, sig, publicKey(ana)));
    }

    // T-2.5: signature of a different file
    @Test
    void signatureOfAnotherFileIsInvalid() throws Exception {
        SigFile sig = sign(contract(), ana, HashAlg.SHA_256);
        Path other = Files.writeString(dir.resolve("other.txt"), "Different terms.");

        assertResult(VerificationResult.INVALID, VerificationService.verify(other, sig, publicKey(ana)));
    }

    // T-5.1: empty file
    @Test
    void emptyFileCanBeSignedAndOneMoreByteIsInvalid() throws Exception {
        Path file = Files.write(dir.resolve("empty.bin"), new byte[0]);
        SigFile sig = sign(file, ana, HashAlg.SHA_256);

        assertResult(VerificationResult.VALID, VerificationService.verify(file, sig, publicKey(ana)));

        Files.write(file, new byte[] {0});
        assertResult(VerificationResult.INVALID, VerificationService.verify(file, sig, publicKey(ana)));
    }

    // T-3.1': every signed field is covered by the signature
    @Test
    void mutatingAnySignedFieldIsInvalid() throws Exception {
        Path file = contract();
        SigFile sig = sign(file, ana, HashAlg.SHA_256);

        for (UnaryOperator<CanonicalHeader> mutation : List.<UnaryOperator<CanonicalHeader>>of(
                h -> copy(h, h.fileName() + "x", h.signerName(), h.signedAt()),
                h -> copy(h, h.fileName(), "Professor X", h.signedAt()),
                h -> copy(h, h.fileName(), h.signerName(), "2000-01-01T00:00:00Z"))) {
            SigFile tampered = new SigFile(mutation.apply(sig.header()), sig.signature());
            assertResult(VerificationResult.INVALID, VerificationService.verify(file, tampered, publicKey(ana)));
        }
    }

    private static CanonicalHeader copy(CanonicalHeader h, String fileName, String signerName, String signedAt) {
        return new CanonicalHeader(h.version(), h.hashAlg(), h.saltLen(), h.mgf(), h.mgfHash(), h.trailer(),
                h.keyFingerprint(), fileName, signerName, signedAt, h.docVersion(), h.prevSigHash());
    }

    @Test
    void mutatingThePssFieldsIsInvalid() throws Exception {
        Path file = contract();
        SigFile sig = sign(file, ana, HashAlg.SHA_256);
        CanonicalHeader h = sig.header();
        CanonicalHeader mutated = new CanonicalHeader(h.version(), h.hashAlg(), 20, h.mgf(), "SHA-1", h.trailer(),
                h.keyFingerprint(), h.fileName(), h.signerName(), h.signedAt(), h.docVersion(), h.prevSigHash());

        assertResult(VerificationResult.INVALID,
                VerificationService.verify(file, new SigFile(mutated, sig.signature()), publicKey(ana)));
    }

    // T-2.7b: the label says SHA-512, the signature was made with SHA-256
    @Test
    void relabeledHashIsInvalid() throws Exception {
        Path file = contract();
        SigFile sig = sign(file, ana, HashAlg.SHA_256);
        CanonicalHeader h = sig.header();
        CanonicalHeader relabeled = new CanonicalHeader(h.version(), HashAlg.SHA_512, 64, h.mgf(), "SHA-512",
                h.trailer(), h.keyFingerprint(), h.fileName(), h.signerName(), h.signedAt(), h.docVersion(), h.prevSigHash());

        assertResult(VerificationResult.INVALID,
                VerificationService.verify(file, new SigFile(relabeled, sig.signature()), publicKey(ana)));
    }

    // T-2.8: a PKCS#1 v1.5 signature over the same message must not verify
    @Test
    void pkcs1SignatureIsInvalid() throws Exception {
        Path file = contract();
        SigFile sig = sign(file, ana, HashAlg.SHA_256);
        Signature pkcs1 = Signature.getInstance("SHA256withRSA");
        pkcs1.initSign(ana.getPrivate());
        SignedMessage.update(pkcs1, sig.header(), file);

        assertResult(VerificationResult.INVALID,
                VerificationService.verify(file, new SigFile(sig.header(), pkcs1.sign()), publicKey(ana)));
    }

    // T-2.4: garbage of the right length is never VALID
    @ParameterizedTest
    @ValueSource(ints = {0x00, 0xFF, 0x5A})
    void garbageSignatureIsNotValid(int fill) throws Exception {
        Path file = contract();
        SigFile sig = sign(file, ana, HashAlg.SHA_256);
        byte[] garbage = new byte[sig.signature().length];
        Arrays.fill(garbage, (byte) fill);

        VerificationOutcome outcome = VerificationService.verify(file, new SigFile(sig.header(), garbage), publicKey(ana));

        assertEquals(VerificationResult.INVALID, outcome.result());
    }

    // T-2.4: a wrong length is rejected before touching the cryptography
    @ParameterizedTest
    @ValueSource(ints = {0, 255, 257, 1024})
    void signatureOfTheWrongLengthIsAnError(int length) throws Exception {
        Path file = contract();
        SigFile sig = sign(file, ana, HashAlg.SHA_256);

        assertResult(VerificationResult.ERROR,
                VerificationService.verify(file, new SigFile(sig.header(), new byte[length]), publicKey(ana)));
    }

    // Wrong key: says which key signed, and does not claim the file was modified
    @Test
    void verifyingWithAnotherKeyIsAnErrorNamingTheSigningKey() throws Exception {
        Path file = contract();

        VerificationOutcome outcome = VerificationService.verify(file, sign(file, ana, HashAlg.SHA_256), publicKey(mallory));

        assertResult(VerificationResult.ERROR, outcome);
        assertTrue(outcome.detail().contains(KeyPairService.fingerprint(ana.getPublic())), outcome.detail());
        assertEquals(KeyPairService.fingerprint(mallory.getPublic()), outcome.keyFingerprint());
    }

    // T-3.6: declared fingerprint altered
    @Test
    void forgedFingerprintDeclarationIsAnError() throws Exception {
        Path file = contract();
        SigFile sig = sign(file, ana, HashAlg.SHA_256);
        CanonicalHeader h = sig.header();
        CanonicalHeader forged = new CanonicalHeader(h.version(), h.hashAlg(), h.saltLen(), h.mgf(), h.mgfHash(),
                h.trailer(), KeyPairService.fingerprint(mallory.getPublic()), h.fileName(), h.signerName(),
                h.signedAt(), h.docVersion(), h.prevSigHash());

        assertResult(VerificationResult.ERROR,
                VerificationService.verify(file, new SigFile(forged, sig.signature()), publicKey(ana)));
    }

    // T-4.1: Mallory signs with her own key and hands over her public key. The math
    // says VALID; the defense is that the displayed fingerprint is not Ana's.
    @Test
    void keySubstitutionIsValidButShowsADifferentFingerprint() throws Exception {
        Path file = contract();

        VerificationOutcome outcome = VerificationService.verify(file, sign(file, mallory, HashAlg.SHA_256), publicKey(mallory));

        assertResult(VerificationResult.VALID, outcome);
        assertNotEquals(KeyPairService.fingerprint(ana.getPublic()), outcome.keyFingerprint());
    }

    @Test
    void missingSignedFileIsAnError() throws Exception {
        SigFile sig = sign(contract(), ana, HashAlg.SHA_256);

        assertResult(VerificationResult.ERROR,
                VerificationService.verify(dir.resolve("missing.txt"), sig, publicKey(ana)));
    }

    @Test
    void filesOnDiskVerify() throws Exception {
        Path file = contract();
        Path sigFile = Files.write(dir.resolve("contract.sig"), sign(file, ana, HashAlg.SHA_256).toJson());
        Path pub = dir.resolve("ana.pub");
        PublicKeyStore.write(ana.getPublic(), pub);

        assertResult(VerificationResult.VALID, VerificationService.verify(file, sigFile, pub));
    }

    @Test
    void editingSignerNameInTheJsonIsInvalid() throws Exception {
        Path file = contract();
        String json = new String(sign(file, ana, HashAlg.SHA_256).toJson(), StandardCharsets.UTF_8);
        assertTrue(json.contains("Ana Perez"));
        Path sigFile = Files.writeString(dir.resolve("contract.sig"), json.replace("Ana Perez", "Professor X"));
        Path pub = dir.resolve("ana.pub");
        PublicKeyStore.write(ana.getPublic(), pub);

        assertResult(VerificationResult.INVALID, VerificationService.verify(file, sigFile, pub));
    }

    @Test
    void unreadableInputsAreErrors() throws Exception {
        Path file = contract();
        Path sigFile = Files.write(dir.resolve("contract.sig"), sign(file, ana, HashAlg.SHA_256).toJson());
        Path pub = dir.resolve("ana.pub");
        PublicKeyStore.write(ana.getPublic(), pub);
        Path badSig = Files.writeString(dir.resolve("bad.sig"), "not json");
        Path badPub = Files.writeString(dir.resolve("bad.pub"), "not a key");

        assertResult(VerificationResult.ERROR, VerificationService.verify(file, dir.resolve("missing.sig"), pub));
        assertResult(VerificationResult.ERROR, VerificationService.verify(file, badSig, pub));

        VerificationOutcome noKey = VerificationService.verify(file, sigFile, badPub);
        assertResult(VerificationResult.ERROR, noKey);
        assertNull(noKey.keyFingerprint());
        assertResult(VerificationResult.ERROR, VerificationService.verify(file, sigFile, dir.resolve("missing.pub")));
    }

    // T-6.2: PSS is randomized, and both signatures verify
    @Test
    void twoSignaturesOfTheSameFileDifferAndBothVerify() throws Exception {
        Path file = contract();
        SigFile first = sign(file, ana, HashAlg.SHA_256);
        SigFile second = sign(file, ana, HashAlg.SHA_256);

        assertFalse(Arrays.equals(first.signature(), second.signature()));
        assertResult(VerificationResult.VALID, VerificationService.verify(file, first, publicKey(ana)));
        assertResult(VerificationResult.VALID, VerificationService.verify(file, second, publicKey(ana)));
    }
}
