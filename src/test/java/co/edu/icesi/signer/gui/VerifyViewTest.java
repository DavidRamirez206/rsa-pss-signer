package co.edu.icesi.signer.gui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import co.edu.icesi.signer.core.Message;
import co.edu.icesi.signer.core.VerificationOutcome;
import co.edu.icesi.signer.core.VerificationResult;
import co.edu.icesi.signer.crypto.VerificationService;
import co.edu.icesi.signer.keystore.PrivateKeyStore;
import co.edu.icesi.signer.policy.LocalState;
import co.edu.icesi.signer.policy.TestState;
import co.edu.icesi.signer.policy.TrustStore;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import javax.swing.SwingUtilities;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class VerifyViewTest {

    private static final Message CHANGED = Message.of("reason.key.changed", "Ana Perez", "AA", "BB");

    private LocalState state;
    private VerifyView view;

    @BeforeEach
    void build() throws Exception {
        I18n.use(I18n.Language.ENGLISH);
        state = TestState.fresh();
        SwingUtilities.invokeAndWait(() -> {
            Theme.install();
            view = new VerifyView(new GuiActions(new PrivateKeyStore(1000), Clock.systemUTC(), state));
        });
    }

    @AfterEach
    void english() {
        I18n.use(I18n.Language.ENGLISH);
    }

    private List<String> shown(VerificationOutcome outcome) throws Exception {
        List<List<String>> lines = new ArrayList<>();
        SwingUtilities.invokeAndWait(() -> {
            view.present(outcome);
            lines.add(view.result.lines());
        });
        return lines.get(0);
    }

    private static VerificationOutcome valid(Message... notes) {
        return new VerificationOutcome(VerificationResult.VALID, "ok", "AB", List.of(notes), null);
    }

    @Test
    void aValidResultListsTheNotes() throws Exception {
        assertEquals(List.of("The signature is valid.", "Document version 2 of a.txt."),
                shown(valid(Message.of("note.version", 2, "a.txt"))));
    }

    @Test
    void theNotesFollowTheChosenLanguage() throws Exception {
        I18n.use(I18n.Language.SPANISH);
        assertEquals(List.of(I18n.t("verify.valid.detail"), "Versión 2 del documento a.txt."),
                shown(valid(Message.of("note.version", 2, "a.txt"))));
    }

    @Test
    void aCryptographicMismatchUsesTheTranslatedText() throws Exception {
        assertEquals(List.of(I18n.t("verify.invalid.detail")),
                shown(new VerificationOutcome(VerificationResult.INVALID, VerificationService.MISMATCH, "AB")));
    }

    // Otherwise "the signature does not match" would hide why: an old version, a changed key
    @Test
    void aPolicyReasonIsShownInTheChosenLanguage() throws Exception {
        Message outdated = Message.of("reason.outdated", 1, "a.txt", 2);
        assertEquals(List.of(outdated.english()),
                shown(VerificationOutcome.because(VerificationResult.INVALID, outdated, "AB")));
        I18n.use(I18n.Language.SPANISH);
        assertEquals(List.of("Versión desactualizada: esta es la versión 1 de a.txt, pero en este equipo ya se"
                + " verificó la versión 2"), shown(VerificationOutcome.because(VerificationResult.INVALID, outdated, "AB")));
    }

    @Test
    void anUntranslatedDetailIsShownAsIs() throws Exception {
        assertEquals(List.of("Could not read the signature file: x"),
                shown(new VerificationOutcome(VerificationResult.ERROR, "Could not read the signature file: x", null)));
    }

    @Test
    void onlyAChangedKeyOffersToForgetIt() throws Exception {
        shown(VerificationOutcome.because(VerificationResult.INVALID, Message.of("reason.outdated", 1, "a", 2), "AB"));
        assertNull(view.result.action());
        shown(VerificationOutcome.because(VerificationResult.INVALID, CHANGED, "BB"));
        assertNotNull(view.result.action());
        assertEquals(I18n.t("verify.forget", "Ana Perez"), view.result.action().getText());
    }

    @Test
    void forgettingNeedsConfirmation() throws Exception {
        new TrustStore(state).pin("Ana Perez", "AA");
        shown(VerificationOutcome.because(VerificationResult.INVALID, CHANGED, "BB"));
        AtomicReference<String> asked = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            view.confirmForget = signer -> {
                asked.set(signer);
                return false;
            };
            view.result.action().doClick();
        });
        assertEquals("Ana Perez", asked.get());
        assertTrue(new TrustStore(state).pinned("Ana Perez").isPresent(), "cancelled: still pinned");

        SwingUtilities.invokeAndWait(() -> {
            view.confirmForget = signer -> true;
            view.result.action().doClick();
        });
        assertTrue(new TrustStore(state).pinned("Ana Perez").isEmpty());
        assertEquals(ResultCard.Tone.SUCCESS, view.result.tone());
        assertEquals(List.of(I18n.t("verify.forgotten.detail", "Ana Perez")), view.result.lines());
    }
}
