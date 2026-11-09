package co.edu.icesi.signer.gui;

import static org.junit.jupiter.api.Assertions.assertEquals;

import co.edu.icesi.signer.core.VerificationOutcome;
import co.edu.icesi.signer.core.VerificationResult;
import co.edu.icesi.signer.crypto.VerificationService;
import co.edu.icesi.signer.keystore.PrivateKeyStore;
import co.edu.icesi.signer.policy.TestState;
import java.time.Clock;
import java.util.List;
import javax.swing.SwingUtilities;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class VerifyViewTest {

    private static VerifyView view;

    @BeforeAll
    static void build() throws Exception {
        I18n.use(I18n.Language.ENGLISH);
        SwingUtilities.invokeAndWait(() -> {
            Theme.install();
            view = new VerifyView(new GuiActions(new PrivateKeyStore(1000), Clock.systemUTC(), TestState.fresh()));
        });
    }

    private static List<String> shown(VerificationOutcome outcome) throws Exception {
        List<List<String>> lines = new java.util.ArrayList<>();
        SwingUtilities.invokeAndWait(() -> {
            view.present(outcome);
            lines.add(view.result.lines());
        });
        return lines.get(0);
    }

    @Test
    void aValidResultListsTheNotes() throws Exception {
        assertEquals(List.of("The signature is valid.", "Document version 2 of a.txt."),
                shown(new VerificationOutcome(VerificationResult.VALID, "ok", "AB",
                        List.of("Document version 2 of a.txt."))));
    }

    @Test
    void aCryptographicMismatchUsesTheTranslatedText() throws Exception {
        assertEquals(List.of(I18n.t("verify.invalid.detail")),
                shown(new VerificationOutcome(VerificationResult.INVALID, VerificationService.MISMATCH, "AB")));
    }

    // Otherwise "the signature does not match" would hide why: an old version, a changed key
    @Test
    void anyOtherReasonForInvalidIsShownAsIs() throws Exception {
        assertEquals(List.of("Outdated version: this is version 1"),
                shown(new VerificationOutcome(VerificationResult.INVALID, "Outdated version: this is version 1", "AB")));
    }
}
