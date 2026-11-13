package co.edu.icesi.signer.gui;

import javax.swing.JOptionPane;
import java.util.function.Predicate;
import co.edu.icesi.signer.core.Message;
import static co.edu.icesi.signer.gui.I18n.t;

import co.edu.icesi.signer.core.VerificationOutcome;
import co.edu.icesi.signer.crypto.VerificationService;
import co.edu.icesi.signer.gui.ResultCard.Tone;
import co.edu.icesi.signer.gui.Widgets.PrimaryButton;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** Verifies a file against its signature and a public key. No password is involved. */
final class VerifyView extends View {
    private static final long serialVersionUID = 1L;

    final FilePicker file = new FilePicker(t("verify.file.placeholder"), false);
    final FilePicker signature = new FilePicker(t("verify.signature.placeholder"), false);
    final FilePicker publicKey = new FilePicker(t("verify.key.placeholder"), false);

    private final PrimaryButton verify = new PrimaryButton(t("verify.submit"));

    /** Asks whether to forget the key pinned for a signer; replaced in tests. */
    Predicate<String> confirmForget = this::askToForget;

    VerifyView(GuiActions actions) {
        super(actions, t("verify.title"), t("verify.subtitle"));

        row(Widgets.field(t("verify.file"), file));
        row(Widgets.field(t("verify.signature"), signature));
        row(Widgets.field(t("verify.key"), publicKey));
        row(verify);

        file.onChange(this::suggestSignature);
        verify.addActionListener(event -> submit());
    }

    /** Fills in {@code <file>.sig} when it exists and the field is still empty. */
    private void suggestSignature() {
        if (!signature.value().isBlank()) {
            return;
        }
        try {
            Path candidate = Path.of(file.value().strip() + ".sig");
            if (Files.isRegularFile(candidate)) {
                javax.swing.SwingUtilities.invokeLater(() -> signature.value(candidate.toString()));
            }
        } catch (InvalidPathException e) {
            // Still being typed: there is nothing to suggest yet
        }
    }

    private void submit() {
        String input = file.value();
        String sig = signature.value();
        String pub = publicKey.value();
        run(verify, () -> actions.verify(input, sig, pub), this::present);
    }

    void present(VerificationOutcome outcome) {
        switch (outcome.result()) {
            case VALID -> {
                List<String> lines = new ArrayList<>(List.of(t("verify.valid.detail")));
                outcome.messages().forEach(message -> lines.add(t(message)));
                result.show(Tone.SUCCESS, t("verify.valid"), lines, outcome.keyFingerprint(), t("verify.valid.note"));
            }
            case INVALID -> {
                String detail = outcome.reason() != null ? t(outcome.reason())
                        : VerificationService.MISMATCH.equals(outcome.detail()) ? t("verify.invalid.detail")
                        : outcome.detail();
                Message reason = outcome.reason();
                if (reason != null && reason.key().equals("reason.key.changed")) {
                    String signer = String.valueOf(reason.args().get(0));
                    result.show(Tone.DANGER, t("verify.invalid"), List.of(detail), outcome.keyFingerprint(),
                            t("verify.invalid.note"), t("verify.forget", signer), () -> forget(signer));
                } else {
                    result.show(Tone.DANGER, t("verify.invalid"), List.of(detail), outcome.keyFingerprint(),
                            t("verify.invalid.note"));
                }
            }
            // A technical detail comes from the services, which only speak English
            case ERROR -> result.show(Tone.CAUTION, t("verify.error"),
                    List.of(outcome.reason() != null ? t(outcome.reason()) : outcome.detail()),
                    outcome.keyFingerprint(), t("verify.error.note"));
        }
    }

    private void forget(String signer) {
        if (!confirmForget.test(signer)) {
            return;
        }
        try {
            actions.forget(signer);
            result.show(Tone.SUCCESS, t("verify.forgotten"), List.of(t("verify.forgotten.detail", signer)), null, null);
        } catch (GuiActions.ActionFailure e) {
            result.show(Tone.CAUTION, t("common.failed"), List.of(e.getMessage()), null, null);
        }
    }

    private boolean askToForget(String signer) {
        Object[] options = {t("verify.forget.confirm"), t("common.cancel")};
        int choice = JOptionPane.showOptionDialog(this, t("verify.forget.message", signer), t("verify.forget.title"),
                JOptionPane.DEFAULT_OPTION, JOptionPane.WARNING_MESSAGE, null, options, options[1]);
        return choice == 0;
    }
}
