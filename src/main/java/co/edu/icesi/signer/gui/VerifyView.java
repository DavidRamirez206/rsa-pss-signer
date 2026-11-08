package co.edu.icesi.signer.gui;

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
            // Notes and policy reasons come from the services, which only speak English
            case VALID -> {
                List<String> lines = new ArrayList<>(List.of(t("verify.valid.detail")));
                lines.addAll(outcome.notes());
                result.show(Tone.SUCCESS, t("verify.valid"), lines, outcome.keyFingerprint(), t("verify.valid.note"));
            }
            case INVALID -> result.show(Tone.DANGER, t("verify.invalid"),
                    List.of(VerificationService.MISMATCH.equals(outcome.detail())
                            ? t("verify.invalid.detail") : outcome.detail()),
                    outcome.keyFingerprint(), t("verify.invalid.note"));
            // The technical detail comes from the services, which only speak English
            case ERROR -> result.show(Tone.CAUTION, t("verify.error"), List.of(outcome.detail()),
                    outcome.keyFingerprint(), t("verify.error.note"));
        }
    }
}
