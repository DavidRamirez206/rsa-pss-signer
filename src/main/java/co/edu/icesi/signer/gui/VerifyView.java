package co.edu.icesi.signer.gui;

import co.edu.icesi.signer.core.VerificationOutcome;
import co.edu.icesi.signer.gui.ResultCard.Tone;
import co.edu.icesi.signer.gui.Widgets.PrimaryButton;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.List;

/** Verifies a file against its signature and a public key. No password is involved. */
final class VerifyView extends View {
    private static final long serialVersionUID = 1L;

    final FilePicker file = new FilePicker("The file to check. You can also drop it here", false);
    final FilePicker signature = new FilePicker("Its .sig file", false);
    final FilePicker publicKey = new FilePicker("The signer's .pub file", false);

    private final PrimaryButton verify = new PrimaryButton("Verify signature");

    VerifyView(GuiActions actions) {
        super(actions, "Verify a signature", "Check that a file is unchanged and was signed with a given key.");

        row(Widgets.field("File", file));
        row(Widgets.field("Signature", signature));
        row(Widgets.field("Public key", publicKey));
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
            case VALID -> result.show(Tone.SUCCESS, "VALID", List.of(outcome.detail()), outcome.keyFingerprint(),
                    "This proves who holds this key, not who the person is. Compare the fingerprint with"
                            + " the signer through an independent channel.");
            case INVALID -> result.show(Tone.DANGER, "INVALID", List.of(outcome.detail()), outcome.keyFingerprint(),
                    "Do not trust this file with this signature.");
            case ERROR -> result.show(Tone.CAUTION, "ERROR", List.of(outcome.detail()), outcome.keyFingerprint(),
                    "No decision could be made, so nothing is confirmed about this file.");
        }
    }
}
