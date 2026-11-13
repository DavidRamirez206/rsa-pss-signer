package co.edu.icesi.signer.gui;

import static co.edu.icesi.signer.gui.I18n.t;

import co.edu.icesi.signer.crypto.HashAlg;
import co.edu.icesi.signer.gui.ResultCard.Tone;
import co.edu.icesi.signer.gui.Widgets.PrimaryButton;
import java.awt.Dimension;
import java.awt.GridLayout;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;
import javax.swing.JComboBox;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;

/** Signs a file with a private key. The signature goes next to it as {@code <file>.sig}. */
final class SignView extends View {
    private static final long serialVersionUID = 1L;

    final FilePicker file = new FilePicker(t("sign.file.placeholder"), false);
    final FilePicker key = new FilePicker(t("sign.key.placeholder"), false);
    final JTextField signer = new JTextField();
    final JPasswordField password = passwordField();

    private final JComboBox<String> hash = new JComboBox<>();
    /** Replaced in tests, which cannot answer a dialog. */
    Predicate<String> confirmOverwrite = this::askToOverwrite;

    final PrimaryButton sign = new PrimaryButton(t("sign.submit"));

    SignView(GuiActions actions) {
        super(actions, t("sign.title"), t("sign.subtitle"));

        for (HashAlg alg : HashAlg.values()) {
            hash.addItem(alg.jcaName());
        }
        hash.setFont(Theme.regular(13.5f));
        signer.setFont(Theme.regular(13.5f));
        signer.putClientProperty("JTextField.placeholderText", "Ana Perez");

        row(Widgets.field(t("sign.file"), file));
        row(Widgets.field(t("sign.key"), key));

        JPanel details = new JPanel(new GridLayout(1, 2, 14, 0));
        details.setOpaque(false);
        details.add(Widgets.field(t("sign.signer"), signer));
        details.add(Widgets.field(t("sign.hash"), hash));
        details.setMaximumSize(new Dimension(Integer.MAX_VALUE, details.getPreferredSize().height));
        row(details);
        row(Widgets.field(t("common.password"), password));
        row(sign);

        sign.addActionListener(event -> submit());
    }

    /** Asks before replacing a signature. Only Overwrite says yes; closing the dialog says no. */
    private boolean askToOverwrite(String signatureFile) {
        String overwrite = t("sign.overwrite.confirm");
        String cancel = t("common.cancel");
        int answer = JOptionPane.showOptionDialog(this,
                t("sign.overwrite.message", signatureFile),
                t("sign.overwrite.title"),
                JOptionPane.DEFAULT_OPTION,
                JOptionPane.WARNING_MESSAGE,
                null,
                new Object[] {overwrite, cancel},
                cancel);
        return agreed(answer);
    }

    /** Option 0 is Overwrite; Cancel and closing the dialog both say no. */
    static boolean agreed(int dialogAnswer) {
        return dialogAnswer == 0;
    }

    private void submit() {
        String input = file.value();
        boolean overwrite = actions.signatureExists(input);
        if (overwrite && !confirmOverwrite.test(Path.of(input.strip() + ".sig").getFileName().toString())) {
            return;
        }
        char[] typed = password.getPassword();
        password.setText("");
        String keyFile = key.value();
        String name = signer.getText();
        HashAlg alg = HashAlg.fromJcaName((String) hash.getSelectedItem()).orElse(HashAlg.SHA_256);
        run(sign, () -> actions.sign(input, keyFile, name, alg, typed, overwrite), signature -> {
            List<String> lines = new ArrayList<>(List.of(
                    t("sign.done.signature", signature.file()),
                    t("sign.done.version", signature.docVersion())));
            if (signature.canHideContent()) {
                lines.add(t("sign.done.format"));
            }
            result.show(signature.canHideContent() ? Tone.CAUTION : Tone.SUCCESS, t("sign.done"), lines,
                    signature.fingerprint(), t("sign.done.note"));
        });
    }
}
