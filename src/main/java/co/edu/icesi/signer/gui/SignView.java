package co.edu.icesi.signer.gui;

import static co.edu.icesi.signer.gui.I18n.t;

import co.edu.icesi.signer.crypto.HashAlg;
import co.edu.icesi.signer.gui.ResultCard.Tone;
import co.edu.icesi.signer.gui.Widgets.PrimaryButton;
import java.awt.Dimension;
import java.awt.GridLayout;
import java.util.List;
import javax.swing.JComboBox;
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
    private final PrimaryButton sign = new PrimaryButton(t("sign.submit"));

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

    private void submit() {
        char[] typed = password.getPassword();
        password.setText("");
        String input = file.value();
        String keyFile = key.value();
        String name = signer.getText();
        HashAlg alg = HashAlg.fromJcaName((String) hash.getSelectedItem()).orElse(HashAlg.SHA_256);
        run(sign, () -> actions.sign(input, keyFile, name, alg, typed), signature -> result.show(
                Tone.SUCCESS,
                t("sign.done"),
                List.of(t("sign.done.signature", signature.file())),
                signature.fingerprint(),
                t("sign.done.note")));
    }
}
