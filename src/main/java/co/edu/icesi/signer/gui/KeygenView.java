package co.edu.icesi.signer.gui;

import static co.edu.icesi.signer.gui.I18n.t;

import co.edu.icesi.signer.cli.Cli;
import co.edu.icesi.signer.crypto.KeyPairService;
import co.edu.icesi.signer.gui.ResultCard.Tone;
import co.edu.icesi.signer.gui.Widgets.PrimaryButton;
import co.edu.icesi.signer.gui.Widgets.SegmentButton;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

/** Generates a key pair into two files. */
final class KeygenView extends View {
    private static final long serialVersionUID = 1L;

    final FilePicker base = new FilePicker(t("keygen.base.placeholder"), true);
    final JPasswordField password = passwordField();
    final JPasswordField confirmation = passwordField();

    private final List<SegmentButton> sizes = new ArrayList<>();
    private final JLabel hint = Widgets.label(" ", Theme.regular(12.5f), Theme.FAINT);
    private final PrimaryButton generate = new PrimaryButton(t("keygen.submit"));

    KeygenView(GuiActions actions) {
        super(actions, t("keygen.title"), t("keygen.subtitle"));

        row(Widgets.field(t("keygen.base"), base));
        row(Widgets.field(t("keygen.size"), sizeSelector()));

        JPanel passwords = new JPanel(new GridLayout(1, 2, 14, 0));
        passwords.setOpaque(false);
        passwords.add(Widgets.field(t("common.password"), password));
        passwords.add(Widgets.field(t("keygen.repeat"), confirmation));
        passwords.setMaximumSize(new Dimension(Integer.MAX_VALUE, passwords.getPreferredSize().height));
        row(passwords);
        row(hint);
        row(generate);

        DocumentListener refresh = new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                refreshHint();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                refreshHint();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                refreshHint();
            }
        };
        password.getDocument().addDocumentListener(refresh);
        confirmation.getDocument().addDocumentListener(refresh);
        refreshHint();

        generate.addActionListener(event -> submit());
    }

    private JPanel sizeSelector() {
        JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        row.setOpaque(false);
        for (int bits : List.of(2048, 3072, 4096)) {
            SegmentButton button = new SegmentButton(t("keygen.bits", bits));
            button.putClientProperty("bits", bits);
            button.select(bits == KeyPairService.DEFAULT_KEY_SIZE);
            button.addActionListener(event -> sizes.forEach(other -> other.select(other == button)));
            sizes.add(button);
            row.add(button);
            row.add(javax.swing.Box.createHorizontalStrut(8));
        }
        return row;
    }

    private int selectedBits() {
        return sizes.stream().filter(SegmentButton::isChosen)
                .map(button -> (Integer) button.getClientProperty("bits"))
                .findFirst().orElse(KeyPairService.DEFAULT_KEY_SIZE);
    }

    private void refreshHint() {
        int length = password.getDocument().getLength();
        int repeated = confirmation.getDocument().getLength();
        if (length < Cli.MIN_PASSWORD_LENGTH) {
            hint.setText(t("keygen.hint.short", length, Cli.MIN_PASSWORD_LENGTH));
            hint.setForeground(Theme.FAINT);
        } else if (repeated == 0) {
            hint.setText(t("keygen.hint.repeat"));
            hint.setForeground(Theme.MUTED);
        } else {
            boolean same = java.util.Arrays.equals(password.getPassword(), confirmation.getPassword());
            hint.setText(t(same ? "keygen.hint.match" : "keygen.hint.mismatch"));
            hint.setForeground(same ? Theme.SUCCESS : Theme.WARNING);
        }
    }

    private void submit() {
        char[] first = password.getPassword();
        char[] second = confirmation.getPassword();
        int bits = selectedBits();
        String target = base.value();
        password.setText("");
        confirmation.setText("");
        run(generate, () -> actions.generateKeys(target, bits, first, second), keys -> result.show(
                Tone.SUCCESS,
                t("keygen.done"),
                List.of(t("keygen.done.private", keys.privateKey()), t("keygen.done.public", keys.publicKey())),
                keys.fingerprint(),
                t("keygen.done.note")));
    }
}
