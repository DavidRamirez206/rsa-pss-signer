package co.edu.icesi.signer.gui;

import static co.edu.icesi.signer.gui.I18n.t;

import co.edu.icesi.signer.gui.I18n.Language;
import co.edu.icesi.signer.gui.Widgets.SegmentButton;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.util.function.Consumer;
import javax.swing.JPanel;

/** The EN / ES selector. */
final class LanguageSwitch extends JPanel {
    private static final long serialVersionUID = 1L;

    final SegmentButton english = option("EN");
    final SegmentButton spanish = option("ES");

    LanguageSwitch(Consumer<Language> onChange) {
        super(new FlowLayout(FlowLayout.LEFT, 6, 0));
        setOpaque(false);
        setAlignmentX(Component.LEFT_ALIGNMENT);
        setToolTipText(t("language.tooltip"));
        english.select(I18n.current() == Language.ENGLISH);
        spanish.select(I18n.current() == Language.SPANISH);
        english.addActionListener(event -> onChange.accept(Language.ENGLISH));
        spanish.addActionListener(event -> onChange.accept(Language.SPANISH));
        add(english);
        add(spanish);
    }

    private static SegmentButton option(String text) {
        SegmentButton button = new SegmentButton(text);
        button.setFont(Theme.medium(12f));
        button.setToolTipText(t("language.tooltip"));
        button.setPreferredSize(new Dimension(48, 30));
        return button;
    }
}
