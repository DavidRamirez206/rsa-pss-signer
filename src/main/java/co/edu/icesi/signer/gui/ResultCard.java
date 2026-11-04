package co.edu.icesi.signer.gui;

import co.edu.icesi.signer.gui.Widgets.Card;
import co.edu.icesi.signer.gui.Widgets.GhostButton;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.util.List;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextArea;

/** The outcome of an operation, colored by what it means. Hidden until there is one. */
final class ResultCard extends Card {
    private static final long serialVersionUID = 1L;

    enum Tone {
        SUCCESS(Theme.SUCCESS),
        DANGER(Theme.RED_BRIGHT),
        CAUTION(Theme.WARNING);

        final Color color;

        Tone(Color color) {
            this.color = color;
        }
    }

    private final JPanel body = new JPanel();
    private final JLabel icon = new JLabel();
    private Tone shown;

    ResultCard() {
        super(new BorderLayout(14, 0));
        setBorder(BorderFactory.createEmptyBorder(16, 18, 16, 18));
        setAlignmentX(Component.LEFT_ALIGNMENT);
        setVisible(false);
        body.setLayout(new BoxLayout(body, BoxLayout.Y_AXIS));
        body.setOpaque(false);
        JPanel iconColumn = new JPanel(new BorderLayout());
        iconColumn.setOpaque(false);
        iconColumn.add(icon, BorderLayout.NORTH);
        add(iconColumn, BorderLayout.WEST);
        add(body, BorderLayout.CENTER);
    }

    void hideResult() {
        setVisible(false);
    }

    /** The tone of the last result shown. */
    Tone tone() {
        return shown;
    }

    /**
     * @param lines details, one per line
     * @param fingerprint shown with a Copy button when not null
     * @param note a closing remark in a quieter color when not null
     */
    void show(Tone tone, String title, List<String> lines, String fingerprint, String note) {
        shown = tone;
        colors(new Color(tone.color.getRed(), tone.color.getGreen(), tone.color.getBlue(), 0x14),
                new Color(tone.color.getRed(), tone.color.getGreen(), tone.color.getBlue(), 0x70));
        icon.setIcon(switch (tone) {
            case SUCCESS -> Icons.check(26, tone.color);
            case DANGER -> Icons.cross(26, tone.color);
            case CAUTION -> Icons.warning(26, tone.color);
        });
        body.removeAll();
        body.add(Widgets.label(title, Theme.semiBold(15.5f), tone.color));
        for (String line : lines) {
            body.add(Box.createVerticalStrut(5));
            body.add(wrapped(line, Theme.regular(13.5f), Theme.TEXT));
        }
        if (fingerprint != null) {
            body.add(Box.createVerticalStrut(12));
            body.add(Widgets.label("Key fingerprint (SHA-256)", Theme.medium(12f), Theme.MUTED));
            body.add(Box.createVerticalStrut(5));
            body.add(fingerprintRow(fingerprint));
        }
        if (note != null) {
            body.add(Box.createVerticalStrut(10));
            body.add(wrapped(note, Theme.regular(12.5f), Theme.MUTED));
        }
        setVisible(true);
        revalidate();
        repaint();
    }

    private static JPanel fingerprintRow(String fingerprint) {
        JPanel row = new JPanel(new BorderLayout(12, 0));
        row.setOpaque(false);
        row.setAlignmentX(Component.LEFT_ALIGNMENT);
        row.add(wrapped(inTwoLines(fingerprint), Theme.fingerprint(12.5f), Theme.TEXT), BorderLayout.CENTER);
        GhostButton copy = new GhostButton("Copy");
        copy.setIcon(Icons.copy(14, Theme.TEXT));
        copy.setPreferredSize(new Dimension(88, 34));
        copy.addActionListener(event -> Toolkit.getDefaultToolkit().getSystemClipboard()
                .setContents(new StringSelection(fingerprint), null));
        JPanel holder = new JPanel(new BorderLayout());
        holder.setOpaque(false);
        holder.add(copy, BorderLayout.NORTH);
        row.add(holder, BorderLayout.EAST);
        return row;
    }

    /** Splits a whole fingerprint evenly, so a line never starts with a stray colon. */
    static String inTwoLines(String fingerprint) {
        int middle = fingerprint.length() / 2 + 1;
        boolean even = fingerprint.length() > middle && fingerprint.charAt(middle - 1) == ':';
        return even ? fingerprint.substring(0, middle) + "\n" + fingerprint.substring(middle) : fingerprint;
    }

    /** Selectable text that wraps, for paths and messages that can be long. */
    private static JTextArea wrapped(String text, Font font, Color color) {
        JTextArea area = new JTextArea(text) {
            private static final long serialVersionUID = 1L;

            // Its height depends on its width, so a new width means a new layout
            @Override
            public void setBounds(int x, int y, int width, int height) {
                boolean rewrap = width != getWidth();
                super.setBounds(x, y, width, height);
                if (rewrap) {
                    revalidate();
                }
            }
        };
        area.setFont(font);
        area.setForeground(color);
        area.setOpaque(false);
        area.setEditable(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setBorder(BorderFactory.createEmptyBorder());
        area.setAlignmentX(Component.LEFT_ALIGNMENT);
        return area;
    }
}
