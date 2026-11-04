package co.edu.icesi.signer.gui;

import co.edu.icesi.signer.gui.Widgets.Card;
import co.edu.icesi.signer.gui.Widgets.GhostButton;
import co.edu.icesi.signer.gui.Widgets.PrimaryButton;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.GridBagLayout;
import java.awt.RenderingHints;
import java.util.List;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.Icon;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;

/** The user manual: a few short pages, shown on first run. It can be skipped at any point. */
final class UserGuide extends JPanel {
    private static final long serialVersionUID = 1L;

    private record Point(Icon icon, String title, String text) {
    }

    private record Page(Icon icon, String title, String intro, List<Point> points) {
    }

    private static Point step(String title, String text) {
        return new Point(Icons.check(20, Theme.RED_BRIGHT), title, text);
    }

    static final List<Page> PAGES = List.of(
            new Page(Icons.brand(44), "Welcome to RSA-PSS Signer",
                    "Sign files so that anyone can confirm they have not changed and which key signed them."
                            + " Files are not encrypted: they stay readable.",
                    List.of(
                            new Point(Icons.key(20, Theme.RED_BRIGHT), "Generate keys", "Create your private and public key, once."),
                            new Point(Icons.pen(20, Theme.RED_BRIGHT), "Sign", "Produce a signature for any file with your private key."),
                            new Point(Icons.shieldCheck(20, Theme.RED_BRIGHT), "Verify", "Check a file with its signature and the signer's public key."))),
            new Page(Icons.key(40, Theme.RED_BRIGHT), "1. Generate your keys",
                    "Open Generate keys. You only need to do this once.",
                    List.of(
                            step("Save as", "Pick a folder and a base name. \"ana\" creates ana.key and ana.pub."),
                            step("Password", "Use at least 12 characters. It cannot be recovered if you forget it."),
                            step("Keep ana.key private", "Never send it to anyone, even though it is encrypted."),
                            step("Share ana.pub", "Give the public key, and its fingerprint, to whoever will verify your files."))),
            new Page(Icons.pen(40, Theme.RED_BRIGHT), "2. Sign a file",
                    "Open Sign. Choose the file and your .key, enter your name and your password.",
                    List.of(
                            step("The signature is a new file", "contract.pdf produces contract.pdf.sig next to it. Nothing is overwritten."),
                            step("Send three things", "The file, its .sig and your .pub."),
                            step("Your name and date are declared", "They are protected by the signature, but they are what you state, not verified facts."))),
            new Page(Icons.shieldCheck(40, Theme.RED_BRIGHT), "3. Verify a signature",
                    "Open Verify. Choose the file, its .sig and the signer's .pub. No password is needed.",
                    List.of(
                            new Point(Icons.check(20, Theme.SUCCESS), "VALID", "The file is unchanged and was signed with this key."),
                            new Point(Icons.cross(20, Theme.RED_BRIGHT), "INVALID", "The file or the signed details changed, or the signature does not match. Do not trust it."),
                            new Point(Icons.warning(20, Theme.WARNING), "ERROR", "No decision could be made, for example a damaged file or a key that is not allowed. Nothing is confirmed."))),
            new Page(Icons.warning(40, Theme.WARNING), "Before you trust a signature",
                    "VALID proves who holds the key, not who that person is. Anyone can create a key under any name.",
                    List.of(
                            step("Compare the fingerprint", "Check it with the signer in person or by phone, not through the channel that delivered the file."),
                            step("Protect your password", "Whoever has your .key can try passwords offline, so the password is the real protection."),
                            step("Renaming is not detected yet", "The file name is signed, but a renamed copy with the same content still verifies."))));

    final GhostButton skip = new GhostButton("Skip");
    final GhostButton back = new GhostButton("Back");
    final PrimaryButton next = new PrimaryButton("Next");

    private final JPanel content = new JPanel(new BorderLayout());
    private final Dots dots = new Dots();
    private final JLabel counter = Widgets.label("", Theme.medium(12.5f), Theme.FAINT);
    private int page;

    UserGuide(Runnable onClose) {
        super(new GridBagLayout());
        setBackground(Theme.BACKGROUND);
        content.setOpaque(false);

        Card card = new Card(new BorderLayout(0, 18));
        card.setBorder(BorderFactory.createEmptyBorder(22, 30, 22, 30));
        card.setPreferredSize(new Dimension(720, 560));

        JPanel top = new JPanel(new BorderLayout());
        top.setOpaque(false);
        // Fixed height, so the page does not jump when Skip disappears on the last one
        top.setPreferredSize(new Dimension(0, 36));
        top.add(counter, BorderLayout.WEST);
        skip.setPreferredSize(new Dimension(84, 36));
        top.add(skip, BorderLayout.EAST);

        JScrollPane scroll = new JScrollPane(content);
        scroll.setBorder(BorderFactory.createEmptyBorder());
        scroll.setOpaque(false);
        scroll.getViewport().setOpaque(false);
        scroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);

        JPanel bottom = new JPanel(new BorderLayout());
        bottom.setOpaque(false);
        bottom.add(dots, BorderLayout.WEST);
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        buttons.setOpaque(false);
        back.setPreferredSize(new Dimension(92, 42));
        next.setPreferredSize(new Dimension(150, 42));
        buttons.add(back);
        buttons.add(next);
        bottom.add(buttons, BorderLayout.EAST);

        card.add(top, BorderLayout.NORTH);
        card.add(scroll, BorderLayout.CENTER);
        card.add(bottom, BorderLayout.SOUTH);
        add(card);

        skip.addActionListener(event -> onClose.run());
        back.addActionListener(event -> show(page - 1));
        next.addActionListener(event -> {
            if (isLastPage()) {
                onClose.run();
            } else {
                show(page + 1);
            }
        });
        show(0);
    }

    int currentPage() {
        return page;
    }

    boolean isLastPage() {
        return page == PAGES.size() - 1;
    }

    /** Shows a page. Reopening the guide starts over with {@code show(0)}. */
    void show(int index) {
        page = index;
        Page current = PAGES.get(index);
        counter.setText("Page " + (index + 1) + " of " + PAGES.size());
        back.setVisible(index > 0);
        skip.setVisible(!isLastPage());
        next.setText(isLastPage() ? "Get started" : "Next");
        dots.repaint();
        content.removeAll();
        content.add(render(current), BorderLayout.NORTH);
        content.revalidate();
        content.repaint();
    }

    private static JComponent render(Page current) {
        JPanel column = new JPanel();
        column.setLayout(new BoxLayout(column, BoxLayout.Y_AXIS));
        column.setOpaque(false);
        JLabel icon = new JLabel(current.icon());
        icon.setAlignmentX(Component.LEFT_ALIGNMENT);
        column.add(icon);
        column.add(Box.createVerticalStrut(14));
        column.add(Widgets.label(current.title(), Theme.bold(24f), Theme.TEXT));
        column.add(Box.createVerticalStrut(8));
        column.add(Widgets.wrapped(current.intro(), Theme.regular(14.5f), Theme.MUTED));
        column.add(Box.createVerticalStrut(20));
        for (Point point : current.points()) {
            column.add(row(point));
            column.add(Box.createVerticalStrut(14));
        }
        return column;
    }

    private static JComponent row(Point point) {
        JPanel row = new JPanel(new BorderLayout(13, 0));
        row.setOpaque(false);
        row.setAlignmentX(Component.LEFT_ALIGNMENT);
        JPanel iconHolder = new JPanel(new BorderLayout());
        iconHolder.setOpaque(false);
        iconHolder.add(new JLabel(point.icon()), BorderLayout.NORTH);
        row.add(iconHolder, BorderLayout.WEST);
        JPanel words = new JPanel();
        words.setLayout(new BoxLayout(words, BoxLayout.Y_AXIS));
        words.setOpaque(false);
        words.add(Widgets.label(point.title(), Theme.semiBold(14f), Theme.TEXT));
        words.add(Box.createVerticalStrut(2));
        words.add(Widgets.wrapped(point.text(), Theme.regular(13.5f), Theme.MUTED));
        row.add(words, BorderLayout.CENTER);
        return row;
    }

    /** The progress indicator: the current page in red. */
    private final class Dots extends JComponent {
        private static final long serialVersionUID = 1L;
        private static final int SIZE = 8;
        private static final int GAP = 8;

        @Override
        public Dimension getPreferredSize() {
            return new Dimension(PAGES.size() * (SIZE + GAP), 42);
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            int y = (getHeight() - SIZE) / 2;
            for (int i = 0; i < PAGES.size(); i++) {
                Color color = i == page ? Theme.RED : Theme.BORDER;
                g2.setColor(color);
                g2.fillOval(i * (SIZE + GAP), y, SIZE, SIZE);
            }
            g2.dispose();
        }
    }
}
