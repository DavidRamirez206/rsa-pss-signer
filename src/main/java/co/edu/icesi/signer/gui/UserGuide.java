package co.edu.icesi.signer.gui;

import static co.edu.icesi.signer.gui.I18n.t;

import co.edu.icesi.signer.gui.I18n.Language;
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
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
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

    /** The pages, built on demand because their text depends on the language. */
    private static List<Page> pages() {
        Icon check = Icons.check(20, Theme.RED_BRIGHT);
        return List.of(
                page(0, Icons.brand(44), Icons.key(20, Theme.RED_BRIGHT), Icons.pen(20, Theme.RED_BRIGHT),
                        Icons.shieldCheck(20, Theme.RED_BRIGHT)),
                page(1, Icons.key(40, Theme.RED_BRIGHT), check, check, check, check),
                page(2, Icons.pen(40, Theme.RED_BRIGHT), check, check, check),
                page(3, Icons.shieldCheck(40, Theme.RED_BRIGHT), Icons.check(20, Theme.SUCCESS),
                        Icons.cross(20, Theme.RED_BRIGHT), Icons.warning(20, Theme.WARNING)),
                page(4, Icons.warning(40, Theme.WARNING), check, check, check));
    }

    private static Page page(int number, Icon icon, Icon... pointIcons) {
        String prefix = "guide." + number + ".";
        List<Point> points = new ArrayList<>();
        for (int i = 0; i < pointIcons.length; i++) {
            String point = prefix + (i + 1);
            points.add(new Point(pointIcons[i], t(point + ".title"), t(point + ".text")));
        }
        return new Page(icon, t(prefix + "title"), t(prefix + "intro"), points);
    }

    static int pageCount() {
        return pages().size();
    }

    final GhostButton skip = new GhostButton(t("guide.skip"));
    final GhostButton back = new GhostButton(t("guide.back"));
    final PrimaryButton next = new PrimaryButton(t("guide.next"));

    private final JPanel content = new JPanel(new BorderLayout());
    private final Dots dots = new Dots();
    private final JLabel counter = Widgets.label("", Theme.medium(12.5f), Theme.FAINT);
    private int page;

    final LanguageSwitch languageSwitch;

    UserGuide(Runnable onClose, Consumer<Language> onLanguage) {
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
        languageSwitch = new LanguageSwitch(onLanguage);
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        actions.setOpaque(false);
        actions.add(languageSwitch);
        actions.add(skip);
        top.add(actions, BorderLayout.EAST);

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
        return page == pageCount() - 1;
    }

    /** Shows a page. Reopening the guide starts over with {@code show(0)}. */
    void show(int index) {
        page = index;
        Page current = pages().get(index);
        counter.setText(t("guide.page", index + 1, pageCount()));
        back.setVisible(index > 0);
        skip.setVisible(!isLastPage());
        next.setText(t(isLastPage() ? "guide.finish" : "guide.next"));
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
            return new Dimension(pageCount() * (SIZE + GAP), 42);
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            int y = (getHeight() - SIZE) / 2;
            for (int i = 0; i < pageCount(); i++) {
                Color color = i == page ? Theme.RED : Theme.BORDER;
                g2.setColor(color);
                g2.fillOval(i * (SIZE + GAP), y, SIZE, SIZE);
            }
            g2.dispose();
        }
    }
}
