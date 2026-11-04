package co.edu.icesi.signer.gui;

import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.geom.RoundRectangle2D;
import java.util.ArrayList;
import java.util.List;
import java.util.function.BiFunction;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.Icon;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;

/** The whole window content: the sidebar and the page it selects. */
final class AppShell extends JPanel {
    private static final long serialVersionUID = 1L;

    final KeygenView keygen;
    final SignView sign;
    final VerifyView verify;

    private final CardLayout pages = new CardLayout();
    private final JPanel content = new JPanel(pages);
    private final List<NavItem> items = new ArrayList<>();

    AppShell(GuiActions actions) {
        super(new BorderLayout());
        setBackground(Theme.BACKGROUND);
        keygen = new KeygenView(actions);
        sign = new SignView(actions);
        verify = new VerifyView(actions);

        content.setBackground(Theme.BACKGROUND);
        content.add(keygen, "keygen");
        content.add(sign, "sign");
        content.add(verify, "verify");

        add(sidebar(), BorderLayout.WEST);
        add(content, BorderLayout.CENTER);
        select("keygen");
    }

    void select(String page) {
        pages.show(content, page);
        items.forEach(item -> item.setActive(item.page.equals(page)));
    }

    private JPanel sidebar() {
        JPanel side = new JPanel() {
            private static final long serialVersionUID = 1L;

            @Override
            protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                g.setColor(Theme.BORDER);
                g.drawLine(getWidth() - 1, 0, getWidth() - 1, getHeight());
            }
        };
        side.setLayout(new BoxLayout(side, BoxLayout.Y_AXIS));
        side.setBackground(Theme.SIDEBAR);
        side.setBorder(BorderFactory.createEmptyBorder(26, 16, 20, 16));
        side.setPreferredSize(new Dimension(236, 0));

        JPanel brand = new JPanel(new BorderLayout(11, 0));
        brand.setOpaque(false);
        brand.setBorder(BorderFactory.createEmptyBorder(0, 8, 0, 0));
        brand.setAlignmentX(Component.LEFT_ALIGNMENT);
        brand.setMaximumSize(new Dimension(Integer.MAX_VALUE, 42));
        brand.add(new JLabel(Icons.brand(34)), BorderLayout.WEST);
        JPanel words = new JPanel();
        words.setLayout(new BoxLayout(words, BoxLayout.Y_AXIS));
        words.setOpaque(false);
        words.add(Widgets.label("RSA-PSS", Theme.bold(16.5f), Theme.TEXT));
        words.add(Widgets.label("Signer and verifier", Theme.regular(11.5f), Theme.MUTED));
        brand.add(words, BorderLayout.CENTER);
        side.add(brand);
        side.add(Box.createVerticalStrut(32));

        side.add(navLabel("OPERATIONS"));
        side.add(Box.createVerticalStrut(8));
        addItem(side, "keygen", "Generate keys", Icons::key);
        side.add(Box.createVerticalStrut(4));
        addItem(side, "sign", "Sign", Icons::pen);
        side.add(Box.createVerticalStrut(4));
        addItem(side, "verify", "Verify", Icons::shieldCheck);

        side.add(Box.createVerticalGlue());
        side.add(footerLine("RSASSA-PSS signatures"));
        side.add(Box.createVerticalStrut(3));
        side.add(footerLine("Fingerprints decide trust"));
        return side;
    }

    private static Component navLabel(String text) {
        JPanel wrapper = new JPanel(new BorderLayout());
        wrapper.setOpaque(false);
        wrapper.setBorder(BorderFactory.createEmptyBorder(0, 8, 0, 0));
        wrapper.setAlignmentX(Component.LEFT_ALIGNMENT);
        wrapper.setMaximumSize(new Dimension(Integer.MAX_VALUE, 18));
        wrapper.add(Widgets.label(text, Theme.semiBold(11f), Theme.FAINT), BorderLayout.WEST);
        return wrapper;
    }

    private static Component footerLine(String text) {
        JPanel wrapper = new JPanel(new BorderLayout());
        wrapper.setOpaque(false);
        wrapper.setBorder(BorderFactory.createEmptyBorder(0, 8, 0, 0));
        wrapper.setAlignmentX(Component.LEFT_ALIGNMENT);
        wrapper.setMaximumSize(new Dimension(Integer.MAX_VALUE, 18));
        wrapper.add(Widgets.label(text, Theme.regular(11f), Theme.FAINT), BorderLayout.WEST);
        return wrapper;
    }

    private void addItem(JPanel side, String page, String text, BiFunction<Integer, Color, Icon> icon) {
        NavItem item = new NavItem(page, text, icon);
        item.addActionListener(event -> select(page));
        items.add(item);
        side.add(item);
    }

    /** A sidebar entry. The active one has a red bar and a red-tinted background. */
    private static final class NavItem extends JButton {
        private static final long serialVersionUID = 1L;

        private final String page;
        private final transient BiFunction<Integer, Color, Icon> icon;
        private boolean active;
        private boolean hover;

        NavItem(String page, String text, BiFunction<Integer, Color, Icon> icon) {
            super(text);
            this.page = page;
            this.icon = icon;
            setContentAreaFilled(false);
            setBorderPainted(false);
            setFocusPainted(false);
            setOpaque(false);
            setHorizontalAlignment(LEFT);
            setIconTextGap(12);
            setFont(Theme.medium(14f));
            setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
            setBorder(BorderFactory.createEmptyBorder(0, 14, 0, 8));
            setAlignmentX(Component.LEFT_ALIGNMENT);
            setMaximumSize(new Dimension(Integer.MAX_VALUE, 44));
            setPreferredSize(new Dimension(200, 44));
            addMouseListener(new MouseAdapter() {
                @Override
                public void mouseEntered(MouseEvent e) {
                    hover = true;
                    repaint();
                }

                @Override
                public void mouseExited(MouseEvent e) {
                    hover = false;
                    repaint();
                }
            });
            setActive(false);
        }

        void setActive(boolean active) {
            this.active = active;
            setForeground(active ? Theme.TEXT : Theme.MUTED);
            setIcon(icon.apply(20, active ? Theme.RED_BRIGHT : Theme.MUTED));
            repaint();
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            if (active || hover) {
                g2.setColor(active ? Theme.RED_TINT : Theme.FIELD);
                g2.fill(new RoundRectangle2D.Float(0, 0, getWidth(), getHeight(), Theme.ARC, Theme.ARC));
            }
            if (active) {
                g2.setColor(Theme.RED);
                g2.fill(new RoundRectangle2D.Float(0, 10, 3.5f, getHeight() - 20f, 3.5f, 3.5f));
            }
            if (isFocusOwner() && !active) {
                g2.setColor(Theme.RED);
                g2.draw(new RoundRectangle2D.Float(0.5f, 0.5f, getWidth() - 1f, getHeight() - 1f, Theme.ARC, Theme.ARC));
            }
            g2.dispose();
            super.paintComponent(g);
        }
    }
}
