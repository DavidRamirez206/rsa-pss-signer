package co.edu.icesi.signer.gui;

import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Component;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GradientPaint;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.LayoutManager;
import java.awt.RenderingHints;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.geom.RoundRectangle2D;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingConstants;

/** Small painted components shared by the views. */
final class Widgets {

    private Widgets() {
    }

    static JLabel label(String text, Font font, Color color) {
        JLabel label = new JLabel(text);
        label.setFont(font);
        label.setForeground(color);
        label.setAlignmentX(Component.LEFT_ALIGNMENT);
        return label;
    }

    /** A field with its caption above it, stretched to the available width. */
    static JComponent field(String caption, JComponent input) {
        JPanel column = new JPanel();
        column.setLayout(new BoxLayout(column, BoxLayout.Y_AXIS));
        column.setOpaque(false);
        column.setAlignmentX(Component.LEFT_ALIGNMENT);
        column.add(label(caption, Theme.medium(13f), Theme.MUTED));
        column.add(Box.createVerticalStrut(7));
        input.setAlignmentX(Component.LEFT_ALIGNMENT);
        column.add(input);
        column.setMaximumSize(new Dimension(Integer.MAX_VALUE, column.getPreferredSize().height));
        return column;
    }

    private static void quality(Graphics2D g) {
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g.setRenderingHint(RenderingHints.KEY_STROKE_CONTROL, RenderingHints.VALUE_STROKE_PURE);
    }

    /** A rounded panel with a hairline border. */
    static class Card extends JPanel {
        private static final long serialVersionUID = 1L;
        private transient Color fill = Theme.SURFACE;
        private transient Color line = Theme.BORDER;

        Card(LayoutManager layout) {
            super(layout);
            setOpaque(false);
        }

        void colors(Color fill, Color line) {
            this.fill = fill;
            this.line = line;
            repaint();
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            quality(g2);
            RoundRectangle2D shape = new RoundRectangle2D.Float(
                    0.5f, 0.5f, getWidth() - 1f, getHeight() - 1f, Theme.ARC * 1.5f, Theme.ARC * 1.5f);
            g2.setColor(fill);
            g2.fill(shape);
            g2.setColor(line);
            g2.setStroke(new BasicStroke(1f));
            g2.draw(shape);
            g2.dispose();
        }
    }

    /** Base for painted buttons: hover and press tracking, no default look. */
    private abstract static class PaintedButton extends JButton {
        private static final long serialVersionUID = 1L;
        boolean hover;
        boolean pressed;

        PaintedButton(String text) {
            super(text);
            setContentAreaFilled(false);
            setBorderPainted(false);
            setFocusPainted(false);
            setOpaque(false);
            setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
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

                @Override
                public void mousePressed(MouseEvent e) {
                    pressed = true;
                    repaint();
                }

                @Override
                public void mouseReleased(MouseEvent e) {
                    pressed = false;
                    repaint();
                }
            });
        }

        void focusRing(Graphics2D g2) {
            if (isFocusOwner()) {
                g2.setColor(Theme.RED_BRIGHT);
                g2.setStroke(new BasicStroke(1.5f));
                g2.draw(new RoundRectangle2D.Float(1f, 1f, getWidth() - 2f, getHeight() - 2f, Theme.ARC, Theme.ARC));
            }
        }
    }

    /** The main action of a view: a red gradient. */
    static final class PrimaryButton extends PaintedButton {
        private static final long serialVersionUID = 1L;

        PrimaryButton(String text) {
            super(text);
            setFont(Theme.semiBold(14.5f));
            setForeground(Color.WHITE);
            setPreferredSize(new Dimension(210, 46));
            setMaximumSize(new Dimension(320, 46));
            setAlignmentX(Component.LEFT_ALIGNMENT);
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            quality(g2);
            Color top = !isEnabled() ? Theme.FIELD_HOVER : pressed ? Theme.RED_DEEP : hover ? Theme.RED_BRIGHT : Theme.RED;
            Color bottom = !isEnabled() ? Theme.FIELD : pressed ? Theme.RED_DEEP : Theme.RED_DEEP.brighter();
            g2.setPaint(new GradientPaint(0, 0, top, 0, getHeight(), bottom));
            g2.fill(new RoundRectangle2D.Float(0, 0, getWidth(), getHeight(), Theme.ARC, Theme.ARC));
            focusRing(g2);
            g2.dispose();
            super.paintComponent(g);
        }
    }

    /** A secondary action: outlined, filled on hover. */
    static final class GhostButton extends PaintedButton {
        private static final long serialVersionUID = 1L;

        GhostButton(String text) {
            super(text);
            setFont(Theme.medium(13f));
            setForeground(Theme.TEXT);
            setHorizontalTextPosition(SwingConstants.RIGHT);
            setIconTextGap(7);
            setPreferredSize(new Dimension(92, 38));
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            quality(g2);
            RoundRectangle2D shape = new RoundRectangle2D.Float(0.5f, 0.5f, getWidth() - 1f, getHeight() - 1f, Theme.ARC, Theme.ARC);
            g2.setColor(pressed ? Theme.RED_TINT : hover ? Theme.FIELD_HOVER : Theme.FIELD);
            g2.fill(shape);
            g2.setColor(hover ? Theme.RED : Theme.BORDER);
            g2.draw(shape);
            focusRing(g2);
            g2.dispose();
            super.paintComponent(g);
        }
    }

    /** One option of a segmented control. */
    static final class SegmentButton extends PaintedButton {
        private static final long serialVersionUID = 1L;
        private boolean selected;

        SegmentButton(String text) {
            super(text);
            setFont(Theme.medium(13.5f));
            setMargin(new java.awt.Insets(0, 4, 0, 4));
            setPreferredSize(new Dimension(108, 38));
            setForeground(Theme.MUTED);
        }

        void select(boolean selected) {
            this.selected = selected;
            setForeground(selected ? Color.WHITE : Theme.MUTED);
            repaint();
        }

        boolean isChosen() {
            return selected;
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            quality(g2);
            RoundRectangle2D shape = new RoundRectangle2D.Float(0.5f, 0.5f, getWidth() - 1f, getHeight() - 1f, Theme.ARC, Theme.ARC);
            g2.setColor(selected ? Theme.RED_TINT : hover ? Theme.FIELD_HOVER : Theme.FIELD);
            g2.fill(shape);
            g2.setColor(selected ? Theme.RED : Theme.BORDER);
            g2.draw(shape);
            focusRing(g2);
            g2.dispose();
            super.paintComponent(g);
        }
    }
}
