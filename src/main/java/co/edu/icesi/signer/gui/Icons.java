package co.edu.icesi.signer.gui;

import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Component;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.geom.Ellipse2D;
import java.awt.geom.Line2D;
import java.awt.geom.Path2D;
import java.awt.geom.RoundRectangle2D;
import java.util.function.Consumer;
import javax.swing.Icon;

/** Line icons drawn on a 24-unit grid, so they stay sharp at any size and need no image files. */
final class Icons {

    private Icons() {
    }

    private static Icon icon(int size, Color color, Consumer<Graphics2D> shape) {
        return new Icon() {
            @Override
            public void paintIcon(Component c, Graphics g, int x, int y) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setRenderingHint(RenderingHints.KEY_STROKE_CONTROL, RenderingHints.VALUE_STROKE_PURE);
                g2.translate(x, y);
                g2.scale(size / 24.0, size / 24.0);
                g2.setColor(color);
                g2.setStroke(new BasicStroke(1.8f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
                shape.accept(g2);
                g2.dispose();
            }

            @Override
            public int getIconWidth() {
                return size;
            }

            @Override
            public int getIconHeight() {
                return size;
            }
        };
    }

    private static Path2D shield() {
        Path2D p = new Path2D.Double();
        p.moveTo(12, 2.5);
        p.lineTo(20, 5.5);
        p.lineTo(20, 11.5);
        p.curveTo(20, 16.5, 16.5, 20, 12, 21.5);
        p.curveTo(7.5, 20, 4, 16.5, 4, 11.5);
        p.lineTo(4, 5.5);
        p.closePath();
        return p;
    }

    private static Path2D checkMark() {
        Path2D p = new Path2D.Double();
        p.moveTo(8.5, 12);
        p.lineTo(11, 14.5);
        p.lineTo(15.5, 9.5);
        return p;
    }

    static Icon key(int size, Color color) {
        return icon(size, color, g -> {
            g.draw(new Ellipse2D.Double(3, 12, 8.5, 8.5));
            g.draw(new Line2D.Double(10.2, 13.3, 20.5, 3));
            g.draw(new Line2D.Double(15.5, 8, 18.5, 11));
            g.draw(new Line2D.Double(18.5, 5, 21, 7.5));
        });
    }

    static Icon pen(int size, Color color) {
        return icon(size, color, g -> {
            Path2D p = new Path2D.Double();
            p.moveTo(4, 20);
            p.lineTo(5, 15.5);
            p.lineTo(16, 4.5);
            p.lineTo(19.5, 8);
            p.lineTo(8.5, 19);
            p.closePath();
            g.draw(p);
            g.draw(new Line2D.Double(13.5, 7, 17, 10.5));
        });
    }

    static Icon shieldCheck(int size, Color color) {
        return icon(size, color, g -> {
            g.draw(shield());
            g.draw(checkMark());
        });
    }

    static Icon check(int size, Color color) {
        return icon(size, color, g -> {
            g.draw(new Ellipse2D.Double(3, 3, 18, 18));
            g.draw(checkMark());
        });
    }

    static Icon cross(int size, Color color) {
        return icon(size, color, g -> {
            g.draw(new Ellipse2D.Double(3, 3, 18, 18));
            g.draw(new Line2D.Double(9, 9, 15, 15));
            g.draw(new Line2D.Double(15, 9, 9, 15));
        });
    }

    static Icon warning(int size, Color color) {
        return icon(size, color, g -> {
            Path2D p = new Path2D.Double();
            p.moveTo(12, 3.5);
            p.lineTo(21.5, 20);
            p.lineTo(2.5, 20);
            p.closePath();
            g.draw(p);
            g.draw(new Line2D.Double(12, 10, 12, 14.5));
            g.draw(new Line2D.Double(12, 17.2, 12, 17.3));
        });
    }

    static Icon copy(int size, Color color) {
        return icon(size, color, g -> {
            g.draw(new RoundRectangle2D.Double(8.5, 8.5, 12, 12, 3, 3));
            Path2D p = new Path2D.Double();
            p.moveTo(15.5, 8.5);
            p.lineTo(15.5, 5.5);
            p.quadTo(15.5, 3.5, 13.5, 3.5);
            p.lineTo(5.5, 3.5);
            p.quadTo(3.5, 3.5, 3.5, 5.5);
            p.lineTo(3.5, 13.5);
            p.quadTo(3.5, 15.5, 5.5, 15.5);
            p.lineTo(8.5, 15.5);
            g.draw(p);
        });
    }

    static Icon book(int size, Color color) {
        return icon(size, color, g -> {
            Path2D p = new Path2D.Double();
            p.moveTo(12, 6.5);
            p.curveTo(10, 4.5, 7, 4, 3.5, 4.5);
            p.lineTo(3.5, 18.5);
            p.curveTo(7, 18, 10, 18.5, 12, 20.5);
            p.curveTo(14, 18.5, 17, 18, 20.5, 18.5);
            p.lineTo(20.5, 4.5);
            p.curveTo(17, 4, 14, 4.5, 12, 6.5);
            g.draw(p);
            g.draw(new Line2D.Double(12, 6.5, 12, 20.5));
        });
    }

    /** The brand mark: a filled shield with a gradient. */
    static Icon brand(int size) {
        return icon(size, Theme.RED, g -> {
            g.setPaint(new java.awt.GradientPaint(0, 2, Theme.RED_BRIGHT, 0, 22, Theme.RED_DEEP));
            g.fill(shield());
            g.setPaint(Color.WHITE);
            g.setStroke(new BasicStroke(2.2f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
            g.draw(checkMark());
        });
    }
}
