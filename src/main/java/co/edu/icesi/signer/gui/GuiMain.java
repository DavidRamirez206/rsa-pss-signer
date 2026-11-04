package co.edu.icesi.signer.gui;

import co.edu.icesi.signer.keystore.PrivateKeyStore;
import java.awt.Dimension;
import java.awt.Graphics2D;
import java.awt.Image;
import java.awt.image.BufferedImage;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JFrame;
import javax.swing.SwingUtilities;

/** Entry point of the graphical interface. */
public final class GuiMain {

    private GuiMain() {
    }

    /** The logo at the sizes window managers ask for. */
    static List<Image> windowIcons() {
        List<Image> images = new ArrayList<>();
        for (int size : new int[] {16, 24, 32, 48, 64, 128, 256}) {
            BufferedImage image = new BufferedImage(size, size, BufferedImage.TYPE_INT_ARGB);
            Graphics2D graphics = image.createGraphics();
            Icons.brand(size).paintIcon(null, graphics, 0, 0);
            graphics.dispose();
            images.add(image);
        }
        return images;
    }

    public static void main(String[] args) {
        System.setProperty("awt.useSystemAAFontSettings", "lcd");
        System.setProperty("swing.aatext", "true");
        SwingUtilities.invokeLater(() -> {
            Theme.install();
            JFrame frame = new JFrame("RSA-PSS Signer");
            frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            frame.setIconImages(windowIcons());
            frame.setContentPane(new AppRoot(
                    new GuiActions(new PrivateKeyStore(), Clock.systemDefaultZone()), new StoredSettings()));
            frame.setMinimumSize(new Dimension(880, 640));
            frame.setSize(1040, 720);
            frame.setLocationRelativeTo(null);
            frame.setVisible(true);
        });
    }
}
