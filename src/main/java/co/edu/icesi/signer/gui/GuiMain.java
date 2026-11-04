package co.edu.icesi.signer.gui;

import co.edu.icesi.signer.keystore.PrivateKeyStore;
import java.awt.Dimension;
import java.time.Clock;
import javax.swing.JFrame;
import javax.swing.SwingUtilities;

/** Entry point of the graphical interface. */
public final class GuiMain {

    private GuiMain() {
    }

    public static void main(String[] args) {
        System.setProperty("awt.useSystemAAFontSettings", "lcd");
        System.setProperty("swing.aatext", "true");
        SwingUtilities.invokeLater(() -> {
            Theme.install();
            JFrame frame = new JFrame("RSA-PSS Signer");
            frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            frame.setContentPane(new AppRoot(
                    new GuiActions(new PrivateKeyStore(), Clock.systemDefaultZone()), new StoredSettings()));
            frame.setMinimumSize(new Dimension(880, 640));
            frame.setSize(1040, 720);
            frame.setLocationRelativeTo(null);
            frame.setVisible(true);
        });
    }
}
