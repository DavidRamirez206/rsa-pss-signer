package co.edu.icesi.signer.gui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.awt.Color;
import java.awt.Image;
import java.awt.image.BufferedImage;
import org.junit.jupiter.api.Test;

class GuiMainTest {

    @Test
    void windowIconsDrawTheLogoOnATransparentBackgroundAtEverySize() {
        int[] expected = {16, 24, 32, 48, 64, 128, 256};
        assertEquals(expected.length, GuiMain.windowIcons().size());

        for (int i = 0; i < expected.length; i++) {
            Image icon = GuiMain.windowIcons().get(i);
            BufferedImage image = (BufferedImage) icon;
            int size = expected[i];
            assertEquals(size, image.getWidth());
            assertEquals(size, image.getHeight());
            assertEquals(0, new Color(image.getRGB(0, 0), true).getAlpha(), "corner at " + size);
            // Inside the shield, below the check mark: opaque and red
            Color inside = new Color(image.getRGB(size / 2, size * 3 / 4), true);
            assertEquals(255, inside.getAlpha(), "shield at " + size);
            assertTrue(inside.getRed() > inside.getGreen() * 2, "red at " + size);
        }
    }
}
