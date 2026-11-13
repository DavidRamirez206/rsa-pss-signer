package co.edu.icesi.signer.gui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import co.edu.icesi.signer.core.VerificationOutcome;
import co.edu.icesi.signer.core.VerificationResult;
import co.edu.icesi.signer.keystore.PrivateKeyStore;
import co.edu.icesi.signer.policy.TestState;
import java.awt.Component;
import java.awt.Container;
import java.awt.Font;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.lang.reflect.InvocationTargetException;
import java.time.Clock;
import javax.swing.JLabel;
import javax.swing.SwingUtilities;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;

/** Builds and paints the real components off screen, so it needs no display. */
class InterfaceTest {

    private static final String FINGERPRINT = "53:BE:83:73:A0:F5:DD:78:68:51:05:C2:18:6D:82:DF:"
            + "67:91:CE:B9:10:E6:F9:5E:80:94:35:59:15:A1:7D:A3";

    @BeforeAll
    static void installTheme() throws InterruptedException, InvocationTargetException {
        SwingUtilities.invokeAndWait(Theme::install);
    }

    @BeforeEach
    void startInEnglish() {
        I18n.use(I18n.Language.ENGLISH);
    }

    private static AppShell shell() {
        return new AppShell(new GuiActions(new PrivateKeyStore(1000), Clock.systemUTC(), TestState.fresh()), () -> { }, language -> { });
    }

    private static void layOut(Component component) {
        component.doLayout();
        if (component instanceof Container container) {
            for (Component child : container.getComponents()) {
                layOut(child);
            }
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"Regular", "Medium", "SemiBold", "Bold"})
    void bundledFontsAreThePlusJakartaSansFamily(String weight) {
        Font font = switch (weight) {
            case "Regular" -> Theme.regular(14f);
            case "Medium" -> Theme.medium(14f);
            case "SemiBold" -> Theme.semiBold(14f);
            default -> Theme.bold(14f);
        };
        assertTrue(font.getFontName().startsWith("Plus Jakarta Sans"), font.getFontName());
        assertEquals(14f, font.getSize2D());
    }

    @ParameterizedTest
    @ValueSource(strings = {"keygen", "sign", "verify"})
    void everyPagePaintsSomethingOnTheBackground(String page) throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            AppShell shell = shell();
            shell.select(page);
            shell.setSize(1040, 720);
            layOut(shell);
            BufferedImage image = new BufferedImage(1040, 720, BufferedImage.TYPE_INT_RGB);
            Graphics2D g = image.createGraphics();
            shell.printAll(g);
            g.dispose();

            boolean red = false;
            for (int y = 0; y < 720 && !red; y += 2) {
                for (int x = 0; x < 1040 && !red; x += 2) {
                    int rgb = image.getRGB(x, y);
                    red = ((rgb >> 16) & 0xFF) > 180 && ((rgb >> 8) & 0xFF) < 70;
                }
            }
            assertTrue(red, "The primary button and active item are red");
        });
    }

    // No outcome other than a real VALID may read as success
    @ParameterizedTest
    @EnumSource(VerificationResult.class)
    void resultCardShowsTheOutcomeItWasGiven(VerificationResult outcome) throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            VerifyView view = shell().verify;
            assertFalse(view.result.isVisible());

            view.present(new VerificationOutcome(outcome, "detail", FINGERPRINT));

            assertTrue(view.result.isVisible());
            assertEquals(outcome.name(), firstLabel(view.result));
            assertEquals(outcome == VerificationResult.VALID, view.result.tone() == ResultCard.Tone.SUCCESS);
        });
    }

    private static String firstLabel(Container container) {
        for (Component child : container.getComponents()) {
            if (child instanceof JLabel label && !label.getText().isEmpty()) {
                return label.getText();
            }
            if (child instanceof Container nested) {
                String found = firstLabel(nested);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }

    @Test
    void passwordFieldsDoNotRevealTheirContent() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            AppShell shell = shell();
            assertTrue(shell.keygen.password.echoCharIsSet());
            assertTrue(shell.keygen.confirmation.echoCharIsSet());
            assertTrue(shell.sign.password.echoCharIsSet());
        });
    }

    @Test
    void fingerprintSplitsEvenlyWithoutAStrayColon() {
        String[] lines = ResultCard.inTwoLines(FINGERPRINT).split("\n");

        assertEquals(2, lines.length);
        assertTrue(lines[0].endsWith(":"), lines[0]);
        assertFalse(lines[1].startsWith(":"), lines[1]);
        assertEquals(FINGERPRINT, lines[0] + lines[1]);
    }

    @Test
    void anUnexpectedLengthIsNotSplit() {
        assertEquals("AB:CD:EF", ResultCard.inTwoLines("AB:CD:EF"));
    }
}
