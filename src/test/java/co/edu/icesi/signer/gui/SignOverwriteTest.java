package co.edu.icesi.signer.gui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import co.edu.icesi.signer.gui.GuiActions.GeneratedKeys;
import co.edu.icesi.signer.keystore.PrivateKeyStore;
import java.lang.reflect.InvocationTargetException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Signing through the real view, with the dialog's answer replaced. */
class SignOverwriteTest {

    private static final String PASSWORD = "correct horse battery";

    private final GuiActions actions = new GuiActions(new PrivateKeyStore(1000), Clock.systemUTC());
    private final List<String> asked = new ArrayList<>();

    @TempDir
    Path dir;

    private Path file;
    private Path sig;
    private SignView view;

    @BeforeAll
    static void installTheme() throws InterruptedException, InvocationTargetException {
        SwingUtilities.invokeAndWait(Theme::install);
    }

    @BeforeEach
    void prepare() throws Exception {
        I18n.use(I18n.Language.ENGLISH);
        GeneratedKeys keys = actions.generateKeys(
                dir.resolve("ana").toString(), 2048, PASSWORD.toCharArray(), PASSWORD.toCharArray());
        file = Files.writeString(dir.resolve("contract.txt"), "content");
        sig = dir.resolve("contract.txt.sig");
        SwingUtilities.invokeAndWait(() -> {
            view = new SignView(actions);
            view.file.value(file.toString());
            view.key.value(keys.privateKey().toString());
            view.signer.setText("Ana Perez");
            view.password.setText(PASSWORD);
        });
    }

    private void clickSign(boolean answer) throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            view.confirmOverwrite = name -> {
                asked.add(name);
                return answer;
            };
            view.sign.doClick();
        });
    }

    private void waitUntilFinished() throws Exception {
        long deadline = System.currentTimeMillis() + 30_000;
        boolean[] done = {false};
        while (!done[0] && System.currentTimeMillis() < deadline) {
            Thread.sleep(50);
            SwingUtilities.invokeAndWait(() -> done[0] = view.result.isVisible());
        }
        assertTrue(done[0], "The operation did not finish");
    }

    @Test
    void onlyTheOverwriteOptionCountsAsYes() {
        assertTrue(SignView.agreed(0));
        assertFalse(SignView.agreed(1));
        assertFalse(SignView.agreed(JOptionPane.CLOSED_OPTION));
    }

    @Test
    void withoutAPreviousSignatureNothingIsAsked() throws Exception {
        clickSign(false);
        waitUntilFinished();

        assertEquals(List.of(), asked);
        assertTrue(Files.size(sig) > 100);
    }

    @Test
    void cancellingKeepsTheSignatureAndThePassword() throws Exception {
        Files.writeString(sig, "old");

        clickSign(false);

        assertEquals(List.of("contract.txt.sig"), asked);
        assertEquals("old", Files.readString(sig));
        SwingUtilities.invokeAndWait(() -> assertEquals(PASSWORD.length(), view.password.getPassword().length));
    }

    @Test
    void acceptingReplacesTheSignature() throws Exception {
        Files.writeString(sig, "old");

        clickSign(true);
        waitUntilFinished();

        assertEquals(List.of("contract.txt.sig"), asked);
        assertEquals(ResultCard.Tone.SUCCESS, view.result.tone());
        assertTrue(Files.size(sig) > 100);
    }
}
