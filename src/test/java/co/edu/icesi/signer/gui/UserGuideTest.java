package co.edu.icesi.signer.gui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import co.edu.icesi.signer.gui.I18n.Language;
import co.edu.icesi.signer.keystore.PrivateKeyStore;
import co.edu.icesi.signer.policy.TestState;
import java.lang.reflect.InvocationTargetException;
import java.time.Clock;
import javax.swing.SwingUtilities;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class UserGuideTest {

    private static final class MemoryState implements Settings {
        boolean seen;
        Language language = Language.ENGLISH;

        MemoryState(boolean seen) {
            this.seen = seen;
        }

        @Override
        public boolean guideSeen() {
            return seen;
        }

        @Override
        public void markGuideSeen() {
            seen = true;
        }

        @Override
        public Language language() {
            return language;
        }

        @Override
        public void language(Language language) {
            this.language = language;
        }
    }

    @BeforeEach
    void startInEnglish() {
        I18n.use(Language.ENGLISH);
    }

    @AfterEach
    void backToEnglish() {
        I18n.use(Language.ENGLISH);
    }

    @BeforeAll
    static void installTheme() throws InterruptedException, InvocationTargetException {
        SwingUtilities.invokeAndWait(Theme::install);
    }

    private static AppRoot root(Settings state) {
        return new AppRoot(new GuiActions(new PrivateKeyStore(1000), Clock.systemUTC(), TestState.fresh()), state);
    }

    private static void onEdt(Runnable test) throws InterruptedException, InvocationTargetException {
        SwingUtilities.invokeAndWait(test);
    }

    @Test
    void firstRunOpensTheGuideOnItsFirstPage() throws Exception {
        onEdt(() -> {
            AppRoot root = root(new MemoryState(false));

            assertTrue(root.isGuideShown());
            assertTrue(root.guide.isVisible());
            assertFalse(root.shell.isVisible());
            assertEquals(0, root.guide.currentPage());
        });
    }

    @Test
    void laterRunsGoStraightToTheApplication() throws Exception {
        onEdt(() -> {
            AppRoot root = root(new MemoryState(true));

            assertFalse(root.isGuideShown());
            assertTrue(root.shell.isVisible());
        });
    }

    @Test
    void skipClosesTheGuideAndIsRemembered() throws Exception {
        onEdt(() -> {
            MemoryState state = new MemoryState(false);
            AppRoot root = root(state);

            root.guide.skip.doClick();

            assertFalse(root.isGuideShown());
            assertTrue(root.shell.isVisible());
            assertTrue(state.seen);
            assertFalse(root(state).isGuideShown());
        });
    }

    @Test
    void skipWorksFromAMiddlePage() throws Exception {
        onEdt(() -> {
            MemoryState state = new MemoryState(false);
            AppRoot root = root(state);
            root.guide.next.doClick();
            assertEquals(1, root.guide.currentPage());

            root.guide.skip.doClick();

            assertFalse(root.isGuideShown());
            assertTrue(state.seen);
        });
    }

    @Test
    void nextReachesTheEndAndGetStartedCloses() throws Exception {
        onEdt(() -> {
            MemoryState state = new MemoryState(false);
            AppRoot root = root(state);
            for (int i = 1; i < UserGuide.pageCount(); i++) {
                assertTrue(root.isGuideShown());
                assertFalse(state.seen, "Not finished on page " + i);
                root.guide.next.doClick();
                assertEquals(i, root.guide.currentPage());
            }
            assertEquals("Get started", root.guide.next.getText());

            root.guide.next.doClick();

            assertFalse(root.isGuideShown());
            assertTrue(state.seen);
        });
    }

    @Test
    void backReturnsAndIsHiddenOnTheFirstPage() throws Exception {
        onEdt(() -> {
            UserGuide guide = root(new MemoryState(false)).guide;
            assertFalse(guide.back.isVisible());

            guide.next.doClick();
            assertTrue(guide.back.isVisible());

            guide.back.doClick();
            assertEquals(0, guide.currentPage());
        });
    }

    @Test
    void guideCanBeReopenedFromTheSidebarAtItsStart() throws Exception {
        onEdt(() -> {
            AppRoot root = root(new MemoryState(false));
            root.guide.next.doClick();
            root.guide.skip.doClick();

            root.shell.guideButton.doClick();

            assertTrue(root.isGuideShown());
            assertEquals(0, root.guide.currentPage());
        });
    }

    @Test
    void closingTheWindowOnTheGuideDoesNotCountAsSeen() throws Exception {
        onEdt(() -> {
            MemoryState state = new MemoryState(false);
            root(state);

            assertFalse(state.seen);
        });
    }

    @Test
    void languageIsAppliedAndSavedAndKeepsPageAndFields() throws Exception {
        onEdt(() -> {
            MemoryState state = new MemoryState(true);
            AppRoot root = root(state);
            root.shell.select("sign");
            root.shell.sign.file.value("contract.pdf");
            root.shell.sign.signer.setText("Ana Perez");
            root.shell.sign.password.setText("not kept");

            root.shell.languageSwitch.spanish.doClick();

            assertEquals(Language.SPANISH, state.language);
            assertEquals(Language.SPANISH, I18n.current());
            assertEquals(I18n.load(Language.SPANISH).getString("nav.guide"), root.shell.guideButton.getText());
            assertTrue(root.shell.sign.isVisible());
            assertEquals("contract.pdf", root.shell.sign.file.value());
            assertEquals("Ana Perez", root.shell.sign.signer.getText());
            assertEquals(0, root.shell.sign.password.getPassword().length);
            assertFalse(root.isGuideShown());
        });
    }

    @Test
    void languageCanChangeInsideTheGuideWithoutLeavingItsPage() throws Exception {
        onEdt(() -> {
            MemoryState state = new MemoryState(false);
            AppRoot root = root(state);
            root.guide.next.doClick();

            root.guide.languageSwitch.spanish.doClick();

            assertTrue(root.isGuideShown());
            assertTrue(root.guide.isVisible());
            assertFalse(root.shell.isVisible());
            assertEquals(1, root.guide.currentPage());
            assertEquals("Omitir", root.guide.skip.getText());
            assertFalse(state.seen, "Changing language is not the same as skipping");
        });
    }

    @Test
    void savedLanguageIsUsedOnStart() throws Exception {
        onEdt(() -> {
            MemoryState state = new MemoryState(true);
            state.language = Language.SPANISH;

            AppRoot root = root(state);

            assertEquals(I18n.load(Language.SPANISH).getString("nav.guide"), root.shell.guideButton.getText());
        });
    }
}
