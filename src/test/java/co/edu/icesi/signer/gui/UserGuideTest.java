package co.edu.icesi.signer.gui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import co.edu.icesi.signer.keystore.PrivateKeyStore;
import java.lang.reflect.InvocationTargetException;
import java.time.Clock;
import javax.swing.SwingUtilities;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class UserGuideTest {

    private static final class MemoryState implements GuideState {
        boolean seen;

        MemoryState(boolean seen) {
            this.seen = seen;
        }

        @Override
        public boolean seen() {
            return seen;
        }

        @Override
        public void markSeen() {
            seen = true;
        }
    }

    @BeforeAll
    static void installTheme() throws InterruptedException, InvocationTargetException {
        SwingUtilities.invokeAndWait(Theme::install);
    }

    private static AppRoot root(GuideState state) {
        return new AppRoot(new GuiActions(new PrivateKeyStore(1000), Clock.systemUTC()), state);
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
            for (int i = 1; i < UserGuide.PAGES.size(); i++) {
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
}
