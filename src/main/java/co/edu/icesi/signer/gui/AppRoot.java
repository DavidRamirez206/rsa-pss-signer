package co.edu.icesi.signer.gui;

import java.awt.CardLayout;
import javax.swing.JPanel;

/** The window content: the application, or the user guide on top of it on first run. */
final class AppRoot extends JPanel {
    private static final long serialVersionUID = 1L;

    private static final String APP = "app";
    private static final String GUIDE = "guide";

    final AppShell shell;
    final UserGuide guide;

    private final CardLayout cards = new CardLayout();
    private final GuideState state;
    private boolean guideShown;

    AppRoot(GuiActions actions, GuideState state) {
        this.state = state;
        setLayout(cards);
        setBackground(Theme.BACKGROUND);
        shell = new AppShell(actions, this::openGuide);
        guide = new UserGuide(this::closeGuide);
        add(shell, APP);
        add(guide, GUIDE);
        if (state.seen()) {
            closeWithoutSaving();
        } else {
            openGuide();
        }
    }

    boolean isGuideShown() {
        return guideShown;
    }

    private void openGuide() {
        guide.show(0);
        cards.show(this, GUIDE);
        guideShown = true;
    }

    private void closeGuide() {
        state.markSeen();
        closeWithoutSaving();
    }

    private void closeWithoutSaving() {
        cards.show(this, APP);
        guideShown = false;
    }
}
