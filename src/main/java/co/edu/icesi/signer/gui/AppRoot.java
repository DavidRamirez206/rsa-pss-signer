package co.edu.icesi.signer.gui;

import co.edu.icesi.signer.gui.I18n.Language;
import java.awt.CardLayout;
import javax.swing.JPanel;

/**
 * The window content: the application, or the user guide on top of it on first run.
 * Changing the language rebuilds both, keeping the page and the non-secret fields.
 * Passwords are not carried over, and they are not kept anywhere else either.
 */
final class AppRoot extends JPanel {
    private static final long serialVersionUID = 1L;

    private static final String APP = "app";
    private static final String GUIDE = "guide";

    AppShell shell;
    UserGuide guide;

    private final CardLayout cards = new CardLayout();
    private final transient GuiActions actions;
    private final transient Settings settings;
    private boolean guideShown;

    AppRoot(GuiActions actions, Settings settings) {
        this.actions = actions;
        this.settings = settings;
        setLayout(cards);
        setBackground(Theme.BACKGROUND);
        I18n.use(settings.language());
        build();
        if (settings.guideSeen()) {
            showApp();
        } else {
            openGuide();
        }
    }

    boolean isGuideShown() {
        return guideShown;
    }

    private void build() {
        removeAll();
        shell = new AppShell(actions, this::openGuide, this::changeLanguage);
        guide = new UserGuide(this::closeGuide, this::changeLanguage);
        add(shell, APP);
        add(guide, GUIDE);
    }

    void changeLanguage(Language language) {
        if (language == I18n.current()) {
            return;
        }
        settings.language(language);
        I18n.use(language);

        AppShell oldShell = shell;
        int guidePage = guide.currentPage();
        build();
        shell.keepFieldsOf(oldShell);
        guide.show(guidePage);
        cards.show(this, guideShown ? GUIDE : APP);
        revalidate();
        repaint();
    }

    private void openGuide() {
        guide.show(0);
        cards.show(this, GUIDE);
        guideShown = true;
    }

    private void closeGuide() {
        settings.markGuideSeen();
        showApp();
    }

    private void showApp() {
        cards.show(this, APP);
        guideShown = false;
    }
}
