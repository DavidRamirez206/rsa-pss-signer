package co.edu.icesi.signer.gui;

import co.edu.icesi.signer.gui.I18n.Language;

/** What the interface remembers between runs. */
interface Settings {

    boolean guideSeen();

    void markGuideSeen();

    Language language();

    void language(Language language);
}
