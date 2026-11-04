package co.edu.icesi.signer.gui;

import co.edu.icesi.signer.gui.I18n.Language;
import java.util.Locale;
import java.util.prefs.BackingStoreException;
import java.util.prefs.Preferences;

/**
 * Keeps the settings in the user's Java preferences. Failing to store them only means
 * they are asked for again next time, so that is not treated as an error.
 */
final class StoredSettings implements Settings {

    private static final String GUIDE_KEY = "userGuideSeen";
    private static final String LANGUAGE_KEY = "language";

    private final Preferences preferences = Preferences.userNodeForPackage(StoredSettings.class);

    @Override
    public boolean guideSeen() {
        return preferences.getBoolean(GUIDE_KEY, false);
    }

    @Override
    public void markGuideSeen() {
        preferences.putBoolean(GUIDE_KEY, true);
        save();
    }

    @Override
    public Language language() {
        String saved = preferences.get(LANGUAGE_KEY, null);
        return saved == null ? I18n.defaultFor(Locale.getDefault()) : Language.fromCode(saved);
    }

    @Override
    public void language(Language language) {
        preferences.put(LANGUAGE_KEY, language.code);
        save();
    }

    private void save() {
        try {
            preferences.flush();
        } catch (BackingStoreException | SecurityException e) {
            System.err.println("Could not save the settings: " + e.getMessage());
        }
    }
}
