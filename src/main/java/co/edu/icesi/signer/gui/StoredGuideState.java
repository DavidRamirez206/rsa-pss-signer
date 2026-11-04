package co.edu.icesi.signer.gui;

import java.util.prefs.BackingStoreException;
import java.util.prefs.Preferences;

/**
 * Keeps the flag in the user's Java preferences. Failing to store it only means the
 * guide appears again next time, so that is not treated as an error.
 */
final class StoredGuideState implements GuideState {

    private static final String KEY = "userGuideSeen";

    private final Preferences preferences = Preferences.userNodeForPackage(StoredGuideState.class);

    @Override
    public boolean seen() {
        return preferences.getBoolean(KEY, false);
    }

    @Override
    public void markSeen() {
        preferences.putBoolean(KEY, true);
        try {
            preferences.flush();
        } catch (BackingStoreException | SecurityException e) {
            System.err.println("Could not remember that the user guide was seen: " + e.getMessage());
        }
    }
}
