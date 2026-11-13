package co.edu.icesi.signer.gui;

import co.edu.icesi.signer.core.Message;
import java.util.Locale;
import java.util.ResourceBundle;
import javax.swing.JComponent;
import javax.swing.UIManager;

/** The language of the interface and the text in it. The command line stays in English. */
final class I18n {

    enum Language {
        ENGLISH("en", Locale.ROOT),
        SPANISH("es", Locale.forLanguageTag("es"));

        final String code;
        final Locale locale;

        Language(String code, Locale locale) {
            this.code = code;
            this.locale = locale;
        }

        static Language fromCode(String code) {
            return code.equals(SPANISH.code) ? SPANISH : ENGLISH;
        }
    }

    private static final String BUNDLE = "i18n.messages";

    private static volatile Language current = Language.ENGLISH;
    private static volatile ResourceBundle messages = load(Language.ENGLISH);

    private I18n() {
    }

    /** The language to start with when none was chosen: Spanish on Spanish systems. */
    static Language defaultFor(Locale system) {
        return system.getLanguage().equals(Language.SPANISH.code) ? Language.SPANISH : Language.ENGLISH;
    }

    static Language current() {
        return current;
    }

    static void use(Language language) {
        messages = load(language);
        current = language;
        // Also translates what Swing draws itself, such as the file chooser
        Locale locale = language == Language.ENGLISH ? Locale.ENGLISH : language.locale;
        JComponent.setDefaultLocale(locale);
        UIManager.getDefaults().setDefaultLocale(locale);
    }

    /** The text for a key, with {@code %s} and {@code %d} filled in when arguments are given. */
    static String t(String key, Object... args) {
        String text = messages.getString(key);
        return args.length == 0 ? text : String.format(text, args);
    }

    /** A message from the services, in the current language. */
    static String t(Message message) {
        return message.in(messages);
    }

    static ResourceBundle load(Language language) {
        return ResourceBundle.getBundle(BUNDLE, language.locale,
                ResourceBundle.Control.getNoFallbackControl(ResourceBundle.Control.FORMAT_PROPERTIES));
    }
}
