package co.edu.icesi.signer.core;

import java.util.List;
import java.util.Locale;
import java.util.ResourceBundle;

/**
 * A text the user reads, kept as a key and its arguments so each interface can show it in
 * its own language: English on the command line, the chosen language in the window.
 * The texts live in the {@code i18n/messages} bundles.
 */
public record Message(String key, List<Object> args) {

    private static final String BUNDLE = "i18n.messages";

    public Message {
        args = List.copyOf(args);
    }

    public static Message of(String key, Object... args) {
        return new Message(key, List.of(args));
    }

    /** The text in a given bundle, with {@code %s} and {@code %d} filled in. */
    public String in(ResourceBundle bundle) {
        return String.format(Locale.ROOT, bundle.getString(key), args.toArray());
    }

    /** The English text, as the command line shows it. */
    public String english() {
        return in(ResourceBundle.getBundle(BUNDLE, Locale.ROOT,
                ResourceBundle.Control.getNoFallbackControl(ResourceBundle.Control.FORMAT_PROPERTIES)));
    }
}
