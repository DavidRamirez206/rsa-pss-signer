package co.edu.icesi.signer.gui;

import com.formdev.flatlaf.FlatDarkLaf;
import java.awt.Color;
import java.awt.Font;
import java.awt.FontFormatException;
import java.awt.Insets;
import java.awt.font.TextAttribute;
import java.io.IOException;
import java.io.InputStream;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import javax.swing.UIManager;

/** The red and black palette and the bundled Plus Jakarta Sans font. */
final class Theme {

    static final Color BACKGROUND = new Color(0x0A0A0D);
    static final Color SIDEBAR = new Color(0x101014);
    static final Color SURFACE = new Color(0x15151A);
    static final Color FIELD = new Color(0x1D1D23);
    static final Color FIELD_HOVER = new Color(0x26262D);
    static final Color BORDER = new Color(0x2C2C34);

    static final Color RED = new Color(0xE3172E);
    static final Color RED_BRIGHT = new Color(0xFF3B4E);
    static final Color RED_DEEP = new Color(0x8E0E1E);
    static final Color RED_TINT = new Color(0xE3, 0x17, 0x2E, 0x24);

    static final Color TEXT = new Color(0xF5F5F7);
    static final Color MUTED = new Color(0xA3A3AE);
    static final Color FAINT = new Color(0x6E6E7A);

    static final Color SUCCESS = new Color(0x2FCB8B);
    static final Color WARNING = new Color(0xF6A723);

    static final int ARC = 12;

    private static final Map<String, Font> LOADED = new ConcurrentHashMap<>();

    private Theme() {
    }

    static Font regular(float size) {
        return font("Regular", size);
    }

    static Font medium(float size) {
        return font("Medium", size);
    }

    static Font semiBold(float size) {
        return font("SemiBold", size);
    }

    static Font bold(float size) {
        return font("Bold", size);
    }

    /** Digits and hex groups line up better in a monospaced font. */
    static Font fingerprint(float size) {
        return new Font(Font.MONOSPACED, Font.PLAIN, Math.round(size));
    }

    private static Font font(String weight, float size) {
        // Kerning and a touch of tracking: at small sizes the default spacing looks cramped
        return LOADED.computeIfAbsent(weight, Theme::load).deriveFont(Map.of(
                TextAttribute.SIZE, size,
                TextAttribute.KERNING, TextAttribute.KERNING_ON,
                TextAttribute.TRACKING, 0.012f));
    }

    private static Font load(String weight) {
        String resource = "/fonts/PlusJakartaSans-" + weight + ".ttf";
        try (InputStream in = Theme.class.getResourceAsStream(resource)) {
            if (in == null) {
                throw new IllegalStateException("Missing font: " + resource);
            }
            return Font.createFont(Font.TRUETYPE_FONT, in);
        } catch (IOException | FontFormatException e) {
            throw new IllegalStateException("Cannot load font: " + resource, e);
        }
    }

    /** Installs the look and feel. Call before creating any component. */
    static void install() {
        FlatDarkLaf.setup();
        Font base = regular(14f);
        UIManager.put("defaultFont", base);
        UIManager.put("Panel.background", BACKGROUND);
        UIManager.put("Label.foreground", TEXT);
        UIManager.put("Component.arc", ARC);
        UIManager.put("Button.arc", ARC);
        UIManager.put("TextComponent.arc", ARC);
        UIManager.put("Component.focusWidth", 1);
        UIManager.put("Component.innerFocusWidth", 0);
        UIManager.put("Component.borderColor", BORDER);
        UIManager.put("Component.focusColor", RED);
        UIManager.put("Component.focusedBorderColor", RED);
        UIManager.put("TextField.background", FIELD);
        UIManager.put("PasswordField.background", FIELD);
        UIManager.put("TextField.foreground", TEXT);
        UIManager.put("PasswordField.foreground", TEXT);
        UIManager.put("TextField.caretForeground", RED_BRIGHT);
        UIManager.put("PasswordField.caretForeground", RED_BRIGHT);
        UIManager.put("TextField.selectionBackground", RED_DEEP);
        UIManager.put("PasswordField.selectionBackground", RED_DEEP);
        UIManager.put("TextField.placeholderForeground", FAINT);
        UIManager.put("TextField.margin", new Insets(8, 12, 8, 12));
        UIManager.put("PasswordField.margin", new Insets(8, 12, 8, 12));
        UIManager.put("ComboBox.background", FIELD);
        UIManager.put("ComboBox.buttonBackground", FIELD);
        UIManager.put("ComboBox.selectionBackground", RED_DEEP);
        UIManager.put("ComboBox.padding", new Insets(6, 10, 6, 10));
        UIManager.put("List.selectionBackground", RED_DEEP);
        UIManager.put("ScrollBar.thumb", BORDER);
        UIManager.put("ScrollBar.track", BACKGROUND);
        UIManager.put("ScrollBar.thumbArc", 999);
        UIManager.put("ScrollBar.width", 8);
    }
}
