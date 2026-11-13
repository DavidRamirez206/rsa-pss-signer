package co.edu.icesi.signer.core;

import java.util.Locale;
import java.util.Set;

/**
 * What a signature cannot cover: it guarantees the bytes, not what a program shows on
 * screen. Formats that can hide content (macros, hidden text, layers, scripts) get a
 * warning before signing. This is a partial mitigation; there is no cryptographic fix.
 */
public final class FileReview {

    private static final Set<String> COMPLEX_FORMATS = Set.of(
            "pdf", "doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx", "pptm",
            "odt", "ods", "odp", "rtf", "htm", "html", "svg");

    private FileReview() {
    }

    /** Whether the file's format can show something other than, or less than, its bytes. */
    public static boolean canHideContent(String fileName) {
        int dot = fileName.lastIndexOf('.');
        return dot >= 0 && COMPLEX_FORMATS.contains(fileName.substring(dot + 1).toLowerCase(Locale.ROOT));
    }

    public static final String WARNING = "This format can hide content (macros, hidden text, layers):"
            + " the signature covers its bytes, not what you see on screen. Sign only what you have checked.";
}
