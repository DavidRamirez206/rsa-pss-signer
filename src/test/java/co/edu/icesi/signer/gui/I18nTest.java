package co.edu.icesi.signer.gui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import co.edu.icesi.signer.core.VerificationOutcome;
import co.edu.icesi.signer.core.VerificationResult;
import co.edu.icesi.signer.gui.I18n.Language;
import co.edu.icesi.signer.keystore.PrivateKeyStore;
import co.edu.icesi.signer.policy.TestState;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.util.Locale;
import java.util.ResourceBundle;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import javax.swing.SwingUtilities;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class I18nTest {

    /** Text that really is the same in both languages. */
    private static final Set<String> SAME_IN_BOTH = Set.of("keygen.bits", "sign.hash", "verify.error", "guide.3.3.title");

    private static final Pattern PLACEHOLDER = Pattern.compile("%[sd]");

    private static final ResourceBundle ENGLISH = I18n.load(Language.ENGLISH);
    private static final ResourceBundle SPANISH = I18n.load(Language.SPANISH);

    @AfterEach
    void backToEnglish() {
        I18n.use(Language.ENGLISH);
    }

    @Test
    void bothLanguagesHaveExactlyTheSameKeys() {
        assertEquals(new TreeSet<>(ENGLISH.keySet()), new TreeSet<>(SPANISH.keySet()));
    }

    // The services name their messages by key: a typo would only show up as a crash in the window
    @Test
    void everyMessageTheServicesUseExists() throws Exception {
        Pattern use = Pattern.compile("Message\\.of\\(\\s*(?:pinNow \\? )?\"([a-z.]+)\"(?:\\s*:\\s*\"([a-z.]+)\")?");
        Set<String> used = new TreeSet<>();
        try (Stream<Path> files = Files.walk(Path.of("src/main/java"))) {
            for (Path file : files.filter(p -> p.toString().endsWith(".java")).toList()) {
                Matcher matcher = use.matcher(Files.readString(file));
                while (matcher.find()) {
                    used.add(matcher.group(1));
                    if (matcher.group(2) != null) {
                        used.add(matcher.group(2));
                    }
                }
            }
        }
        assertTrue(used.size() >= 20, used.toString());
        for (String key : used) {
            assertTrue(ENGLISH.containsKey(key), key);
        }
    }

    @Test
    void spanishIsActuallyTranslated() {
        for (String key : ENGLISH.keySet()) {
            if (!SAME_IN_BOTH.contains(key)) {
                assertNotEquals(ENGLISH.getString(key), SPANISH.getString(key), key);
            }
        }
    }

    @Test
    void placeholdersMatchSoFormattingCannotFail() {
        for (String key : ENGLISH.keySet()) {
            assertEquals(placeholders(ENGLISH.getString(key)), placeholders(SPANISH.getString(key)), key);
        }
    }

    private static String placeholders(String text) {
        StringBuilder found = new StringBuilder();
        Matcher matcher = PLACEHOLDER.matcher(text);
        while (matcher.find()) {
            found.append(matcher.group());
        }
        return found.toString();
    }

    @Test
    void spanishAccentsAreReadAsUtf8() {
        assertEquals("Contrase\u00f1a", SPANISH.getString("common.password"));
    }

    @Test
    void textFollowsTheLanguageInUse() {
        I18n.use(Language.SPANISH);
        assertEquals("Omitir", I18n.t("guide.skip"));
        assertTrue(I18n.t("guide.page", 2, 5).startsWith("P\u00e1gina 2"), I18n.t("guide.page", 2, 5));

        I18n.use(Language.ENGLISH);
        assertEquals("Skip", I18n.t("guide.skip"));
    }

    @Test
    void systemLanguageDecidesTheStart() {
        assertEquals(Language.SPANISH, I18n.defaultFor(Locale.forLanguageTag("es-CO")));
        assertEquals(Language.ENGLISH, I18n.defaultFor(Locale.US));
        assertEquals(Language.ENGLISH, I18n.defaultFor(Locale.GERMANY));
    }

    @Test
    void unknownSavedCodeFallsBackToEnglish() {
        assertEquals(Language.SPANISH, Language.fromCode("es"));
        assertEquals(Language.ENGLISH, Language.fromCode("xx"));
    }

    // The translation must never make a bad result read as success
    @Test
    void spanishOutcomesKeepTheirMeaning() throws Exception {
        I18n.use(Language.SPANISH);
        SwingUtilities.invokeAndWait(() -> {
            Theme.install();
            VerifyView view = new VerifyView(new GuiActions(new PrivateKeyStore(1000), Clock.systemUTC(), TestState.fresh()));

            view.present(new VerificationOutcome(VerificationResult.VALID, "detail", null));
            assertEquals(ResultCard.Tone.SUCCESS, view.result.tone());

            view.present(new VerificationOutcome(VerificationResult.INVALID, "detail", null));
            assertEquals(ResultCard.Tone.DANGER, view.result.tone());

            view.present(new VerificationOutcome(VerificationResult.ERROR, "detail", null));
            assertEquals(ResultCard.Tone.CAUTION, view.result.tone());
        });
    }
}
