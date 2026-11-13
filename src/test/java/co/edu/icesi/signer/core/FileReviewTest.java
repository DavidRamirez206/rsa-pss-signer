package co.edu.icesi.signer.core;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/** Type 3: a warning for formats that can show something other than their bytes. */
class FileReviewTest {

    @ParameterizedTest
    @CsvSource({"contract.pdf, true", "REPORT.DOCX, true", "sheet.xlsm, true", "page.html, true",
        "notes.txt, false", "data.csv, false", "archive.tar.gz, false", "pdf, false", "no-extension, false",
        "trailing.dot., false"})
    void flagsFormatsThatCanHideContent(String name, boolean expected) {
        assertEquals(expected, FileReview.canHideContent(name));
    }
}
