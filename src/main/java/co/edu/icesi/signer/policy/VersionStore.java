package co.edu.icesi.signer.policy;

import java.io.IOException;
import java.util.Properties;

/**
 * The highest version of each document verified on this machine, so an older version
 * presented later is detected. A document is identified by the signer's key and the
 * file name in the signature. On another machine, or after deleting this state, an
 * old version verifies again: a signature on its own cannot tell which version is current.
 */
public final class VersionStore {

    static final String FILE = "document-versions.properties";

    private final LocalState state;

    public VersionStore(LocalState state) {
        this.state = state;
    }

    private static String key(String keyFingerprint, String fileName) {
        return keyFingerprint + "/" + fileName;
    }

    /** The highest version seen for this document, or 0 if none. */
    public int highestSeen(String keyFingerprint, String fileName) throws IOException {
        String value = state.load(FILE).getProperty(key(keyFingerprint, fileName));
        if (value == null) {
            return 0;
        }
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            throw new IOException("Corrupt entry in " + FILE + " for " + fileName, e);
        }
    }

    /** Records a verified version if it is higher than what was seen. */
    public void record(String keyFingerprint, String fileName, int docVersion) throws IOException {
        if (docVersion <= highestSeen(keyFingerprint, fileName)) {
            return;
        }
        Properties versions = state.load(FILE);
        versions.setProperty(key(keyFingerprint, fileName), Integer.toString(docVersion));
        state.save(FILE, versions, "Key fingerprint/file name = highest document version verified");
    }
}
