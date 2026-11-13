package co.edu.icesi.signer.policy;

import java.io.IOException;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.TreeMap;

/**
 * Trust on first use, like SSH's {@code known_hosts}: the first valid signature from a
 * signer name pins its key, and a later signature under that name with another key is
 * flagged. It trusts that the first contact was legitimate: if Mallory's key arrives
 * first as "Ana", it is Mallory's key that gets pinned.
 */
public final class TrustStore {

    static final String FILE = "trusted-keys.properties";

    private final LocalState state;

    public TrustStore(LocalState state) {
        this.state = state;
    }

    /** The fingerprint pinned for this signer, if any. */
    public Optional<String> pinned(String signerName) throws IOException {
        return Optional.ofNullable(state.load(FILE).getProperty(signerName));
    }

    /** Pins the key of a signer that has none yet. */
    public void pin(String signerName, String fingerprint) throws IOException {
        Properties keys = state.load(FILE);
        if (keys.containsKey(signerName)) {
            throw new IllegalStateException("A key is already pinned for " + signerName);
        }
        keys.setProperty(signerName, fingerprint);
        state.save(FILE, keys, "Signer name = pinned key fingerprint (trust on first use)");
    }

    /** Forgets a signer's key, so the next valid signature pins a new one. */
    public boolean remove(String signerName) throws IOException {
        Properties keys = state.load(FILE);
        if (keys.remove(signerName) == null) {
            return false;
        }
        state.save(FILE, keys, "Signer name = pinned key fingerprint (trust on first use)");
        return true;
    }

    /** All pinned keys, by signer name. */
    public Map<String, String> all() throws IOException {
        Map<String, String> result = new TreeMap<>();
        state.load(FILE).forEach((name, fingerprint) -> result.put((String) name, (String) fingerprint));
        return result;
    }
}
