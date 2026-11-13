package co.edu.icesi.signer.timestamp;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * A time stamp: the authority's signature over the hash of a {@code .sig} and its own time.
 * Stored as strict JSON, like the {@code .sig}; what is signed is {@link #canonicalBytes()}.
 *
 * @param sigHash lowercase hex SHA-256 of the stamped {@code .sig} file
 * @param time ISO-8601 time from the authority's clock
 * @param authorityFingerprint fingerprint of the authority's public key
 * @param signature RSASSA-PSS signature with SHA-256 over the canonical bytes
 */
public record TimeToken(String sigHash, String time, String authorityFingerprint, byte[] signature) {

    /** Largest token accepted, checked before reading it. */
    public static final long MAX_FILE_SIZE = 64 * 1024;

    private static final int VERSION = 1;
    private static final Pattern SHA256_HEX = Pattern.compile("[0-9a-f]{64}");
    private static final Pattern FINGERPRINT = Pattern.compile("([0-9A-F]{2}:){31}[0-9A-F]{2}");
    private static final Pattern TIME = Pattern.compile("[0-9T:+\\-Z]{20,25}");
    private static final Set<String> FIELDS = Set.of("version", "sigHash", "time", "authorityFingerprint", "signature");

    private static final JsonMapper MAPPER = JsonMapper.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .build();

    /** What the authority signs, one field per line in a fixed order. */
    public byte[] canonicalBytes() {
        return ("tstv1\n"
                + "sigHash=" + sigHash + "\n"
                + "time=" + time + "\n"
                + "authorityFingerprint=" + authorityFingerprint + "\n").getBytes(StandardCharsets.UTF_8);
    }

    public byte[] toJson() {
        ObjectNode root = MAPPER.createObjectNode();
        root.put("version", VERSION);
        root.put("sigHash", sigHash);
        root.put("time", time);
        root.put("authorityFingerprint", authorityFingerprint);
        root.put("signature", Base64.getEncoder().encodeToString(signature));
        try {
            return MAPPER.writerWithDefaultPrettyPrinter().writeValueAsBytes(root);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Could not serialize the time stamp", e);
        }
    }

    /**
     * Parses a token strictly: exact fields, fixed formats, canonical Base64.
     *
     * @throws IOException if the content is not a valid token
     */
    public static TimeToken parse(byte[] json) throws IOException {
        JsonNode root;
        try {
            root = MAPPER.readTree(json);
        } catch (IOException e) {
            throw new IOException("The time stamp is not valid JSON", e);
        }
        if (root == null || !root.isObject()) {
            throw new IOException("The time stamp must be a JSON object");
        }
        for (String field : FIELDS) {
            if (!root.has(field)) {
                throw new IOException("Missing field in the time stamp: " + field);
            }
        }
        if (root.size() != FIELDS.size()) {
            throw new IOException("Unknown field in the time stamp");
        }
        if (!root.get("version").isInt() || root.get("version").intValue() != VERSION) {
            throw new IOException("Time stamp version not supported");
        }
        String sigHash = text(root, "sigHash", SHA256_HEX);
        String time = text(root, "time", TIME);
        String fingerprint = text(root, "authorityFingerprint", FINGERPRINT);
        String encoded = text(root, "signature", null);
        byte[] signature;
        try {
            signature = Base64.getDecoder().decode(encoded);
        } catch (IllegalArgumentException e) {
            throw new IOException("Field signature of the time stamp is not valid Base64", e);
        }
        if (!Base64.getEncoder().encodeToString(signature).equals(encoded)) {
            throw new IOException("Field signature of the time stamp is not canonical Base64");
        }
        return new TimeToken(sigHash, time, fingerprint, signature);
    }

    private static String text(JsonNode root, String field, Pattern format) throws IOException {
        JsonNode value = root.get(field);
        if (!value.isTextual() || (format != null && !format.matcher(value.textValue()).matches())) {
            throw new IOException("Field " + field + " of the time stamp is malformed");
        }
        return value.textValue();
    }
}
