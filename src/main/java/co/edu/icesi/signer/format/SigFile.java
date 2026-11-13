package co.edu.icesi.signer.format;

import co.edu.icesi.signer.crypto.HashAlg;
import co.edu.icesi.signer.crypto.PssParams;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.util.Base64;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * A {@code .sig} file: the signed {@link CanonicalHeader} plus the signature bytes,
 * stored as UTF-8 JSON.
 *
 * <p>Parsing is strict: duplicate keys, trailing content, missing, unknown or
 * wrongly typed fields and hashes outside the allowlist are all rejected. An unknown
 * field would be metadata outside the signature.
 */
public record SigFile(CanonicalHeader header, byte[] signature) {

    /** Largest {@code .sig} accepted, checked before reading it. */
    public static final long MAX_FILE_SIZE = 64 * 1024;

    private static final Pattern FINGERPRINT = Pattern.compile("([0-9A-F]{2}:){31}[0-9A-F]{2}");

    private static final JsonMapper MAPPER = JsonMapper.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .build();

    private static final Pattern SHA256_HEX = Pattern.compile("[0-9a-f]{64}");

    private static final Set<String> LEGACY_FIELDS = Set.of(
            "version", "hashAlg", "pss", "keyFingerprint", "fileName", "signerName", "signedAt", "signature");
    private static final Set<String> TOP_LEVEL_FIELDS = Set.of(
            "version", "hashAlg", "pss", "keyFingerprint", "fileName", "signerName", "signedAt",
            "docVersion", "prevSigHash", "signature");
    private static final Set<String> PSS_FIELDS = Set.of("saltLen", "mgf", "mgfHash", "trailer");

    /** Lowercase hex SHA-256 of a {@code .sig} file's bytes, as {@code prevSigHash} records it. */
    public static String hashOf(byte[] sigFile) {
        return java.util.HexFormat.of().formatHex(HashAlg.SHA_256.newDigest().digest(sigFile));
    }

    /** Serializes to pretty-printed UTF-8 JSON. */
    public byte[] toJson() {
        ObjectNode root = MAPPER.createObjectNode();
        root.put("version", header.version());
        root.put("hashAlg", header.hashAlg().jcaName());
        ObjectNode pss = root.putObject("pss");
        pss.put("saltLen", header.saltLen());
        pss.put("mgf", header.mgf());
        pss.put("mgfHash", header.mgfHash());
        pss.put("trailer", header.trailer());
        root.put("keyFingerprint", header.keyFingerprint());
        root.put("fileName", header.fileName());
        root.put("signerName", header.signerName());
        root.put("signedAt", header.signedAt());
        if (header.hasDocVersion()) {
            root.put("docVersion", header.docVersion());
            root.put("prevSigHash", header.prevSigHash());
        }
        root.put("signature", Base64.getEncoder().encodeToString(signature));
        try {
            return MAPPER.writerWithDefaultPrettyPrinter().writeValueAsBytes(root);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Could not serialize the signature file", e);
        }
    }

    /**
     * Parses UTF-8 JSON.
     *
     * @throws SigValidationException if the content is not a valid {@code .sig}
     */
    public static SigFile parse(byte[] json) throws SigValidationException {
        JsonNode root;
        try {
            root = MAPPER.readTree(json);
        } catch (IOException e) {
            throw new SigValidationException("The signature file is not valid JSON", e);
        }
        if (root == null || !root.isObject()) {
            throw new SigValidationException("The signature file must be a JSON object");
        }
        if (!root.has("version")) {
            throw new SigValidationException("Missing field: version");
        }
        int version = integer(root, "version");
        boolean legacy = version == CanonicalHeader.LEGACY_VERSION;
        if (!legacy && version != CanonicalHeader.CURRENT_VERSION) {
            throw new SigValidationException("Signature format version not supported: " + version);
        }
        requireExactFields(root, legacy ? LEGACY_FIELDS : TOP_LEVEL_FIELDS, "");
        JsonNode pss = root.get("pss");
        if (!pss.isObject()) {
            throw new SigValidationException("Field pss must be an object");
        }
        requireExactFields(pss, PSS_FIELDS, "pss.");

        String hashLabel = text(root, "hashAlg");
        HashAlg hashAlg = HashAlg.fromJcaName(hashLabel)
                .orElseThrow(() -> new SigValidationException("Hash algorithm not allowed: " + hashLabel));

        byte[] signature = decodeSignature(text(root, "signature"));

        try {
            CanonicalHeader header = new CanonicalHeader(
                    version,
                    hashAlg,
                    integer(pss, "saltLen"),
                    text(pss, "mgf"),
                    text(pss, "mgfHash"),
                    integer(pss, "trailer"),
                    text(root, "keyFingerprint"),
                    text(root, "fileName"),
                    text(root, "signerName"),
                    text(root, "signedAt"),
                    legacy ? 0 : integer(root, "docVersion"),
                    legacy ? "" : text(root, "prevSigHash"));
            requireExpectedValues(header);
            return new SigFile(header, signature);
        } catch (IllegalArgumentException e) {
            throw new SigValidationException(e.getMessage(), e);
        }
    }

    /**
     * Checks values the format fixes completely. They are signed too, so a changed one
     * would also end in INVALID, but it is a malformed file rather than a bad signature.
     */
    private static void requireExpectedValues(CanonicalHeader header) throws SigValidationException {
        HashAlg hash = header.hashAlg();
        if (header.saltLen() != hash.digestLength()) {
            throw new SigValidationException("Field pss.saltLen must be " + hash.digestLength() + " for " + hash.jcaName());
        }
        if (!PssParams.MGF.equals(header.mgf())) {
            throw new SigValidationException("Field pss.mgf must be " + PssParams.MGF);
        }
        if (!hash.jcaName().equals(header.mgfHash())) {
            throw new SigValidationException("Field pss.mgfHash must be " + hash.jcaName());
        }
        if (header.trailer() != PssParams.TRAILER_FIELD) {
            throw new SigValidationException("Field pss.trailer must be " + PssParams.TRAILER_FIELD);
        }
        if (!FINGERPRINT.matcher(header.keyFingerprint()).matches()) {
            throw new SigValidationException("Field keyFingerprint is not a SHA-256 fingerprint");
        }
        String fileName = header.fileName();
        if (fileName.isEmpty() || fileName.contains("/") || fileName.contains("\\")) {
            throw new SigValidationException("Field fileName must be a base name, without any path");
        }
        if (header.hasDocVersion()) {
            if (header.docVersion() < 1) {
                throw new SigValidationException("Field docVersion must be 1 or more");
            }
            boolean first = header.docVersion() == 1;
            if (first != header.prevSigHash().isEmpty()) {
                throw new SigValidationException(first
                        ? "Field prevSigHash must be empty for version 1"
                        : "Field prevSigHash must chain to the previous version");
            }
            if (!first && !SHA256_HEX.matcher(header.prevSigHash()).matches()) {
                throw new SigValidationException("Field prevSigHash is not a lowercase hex SHA-256");
            }
        }
    }

    /** Only the canonical encoding is accepted: the JDK decoder also takes unpadded input. */
    private static byte[] decodeSignature(String encoded) throws SigValidationException {
        try {
            byte[] decoded = Base64.getDecoder().decode(encoded);
            if (!Base64.getEncoder().encodeToString(decoded).equals(encoded)) {
                throw new SigValidationException("Field signature is not canonical Base64");
            }
            return decoded;
        } catch (IllegalArgumentException e) {
            throw new SigValidationException("Field signature is not valid Base64", e);
        }
    }

    private static void requireExactFields(JsonNode node, Set<String> expected, String prefix)
            throws SigValidationException {
        for (String field : expected) {
            if (!node.has(field)) {
                throw new SigValidationException("Missing field: " + prefix + field);
            }
        }
        for (var names = node.fieldNames(); names.hasNext(); ) {
            String field = names.next();
            if (!expected.contains(field)) {
                throw new SigValidationException("Unknown field: " + prefix + field);
            }
        }
    }

    private static String text(JsonNode node, String field) throws SigValidationException {
        JsonNode value = node.get(field);
        if (!value.isTextual()) {
            throw new SigValidationException("Field " + field + " must be a string");
        }
        return value.textValue();
    }

    private static int integer(JsonNode node, String field) throws SigValidationException {
        JsonNode value = node.get(field);
        if (!value.isInt()) {
            throw new SigValidationException("Field " + field + " must be an integer");
        }
        return value.intValue();
    }
}
