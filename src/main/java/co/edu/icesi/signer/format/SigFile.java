package co.edu.icesi.signer.format;

import co.edu.icesi.signer.crypto.HashAlg;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.util.Base64;
import java.util.Set;

/**
 * A {@code .sig} file: the signed {@link CanonicalHeader} plus the signature bytes,
 * stored as UTF-8 JSON.
 *
 * <p>Parsing is strict: duplicate keys, trailing content, missing, unknown or
 * wrongly typed fields and hashes outside the allowlist are all rejected. An unknown
 * field would be metadata outside the signature.
 */
public record SigFile(CanonicalHeader header, byte[] signature) {

    private static final JsonMapper MAPPER = JsonMapper.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .build();

    private static final Set<String> TOP_LEVEL_FIELDS = Set.of(
            "version", "hashAlg", "pss", "keyFingerprint", "fileName", "signerName", "signedAt", "signature");
    private static final Set<String> PSS_FIELDS = Set.of("saltLen", "mgf", "mgfHash", "trailer");

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
        requireExactFields(root, TOP_LEVEL_FIELDS, "");
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
                    integer(root, "version"),
                    hashAlg,
                    integer(pss, "saltLen"),
                    text(pss, "mgf"),
                    text(pss, "mgfHash"),
                    integer(pss, "trailer"),
                    text(root, "keyFingerprint"),
                    text(root, "fileName"),
                    text(root, "signerName"),
                    text(root, "signedAt"));
            return new SigFile(header, signature);
        } catch (IllegalArgumentException e) {
            throw new SigValidationException(e.getMessage(), e);
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
