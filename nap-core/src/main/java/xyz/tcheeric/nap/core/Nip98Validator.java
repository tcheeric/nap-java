package xyz.tcheeric.nap.core;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import nostr.crypto.schnorr.Schnorr;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;

/**
 * Stateless NIP-98 validation matching the TypeScript {@code verifyNip98Completion()} exactly.
 *
 * <p>Validation order:
 * <ol>
 *   <li>Parse {@code Authorization: Nostr <base64>} header</li>
 *   <li>Verify {@code kind == 27235} and {@code content == ""}</li>
 *   <li>Verify Schnorr signature</li>
 *   <li>Verify {@code created_at} within clock skew window</li>
 *   <li>Verify {@code u} tag matches URL (normalized)</li>
 *   <li>Verify {@code method} tag matches HTTP method</li>
 *   <li>Verify {@code payload} tag matches SHA-256 of raw body</li>
 *   <li>Extract {@code challenge} and {@code challenge_id} tags</li>
 * </ol>
 */
public final class Nip98Validator {

    private static final Logger log = LoggerFactory.getLogger(Nip98Validator.class);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final HexFormat HEX = HexFormat.of();
    private static final String NOSTR_PREFIX = "Nostr ";

    private Nip98Validator() {
    }

    /**
     * Validates a NIP-98 authorization header and returns the extracted completion data.
     */
    public static Nip98ValidationResult verifyNip98Completion(VerifyNip98CompletionInput input) {
        if (input.authorization() == null || input.authorization().isBlank()) {
            return Nip98ValidationResult.failure(NapErrorCode.NAP_COMPLETE_MISSING_AUTH_HEADER);
        }

        if (!input.authorization().startsWith(NOSTR_PREFIX)) {
            return Nip98ValidationResult.failure(NapErrorCode.NAP_COMPLETE_INVALID_AUTH_SCHEME);
        }

        Nip98Event event = parseNostrAuthorizationHeader(input.authorization());
        if (event == null) {
            return Nip98ValidationResult.failure(NapErrorCode.NAP_COMPLETE_INVALID_EVENT_JSON);
        }

        if (event.kind() != 27235) {
            return Nip98ValidationResult.failure(NapErrorCode.NAP_COMPLETE_INVALID_KIND);
        }

        if (!"".equals(event.content())) {
            return Nip98ValidationResult.failure(NapErrorCode.NAP_COMPLETE_INVALID_EVENT_JSON);
        }

        if (!verifySignature(event)) {
            return Nip98ValidationResult.failure(NapErrorCode.NAP_COMPLETE_INVALID_SIGNATURE);
        }

        int maxSkew = input.maxClockSkewSeconds() > 0
                ? input.maxClockSkewSeconds()
                : VerifyNip98CompletionInput.DEFAULT_MAX_CLOCK_SKEW_SECONDS;
        if (Math.abs(input.now() - event.createdAt()) > maxSkew) {
            return Nip98ValidationResult.failure(NapErrorCode.NAP_COMPLETE_CREATED_AT_OUT_OF_RANGE);
        }

        String urlTag = getSingleTag(event, "u");
        if (urlTag == null) {
            return Nip98ValidationResult.failure(NapErrorCode.NAP_COMPLETE_INVALID_EVENT_JSON);
        }
        if (!exactUrlMatch(urlTag, input.url())) {
            return Nip98ValidationResult.failure(NapErrorCode.NAP_COMPLETE_URL_MISMATCH);
        }

        String methodTag = getSingleTag(event, "method");
        if (methodTag == null) {
            return Nip98ValidationResult.failure(NapErrorCode.NAP_COMPLETE_INVALID_EVENT_JSON);
        }
        if (!methodTag.equalsIgnoreCase(input.method())) {
            return Nip98ValidationResult.failure(NapErrorCode.NAP_COMPLETE_METHOD_MISMATCH);
        }

        String payloadTag = getSingleTag(event, "payload");
        if (payloadTag == null) {
            return Nip98ValidationResult.failure(NapErrorCode.NAP_COMPLETE_MISSING_PAYLOAD);
        }
        String expectedPayload = sha256Hex(input.rawBody());
        if (!payloadTag.equals(expectedPayload)) {
            return Nip98ValidationResult.failure(NapErrorCode.NAP_COMPLETE_PAYLOAD_MISMATCH);
        }

        String challengeIdTag = getSingleTag(event, "challenge_id");
        if (challengeIdTag == null) {
            return Nip98ValidationResult.failure(NapErrorCode.NAP_COMPLETE_MISSING_CHALLENGE_ID);
        }
        if (input.body() == null || input.body().challengeId() == null
                || !challengeIdTag.equals(input.body().challengeId())) {
            return Nip98ValidationResult.failure(NapErrorCode.NAP_COMPLETE_MISSING_CHALLENGE_ID);
        }

        String challengeTag = getSingleTag(event, "challenge");
        if (challengeTag == null) {
            return Nip98ValidationResult.failure(NapErrorCode.NAP_COMPLETE_CHALLENGE_MISMATCH);
        }

        return Nip98ValidationResult.success(new VerifiedNip98Completion(
                event, challengeTag, challengeIdTag, payloadTag
        ));
    }

    /**
     * Validates that created_at falls within the challenge-bound window.
     */
    public static boolean validateChallengeBoundCreatedAt(
            long createdAt, long issuedAt, long expiresAt,
            int lowerBoundGraceSeconds, int upperBoundGraceSeconds
    ) {
        return createdAt >= (issuedAt - lowerBoundGraceSeconds)
                && createdAt <= (expiresAt + upperBoundGraceSeconds);
    }

    static Nip98Event parseNostrAuthorizationHeader(String authorization) {
        try {
            String base64Event = authorization.substring(NOSTR_PREFIX.length());
            byte[] eventBytes = Base64.getDecoder().decode(base64Event);
            String json = new String(eventBytes, StandardCharsets.UTF_8);
            JsonNode node = OBJECT_MAPPER.readTree(json);

            String id = node.path("id").asText(null);
            String pubkey = node.path("pubkey").asText(null);
            long createdAt = node.path("created_at").asLong(0);
            int kind = node.path("kind").asInt(-1);
            String content = node.path("content").asText(null);
            String sig = node.path("sig").asText(null);

            if (id == null || pubkey == null || sig == null || content == null) {
                return null;
            }

            List<List<String>> tags = new ArrayList<>();
            JsonNode tagsNode = node.path("tags");
            if (tagsNode.isArray()) {
                for (JsonNode tagArray : tagsNode) {
                    if (tagArray.isArray()) {
                        List<String> tag = new ArrayList<>();
                        for (JsonNode element : tagArray) {
                            tag.add(element.asText());
                        }
                        tags.add(tag);
                    }
                }
            }

            return new Nip98Event(id, pubkey, createdAt, kind, tags, content, sig);
        } catch (Exception e) {
            log.debug("Failed to parse Nostr authorization header: {}", e.getMessage());
            return null;
        }
    }

    static String getSingleTag(Nip98Event event, String tagName) {
        List<List<String>> matches = event.tags().stream()
                .filter(tag -> tag.size() >= 2 && tagName.equals(tag.get(0)))
                .toList();

        if (matches.size() != 1) {
            return null;
        }
        return matches.get(0).get(1);
    }

    static boolean exactUrlMatch(String url1, String url2) {
        try {
            URI u1 = URI.create(url1).normalize();
            URI u2 = URI.create(url2).normalize();
            return u1.equals(u2);
        } catch (Exception e) {
            return url1.equals(url2);
        }
    }

    static String sha256Hex(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data);
            return HEX.formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    /**
     * The id is <em>recomputed</em> before the signature is checked, never trusted as presented.
     *
     * <p>Verifying a signature over the id the caller supplied proves only that the key signed
     * <em>some</em> event. Every other field — the {@code u}, {@code payload}, {@code challenge}
     * and {@code challenge_id} tags included — is read from the same caller-supplied JSON, so
     * without this check any note the victim ever published could be re-dressed as a completion
     * for a challenge the attacker opened, and the signature would still verify. Recomputing is
     * what binds the signature to the fields the rest of this validator inspects.
     *
     * <p>Matches {@code verifyEvent()} in {@code nostr-tools}, which the TypeScript
     * implementation relies on for the same check.
     */
    static boolean verifySignature(Nip98Event event) {
        try {
            byte[] message = HEX.parseHex(event.id());
            byte[] publicKey = HEX.parseHex(event.pubkey());
            byte[] signature = HEX.parseHex(event.sig());

            if (message.length != 32 || publicKey.length != 32 || signature.length != 64) {
                return false;
            }

            if (!MessageDigest.isEqual(message, computeEventId(event))) {
                log.debug("Event id does not match the canonical serialization");
                return false;
            }

            return Schnorr.verify(message, publicKey, signature);
        } catch (Exception e) {
            log.debug("Signature verification failed: {}", e.getMessage());
            return false;
        }
    }

    /**
     * {@code sha256(utf8([0, pubkey, created_at, kind, tags, content]))} — the NIP-01 canonical
     * serialization, compact and in this exact field order.
     */
    private static byte[] computeEventId(Nip98Event event) throws Exception {
        ArrayNode serialized = OBJECT_MAPPER.createArrayNode();
        serialized.add(0);
        serialized.add(event.pubkey());
        serialized.add(event.createdAt());
        serialized.add(event.kind());
        ArrayNode tags = serialized.addArray();
        for (List<String> tag : event.tags()) {
            ArrayNode element = tags.addArray();
            tag.forEach(element::add);
        }
        serialized.add(event.content());

        return MessageDigest.getInstance("SHA-256")
                .digest(OBJECT_MAPPER.writeValueAsBytes(serialized));
    }

    /**
     * Result of NIP-98 validation — either a success with the verified completion data,
     * or a failure with the error code.
     */
    public sealed interface Nip98ValidationResult {

        record Success(VerifiedNip98Completion value) implements Nip98ValidationResult {
        }

        record Failure(NapErrorCode code, boolean retryable) implements Nip98ValidationResult {
        }

        static Nip98ValidationResult success(VerifiedNip98Completion value) {
            return new Success(value);
        }

        static Nip98ValidationResult failure(NapErrorCode code) {
            return new Failure(code, code.isRetryable());
        }

        default boolean isSuccess() {
            return this instanceof Success;
        }
    }
}
