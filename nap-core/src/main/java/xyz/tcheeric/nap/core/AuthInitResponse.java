package xyz.tcheeric.nap.core;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

import java.util.List;

/**
 * The {@code /auth/init} response (RFC §24.3).
 *
 * <h2>Unknown fields are ignored deliberately</h2>
 *
 * <p>Jackson's default is to throw on an unrecognised property, which turns every additive
 * field the RFC permits into a breaking change for this client. It is not hypothetical: the
 * TypeScript implementation added {@code supported_extensions} and a Java client reading that
 * response failed with {@code UnrecognizedPropertyException} before this annotation existed.
 *
 * <p>An additive field is only additive if the other implementation tolerates it, so tolerance
 * is part of the protocol contract rather than a Jackson preference.
 *
 * <h2>Nulls are omitted, not serialised</h2>
 *
 * <p>{@code NON_NULL} matters here rather than being tidiness. The TypeScript field is
 * {@code supported_extensions?: string[]}, and the contract is that <em>absence</em> means "the
 * server makes no claim". Emitting {@code "supported_extensions": null} would be a type
 * violation on that side and would read as a claim to any client testing for the key's presence
 * rather than its truthiness.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record AuthInitResponse(
        String challengeId,
        String challenge,
        String authUrl,
        String authMethod,
        long issuedAt,
        long expiresAt,
        /**
         * Extensions the server understands, e.g. {@code ["voucher-acl/1"]}; {@code null} when
         * the server makes no claim.
         *
         * <p>Absence means "makes no claim", not "supports nothing": every server predating the
         * field omits it, including servers that support an extension. A client MUST treat null
         * as unknown and try, rather than as a refusal.
         */
        List<String> supportedExtensions
) {

    /**
     * The six-argument form, for a server that advertises no extensions.
     *
     * <p>Kept so adding the field stays source-compatible for callers that have nothing to
     * advertise, which is every caller today. Omitting it would make an additive protocol field
     * a breaking API change, which is the opposite of what §24.3 intends.
     */
    public AuthInitResponse(
            String challengeId,
            String challenge,
            String authUrl,
            String authMethod,
            long issuedAt,
            long expiresAt
    ) {
        this(challengeId, challenge, authUrl, authMethod, issuedAt, expiresAt, null);
    }
}
