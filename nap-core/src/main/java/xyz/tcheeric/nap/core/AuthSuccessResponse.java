package xyz.tcheeric.nap.core;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

import java.util.List;

/**
 * Body of a successful {@code POST /auth/complete}.
 *
 * <p>{@code stepUpToken} / {@code stepUpExpiresAt} are populated only when the
 * request asked for a step-up ({@link AuthCompleteRequest#stepUp()}); they are
 * omitted from the JSON otherwise, matching the TypeScript reference where they
 * are optional fields rather than nulls.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record AuthSuccessResponse(
        String status,
        String accessToken,
        String tokenType,
        long expiresAt,
        long absoluteExpiryAt,
        Principal principal,
        List<String> roles,
        List<String> permissions,
        String stepUpToken,
        Long stepUpExpiresAt
) {

    public AuthSuccessResponse(String status, String accessToken, String tokenType, long expiresAt,
                               long absoluteExpiryAt, Principal principal, List<String> roles,
                               List<String> permissions) {
        this(status, accessToken, tokenType, expiresAt, absoluteExpiryAt, principal, roles,
                permissions, null, null);
    }

    /**
     * Back-compat constructor — pre-006 callers didn't supply {@code absoluteExpiryAt};
     * default it to {@code expiresAt} (no sliding).
     */
    public AuthSuccessResponse(String status, String accessToken, String tokenType, long expiresAt,
                               Principal principal, List<String> roles, List<String> permissions) {
        this(status, accessToken, tokenType, expiresAt, expiresAt, principal, roles, permissions);
    }

    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public record Principal(String npub, String pubkey) {
    }
}
