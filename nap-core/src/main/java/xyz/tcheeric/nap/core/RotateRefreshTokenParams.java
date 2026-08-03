package xyz.tcheeric.nap.core;

import java.util.List;

/**
 * Arguments to {@link SessionStore#rotateRefreshToken} (RFC §14.1).
 *
 * @param expectedRefreshToken the token the caller presented. The store must only rotate if
 *                             the row still holds it — that compare-and-swap is what stops
 *                             two concurrent refreshes off one credential from both
 *                             succeeding.
 * @param roles                re-resolved at refresh time, not carried over from login.
 */
public record RotateRefreshTokenParams(
        String expectedRefreshToken,
        String accessToken,
        String refreshToken,
        long now,
        long expiresAt,
        long refreshExpiresAt,
        List<String> roles,
        List<String> permissions
) {
}
