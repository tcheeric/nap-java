package xyz.tcheeric.nap.core;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

import java.util.List;

/**
 * NAP session record.
 *
 * <p><b>Sliding-window fields (spec 006):</b>
 * <ul>
 *   <li>{@code issuedAt} — immutable creation time.</li>
 *   <li>{@code lastActivityAt} — timestamp of the most recent {@link SessionStore#touch touch}.
 *       Starts equal to {@code issuedAt}; advanced on every authenticated request.</li>
 *   <li>{@code expiresAt} — the effective (sliding) expiry: capped at {@code absoluteExpiryAt}
 *       and advanced by {@code touch} up to that cap. A filter may treat {@code expiresAt <= now}
 *       as "session ended".</li>
 *   <li>{@code absoluteExpiryAt} — immutable hard cap on the session's total lifetime.</li>
 * </ul>
 * For pre-006 call sites that only know {@code issuedAt}/{@code expiresAt}, the
 * {@link #create(String, String, String, String, String, List, List, long, long)} factory
 * defaults {@code lastActivityAt = issuedAt} and {@code absoluteExpiryAt = expiresAt},
 * giving a non-sliding session.
 *
 * <p><b>Refresh-token fields (RFC §14.1):</b> {@code refreshToken} /
 * {@code refreshExpiresAt} hold the credential {@code POST /auth/refresh} accepts, and
 * {@code previousRefreshToken} the one it just retired. Keeping one step of history is
 * what makes a replay distinguishable from a made-up token — see
 * {@link SessionStore#getByRefreshToken}. All three are {@code null} when the deployment
 * does not issue refresh tokens.
 */
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record SessionRecord(
        String sessionId,
        String challengeId,
        String accessToken,
        String principalNpub,
        String principalPubkey,
        List<String> roles,
        List<String> permissions,
        long issuedAt,
        long lastActivityAt,
        long expiresAt,
        long absoluteExpiryAt,
        Long revokedAt,
        String stepUpToken,
        Long stepUpExpiresAt,
        String refreshToken,
        Long refreshExpiresAt,
        String previousRefreshToken
) {

    /** Pre-refresh-token constructor: the three refresh fields default to {@code null}. */
    public SessionRecord(
            String sessionId,
            String challengeId,
            String accessToken,
            String principalNpub,
            String principalPubkey,
            List<String> roles,
            List<String> permissions,
            long issuedAt,
            long lastActivityAt,
            long expiresAt,
            long absoluteExpiryAt,
            Long revokedAt,
            String stepUpToken,
            Long stepUpExpiresAt
    ) {
        this(sessionId, challengeId, accessToken, principalNpub, principalPubkey,
                roles, permissions, issuedAt, lastActivityAt, expiresAt, absoluteExpiryAt,
                revokedAt, stepUpToken, stepUpExpiresAt, null, null, null);
    }

    /**
     * Create a session with explicit sliding-window fields (spec 006).
     */
    public static SessionRecord create(
            String sessionId,
            String challengeId,
            String accessToken,
            String principalNpub,
            String principalPubkey,
            List<String> roles,
            List<String> permissions,
            long issuedAt,
            long lastActivityAt,
            long expiresAt,
            long absoluteExpiryAt
    ) {
        return new SessionRecord(
                sessionId, challengeId, accessToken, principalNpub, principalPubkey,
                roles, permissions, issuedAt, lastActivityAt, expiresAt, absoluteExpiryAt,
                null, null, null
        );
    }

    /**
     * Back-compat factory for callers that only know {@code issuedAt}/{@code expiresAt}.
     * Defaults {@code lastActivityAt = issuedAt} and {@code absoluteExpiryAt = expiresAt},
     * producing a non-sliding session equivalent to the pre-006 shape.
     */
    public static SessionRecord create(
            String sessionId,
            String challengeId,
            String accessToken,
            String principalNpub,
            String principalPubkey,
            List<String> roles,
            List<String> permissions,
            long issuedAt,
            long expiresAt
    ) {
        return create(
                sessionId, challengeId, accessToken, principalNpub, principalPubkey,
                roles, permissions, issuedAt, issuedAt, expiresAt, expiresAt
        );
    }

    /**
     * Whether the session is still usable at {@code now} under sliding semantics:
     * not revoked, and both the effective (sliding) expiry and the absolute cap
     * are in the future.
     */
    public boolean isActive(long now) {
        return revokedAt == null && expiresAt > now && absoluteExpiryAt > now;
    }

    /** Copy with the roles/permissions a resolver just re-read. */
    public SessionRecord withAcl(List<String> newRoles, List<String> newPermissions) {
        return new SessionRecord(
                sessionId, challengeId, accessToken, principalNpub, principalPubkey,
                newRoles, newPermissions, issuedAt, lastActivityAt, expiresAt, absoluteExpiryAt,
                revokedAt, stepUpToken, stepUpExpiresAt,
                refreshToken, refreshExpiresAt, previousRefreshToken);
    }

    /** Copy marked revoked at {@code nowUnix}. */
    public SessionRecord withRevokedAt(long nowUnix) {
        return new SessionRecord(
                sessionId, challengeId, accessToken, principalNpub, principalPubkey,
                roles, permissions, issuedAt, lastActivityAt, expiresAt, absoluteExpiryAt,
                nowUnix, stepUpToken, stepUpExpiresAt,
                refreshToken, refreshExpiresAt, previousRefreshToken);
    }

    /** Copy with the sliding window advanced (see {@link SessionStore#touch}). */
    public SessionRecord withSlidingWindow(long newLastActivityAt, long newExpiresAt) {
        return new SessionRecord(
                sessionId, challengeId, accessToken, principalNpub, principalPubkey,
                roles, permissions, issuedAt, newLastActivityAt, newExpiresAt, absoluteExpiryAt,
                revokedAt, stepUpToken, stepUpExpiresAt,
                refreshToken, refreshExpiresAt, previousRefreshToken);
    }

    /**
     * Copy with both tokens swapped and the outgoing refresh token retained as
     * {@code previousRefreshToken} (RFC §14.1).
     */
    public SessionRecord withRotatedRefresh(RotateRefreshTokenParams params) {
        return new SessionRecord(
                sessionId, challengeId, params.accessToken(), principalNpub, principalPubkey,
                params.roles(), params.permissions(),
                issuedAt, params.now(), params.expiresAt(), absoluteExpiryAt,
                revokedAt, stepUpToken, stepUpExpiresAt,
                params.refreshToken(), params.refreshExpiresAt(), refreshToken);
    }

    /** Copy carrying a freshly minted refresh credential. */
    public SessionRecord withRefresh(String newRefreshToken, long newRefreshExpiresAt) {
        return new SessionRecord(
                sessionId, challengeId, accessToken, principalNpub, principalPubkey,
                roles, permissions, issuedAt, lastActivityAt, expiresAt, absoluteExpiryAt,
                revokedAt, stepUpToken, stepUpExpiresAt,
                newRefreshToken, newRefreshExpiresAt, previousRefreshToken);
    }
}
