package xyz.tcheeric.nap.core;

import java.util.Optional;

public interface SessionStore {

    SessionRecord createForChallenge(SessionRecord record);

    Optional<SessionRecord> getBySessionId(String sessionId);

    Optional<SessionRecord> getByAccessToken(String accessToken);

    void revokeBySessionId(String sessionId, long nowUnix);

    int revokeByPrincipal(String pubkey, long nowUnix);

    /**
     * Advance the sliding window on an active session (spec 006). Updates
     * {@code lastActivityAt} and {@code expiresAt} atomically; leaves
     * {@code absoluteExpiryAt} untouched. No-op when the session is absent,
     * revoked, or past its absolute expiry.
     *
     * <p>The caller is responsible for clamping {@code newExpiresAt} to
     * {@code absoluteExpiryAt} — the store enforces no policy, only storage.
     *
     * @param sessionId            opaque session identifier (same value read from the cookie)
     * @param newLastActivityAt    unix-seconds; typically {@code now}
     * @param newExpiresAt         unix-seconds; typically {@code min(now + idleTtl, absoluteExpiryAt)}
     */
    void touch(String sessionId, long newLastActivityAt, long newExpiresAt);

    /**
     * Look up a session by either its current <em>or</em> its previous refresh token
     * (RFC §14.1). Both, deliberately: returning nothing for a retired token would make a
     * replay indistinguishable from a made-up one, and the whole point of rotation is that
     * the difference is detectable. Revoked rows must still be returned for the same
     * reason.
     *
     * <p>Defaults to empty so stores written before refresh tokens keep compiling. Leaving
     * it unimplemented means {@code refreshTtlSeconds} cannot be configured — the server
     * refuses to start rather than serve a {@code /auth/refresh} that always fails.
     */
    default Optional<SessionRecord> getByRefreshToken(String refreshToken) {
        return Optional.empty();
    }

    /**
     * Swap in a new access and refresh token on an existing session, retaining the outgoing
     * refresh token as {@code previousRefreshToken}. Returns the updated record, or empty if
     * the session is gone or no longer holds
     * {@link RotateRefreshTokenParams#expectedRefreshToken}.
     *
     * <p>Rotation stays on the one row: the row <em>is</em> the token family, so revoking it
     * on a replay revokes the lineage without a separate family table.
     */
    default Optional<SessionRecord> rotateRefreshToken(String sessionId, RotateRefreshTokenParams params) {
        return Optional.empty();
    }

    /**
     * Whether this store can back {@code /auth/refresh}. Both methods above default to a
     * no-op, so a store that implements neither would otherwise mint refresh tokens that
     * every refresh then rejects.
     */
    default boolean supportsRefreshTokens() {
        return false;
    }
}
