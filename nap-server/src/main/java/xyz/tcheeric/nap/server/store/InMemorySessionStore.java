package xyz.tcheeric.nap.server.store;

import xyz.tcheeric.nap.core.RotateRefreshTokenParams;
import xyz.tcheeric.nap.core.SessionRecord;
import xyz.tcheeric.nap.core.SessionStore;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory SessionStore for testing and single-instance deployments.
 */
public final class InMemorySessionStore implements SessionStore {

    private final ConcurrentHashMap<String, SessionRecord> bySessionId = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, SessionRecord> byAccessToken = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, SessionRecord> byChallengeId = new ConcurrentHashMap<>();
    /** Holds both the current and the previous refresh token — see {@link #getByRefreshToken}. */
    private final ConcurrentHashMap<String, SessionRecord> byRefreshToken = new ConcurrentHashMap<>();

    @Override
    public SessionRecord createForChallenge(SessionRecord record) {
        var existing = byChallengeId.putIfAbsent(record.challengeId(), record);
        if (existing != null) {
            return existing;
        }
        bySessionId.put(record.sessionId(), record);
        byAccessToken.put(record.accessToken(), record);
        if (record.refreshToken() != null) {
            byRefreshToken.put(record.refreshToken(), record);
        }
        return record;
    }

    @Override
    public Optional<SessionRecord> getBySessionId(String sessionId) {
        return Optional.ofNullable(bySessionId.get(sessionId))
                .filter(s -> s.revokedAt() == null);
    }

    @Override
    public Optional<SessionRecord> getByAccessToken(String accessToken) {
        return Optional.ofNullable(byAccessToken.get(accessToken))
                .filter(s -> s.revokedAt() == null);
    }

    @Override
    public void revokeBySessionId(String sessionId, long nowUnix) {
        bySessionId.computeIfPresent(sessionId, (key, existing) -> {
            if (existing.revokedAt() != null) return existing;
            var revoked = existing.withRevokedAt(nowUnix);
            reindex(revoked);
            return revoked;
        });
    }

    @Override
    public int revokeByPrincipal(String pubkey, long nowUnix) {
        int count = 0;
        for (var entry : bySessionId.entrySet()) {
            if (pubkey.equals(entry.getValue().principalPubkey()) && entry.getValue().revokedAt() == null) {
                revokeBySessionId(entry.getKey(), nowUnix);
                count++;
            }
        }
        return count;
    }

    @Override
    public void touch(String sessionId, long newLastActivityAt, long newExpiresAt) {
        bySessionId.computeIfPresent(sessionId, (key, existing) -> {
            if (existing.revokedAt() != null) return existing;
            if (existing.absoluteExpiryAt() <= newLastActivityAt) return existing;
            // Never extend past the absolute cap, even if the caller asks us to.
            long clampedExpiresAt = Math.min(newExpiresAt, existing.absoluteExpiryAt());
            var touched = existing.withSlidingWindow(newLastActivityAt, clampedExpiresAt);
            reindex(touched);
            return touched;
        });
    }

    /** Deliberately no revoked filter: a replay on a revoked session must stay visible. */
    @Override
    public Optional<SessionRecord> getByRefreshToken(String refreshToken) {
        return Optional.ofNullable(byRefreshToken.get(refreshToken));
    }

    @Override
    public Optional<SessionRecord> rotateRefreshToken(String sessionId, RotateRefreshTokenParams params) {
        // Captured inside the atomic swap so a concurrent rotation cannot make us evict
        // tokens the winner still recognises.
        var superseded = new SessionRecord[1];

        var rotated = bySessionId.computeIfPresent(sessionId, (key, existing) -> {
            // Revocation is part of the compare-and-swap, matching `AND revoked_at IS NULL` in
            // JdbcSessionStore: a revoke landing between the server's check and this call must
            // lose here too, or the two stores disagree under exactly the race the CAS exists for.
            if (existing.revokedAt() != null) return existing;
            if (!params.expectedRefreshToken().equals(existing.refreshToken())) return existing;
            superseded[0] = existing;
            return existing.withRotatedRefresh(params);
        });

        if (superseded[0] == null || rotated == null) {
            return Optional.empty();
        }

        // The token two rotations back stops being recognisable here. That is the intended
        // bound: whoever rotated past it already answered for it.
        if (superseded[0].previousRefreshToken() != null) {
            byRefreshToken.remove(superseded[0].previousRefreshToken());
        }
        byAccessToken.remove(superseded[0].accessToken());
        reindex(rotated);
        return Optional.of(rotated);
    }

    @Override
    public boolean supportsRefreshTokens() {
        return true;
    }

    /** Point every secondary index at the new immutable copy of the session. */
    private void reindex(SessionRecord record) {
        byAccessToken.put(record.accessToken(), record);
        byChallengeId.put(record.challengeId(), record);
        if (record.refreshToken() != null) {
            byRefreshToken.put(record.refreshToken(), record);
        }
        if (record.previousRefreshToken() != null) {
            byRefreshToken.put(record.previousRefreshToken(), record);
        }
    }

    public void clear() {
        bySessionId.clear();
        byAccessToken.clear();
        byChallengeId.clear();
        byRefreshToken.clear();
    }
}
