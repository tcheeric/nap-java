package xyz.tcheeric.nap.core;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

/**
 * @param clientIp     caller address as resolved by the adapter's trust policy, or {@code null}
 *                     when it opted out of reporting one. Feeds the per-address outstanding cap
 *                     (RFC §17.4).
 * @param failureCount proof failures counted against this challenge (RFC §13.4).
 */
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record ChallengeRecord(
        String challengeId,
        String challenge,
        String npub,
        String pubkey,
        String authUrl,
        String authMethod,
        long issuedAt,
        long expiresAt,
        ChallengeState state,
        String redeemedEventId,
        String redeemedSessionId,
        Long resultCacheUntil,
        String clientIp,
        int failureCount
) {

    public ChallengeRecord(
            String challengeId,
            String challenge,
            String npub,
            String pubkey,
            String authUrl,
            String authMethod,
            long issuedAt,
            long expiresAt,
            ChallengeState state,
            String redeemedEventId,
            String redeemedSessionId,
            Long resultCacheUntil
    ) {
        this(challengeId, challenge, npub, pubkey, authUrl, authMethod, issuedAt, expiresAt,
                state, redeemedEventId, redeemedSessionId, resultCacheUntil, null, 0);
    }

    public static ChallengeRecord issued(
            String challengeId,
            String challenge,
            String npub,
            String pubkey,
            String authUrl,
            String authMethod,
            long issuedAt,
            long expiresAt
    ) {
        return issued(challengeId, challenge, npub, pubkey, authUrl, authMethod,
                issuedAt, expiresAt, null);
    }

    public static ChallengeRecord issued(
            String challengeId,
            String challenge,
            String npub,
            String pubkey,
            String authUrl,
            String authMethod,
            long issuedAt,
            long expiresAt,
            String clientIp
    ) {
        return new ChallengeRecord(
                challengeId, challenge, npub, pubkey, authUrl, authMethod,
                issuedAt, expiresAt, ChallengeState.ISSUED, null, null, null, clientIp, 0
        );
    }
}
