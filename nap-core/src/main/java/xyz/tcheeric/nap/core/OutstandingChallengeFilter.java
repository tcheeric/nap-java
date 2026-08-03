package xyz.tcheeric.nap.core;

/**
 * Filter for {@link ChallengeStore#countOutstanding}. Exactly one of {@code npub} /
 * {@code clientIp} is normally set; both null counts every outstanding challenge.
 */
public record OutstandingChallengeFilter(String npub, String clientIp, long now) {

    public static OutstandingChallengeFilter forNpub(String npub, long now) {
        return new OutstandingChallengeFilter(npub, null, now);
    }

    public static OutstandingChallengeFilter forClientIp(String clientIp, long now) {
        return new OutstandingChallengeFilter(null, clientIp, now);
    }
}
