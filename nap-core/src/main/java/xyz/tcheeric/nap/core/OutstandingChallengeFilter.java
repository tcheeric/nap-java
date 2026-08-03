package xyz.tcheeric.nap.core;

/**
 * Filter for {@link ChallengeStore#countOutstanding}. Set fields are ANDed; both null counts
 * every outstanding challenge.
 */
public record OutstandingChallengeFilter(String npub, String clientIp, long now) {

    public static OutstandingChallengeFilter forNpub(String npub, long now) {
        return new OutstandingChallengeFilter(npub, null, now);
    }

    /**
     * Per-principal count scoped to one caller address — the per-npub cap uses this whenever
     * the adapter reports an address, so that filling a stranger's slots from elsewhere cannot
     * lock them out of an unauthenticated endpoint.
     */
    public static OutstandingChallengeFilter forNpubAtClientIp(String npub, String clientIp, long now) {
        return new OutstandingChallengeFilter(npub, clientIp, now);
    }

    public static OutstandingChallengeFilter forClientIp(String clientIp, long now) {
        return new OutstandingChallengeFilter(null, clientIp, now);
    }
}
