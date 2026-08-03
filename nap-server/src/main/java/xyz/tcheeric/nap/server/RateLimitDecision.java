package xyz.tcheeric.nap.server;

/**
 * @param retryAfterSeconds seconds until the caller's window resets, surfaced as the
 *                          {@code Retry-After} header on the 429. {@code null} when allowed.
 */
public record RateLimitDecision(boolean allowed, Integer retryAfterSeconds) {

    private static final RateLimitDecision ALLOW = new RateLimitDecision(true, null);

    /** Named {@code allow} because {@code allowed()} is the record's accessor. */
    public static RateLimitDecision allow() {
        return ALLOW;
    }

    public static RateLimitDecision denied(int retryAfterSeconds) {
        return new RateLimitDecision(false, retryAfterSeconds);
    }
}
