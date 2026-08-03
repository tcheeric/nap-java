package xyz.tcheeric.nap.server;

/**
 * Pluggable rate limiter (RFC §17.1).
 *
 * <p>{@code /auth/init} is unauthenticated and writes a row per call, so a limiter in front of
 * it is the difference between a public endpoint and a public write amplifier.
 * {@link InMemoryRateLimiter} covers a single process; anything multi-instance needs a shared
 * backend behind this interface.
 */
@FunctionalInterface
public interface RateLimiter {

    RateLimitDecision check(RateLimitKey key);
}
