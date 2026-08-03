package xyz.tcheeric.nap.server;

import xyz.tcheeric.nap.core.ChallengeStore;
import xyz.tcheeric.nap.core.SessionStore;

import java.security.SecureRandom;
import java.time.Clock;

/**
 * @param rateLimiter                     {@code null} disables rate limiting entirely. The
 *                                        builder installs an {@link InMemoryRateLimiter} unless
 *                                        {@code rateLimiter(null)} says otherwise: the response
 *                                        floor below holds every unauthenticated request open,
 *                                        which without a limiter is a concurrency amplifier
 *                                        rather than a timing defence.
 * @param stepUpTtlSeconds                lifetime of the token minted for a
 *                                        {@code "step_up": true} completion (RFC §10.3).
 * @param minAuthResponseMillis           floor every auth response is held to, plus
 *                                        {@code responseJitterMillis} of jitter (RFC §15). The
 *                                        generic 401 hides which check failed; latency did not.
 *                                        Jitter alone would not close it — it hides samples, not
 *                                        the mean — so the floor does the work. Set to 0 in tests.
 */
public record NapServerOptions(
        ChallengeStore challengeStore,
        SessionStore sessionStore,
        AclResolver aclResolver,
        EventReplayGuard eventReplayGuard,
        RateLimiter rateLimiter,
        Clock clock,
        SecureRandom random,
        int challengeTtlSeconds,
        int sessionTtlSeconds,
        int sessionIdleTtlSeconds,
        int sessionAbsoluteTtlSeconds,
        int resultCacheTtlSeconds,
        int maxClockSkewSeconds,
        int lowerBoundGraceSeconds,
        int upperBoundGraceSeconds,
        int stepUpTtlSeconds,
        int maxOutstandingChallengesPerNpub,
        int maxOutstandingChallengesPerIp,
        int maxFailuresPerChallenge,
        int minAuthResponseMillis,
        int responseJitterMillis
) {

    public static final int DEFAULT_CHALLENGE_TTL_SECONDS = 60;
    /** RFC §10.1 caps the challenge TTL; a longer one widens the replay window for a captured proof. */
    public static final int MAX_CHALLENGE_TTL_SECONDS = 60;
    public static final int DEFAULT_SESSION_TTL_SECONDS = 3600;
    public static final int DEFAULT_SESSION_IDLE_TTL_SECONDS = 900;     // 15 min (spec 006)
    public static final int DEFAULT_SESSION_ABSOLUTE_TTL_SECONDS = 43200; // 12 h  (spec 006)
    public static final int DEFAULT_RESULT_CACHE_TTL_SECONDS = 30;
    public static final int DEFAULT_MAX_CLOCK_SKEW_SECONDS = 60;
    public static final int DEFAULT_LOWER_BOUND_GRACE_SECONDS = 30;
    public static final int DEFAULT_UPPER_BOUND_GRACE_SECONDS = 5;
    public static final int DEFAULT_STEP_UP_TTL_SECONDS = 600;
    public static final int DEFAULT_MAX_OUTSTANDING_PER_NPUB = 10;
    public static final int DEFAULT_MAX_OUTSTANDING_PER_IP = 30;
    public static final int DEFAULT_MAX_FAILURES_PER_CHALLENGE = 5;
    public static final int DEFAULT_MIN_AUTH_RESPONSE_MILLIS = 100;
    public static final int DEFAULT_RESPONSE_JITTER_MILLIS = 25;

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private ChallengeStore challengeStore;
        private SessionStore sessionStore;
        private AclResolver aclResolver;
        private EventReplayGuard eventReplayGuard = EventReplayGuard.inMemory();
        private RateLimiter rateLimiter;
        private boolean rateLimiterSet;
        private Clock clock = Clock.systemUTC();
        private SecureRandom random = new SecureRandom();
        private int challengeTtlSeconds = DEFAULT_CHALLENGE_TTL_SECONDS;
        private int sessionTtlSeconds = DEFAULT_SESSION_TTL_SECONDS;
        private Integer sessionIdleTtlSeconds;
        private Integer sessionAbsoluteTtlSeconds;
        private int resultCacheTtlSeconds = DEFAULT_RESULT_CACHE_TTL_SECONDS;
        private int maxClockSkewSeconds = DEFAULT_MAX_CLOCK_SKEW_SECONDS;
        private int lowerBoundGraceSeconds = DEFAULT_LOWER_BOUND_GRACE_SECONDS;
        private int upperBoundGraceSeconds = DEFAULT_UPPER_BOUND_GRACE_SECONDS;
        private int stepUpTtlSeconds = DEFAULT_STEP_UP_TTL_SECONDS;
        private int maxOutstandingChallengesPerNpub = DEFAULT_MAX_OUTSTANDING_PER_NPUB;
        private int maxOutstandingChallengesPerIp = DEFAULT_MAX_OUTSTANDING_PER_IP;
        private int maxFailuresPerChallenge = DEFAULT_MAX_FAILURES_PER_CHALLENGE;
        private int minAuthResponseMillis = DEFAULT_MIN_AUTH_RESPONSE_MILLIS;
        private int responseJitterMillis = DEFAULT_RESPONSE_JITTER_MILLIS;

        public Builder challengeStore(ChallengeStore store) { this.challengeStore = store; return this; }
        public Builder sessionStore(SessionStore store) { this.sessionStore = store; return this; }
        public Builder aclResolver(AclResolver resolver) { this.aclResolver = resolver; return this; }
        public Builder eventReplayGuard(EventReplayGuard replayGuard) { this.eventReplayGuard = replayGuard; return this; }

        /** Pass {@code null} to opt out of rate limiting deliberately. */
        public Builder rateLimiter(RateLimiter limiter) {
            this.rateLimiter = limiter;
            this.rateLimiterSet = true;
            return this;
        }

        public Builder clock(Clock clock) { this.clock = clock; return this; }
        public Builder random(SecureRandom random) { this.random = random; return this; }
        public Builder challengeTtlSeconds(int ttl) { this.challengeTtlSeconds = ttl; return this; }
        public Builder sessionTtlSeconds(int ttl) { this.sessionTtlSeconds = ttl; return this; }
        public Builder sessionIdleTtlSeconds(int ttl) { this.sessionIdleTtlSeconds = ttl; return this; }
        public Builder sessionAbsoluteTtlSeconds(int ttl) { this.sessionAbsoluteTtlSeconds = ttl; return this; }
        public Builder resultCacheTtlSeconds(int ttl) { this.resultCacheTtlSeconds = ttl; return this; }
        public Builder maxClockSkewSeconds(int skew) { this.maxClockSkewSeconds = skew; return this; }
        public Builder lowerBoundGraceSeconds(int grace) { this.lowerBoundGraceSeconds = grace; return this; }
        public Builder upperBoundGraceSeconds(int grace) { this.upperBoundGraceSeconds = grace; return this; }
        public Builder stepUpTtlSeconds(int ttl) { this.stepUpTtlSeconds = ttl; return this; }
        public Builder maxOutstandingChallengesPerNpub(int max) { this.maxOutstandingChallengesPerNpub = max; return this; }
        public Builder maxOutstandingChallengesPerIp(int max) { this.maxOutstandingChallengesPerIp = max; return this; }
        public Builder maxFailuresPerChallenge(int max) { this.maxFailuresPerChallenge = max; return this; }
        public Builder minAuthResponseMillis(int millis) { this.minAuthResponseMillis = millis; return this; }
        public Builder responseJitterMillis(int millis) { this.responseJitterMillis = millis; return this; }

        public NapServerOptions build() {
            if (challengeStore == null) throw new IllegalStateException("challengeStore is required");
            if (sessionStore == null) throw new IllegalStateException("sessionStore is required");
            if (aclResolver == null) aclResolver = new AllowAllAclResolver();
            if (eventReplayGuard == null) eventReplayGuard = EventReplayGuard.inMemory();
            // Fail at wiring time rather than silently issuing a non-conformant challenge.
            if (challengeTtlSeconds < 1 || challengeTtlSeconds > MAX_CHALLENGE_TTL_SECONDS) {
                throw new IllegalStateException(
                        "challengeTtlSeconds must be between 1 and " + MAX_CHALLENGE_TTL_SECONDS
                                + " (RFC §10.1), got " + challengeTtlSeconds);
            }
            if (!rateLimiterSet) rateLimiter = InMemoryRateLimiter.create();
            // Default policy: when the caller didn't set idle/absolute explicitly, derive
            // from sessionTtlSeconds (pre-006 semantics → fixed TTL, no slide) so
            // back-compat callers get the old behavior. New callers SHOULD set both.
            int idleTtl = sessionIdleTtlSeconds != null ? sessionIdleTtlSeconds : sessionTtlSeconds;
            int absoluteTtl = sessionAbsoluteTtlSeconds != null ? sessionAbsoluteTtlSeconds : sessionTtlSeconds;
            return new NapServerOptions(
                    challengeStore, sessionStore, aclResolver, eventReplayGuard, rateLimiter,
                    clock, random,
                    challengeTtlSeconds, sessionTtlSeconds, idleTtl, absoluteTtl,
                    resultCacheTtlSeconds, maxClockSkewSeconds,
                    lowerBoundGraceSeconds, upperBoundGraceSeconds,
                    stepUpTtlSeconds, maxOutstandingChallengesPerNpub, maxOutstandingChallengesPerIp,
                    maxFailuresPerChallenge, minAuthResponseMillis, responseJitterMillis
            );
        }
    }
}
