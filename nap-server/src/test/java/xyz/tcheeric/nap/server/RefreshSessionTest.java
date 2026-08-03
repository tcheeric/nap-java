package xyz.tcheeric.nap.server;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import xyz.tcheeric.nap.core.AclDecision;
import xyz.tcheeric.nap.core.NapErrorCode;
import xyz.tcheeric.nap.core.SessionRecord;
import xyz.tcheeric.nap.core.SessionStore;
import xyz.tcheeric.nap.server.store.InMemoryChallengeStore;
import xyz.tcheeric.nap.server.store.InMemorySessionStore;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Refresh-token rotation (RFC §14.1).
 *
 * <p>Sessions are seeded straight into the store: refresh needs no challenge, and going through
 * a full NIP-98 exchange for each case would only test the exchange again. The end-to-end path —
 * login mints a refresh token, that token rotates — is covered by {@code RefreshRoundTripTest}
 * in {@code nap-it}.
 */
class RefreshSessionTest {

    private static final long T0 = 1_700_000_000L;
    private static final String NPUB = "npub1example";
    private static final String PUBKEY = "aa".repeat(32);

    private InMemorySessionStore store;
    private MutableClock clock;
    private MutableAclResolver acl;

    @BeforeEach
    void setUp() {
        store = new InMemorySessionStore();
        clock = new MutableClock(T0);
        acl = new MutableAclResolver();
    }

    @Test
    void rotatesBothTokensAndKeepsOneStepOfHistory() {
        SessionRecord seeded = seed("refresh-1", T0 + 3600);
        NapServer server = server(store, 3600);

        clock.set(T0 + 60);
        RefreshSessionOutcome outcome = server.refreshSession(new RefreshSessionInput("refresh-1", "1.2.3.4"));

        assertThat(outcome.isSuccess()).isTrue();
        SessionRecord rotated = ((RefreshSessionOutcome.Success) outcome).session();
        assertThat(rotated.sessionId()).isEqualTo(seeded.sessionId());
        assertThat(rotated.refreshToken()).isNotBlank().isNotEqualTo("refresh-1");
        assertThat(rotated.previousRefreshToken()).isEqualTo("refresh-1");
        assertThat(rotated.accessToken()).isNotBlank().isNotEqualTo(seeded.accessToken());
        assertThat(rotated.refreshExpiresAt()).isEqualTo(T0 + 60 + 3600);
        // The idle window advances; the absolute cap the session was created with does not.
        assertThat(rotated.expiresAt()).isEqualTo(T0 + 60 + 900);
        assertThat(rotated.absoluteExpiryAt()).isEqualTo(seeded.absoluteExpiryAt());
        assertThat(store.getByAccessToken(seeded.accessToken())).isEmpty();
    }

    @Test
    void clampsToAbsoluteExpiry() {
        store.createForChallenge(record("sess-1", "chal-1", "access-1", "refresh-1",
                T0 + 3600, T0 + 900, T0 + 120, null));
        NapServer server = server(store, 3600);

        clock.set(T0 + 60);
        var outcome = server.refreshSession(new RefreshSessionInput("refresh-1", "1.2.3.4"));

        assertThat(((RefreshSessionOutcome.Success) outcome).session().expiresAt()).isEqualTo(T0 + 120);
    }

    @Test
    void replayingRetiredTokenRevokesTheWholeFamily() {
        seed("refresh-1", T0 + 3600);
        NapServer server = server(store, 3600);

        var first = server.refreshSession(new RefreshSessionInput("refresh-1", "1.2.3.4"));
        String liveToken = ((RefreshSessionOutcome.Success) first).session().refreshToken();

        var replay = server.refreshSession(new RefreshSessionInput("refresh-1", "1.2.3.4"));
        assertThat(failure(replay).code()).isEqualTo(NapErrorCode.NAP_REFRESH_REUSED);

        // The thief's replay costs the legitimate holder its session too. That is the point:
        // one of the two is an attacker and the server cannot tell which.
        var afterTheft = server.refreshSession(new RefreshSessionInput(liveToken, "1.2.3.4"));
        assertThat(failure(afterTheft).code()).isEqualTo(NapErrorCode.NAP_REFRESH_REVOKED);
        assertThat(store.getBySessionId("sess-1")).isEmpty();
    }

    @Test
    void unknownAndMissingTokensAnswerAlike() {
        seed("refresh-1", T0 + 3600);
        NapServer server = server(store, 3600);

        assertThat(failure(server.refreshSession(new RefreshSessionInput("nope", "1.2.3.4"))).code())
                .isEqualTo(NapErrorCode.NAP_REFRESH_UNKNOWN_TOKEN);
        assertThat(failure(server.refreshSession(new RefreshSessionInput(null, "1.2.3.4"))).code())
                .isEqualTo(NapErrorCode.NAP_REFRESH_UNKNOWN_TOKEN);
        assertThat(failure(server.refreshSession(new RefreshSessionInput("  ", "1.2.3.4"))).code())
                .isEqualTo(NapErrorCode.NAP_REFRESH_UNKNOWN_TOKEN);
    }

    /** An unconfigured deployment must not be distinguishable from a wrong token. */
    @Test
    void refreshDisabledLooksLikeAnUnknownToken() {
        seed("refresh-1", T0 + 3600);
        NapServer server = server(store, 0);

        assertThat(failure(server.refreshSession(new RefreshSessionInput("refresh-1", "1.2.3.4"))).code())
                .isEqualTo(NapErrorCode.NAP_REFRESH_UNKNOWN_TOKEN);
    }

    @Test
    void expiredRefreshToken() {
        seed("refresh-1", T0 + 60);
        NapServer server = server(store, 3600);

        clock.set(T0 + 61);
        assertThat(failure(server.refreshSession(new RefreshSessionInput("refresh-1", "1.2.3.4"))).code())
                .isEqualTo(NapErrorCode.NAP_REFRESH_EXPIRED);
    }

    @Test
    void revokedSession() {
        seed("refresh-1", T0 + 3600);
        store.revokeBySessionId("sess-1", T0 + 10);
        NapServer server = server(store, 3600);

        assertThat(failure(server.refreshSession(new RefreshSessionInput("refresh-1", "1.2.3.4"))).code())
                .isEqualTo(NapErrorCode.NAP_REFRESH_REVOKED);
    }

    @Test
    void aclDenialWithoutRevokeLeavesTheSessionAlone() {
        seed("refresh-1", T0 + 3600);
        NapServer server = server(store, 3600);
        acl.decision = AclDecision.denied("acl unreadable");

        assertThat(failure(server.refreshSession(new RefreshSessionInput("refresh-1", "1.2.3.4"))).code())
                .isEqualTo(NapErrorCode.NAP_REFRESH_ACL_DENIED);
        assertThat(store.getBySessionId("sess-1")).isPresent();
    }

    @Test
    void aclDenialWithRevokeEndsEverySessionThePrincipalHolds() {
        seed("refresh-1", T0 + 3600);
        NapServer server = server(store, 3600);
        acl.decision = AclDecision.denied("suspended", true);

        assertThat(failure(server.refreshSession(new RefreshSessionInput("refresh-1", "1.2.3.4"))).code())
                .isEqualTo(NapErrorCode.NAP_REFRESH_ACL_DENIED);
        assertThat(store.getBySessionId("sess-1")).isEmpty();
    }

    /** Refresh is where a role change reaches a live session — that is why the ACL is re-read. */
    @Test
    void rotatedSessionCarriesTheCurrentAcl() {
        seed("refresh-1", T0 + 3600);
        NapServer server = server(store, 3600);
        acl.decision = AclDecision.allowed(List.of("admin"), List.of("orders:write"));

        var outcome = server.refreshSession(new RefreshSessionInput("refresh-1", "1.2.3.4"));

        SessionRecord rotated = ((RefreshSessionOutcome.Success) outcome).session();
        assertThat(rotated.roles()).containsExactly("admin");
        assertThat(rotated.permissions()).containsExactly("orders:write");
    }

    @Test
    void rateLimitedCarriesRetryAfter() {
        seed("refresh-1", T0 + 3600);
        NapServer server = NapServer.create(baseOptions(store, 3600)
                .rateLimiter(key -> RateLimitDecision.denied(42))
                .build());

        var outcome = server.refreshSession(new RefreshSessionInput("refresh-1", "1.2.3.4"));

        assertThat(failure(outcome).code()).isEqualTo(NapErrorCode.NAP_REFRESH_RATE_LIMITED);
        assertThat(failure(outcome).retryAfterSeconds()).isEqualTo(42);
        assertThat(failure(outcome).retryable()).isTrue();
    }

    /**
     * Minting refresh tokens a store cannot honour would hand out credentials that fail at
     * every use, so the misconfiguration is refused at startup rather than at 3am.
     */
    @Test
    void refreshTtlRequiresAStoreThatSupportsIt() {
        SessionStore plainStore = new SessionStore() {
            @Override
            public SessionRecord createForChallenge(SessionRecord record) {
                return record;
            }

            @Override
            public Optional<SessionRecord> getBySessionId(String sessionId) {
                return Optional.empty();
            }

            @Override
            public Optional<SessionRecord> getByAccessToken(String accessToken) {
                return Optional.empty();
            }

            @Override
            public void revokeBySessionId(String sessionId, long nowUnix) {
            }

            @Override
            public int revokeByPrincipal(String pubkey, long nowUnix) {
                return 0;
            }

            @Override
            public void touch(String sessionId, long newLastActivityAt, long newExpiresAt) {
            }
        };

        assertThatThrownBy(() -> baseOptions(plainStore, 3600).build())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("getByRefreshToken");
    }

    // --- helpers -------------------------------------------------------------------------

    private SessionRecord seed(String refreshToken, long refreshExpiresAt) {
        return store.createForChallenge(record("sess-1", "chal-1", "access-1", refreshToken,
                refreshExpiresAt, T0 + 900, T0 + 43200, null));
    }

    private static SessionRecord record(String sessionId, String challengeId, String accessToken,
                                        String refreshToken, long refreshExpiresAt,
                                        long expiresAt, long absoluteExpiryAt,
                                        String previousRefreshToken) {
        return new SessionRecord(
                sessionId, challengeId, accessToken, NPUB, PUBKEY,
                List.of("user"), List.of("orders:read"),
                T0, T0, expiresAt, absoluteExpiryAt,
                null, null, null,
                refreshToken, refreshExpiresAt, previousRefreshToken);
    }

    private NapServer server(SessionStore sessionStore, int refreshTtlSeconds) {
        return NapServer.create(baseOptions(sessionStore, refreshTtlSeconds).build());
    }

    private NapServerOptions.Builder baseOptions(SessionStore sessionStore, int refreshTtlSeconds) {
        return NapServerOptions.builder()
                .challengeStore(new InMemoryChallengeStore())
                .sessionStore(sessionStore)
                .aclResolver(acl)
                .clock(clock)
                .sessionIdleTtlSeconds(900)
                .sessionAbsoluteTtlSeconds(43200)
                .refreshTtlSeconds(refreshTtlSeconds)
                .minAuthResponseMillis(0)
                .responseJitterMillis(0);
    }

    private static RefreshSessionOutcome.Failure failure(RefreshSessionOutcome outcome) {
        assertThat(outcome).isInstanceOf(RefreshSessionOutcome.Failure.class);
        return (RefreshSessionOutcome.Failure) outcome;
    }

    private static final class MutableAclResolver implements AclResolver {
        private AclDecision decision = AclDecision.allowed(List.of("user"), List.of("orders:read"));

        @Override
        public AclDecision resolve(String npub, String pubkey) {
            return decision;
        }
    }

    private static final class MutableClock extends Clock {
        private volatile long epochSecond;

        MutableClock(long epochSecond) {
            this.epochSecond = epochSecond;
        }

        void set(long value) {
            this.epochSecond = value;
        }

        @Override
        public ZoneId getZone() {
            return ZoneId.of("UTC");
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return Instant.ofEpochSecond(epochSecond);
        }
    }
}
