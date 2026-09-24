package xyz.tcheeric.nap.server.store;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import xyz.tcheeric.nap.core.ChallengeRecord;
import xyz.tcheeric.nap.core.RedeemParams;
import xyz.tcheeric.nap.core.SessionRecord;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The in-memory stores must not grow without bound (#31).
 *
 * <p>Both maps are filled by unauthenticated traffic: {@code /auth/init} writes a challenge under
 * a fresh random id, and every completion writes a session. Marking a record expired or revoked
 * and keeping it means the footprint tracks total login volume, which is something a caller can
 * accelerate.
 *
 * <p>What makes these tests worth more than a size assertion is the second half of each: the
 * records that must <em>survive</em>. A sweep that also drops those is not a fix, it is a
 * different bug.
 */
class InMemoryStoreEvictionTest {

    private static final long NOW = 1_700_000_000L;

    /** A clock the test moves by hand, so eviction is exercised without sleeping. */
    private static final class MutableClock extends Clock {
        private long epochSecond;

        MutableClock(long epochSecond) {
            this.epochSecond = epochSecond;
        }

        void advanceSeconds(long seconds) {
            epochSecond += seconds;
        }

        @Override public java.time.ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(java.time.ZoneId zone) { return this; }
        @Override public Instant instant() { return Instant.ofEpochSecond(epochSecond); }
    }

    @Nested
    class ChallengeStore {

        private static ChallengeRecord issued(String id, long issuedAt, long expiresAt) {
            return ChallengeRecord.issued(
                    id, "challenge-" + id, "npub1test", "pubkey-abc",
                    "https://auth.example.com", "nip98", issuedAt, expiresAt);
        }

        @Test
        void dropsChallengesThatCanNoLongerBeRedeemed() {
            MutableClock clock = new MutableClock(NOW);
            InMemoryChallengeStore store = new InMemoryChallengeStore(clock);

            for (int i = 0; i < 1_000; i++) {
                store.create(issued("expired-" + i, NOW, NOW + 60));
            }
            assertThat(store.size()).isEqualTo(1_000);

            clock.advanceSeconds(120);
            store.create(issued("live", NOW + 120, NOW + 180));

            assertThat(store.size()).isEqualTo(1);
            assertThat(store.get("live")).isPresent();
            assertThat(store.get("expired-0")).isEmpty();
        }

        /**
         * RFC §13.3 makes a repeat submission of the same completion return the cached result
         * rather than a second login. That only works while the redeemed challenge is still
         * there, so the result-cache window is the retention bound and not the expiry.
         */
        @Test
        void keepsARedeemedChallengeUntilItsResultCacheExpires() {
            MutableClock clock = new MutableClock(NOW);
            InMemoryChallengeStore store = new InMemoryChallengeStore(clock);
            store.create(issued("redeemed", NOW, NOW + 60));
            store.redeem("redeemed", new RedeemParams("event-1", "session-1", NOW, NOW + 300));

            // Past the challenge's own expiry, still inside the result cache.
            clock.advanceSeconds(120);
            store.create(issued("trigger-a", NOW + 120, NOW + 180));

            assertThat(store.get("redeemed")).isPresent();

            // Past the result cache too, so a retry can no longer be answered from it.
            clock.advanceSeconds(300);
            store.create(issued("trigger-b", NOW + 420, NOW + 480));

            assertThat(store.get("redeemed")).isEmpty();
        }
    }

    @Nested
    class SessionStore {

        private static SessionRecord session(String id, long absoluteExpiryAt) {
            return SessionRecord.create(
                    id, "challenge-" + id, "access-" + id,
                    "npub1test", "a".repeat(64),
                    List.of(), List.of(),
                    NOW, NOW, NOW + 900, absoluteExpiryAt);
        }

        @Test
        void dropsSessionsPastTheirAbsoluteCap() {
            MutableClock clock = new MutableClock(NOW);
            InMemorySessionStore store = new InMemorySessionStore(clock);

            for (int i = 0; i < 500; i++) {
                store.createForChallenge(session("dead-" + i, NOW + 60));
            }
            assertThat(store.size()).isEqualTo(500);

            clock.advanceSeconds(120);
            store.createForChallenge(session("live", NOW + 100_000));

            assertThat(store.size()).isEqualTo(1);
            assertThat(store.getBySessionId("live")).isPresent();
            // Swept from every index, not just the primary one.
            assertThat(store.getByAccessToken("access-dead-0")).isEmpty();
            assertThat(store.getBySessionId("dead-0")).isEmpty();
        }

        /**
         * A refresh token outliving the access window is the case reuse detection depends on:
         * {@code getByRefreshToken} deliberately answers for revoked sessions so a replay is
         * recognisable. Evicting on the access window alone would turn a detected reuse into an
         * unknown token, which is the one signal that says a credential leaked.
         */
        @Test
        void keepsASessionWhoseRefreshWindowIsStillOpen() {
            MutableClock clock = new MutableClock(NOW);
            InMemorySessionStore store = new InMemorySessionStore(clock);

            SessionRecord withRefresh = new SessionRecord(
                    "sid-refresh", "chal-r", "access-r",
                    "npub1test", "a".repeat(64),
                    List.of(), List.of(),
                    NOW, NOW, NOW + 60, NOW + 60,
                    null, null, null,
                    "refresh-r", NOW + 86_400, null);
            store.createForChallenge(withRefresh);

            // Well past the absolute cap, still inside the refresh window.
            clock.advanceSeconds(3_600);
            store.createForChallenge(session("trigger", NOW + 100_000));

            assertThat(store.getByRefreshToken("refresh-r")).isPresent();

            // Past the refresh window too.
            clock.advanceSeconds(90_000);
            store.createForChallenge(session("trigger-2", NOW + 200_000));

            assertThat(store.getByRefreshToken("refresh-r")).isEmpty();
        }
    }
}
