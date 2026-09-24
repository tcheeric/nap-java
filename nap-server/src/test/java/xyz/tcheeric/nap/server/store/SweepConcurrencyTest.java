package xyz.tcheeric.nap.server.store;

import org.junit.jupiter.api.Test;
import xyz.tcheeric.nap.core.SessionRecord;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.concurrent.*;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * The sweep runs on live traffic, so it races every writer.
 *
 * <p>Eviction touches four index maps that are views on one record, and it does so while
 * other threads are inserting. Getting that wrong does not throw: it silently drops a live
 * session from one index while leaving it in another, which presents much later as a
 * session that authenticates through the cookie and then cannot be found by id. Worth a
 * test that actually contends rather than reasoning about ConcurrentHashMap semantics.
 */
class SweepConcurrencyTest {
    private static final long NOW = 1_700_000_000L;

    private static final class MutClock extends Clock {
        volatile long s;
        MutClock(long s){this.s=s;}
        @Override public java.time.ZoneId getZone(){return ZoneOffset.UTC;}
        @Override public Clock withZone(java.time.ZoneId z){return this;}
        @Override public Instant instant(){return Instant.ofEpochSecond(s);}
    }

    /**
     * Concurrent creates while sweeping must not lose a live session or leave a stale index.
     *
     * <p>Asserts reachability through both {@code getBySessionId} and {@code getByAccessToken},
     * because the failure mode this guards against is the two disagreeing.
     */
    @Test
    void concurrentCreatesDuringSweepKeepIndexesConsistent() throws Exception {
        MutClock clock = new MutClock(NOW);
        InMemorySessionStore store = new InMemorySessionStore(clock);

        // Seed dead sessions.
        for (int i = 0; i < 200; i++) {
            store.createForChallenge(new SessionRecord(
                "dead"+i, "c-dead"+i, "a-dead"+i, "npub", "a".repeat(64),
                List.of(), List.of(), NOW, NOW, NOW+10, NOW+10, null, null, null, null, null, null));
        }
        clock.s = NOW + 1000;  // everything above is now dead

        // Hammer createForChallenge from several threads while sweeps fire.
        ExecutorService pool = Executors.newFixedThreadPool(8);
        CountDownLatch go = new CountDownLatch(1);
        for (int t = 0; t < 8; t++) {
            final int tid = t;
            pool.submit(() -> {
                go.await();
                for (int i = 0; i < 50; i++) {
                    String id = "live-" + tid + "-" + i;
                    store.createForChallenge(new SessionRecord(
                        id, "c-"+id, "a-"+id, "npub", "a".repeat(64),
                        List.of(), List.of(), clock.s, clock.s, clock.s+3600, clock.s+3600,
                        null, null, null, null, null, null));
                }
                return null;
            });
        }
        go.countDown();
        pool.shutdown();
        assertThat(pool.awaitTermination(30, TimeUnit.SECONDS)).isTrue();

        // Every live session must be reachable through BOTH indexes.
        for (int t = 0; t < 8; t++) {
            for (int i = 0; i < 50; i++) {
                String id = "live-" + t + "-" + i;
                assertThat(store.getBySessionId(id)).as("by id: " + id).isPresent();
                assertThat(store.getByAccessToken("a-" + id)).as("by token: " + id).isPresent();
            }
        }
        // And the dead ones are gone from the primary index.
        assertThat(store.size()).isEqualTo(400);
    }
}
