package xyz.tcheeric.nap.server;

import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The replay guard has to hold two properties at once, and the obvious implementation of each
 * breaks the other: it must reject a replayed id, and it must not remember ids forever.
 *
 * <p>The previous {@code inMemory()} kept every id in a map that was only ever added to, so a
 * service authenticating steadily leaked memory for its whole lifetime, at a rate the caller
 * chose. These tests pin the eviction and then re-check that eviction did not quietly cost the
 * replay rejection it exists to provide.
 */
class BoundedEventReplayGuardTest {

    /** A clock the test advances by hand, so retention is asserted rather than waited out. */
    private static final class MutableClock extends Clock {
        private Instant now = Instant.parse("2026-01-01T00:00:00Z");

        @Override public java.time.ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(java.time.ZoneId zone) { return this; }
        @Override public Instant instant() { return now; }

        void advance(Duration d) { now = now.plus(d); }
    }

    @Test
    void rejectsReplayWithinRetentionWindow() {
        MutableClock clock = new MutableClock();
        EventReplayGuard guard = EventReplayGuard.inMemory(60, clock);

        assertTrue(guard.tryAcquire("event-a"), "first use of an id must be accepted");
        assertFalse(guard.tryAcquire("event-a"), "the same id must not be usable twice");

        // Still inside the window: the id is remembered, so the replay is still refused.
        clock.advance(Duration.ofSeconds(59));
        assertFalse(guard.tryAcquire("event-a"), "replay must stay refused for the full window");
    }

    @Test
    void distinctIdsAreIndependent() {
        EventReplayGuard guard = EventReplayGuard.inMemory(60, new MutableClock());
        assertTrue(guard.tryAcquire("event-a"));
        assertTrue(guard.tryAcquire("event-b"), "one id being spent must not block another");
    }

    /**
     * The regression. Against the old unbounded guard the map only grew, so size stayed at the
     * number of ids ever seen; here entries past the retention window are dropped.
     */
    @Test
    void evictsEntriesOnceTheyAreTooOldToMatter() {
        MutableClock clock = new MutableClock();
        EventReplayGuard guard = EventReplayGuard.inMemory(60, clock);

        for (int i = 0; i < 500; i++) {
            assertTrue(guard.tryAcquire("event-" + i));
            // Same second for all 500, so they expire together.
        }
        assertEquals(500, size(guard), "ids inside the window must still be retained");

        // Past the window. These ids now fail the NIP-98 timestamp check on their own merits,
        // so holding them costs memory and buys nothing.
        clock.advance(Duration.ofSeconds(61));
        assertTrue(guard.tryAcquire("trigger-sweep"));

        assertEquals(1, size(guard),
                "expired ids must be evicted, leaving only the id that triggered the sweep");
    }

    /**
     * Memory must not grow without bound under sustained load. Ten thousand events spread over
     * time would have left ten thousand entries in the old guard; the bounded one holds only
     * what the window covers.
     */
    @Test
    void memoryStaysBoundedUnderSustainedLoad() {
        MutableClock clock = new MutableClock();
        EventReplayGuard guard = EventReplayGuard.inMemory(10, clock);

        for (int i = 0; i < 10_000; i++) {
            assertTrue(guard.tryAcquire("event-" + i));
            clock.advance(Duration.ofSeconds(1));
        }

        assertTrue(size(guard) <= 12,
                "retention is 10s at 1 event/s, so the map must hold ~10 entries, not 10000; was "
                        + size(guard));
    }

    /**
     * Eviction must not become a replay window: an id whose entry was swept is accepted again,
     * which is safe only because the timestamp check independently rejects an event that old.
     * Documented here so the coupling to maxClockSkewSeconds is not silently broken.
     */
    @Test
    void idIsAcceptedAgainOnceItsEventCouldNoLongerPassTheTimestampCheck() {
        MutableClock clock = new MutableClock();
        EventReplayGuard guard = EventReplayGuard.inMemory(60, clock);

        assertTrue(guard.tryAcquire("event-a"));
        clock.advance(Duration.ofSeconds(61));

        assertTrue(guard.tryAcquire("event-a"),
                "after retention the guard forgets, so retention must be >= the skew allowance");
    }

    @Test
    void rejectsNonPositiveRetention() {
        // A zero or negative window would forget an id immediately, disabling replay protection
        // while still looking like it was enabled.
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
                () -> EventReplayGuard.inMemory(0));
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
                () -> EventReplayGuard.inMemory(-1));
    }

    @Test
    void concurrentAcquireOfSameIdAdmitsExactlyOne() throws Exception {
        EventReplayGuard guard = EventReplayGuard.inMemory(60, new MutableClock());
        int threads = 32;
        var barrier = new java.util.concurrent.CyclicBarrier(threads);
        var accepted = new java.util.concurrent.atomic.AtomicInteger();
        var pool = java.util.concurrent.Executors.newFixedThreadPool(threads);
        try {
            for (int i = 0; i < threads; i++) {
                pool.submit(() -> {
                    barrier.await();
                    if (guard.tryAcquire("contended")) {
                        accepted.incrementAndGet();
                    }
                    return null;
                });
            }
            pool.shutdown();
            assertTrue(pool.awaitTermination(10, java.util.concurrent.TimeUnit.SECONDS));
        } finally {
            pool.shutdownNow();
        }
        assertEquals(1, accepted.get(),
                "a race between concurrent uses of one event must admit exactly one");
    }

    private static int size(EventReplayGuard guard) {
        return ((EventReplayGuard.BoundedEventReplayGuard) guard).size();
    }
}
