package xyz.tcheeric.nap.server;

import java.time.Clock;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Guards against replaying the same NIP-98 event across multiple completion attempts.
 */
@FunctionalInterface
public interface EventReplayGuard {

    boolean tryAcquire(String eventId);

    /**
     * Returns a no-op guard that accepts all events (no replay protection).
     */
    static EventReplayGuard noop() {
        return eventId -> true;
    }

    /**
     * An in-memory guard that rejects replayed event IDs, forgetting them once they are too old
     * to be accepted anyway.
     *
     * <p>Suitable for single-instance deployments. Behind more than one instance each process
     * keeps its own set, so an event replayed against a different instance is not caught; a
     * shared store behind this same interface is what fixes that.
     *
     * @param retentionSeconds how long an id is remembered. Set this to the window in which a
     *                         replayed event would still be accepted on its own merits, which is
     *                         the NIP-98 clock skew allowance: past that the timestamp check
     *                         rejects the event and remembering it adds nothing.
     */
    static EventReplayGuard inMemory(long retentionSeconds) {
        return inMemory(retentionSeconds, Clock.systemUTC());
    }

    /**
     * As {@link #inMemory(long)}, with an injectable clock for tests.
     */
    static EventReplayGuard inMemory(long retentionSeconds, Clock clock) {
        return new BoundedEventReplayGuard(retentionSeconds, clock);
    }

    /**
     * An in-memory guard that remembers every event id forever.
     *
     * @deprecated Unbounded. The map is only ever added to, so a service that authenticates
     *     steadily leaks memory for as long as it runs, and the leak is driven by request volume,
     *     which makes it something an attacker can accelerate. Prefer {@link #inMemory(long)},
     *     passing the clock-skew allowance: an id older than that is rejected by the timestamp
     *     check regardless, so retaining it buys nothing.
     */
    @Deprecated(forRemoval = true)
    static EventReplayGuard inMemory() {
        ConcurrentHashMap<String, Boolean> seen = new ConcurrentHashMap<>();
        return eventId -> seen.putIfAbsent(eventId, Boolean.TRUE) == null;
    }

    /**
     * Single-use event ids with time-based eviction.
     *
     * <p>Eviction runs on insert rather than on a timer, so the class owns no thread and cannot
     * outlive its holder. The sweep is rate-limited to once a second: without that, a burst would
     * make every request walk the whole map.
     */
    final class BoundedEventReplayGuard implements EventReplayGuard {

        private final Map<String, Long> seen = new ConcurrentHashMap<>();
        private final AtomicLong lastSweptAt = new AtomicLong(Long.MIN_VALUE);
        private final long retentionSeconds;
        private final Clock clock;

        private BoundedEventReplayGuard(long retentionSeconds, Clock clock) {
            if (retentionSeconds <= 0) {
                throw new IllegalArgumentException("retentionSeconds must be positive");
            }
            this.retentionSeconds = retentionSeconds;
            this.clock = clock;
        }

        @Override
        public boolean tryAcquire(String eventId) {
            long now = clock.instant().getEpochSecond();
            sweep(now);
            // putIfAbsent is the whole guard: the first caller to insert wins, and concurrent
            // duplicates see a non-null previous value. Storing the expiry rather than a boolean
            // is what lets the sweep decide when the entry stops mattering.
            return seen.putIfAbsent(eventId, now + retentionSeconds) == null;
        }

        private void sweep(long now) {
            long last = lastSweptAt.get();
            if (now <= last) {
                return;
            }
            if (!lastSweptAt.compareAndSet(last, now)) {
                // Another thread is sweeping this second; one pass is enough.
                return;
            }
            seen.values().removeIf(expiry -> expiry <= now);
        }

        /** Entries currently retained. For tests and diagnostics. */
        public int size() {
            return seen.size();
        }
    }
}
