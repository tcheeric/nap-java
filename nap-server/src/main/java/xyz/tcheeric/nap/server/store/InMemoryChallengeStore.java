package xyz.tcheeric.nap.server.store;

import xyz.tcheeric.nap.core.ChallengeRecord;
import xyz.tcheeric.nap.core.ChallengeState;
import xyz.tcheeric.nap.core.ChallengeStore;
import xyz.tcheeric.nap.core.OutstandingChallengeFilter;
import xyz.tcheeric.nap.core.RecordChallengeFailureResult;
import xyz.tcheeric.nap.core.RedeemParams;
import xyz.tcheeric.nap.core.RedeemResult;

import java.time.Clock;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * In-memory ChallengeStore for testing and single-instance deployments.
 *
 * <p>Bounded. Records are dropped once they can no longer affect a decision, because the map is
 * filled by {@code /auth/init}, which is unauthenticated: without eviction the footprint grows
 * with login volume at a rate the caller sets. The outstanding-challenge caps do not help, since
 * they count only records still in {@code ISSUED} and so bound concurrency rather than memory.
 */
public final class InMemoryChallengeStore implements ChallengeStore {

    private final ConcurrentHashMap<String, ChallengeRecord> store = new ConcurrentHashMap<>();
    private final AtomicLong lastSweptAt = new AtomicLong(Long.MIN_VALUE);
    private final Clock clock;

    public InMemoryChallengeStore() {
        this(Clock.systemUTC());
    }

    /** @param clock injectable so eviction is testable without sleeping. */
    public InMemoryChallengeStore(Clock clock) {
        this.clock = clock;
    }

    @Override
    public void create(ChallengeRecord record) {
        // Swept here rather than on a timer: the store owns no thread and cannot outlive its
        // holder, which is the same shape BoundedEventReplayGuard uses. create() is also the
        // method an attacker drives, so the work lands where the growth comes from.
        sweep(clock.instant().getEpochSecond());
        store.put(record.challengeId(), record);
    }

    /**
     * Drop records that can no longer affect a decision.
     *
     * <p>The bound is {@code resultCacheUntil} when one is set, and {@code expiresAt} otherwise.
     * That distinction is load-bearing: a redeemed challenge inside its result-cache window is
     * what makes a client retry idempotent (RFC §13.3), so evicting on expiry alone would turn a
     * duplicate submission into a fresh login attempt against a challenge that no longer exists.
     *
     * <p>Rate-limited to once per clock tick. Without that a burst makes every request walk the
     * whole map, which is the load profile eviction exists to prevent.
     */
    private void sweep(long now) {
        long last = lastSweptAt.get();
        if (now <= last || !lastSweptAt.compareAndSet(last, now)) {
            return;
        }
        store.values().removeIf(record -> {
            Long cacheUntil = record.resultCacheUntil();
            return (cacheUntil != null ? cacheUntil : record.expiresAt()) < now;
        });
    }

    /** Records currently retained. For tests and diagnostics. */
    public int size() {
        return store.size();
    }

    @Override
    public Optional<ChallengeRecord> get(String challengeId) {
        return Optional.ofNullable(store.get(challengeId));
    }

    @Override
    public RedeemResult redeem(String challengeId, RedeemParams params) {
        var ref = new Object() { RedeemResult result = RedeemResult.NOT_FOUND; };

        store.computeIfPresent(challengeId, (key, existing) -> {
            if (existing.state() == ChallengeState.EXPIRED || existing.expiresAt() < params.now()) {
                ref.result = RedeemResult.EXPIRED;
                return existing;
            }
            if (existing.state() != ChallengeState.ISSUED) {
                ref.result = RedeemResult.ALREADY_REDEEMED;
                return existing;
            }
            ref.result = RedeemResult.REDEEMED;
            return withState(existing, ChallengeState.REDEEMED,
                    params.eventId(), params.sessionId(), params.resultCacheUntil(),
                    existing.failureCount());
        });

        return ref.result;
    }

    @Override
    public int markExpired(long nowUnix) {
        int count = 0;
        for (var entry : store.entrySet()) {
            var record = entry.getValue();
            if (record.state() == ChallengeState.ISSUED && record.expiresAt() < nowUnix) {
                store.computeIfPresent(entry.getKey(), (key, existing) -> {
                    if (existing.state() == ChallengeState.ISSUED && existing.expiresAt() < nowUnix) {
                        return withState(existing, ChallengeState.EXPIRED,
                                null, null, null, existing.failureCount());
                    }
                    return existing;
                });
                count++;
            }
        }
        return count;
    }

    @Override
    public OptionalInt countOutstanding(OutstandingChallengeFilter filter) {
        int count = 0;
        for (var record : store.values()) {
            if (record.state() != ChallengeState.ISSUED || record.expiresAt() < filter.now()) {
                continue;
            }
            if (filter.npub() != null && !filter.npub().equals(record.npub())) {
                continue;
            }
            if (filter.clientIp() != null && !filter.clientIp().equals(record.clientIp())) {
                continue;
            }
            count++;
        }
        return OptionalInt.of(count);
    }

    /** Atomic through {@code computeIfPresent} so concurrent attempts cannot lose increments. */
    @Override
    public RecordChallengeFailureResult recordFailure(String challengeId, long now, int maxFailures) {
        var ref = new Object() { RecordChallengeFailureResult result; };

        store.computeIfPresent(challengeId, (key, existing) -> {
            if (existing.state() != ChallengeState.ISSUED) {
                return existing;
            }
            int failureCount = existing.failureCount() + 1;
            ChallengeState state = failureCount >= maxFailures
                    ? ChallengeState.FAILED_TERMINAL
                    : existing.state();
            ref.result = new RecordChallengeFailureResult(failureCount, state);
            return withState(existing, state, existing.redeemedEventId(),
                    existing.redeemedSessionId(), existing.resultCacheUntil(), failureCount);
        });

        return ref.result;
    }

    public void clear() {
        store.clear();
    }

    private static ChallengeRecord withState(ChallengeRecord existing, ChallengeState state,
                                             String redeemedEventId, String redeemedSessionId,
                                             Long resultCacheUntil, int failureCount) {
        return new ChallengeRecord(
                existing.challengeId(), existing.challenge(), existing.npub(), existing.pubkey(),
                existing.authUrl(), existing.authMethod(), existing.issuedAt(), existing.expiresAt(),
                Objects.requireNonNull(state), redeemedEventId, redeemedSessionId, resultCacheUntil,
                existing.clientIp(), failureCount
        );
    }
}
