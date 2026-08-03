package xyz.tcheeric.nap.server.store;

import xyz.tcheeric.nap.core.ChallengeRecord;
import xyz.tcheeric.nap.core.ChallengeState;
import xyz.tcheeric.nap.core.ChallengeStore;
import xyz.tcheeric.nap.core.OutstandingChallengeFilter;
import xyz.tcheeric.nap.core.RecordChallengeFailureResult;
import xyz.tcheeric.nap.core.RedeemParams;
import xyz.tcheeric.nap.core.RedeemResult;

import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory ChallengeStore for testing and single-instance deployments.
 */
public final class InMemoryChallengeStore implements ChallengeStore {

    private final ConcurrentHashMap<String, ChallengeRecord> store = new ConcurrentHashMap<>();

    @Override
    public void create(ChallengeRecord record) {
        store.put(record.challengeId(), record);
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
