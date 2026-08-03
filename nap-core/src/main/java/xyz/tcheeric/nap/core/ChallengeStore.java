package xyz.tcheeric.nap.core;

import java.util.Optional;
import java.util.OptionalInt;

public interface ChallengeStore {

    void create(ChallengeRecord record);

    Optional<ChallengeRecord> get(String challengeId);

    RedeemResult redeem(String challengeId, RedeemParams params);

    int markExpired(long nowUnix);

    /**
     * Count unexpired challenges still in {@code issued} state for a principal or a caller
     * address (RFC §17.4).
     *
     * <p>Defaults to {@link OptionalInt#empty()} so existing custom stores keep compiling.
     * A store that does not implement it cannot enforce
     * {@code maxOutstandingChallengesPerNpub} / {@code maxOutstandingChallengesPerIp} —
     * a store that cannot count cannot cap, and the caps are skipped rather than failing
     * closed on every request.
     */
    default OptionalInt countOutstanding(OutstandingChallengeFilter filter) {
        return OptionalInt.empty();
    }

    /**
     * Increment a challenge's failure counter, moving it to
     * {@link ChallengeState#FAILED_TERMINAL} once {@code maxFailures} is reached (RFC §13.4).
     *
     * <p>Optional for the same reason as {@link #countOutstanding}. Must be atomic:
     * concurrent attempts on one challenge would otherwise lose increments to a
     * read-modify-write race and never reach the cap.
     *
     * @return the new count and state, or {@code null} when the challenge is absent, no
     *         longer {@code issued}, or the store does not implement the counter.
     */
    default RecordChallengeFailureResult recordFailure(String challengeId, long now, int maxFailures) {
        return null;
    }
}
