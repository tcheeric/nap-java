package xyz.tcheeric.nap.core;

/** Result of {@link ChallengeStore#recordFailure}: the new count and the resulting state. */
public record RecordChallengeFailureResult(int failureCount, ChallengeState state) {
}
