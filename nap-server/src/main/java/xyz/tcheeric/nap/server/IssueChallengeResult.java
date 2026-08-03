package xyz.tcheeric.nap.server;

import xyz.tcheeric.nap.core.AuthInitResponse;
import xyz.tcheeric.nap.core.NapErrorCode;

public sealed interface IssueChallengeResult {

    record Success(AuthInitResponse value) implements IssueChallengeResult {
    }

    /**
     * @param retryAfterSeconds set only on {@code NAP_INIT_RATE_LIMITED}; adapters surface it
     *                          as the {@code Retry-After} header on the 429.
     */
    record Failure(NapErrorCode code, boolean retryable, Integer retryAfterSeconds)
            implements IssueChallengeResult {

        public Failure(NapErrorCode code, boolean retryable) {
            this(code, retryable, null);
        }
    }

    static IssueChallengeResult failure(NapErrorCode code) {
        return new Failure(code, code.isRetryable(), null);
    }

    static IssueChallengeResult rateLimited(NapErrorCode code, Integer retryAfterSeconds) {
        return new Failure(code, code.isRetryable(), retryAfterSeconds);
    }

    default boolean isSuccess() {
        return this instanceof Success;
    }
}
