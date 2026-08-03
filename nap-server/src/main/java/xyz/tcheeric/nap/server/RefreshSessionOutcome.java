package xyz.tcheeric.nap.server;

import xyz.tcheeric.nap.core.NapErrorCode;
import xyz.tcheeric.nap.core.SessionRecord;

public sealed interface RefreshSessionOutcome {

    record Success(SessionRecord session) implements RefreshSessionOutcome {
    }

    /**
     * @param retryAfterSeconds set only on {@code NAP_REFRESH_RATE_LIMITED}; adapters surface
     *                          it as the {@code Retry-After} header on the 429.
     */
    record Failure(NapErrorCode code, boolean retryable, Integer retryAfterSeconds)
            implements RefreshSessionOutcome {
    }

    static RefreshSessionOutcome success(SessionRecord session) {
        return new Success(session);
    }

    static RefreshSessionOutcome failure(NapErrorCode code) {
        return new Failure(code, code.isRetryable(), null);
    }

    static RefreshSessionOutcome rateLimited(NapErrorCode code, Integer retryAfterSeconds) {
        return new Failure(code, code.isRetryable(), retryAfterSeconds);
    }

    default boolean isSuccess() {
        return this instanceof Success;
    }
}
