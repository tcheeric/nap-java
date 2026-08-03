package xyz.tcheeric.nap.server;

import xyz.tcheeric.nap.core.NapErrorCode;
import xyz.tcheeric.nap.core.SessionRecord;
import xyz.tcheeric.nap.core.VerifyCompleteResult;

public sealed interface VerifyCompletionOutcome {

    record Success(SessionRecord session) implements VerifyCompletionOutcome {
    }

    /**
     * @param retryAfterSeconds set only on {@code NAP_COMPLETE_RATE_LIMITED}; adapters surface
     *                          it as the {@code Retry-After} header on the 429.
     */
    record Failure(NapErrorCode code, boolean retryable, Integer retryAfterSeconds)
            implements VerifyCompletionOutcome {

        public Failure(NapErrorCode code, boolean retryable) {
            this(code, retryable, null);
        }
    }

    record MalformedRequest() implements VerifyCompletionOutcome {
    }

    static VerifyCompletionOutcome success(SessionRecord session) {
        return new Success(session);
    }

    static VerifyCompletionOutcome failure(NapErrorCode code) {
        return new Failure(code, code.isRetryable(), null);
    }

    static VerifyCompletionOutcome rateLimited(NapErrorCode code, Integer retryAfterSeconds) {
        return new Failure(code, code.isRetryable(), retryAfterSeconds);
    }

    static VerifyCompletionOutcome malformed() {
        return new MalformedRequest();
    }

    static VerifyCompletionOutcome fromResult(VerifyCompleteResult result) {
        return switch (result) {
            case VerifyCompleteResult.Success s -> success(s.session());
            case VerifyCompleteResult.Failure f -> failure(f.code());
        };
    }

    default boolean isSuccess() {
        return this instanceof Success;
    }
}
