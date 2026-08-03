package xyz.tcheeric.nap.core;

/**
 * All NAP v2 error codes matching the TypeScript reference implementation.
 */
public enum NapErrorCode {

    NAP_INIT_INVALID_NPUB(false),
    NAP_INIT_RATE_LIMITED(true),
    NAP_INIT_INTERNAL(true),

    NAP_COMPLETE_MISSING_AUTH_HEADER(false),
    NAP_COMPLETE_INVALID_AUTH_SCHEME(false),
    NAP_COMPLETE_INVALID_EVENT_JSON(false),
    NAP_COMPLETE_INVALID_KIND(false),
    NAP_COMPLETE_INVALID_SIGNATURE(false),
    NAP_COMPLETE_CREATED_AT_OUT_OF_RANGE(true),
    NAP_COMPLETE_URL_MISMATCH(false),
    NAP_COMPLETE_METHOD_MISMATCH(false),
    NAP_COMPLETE_MISSING_PAYLOAD(false),
    NAP_COMPLETE_PAYLOAD_MISMATCH(false),
    NAP_COMPLETE_MISSING_CHALLENGE_ID(false),
    NAP_COMPLETE_UNKNOWN_CHALLENGE(true),
    NAP_COMPLETE_EXPIRED_CHALLENGE(false),
    NAP_COMPLETE_REDEEMED_CHALLENGE(false),
    NAP_COMPLETE_CHALLENGE_MISMATCH(false),
    NAP_COMPLETE_PRINCIPAL_MISMATCH(false),
    NAP_COMPLETE_ACL_DENIED(false),
    /** The challenge burned through its failure budget (RFC §13.4) — a retry cannot help. */
    NAP_COMPLETE_FAILED_TERMINAL(false),
    NAP_COMPLETE_RATE_LIMITED(true),
    NAP_COMPLETE_INTERNAL(true),

    /**
     * RFC §14.1. Not retryable, every one of them: the presented credential is gone and
     * only a fresh NIP-98 login replaces it. {@code NAP_REFRESH_REUSED} in particular means
     * the whole session was just revoked — a retired token came back, so two parties held
     * the lineage and the server cannot tell which was the thief.
     */
    NAP_REFRESH_UNKNOWN_TOKEN(false),
    NAP_REFRESH_REUSED(false),
    NAP_REFRESH_EXPIRED(false),
    NAP_REFRESH_REVOKED(false),
    NAP_REFRESH_ACL_DENIED(false),
    NAP_REFRESH_RATE_LIMITED(true),
    NAP_REFRESH_INTERNAL(true);

    private final boolean retryable;

    NapErrorCode(boolean retryable) {
        this.retryable = retryable;
    }

    public boolean isRetryable() {
        return retryable;
    }
}
