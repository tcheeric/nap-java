package xyz.tcheeric.nap.server;

/** The counters RFC §19.3 asks implementations to emit. */
public enum NapCounter {
    AUTH_INIT_TOTAL("auth_init_total"),
    AUTH_COMPLETE_TOTAL("auth_complete_total"),
    AUTH_SUCCESS_TOTAL("auth_success_total"),
    AUTH_FAILURE_TOTAL("auth_failure_total"),
    AUTH_RATE_LIMITED_TOTAL("auth_rate_limited_total"),
    CHALLENGE_REDEEMED_TOTAL("challenge_redeemed_total"),
    CHALLENGE_RETRY_HIT_TOTAL("challenge_retry_hit_total"),
    CHALLENGE_EXPIRED_TOTAL("challenge_expired_total"),
    AUDIENCE_MISMATCH_TOTAL("audience_mismatch_total"),
    PAYLOAD_MISMATCH_TOTAL("payload_mismatch_total");

    private final String metricName;

    NapCounter(String metricName) {
        this.metricName = metricName;
    }

    /** The name to export, matching the TypeScript implementation byte for byte. */
    public String metricName() {
        return metricName;
    }
}
