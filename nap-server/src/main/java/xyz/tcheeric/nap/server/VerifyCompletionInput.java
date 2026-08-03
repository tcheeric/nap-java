package xyz.tcheeric.nap.server;

/**
 * @param clientIp caller address as resolved by the adapter's trust policy, or {@code null}.
 *                 Only the pre-proof rate-limit check depends on it; the post-proof check
 *                 keys on the proved pubkey, so opting out here does not leave
 *                 {@code /auth/complete} unbounded.
 */
public record VerifyCompletionInput(
        String authorization,
        String method,
        String url,
        byte[] rawBody,
        String clientIp
) {

    public VerifyCompletionInput(String authorization, String method, String url, byte[] rawBody) {
        this(authorization, method, url, rawBody, null);
    }
}
