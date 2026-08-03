package xyz.tcheeric.nap.server;

/**
 * Dimensions a {@link RateLimiter} counts a request against.
 *
 * @param scope    {@code "init"} or {@code "complete"} — the two scopes keep separate budgets.
 * @param npub     bech32 principal, known before any proof on {@code /auth/init}.
 * @param pubkey   hex principal, known only <em>after</em> the NIP-98 signature verifies.
 *                 The pre-proof check on {@code /auth/complete} has only {@code clientIp} to
 *                 work with — nothing at all when the adapter opts out of address reporting.
 *                 Counting this dimension again once the signature is good bounds an attacker
 *                 to one Schnorr verify per counted request instead of unbounded.
 * @param clientIp caller address, resolved by the adapter's trust policy.
 */
public record RateLimitKey(String scope, String npub, String pubkey, String clientIp) {

    public static RateLimitKey init(String npub, String clientIp) {
        return new RateLimitKey("init", npub, null, clientIp);
    }

    public static RateLimitKey complete(String pubkey, String clientIp) {
        return new RateLimitKey("complete", null, pubkey, clientIp);
    }
}
