package xyz.tcheeric.nap.server;

/**
 * @param clientIp caller address as resolved by the adapter's trust policy, or {@code null} to
 *                 opt out — the per-address cap and rate-limit dimension are then skipped
 *                 rather than enforced against a value anyone can forge.
 */
public record IssueChallengeInput(String npub, String authUrl, String authMethod, String clientIp) {

    public IssueChallengeInput(String npub, String authUrl) {
        this(npub, authUrl, "POST", null);
    }

    public IssueChallengeInput(String npub, String authUrl, String authMethod) {
        this(npub, authUrl, authMethod, null);
    }
}
