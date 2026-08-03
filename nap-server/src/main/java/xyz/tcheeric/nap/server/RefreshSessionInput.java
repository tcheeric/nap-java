package xyz.tcheeric.nap.server;

/**
 * @param refreshToken the bearer credential from {@code Authorization}, or {@code null} when
 *                     absent.
 * @param clientIp     caller address, resolved by the adapter's trust policy.
 */
public record RefreshSessionInput(String refreshToken, String clientIp) {
}
