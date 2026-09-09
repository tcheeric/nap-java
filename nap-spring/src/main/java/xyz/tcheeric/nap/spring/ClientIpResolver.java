package xyz.tcheeric.nap.spring;

import jakarta.servlet.http.HttpServletRequest;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Produces the caller address that {@link xyz.tcheeric.nap.server.RateLimitKey} counts against.
 *
 * <p>{@code RateLimitKey} documents {@code clientIp} as "resolved by the adapter's trust policy",
 * and this adapter had no policy: it passed {@code request.getRemoteAddr()} straight through. Behind
 * a reverse proxy that is the proxy's address, identical for every caller, so the whole client
 * dimension of the rate limiter collapses into one bucket. The first thirty requests through the
 * proxy exhaust the window and everyone else is refused: a denial of service that an attacker gets
 * for free and that looks like the rate limiter working.
 *
 * <p>The naive repair is worse. Reading {@code X-Forwarded-For} unconditionally lets any caller set
 * the header themselves and mint a fresh bucket per request, which removes the limit rather than
 * fixing it. A forwarded address is only worth anything if you know the hop that wrote it, so this
 * interface makes the deployment say which proxies it trusts.
 *
 * <h2>Choosing an implementation</h2>
 *
 * <ul>
 *   <li>No proxy: {@link #remoteAddr()}, the default. {@code getRemoteAddr()} is the peer, which is
 *       the truth when the peer is the client.</li>
 *   <li>Behind proxies you operate: {@link #forwardedFor(List)} with their addresses. The rightmost
 *       entry not in that set is the first address a hop you trust actually observed.</li>
 *   <li>Anything more involved (PROXY protocol, a CDN header, a mesh identity): implement this
 *       interface.</li>
 * </ul>
 *
 * @see AudienceResolver for the same reasoning applied to the NIP-98 audience
 */
@FunctionalInterface
public interface ClientIpResolver {

    /**
     * @return the caller address, or {@code null} to decline to report one. Returning {@code null}
     *         is honest when the address cannot be established, and the limiter still counts the
     *         principal dimensions.
     */
    String resolve(HttpServletRequest request);

    /**
     * The TCP peer address. Correct when nothing sits between the client and this process.
     */
    static ClientIpResolver remoteAddr() {
        return HttpServletRequest::getRemoteAddr;
    }

    /**
     * Walks {@code X-Forwarded-For} right to left and returns the first address that is not a
     * trusted proxy.
     *
     * <p>Right to left because the list is appended to: the rightmost entry was written by the
     * closest hop and is the only one whose provenance is known. Everything to the left of the
     * first untrusted entry is client-supplied and is discarded, which is what stops a caller
     * forging a fresh bucket by sending their own header.
     *
     * @param trustedProxies addresses of the proxies in front of this service. Empty means trust
     *                       nothing, which degrades to {@link #remoteAddr()}.
     */
    static ClientIpResolver forwardedFor(List<String> trustedProxies) {
        Set<String> trusted = new LinkedHashSet<>();
        if (trustedProxies != null) {
            for (String proxy : trustedProxies) {
                if (proxy != null && !proxy.isBlank()) {
                    trusted.add(proxy.trim().toLowerCase(Locale.ROOT));
                }
            }
        }
        return request -> {
            String peer = request.getRemoteAddr();
            if (trusted.isEmpty() || peer == null
                    || !trusted.contains(peer.toLowerCase(Locale.ROOT))) {
                // The immediate peer is not a proxy we trust, so no forwarded header it relayed
                // can be believed either.
                return peer;
            }
            String header = request.getHeader("X-Forwarded-For");
            if (header == null || header.isBlank()) {
                return peer;
            }
            List<String> hops = new ArrayList<>();
            for (String hop : header.split(",")) {
                String trimmed = hop.trim();
                if (!trimmed.isEmpty()) {
                    hops.add(trimmed);
                }
            }
            for (int i = hops.size() - 1; i >= 0; i--) {
                String candidate = hops.get(i);
                if (!trusted.contains(candidate.toLowerCase(Locale.ROOT))) {
                    return candidate;
                }
            }
            // Every hop is a trusted proxy, so the original client address was never recorded.
            return peer;
        };
    }
}
