package xyz.tcheeric.nap.spring;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Produces the NIP-98 audience — the {@code u} tag value the proof must be signed for
 * (RFC §20.2).
 *
 * <p>The returned string is used verbatim. Bind one when the completion endpoint is not
 * {@code <externalBaseUrl>/api/v1/auth/complete}: a rewriting gateway, a servlet context
 * path, or a mount prefix the request does not carry. {@code nap.external-base-url} stays
 * the shorthand for the common case, and the auto-configuration refuses to start if both
 * are supplied — a wiring error is worth failing at startup rather than as a uniform 401
 * per request.
 *
 * <p>This is security-relevant, not cosmetic. The audience is what stops a proof signed for
 * one host from authenticating at another, so deriving it from a request header means
 * trusting whatever the caller sent. Prefer a pinned constant or a Host allowlist.
 */
@FunctionalInterface
public interface AudienceResolver {

    String resolve(HttpServletRequest request);
}
