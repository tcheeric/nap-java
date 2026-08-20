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
 * trusting whatever the caller sent — the thing WebAuthn L3 §13.5.9 makes it normative for a
 * relying party not to do. Prefer a pinned constant. If you must read the request, match
 * {@code Host} against an allowlist of the hosts you answer on, exact-match by default
 * (§13.5.8: an RP should not accept subdomains unless it means to).
 *
 * <p>An allowlist over hosts still leaves the scheme attacker-influenced. Behind a proxy,
 * {@code request.getScheme()} is whatever {@code X-Forwarded-Proto} claimed, so a resolver
 * that composes {@code getScheme() + "://" + host} can be downgraded to {@code http} on a
 * host that is on the list. Pin the scheme in the allowlist entry rather than reading it —
 * {@code "https://api.example.com"} — the same way
 * {@code @imani/nap-server}'s {@code createAudienceHostAllowlist()} does.
 */
@FunctionalInterface
public interface AudienceResolver {

    String resolve(HttpServletRequest request);
}
