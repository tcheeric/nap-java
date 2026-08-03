package xyz.tcheeric.nap.core;

import java.util.List;

/**
 * Outcome of an ACL lookup.
 *
 * @param revokeSessions set only on a denial the resolver is <em>certain</em> about — the
 *                       principal was suspended, not merely unreadable. Only then do callers
 *                       revoke every session the principal holds. A resolver answering
 *                       "denied" because it could not <em>read</em> the ACL (a lagging
 *                       replica, a row mid-rewrite) denies the one request and no more;
 *                       the alternative turns a transient store problem into a forced
 *                       re-login for everyone, recoverable only by a fresh NIP-98 exchange.
 */
public record AclDecision(
        boolean allowed,
        List<String> roles,
        List<String> permissions,
        String reason,
        boolean revokeSessions
) {

    public AclDecision(boolean allowed, List<String> roles, List<String> permissions) {
        this(allowed, roles, permissions, null, false);
    }

    public static AclDecision allowed(List<String> roles, List<String> permissions) {
        return new AclDecision(true, roles, permissions, null, false);
    }

    public static AclDecision denied() {
        return denied(null);
    }

    public static AclDecision denied(String reason) {
        return denied(reason, false);
    }

    public static AclDecision denied(String reason, boolean revokeSessions) {
        return new AclDecision(false, List.of(), List.of(), reason, revokeSessions);
    }
}
