package xyz.tcheeric.nap.spring.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import xyz.tcheeric.nap.core.AclDecision;
import xyz.tcheeric.nap.core.SessionRecord;
import xyz.tcheeric.nap.server.AclResolver;
import xyz.tcheeric.nap.core.SessionStore;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Validates NAP session cookies on protected paths and populates Spring SecurityContext.
 */
public class NapSessionFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(NapSessionFilter.class);

    /**
     * Ceiling on distinct principals held in {@link #aclCache}. Reaching it triggers a sweep of
     * entries whose refresh deadline has passed; an auto-provisioning resolver otherwise leaves
     * the principal set open-ended.
     */
    static final int MAX_CACHED_PRINCIPALS = 10_000;

    /**
     * Floor on the interval between sweeps. Without it a cache held at its ceiling by live
     * traffic scans every entry on every miss, which is the load profile the ceiling exists
     * to protect against.
     */
    private static final long MIN_SWEEP_INTERVAL_SECONDS = 1;

    private final SessionStore sessionStore;
    private final AclResolver aclResolver;
    private final String cookieName;
    private final List<String> protectedPrefixes;
    private final Duration aclRefreshInterval;
    /**
     * Keyed by principal pubkey, which is what the cached decision actually depends on: N sessions
     * of one principal collapse to one entry, and a role change lands on all of them together.
     */
    private final Map<String, CachedAclDecision> aclCache = new ConcurrentHashMap<>();
    private final AtomicLong lastSweepEpochSecond = new AtomicLong(Long.MIN_VALUE);

    public NapSessionFilter(SessionStore sessionStore,
                            AclResolver aclResolver,
                            String cookieName,
                            List<String> protectedPrefixes,
                            Duration aclRefreshInterval) {
        this.sessionStore = sessionStore;
        this.aclResolver = aclResolver;
        this.cookieName = cookieName;
        this.protectedPrefixes = protectedPrefixes;
        this.aclRefreshInterval = aclRefreshInterval;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                     FilterChain filterChain) throws ServletException, IOException {
        String path = request.getRequestURI();
        boolean isProtected = protectedPrefixes.stream().anyMatch(path::startsWith);

        if (!isProtected) {
            filterChain.doFilter(request, response);
            return;
        }

        if (SecurityContextHolder.getContext().getAuthentication() != null
                && SecurityContextHolder.getContext().getAuthentication().isAuthenticated()) {
            filterChain.doFilter(request, response);
            return;
        }

        String sessionId = extractCookie(request);
        if (sessionId == null) {
            filterChain.doFilter(request, response);
            return;
        }

        var session = sessionStore.getBySessionId(sessionId);

        if (session.isEmpty()) {
            filterChain.doFilter(request, response);
            return;
        }

        SessionRecord record = session.get();
        if (isExpired(record)) {
            sessionStore.revokeBySessionId(record.sessionId(), Instant.now().getEpochSecond());
            filterChain.doFilter(request, response);
            return;
        }

        AclDecision aclDecision = resolveAcl(record);
        if (!aclDecision.allowed()) {
            log.warn("nap_session_acl_denied pubkey={} session_id={} reason={}",
                    record.principalPubkey(), record.sessionId(), aclDecision.reason());
            // Only an affirmative denial ends the principal's sessions — every one of them,
            // not just the one that happened to make this request, or a suspended user keeps
            // working from their other tabs until each expires. A resolver that answers
            // "denied" because it could not read the ACL — a lagging replica, a row
            // mid-rewrite — blocks this request and no more; revoking would cost a fresh
            // NIP-98 login for someone else's transient failure.
            if (aclDecision.revokeSessions()) {
                sessionStore.revokeByPrincipal(record.principalPubkey(), Instant.now().getEpochSecond());
                aclCache.remove(record.principalPubkey());
            }
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            return;
        }

        SessionRecord effectiveRecord = record.withAcl(aclDecision.roles(), aclDecision.permissions());

        SecurityContextHolder.getContext().setAuthentication(new NapAuthenticationToken(effectiveRecord));
        try {
            filterChain.doFilter(request, response);
        } finally {
            SecurityContextHolder.clearContext();
        }
    }

    private String extractCookie(HttpServletRequest request) {
        if (request.getCookies() == null) return null;
        return Arrays.stream(request.getCookies())
                .filter(c -> cookieName.equals(c.getName()))
                .map(Cookie::getValue)
                .findFirst()
                .orElse(null);
    }

    private boolean isExpired(SessionRecord record) {
        long now = Instant.now().getEpochSecond();
        // Either the sliding (idle) deadline or the absolute cap triggers expiry.
        return record.revokedAt() != null
                || record.expiresAt() <= now
                || record.absoluteExpiryAt() <= now;
    }

    private AclDecision resolveAcl(SessionRecord session) {
        long now = Instant.now().getEpochSecond();
        CachedAclDecision cachedDecision = aclCache.get(session.principalPubkey());
        if (cachedDecision != null && cachedDecision.validUntilEpochSecond() > now) {
            return cachedDecision.decision();
        }

        AclDecision refreshedDecision = aclResolver.resolve(session.principalNpub(), session.principalPubkey());
        // Only a grant is cached. A denial the resolver is certain about revokes the principal's
        // sessions, so the next request stops at the session store and the entry would never be
        // read; a denial it is not certain about — a lagging replica, a row mid-rewrite — must
        // not be held, or one unreadable lookup locks every session the principal holds out for
        // a whole refresh interval instead of for the single request that hit the fault.
        if (refreshedDecision.allowed() && admit(now)) {
            aclCache.put(session.principalPubkey(), new CachedAclDecision(
                    refreshedDecision,
                    now + aclRefreshInterval.toSeconds()
            ));
        }
        return refreshedDecision;
    }

    /**
     * Whether a new principal may be cached, sweeping stale entries first. Declining to cache
     * once the sweep cannot free room keeps the map bounded: correctness does not depend on the
     * cache, only the resolver call rate does.
     */
    private boolean admit(long now) {
        if (aclCache.size() < MAX_CACHED_PRINCIPALS) {
            return true;
        }
        long lastSweep = lastSweepEpochSecond.get();
        if (now - lastSweep >= MIN_SWEEP_INTERVAL_SECONDS
                && lastSweepEpochSecond.compareAndSet(lastSweep, now)) {
            aclCache.entrySet().removeIf(e -> e.getValue().validUntilEpochSecond() <= now);
        }
        return aclCache.size() < MAX_CACHED_PRINCIPALS;
    }

    /** Visible for tests: number of principals currently cached. */
    int aclCacheSize() {
        return aclCache.size();
    }

    /**
     * Spring Security authentication token backed by a NAP session.
     */
    public static class NapAuthenticationToken extends AbstractAuthenticationToken {
        private final SessionRecord session;

        public NapAuthenticationToken(SessionRecord session) {
            super(toAuthorities(session.roles(), session.permissions()));
            this.session = session;
            setAuthenticated(true);
        }

        @Override
        public Object getCredentials() {
            return session.accessToken();
        }

        @Override
        public Object getPrincipal() {
            return session.principalPubkey();
        }

        public SessionRecord getSession() {
            return session;
        }

        public String getPubkey() {
            return session.principalPubkey();
        }

        private static Collection<GrantedAuthority> toAuthorities(List<String> roles, List<String> permissions) {
            return java.util.stream.Stream.concat(
                            permissions.stream(),
                            roles.stream().map(NapAuthenticationToken::toRoleAuthority)
                    )
                    .distinct()
                    .map(SimpleGrantedAuthority::new)
                    .map(GrantedAuthority.class::cast)
                    .toList();
        }

        /**
         * Canonical role-to-authority mapping. Public so {@code NapPermissionInterceptor}
         * resolves {@code @RequiresRole} through the same rule that populated the
         * authorities, rather than duplicating the prefix and casing.
         */
        public static String toRoleAuthority(String role) {
            return "ROLE_" + role.toUpperCase();
        }
    }

    private record CachedAclDecision(AclDecision decision, long validUntilEpochSecond) {
    }
}
