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

/**
 * Validates NAP session cookies on protected paths and populates Spring SecurityContext.
 */
public class NapSessionFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(NapSessionFilter.class);

    private final SessionStore sessionStore;
    private final AclResolver aclResolver;
    private final String cookieName;
    private final List<String> protectedPrefixes;
    private final Duration aclRefreshInterval;
    private final Map<String, CachedAclDecision> aclCache = new ConcurrentHashMap<>();

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
            // Only an affirmative denial ends the session. A resolver that answers "denied"
            // because it could not read the ACL — a lagging replica, a row mid-rewrite —
            // blocks this request and no more; revoking would cost a fresh NIP-98 login.
            if (aclDecision.revokeSessions()) {
                sessionStore.revokeBySessionId(record.sessionId(), Instant.now().getEpochSecond());
            }
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            return;
        }

        SessionRecord effectiveRecord = new SessionRecord(
                record.sessionId(),
                record.challengeId(),
                record.accessToken(),
                record.principalNpub(),
                record.principalPubkey(),
                aclDecision.roles(),
                aclDecision.permissions(),
                record.issuedAt(),
                record.lastActivityAt(),
                record.expiresAt(),
                record.absoluteExpiryAt(),
                record.revokedAt(),
                record.stepUpToken(),
                record.stepUpExpiresAt()
        );

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
        CachedAclDecision cachedDecision = aclCache.get(session.sessionId());
        if (cachedDecision != null && cachedDecision.validUntilEpochSecond() > now) {
            return cachedDecision.decision();
        }

        AclDecision refreshedDecision = aclResolver.resolve(session.principalNpub(), session.principalPubkey());
        aclCache.put(session.sessionId(), new CachedAclDecision(
                refreshedDecision,
                now + aclRefreshInterval.toSeconds()
        ));
        return refreshedDecision;
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
