package xyz.tcheeric.nap.spring.filter;

import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import xyz.tcheeric.nap.core.AclDecision;
import xyz.tcheeric.nap.core.SessionRecord;
import xyz.tcheeric.nap.server.AclResolver;
import xyz.tcheeric.nap.core.SessionStore;

import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Verifies session-cookie authentication refreshes ACL decisions without re-querying on every request.
 */
class NapSessionFilterTest {

    private final SessionStore sessionStore = mock(SessionStore.class);
    private final AclResolver aclResolver = mock(AclResolver.class);

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void doFilterInternal_deniesSuspendedSessions() throws Exception {
        SessionRecord session = sessionRecord();
        when(sessionStore.getByAccessToken("access-token-123")).thenReturn(Optional.of(session));
        when(aclResolver.resolve(session.principalNpub(), session.principalPubkey()))
                .thenReturn(AclDecision.denied("suspended", true));

        MockHttpServletResponse response = denyAndCapture();

        assertThat(response.getStatus()).isEqualTo(403);
        // Every session the principal holds, not just the one that happened to make this
        // request: a suspension the ACL states affirmatively is about the principal.
        verify(sessionStore).revokeByPrincipal(eq(session.principalPubkey()), anyLong());
        verify(sessionStore, never()).revokeBySessionId(any(), anyLong());
    }

    @Test
    void doFilterInternal_deniesWithoutRevokingWhenTheDenialIsNotAffirmative() throws Exception {
        // A resolver that answers "denied" because it could not read the ACL — a lagging
        // replica, a row mid-rewrite — blocks this request and no more. Revoking would cost
        // the user a fresh NIP-98 login for someone else's transient failure.
        SessionRecord session = sessionRecord();
        when(sessionStore.getByAccessToken("access-token-123")).thenReturn(Optional.of(session));
        when(aclResolver.resolve(session.principalNpub(), session.principalPubkey()))
                .thenReturn(AclDecision.denied("acl_unavailable"));

        MockHttpServletResponse response = denyAndCapture();

        assertThat(response.getStatus()).isEqualTo(403);
        verify(sessionStore, never()).revokeByPrincipal(any(), anyLong());
        verify(sessionStore, never()).revokeBySessionId(any(), anyLong());
    }

    private MockHttpServletResponse denyAndCapture() throws Exception {
        NapSessionFilter filter = new NapSessionFilter(
                sessionStore,
                aclResolver,
                "merchant_session",
                List.of("/internal/v1/merchants"),
                Duration.ofMinutes(5)
        );
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilterInternal(request(), response, (req, res) -> {
            throw new AssertionError("denied session should not reach the handler");
        });
        return response;
    }

    @Test
    void doFilterInternal_cachesAclRefreshesForTheConfiguredInterval() throws Exception {
        SessionRecord session = sessionRecord();
        when(sessionStore.getByAccessToken("access-token-123")).thenReturn(Optional.of(session));
        when(aclResolver.resolve(session.principalNpub(), session.principalPubkey()))
                .thenReturn(AclDecision.allowed(List.of("admin"), List.of("admin", "read")));

        NapSessionFilter filter = new NapSessionFilter(
                sessionStore,
                aclResolver,
                "merchant_session",
                List.of("/internal/v1/merchants"),
                Duration.ofMinutes(5)
        );
        AtomicReference<Authentication> firstAuth = new AtomicReference<>();
        AtomicReference<Authentication> secondAuth = new AtomicReference<>();

        filter.doFilterInternal(request(), new MockHttpServletResponse(), (req, res) ->
                firstAuth.set(SecurityContextHolder.getContext().getAuthentication()));
        filter.doFilterInternal(request(), new MockHttpServletResponse(), (req, res) ->
                secondAuth.set(SecurityContextHolder.getContext().getAuthentication()));

        assertThat(firstAuth.get()).isNotNull();
        assertThat(secondAuth.get()).isNotNull();
        assertThat(firstAuth.get().getAuthorities()).extracting("authority")
                .contains("admin", "ROLE_ADMIN");
        verify(aclResolver, times(1)).resolve(session.principalNpub(), session.principalPubkey());
    }

    @Test
    void doFilterInternal_unprotectedPath_passesThrough() throws Exception {
        // Arrange
        NapSessionFilter filter = new NapSessionFilter(
                sessionStore, aclResolver, "merchant_session",
                List.of("/internal/v1/merchants"), Duration.ofMinutes(5)
        );
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/public/health");
        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicReference<Authentication> capturedAuth = new AtomicReference<>();

        // Act
        filter.doFilterInternal(request, response, (req, res) ->
                capturedAuth.set(SecurityContextHolder.getContext().getAuthentication()));

        // Assert
        assertThat(capturedAuth.get()).isNull();
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    void doFilterInternal_noCookie_passesThrough() throws Exception {
        // Arrange
        NapSessionFilter filter = new NapSessionFilter(
                sessionStore, aclResolver, "merchant_session",
                List.of("/internal/v1/merchants"), Duration.ofMinutes(5)
        );
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/internal/v1/merchants/list");
        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicReference<Authentication> capturedAuth = new AtomicReference<>();

        // Act
        filter.doFilterInternal(request, response, (req, res) ->
                capturedAuth.set(SecurityContextHolder.getContext().getAuthentication()));

        // Assert
        assertThat(capturedAuth.get()).isNull();
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    void doFilterInternal_expiredSession_revokesAndPassesThrough() throws Exception {
        // Arrange
        long now = java.time.Instant.now().getEpochSecond();
        SessionRecord expired = SessionRecord.create(
                "session-123", "challenge-123", "access-token-123",
                "npub1test", "a".repeat(64),
                List.of("merchant"), List.of("read"),
                now - 7200, now - 3600  // expired 1 hour ago
        );
        when(sessionStore.getByAccessToken("access-token-123")).thenReturn(Optional.of(expired));

        NapSessionFilter filter = new NapSessionFilter(
                sessionStore, aclResolver, "merchant_session",
                List.of("/internal/v1/merchants"), Duration.ofMinutes(5)
        );
        MockHttpServletRequest request = request();
        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicReference<Authentication> capturedAuth = new AtomicReference<>();

        // Act
        filter.doFilterInternal(request, response, (req, res) ->
                capturedAuth.set(SecurityContextHolder.getContext().getAuthentication()));

        // Assert
        assertThat(capturedAuth.get()).isNull();
        verify(sessionStore).revokeBySessionId(eq("session-123"), anyLong());
    }

    @Test
    void doFilterInternal_sessionNotFound_passesThrough() throws Exception {
        // Arrange
        when(sessionStore.getByAccessToken("access-token-123")).thenReturn(Optional.empty());

        NapSessionFilter filter = new NapSessionFilter(
                sessionStore, aclResolver, "merchant_session",
                List.of("/internal/v1/merchants"), Duration.ofMinutes(5)
        );
        MockHttpServletRequest request = request();
        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicReference<Authentication> capturedAuth = new AtomicReference<>();

        // Act
        filter.doFilterInternal(request, response, (req, res) ->
                capturedAuth.set(SecurityContextHolder.getContext().getAuthentication()));

        // Assert
        assertThat(capturedAuth.get()).isNull();
        assertThat(response.getStatus()).isEqualTo(200);
    }

    private MockHttpServletRequest request() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/internal/v1/merchants/test/suspend");
        request.setCookies(new Cookie("merchant_session", "access-token-123"));
        return request;
    }

    @Test
    void doFilterInternal_cachesOneDecisionPerPrincipalNotPerSession() throws Exception {
        // Many sessions of one principal — separate tabs, devices — resolve the same ACL, so
        // the cache holds one entry and the resolver is asked once.
        NapSessionFilter filter = new NapSessionFilter(
                sessionStore, aclResolver, "merchant_session",
                List.of("/internal/v1/merchants"), Duration.ofMinutes(5)
        );
        when(aclResolver.resolve("npub1test", "a".repeat(64)))
                .thenReturn(AclDecision.allowed(List.of("merchant"), List.of("read")));

        for (int i = 0; i < 50; i++) {
            String sessionId = "session-" + i;
            String accessToken = "access-token-" + i;
            when(sessionStore.getByAccessToken(accessToken))
                    .thenReturn(Optional.of(sessionRecord(sessionId, accessToken)));
            MockHttpServletRequest request =
                    new MockHttpServletRequest("POST", "/internal/v1/merchants/test/suspend");
            request.setCookies(new Cookie("merchant_session", accessToken));
            filter.doFilterInternal(request, new MockHttpServletResponse(), (req, res) -> { });
        }

        verify(aclResolver, times(1)).resolve("npub1test", "a".repeat(64));
        assertThat(filter.aclCacheSize()).isEqualTo(1);
    }

    @Test
    void doFilterInternal_doesNotCacheADenialTheResolverIsUnsureOf() throws Exception {
        // "Denied" because the ACL could not be read must cost the one request that hit the
        // fault. Caching it would lock the principal out for a whole refresh interval, and
        // because the cache is now per-principal that would take every session down with it.
        SessionRecord session = sessionRecord();
        when(sessionStore.getByAccessToken("access-token-123")).thenReturn(Optional.of(session));
        when(aclResolver.resolve(session.principalNpub(), session.principalPubkey()))
                .thenReturn(AclDecision.denied("acl_unavailable"))
                .thenReturn(AclDecision.allowed(List.of("merchant"), List.of("read")));

        NapSessionFilter filter = new NapSessionFilter(
                sessionStore, aclResolver, "merchant_session",
                List.of("/internal/v1/merchants"), Duration.ofMinutes(5)
        );
        MockHttpServletResponse denied = new MockHttpServletResponse();
        filter.doFilterInternal(request(), denied, (req, res) -> { });

        AtomicReference<Authentication> retryAuth = new AtomicReference<>();
        filter.doFilterInternal(request(), new MockHttpServletResponse(), (req, res) ->
                retryAuth.set(SecurityContextHolder.getContext().getAuthentication()));

        assertThat(denied.getStatus()).isEqualTo(403);
        assertThat(retryAuth.get()).isNotNull();
        assertThat(filter.aclCacheSize()).isEqualTo(1);
        verify(aclResolver, times(2)).resolve(session.principalNpub(), session.principalPubkey());
    }

    /**
     * A session of the shared principal, with its own id and its own access token. Distinct
     * tokens are what make the per-principal cache assertion meaningful: N sessions now look
     * up N different credentials and must still collapse to one cache entry.
     */
    private SessionRecord sessionRecord(String sessionId, String accessToken) {
        long now = java.time.Instant.now().getEpochSecond();
        return SessionRecord.create(
                sessionId,
                "challenge-123",
                accessToken,
                "npub1test",
                "a".repeat(64),
                List.of("merchant"),
                List.of("read"),
                now,
                now + 3_600
        );
    }

    /**
     * Protection must not depend on the servlet context path (#29).
     *
     * <p>This filter matched the raw {@code getRequestURI()} while NapPermissionInterceptor
     * stripped the context path first, so a deployment under {@code /app} had a filter that
     * skipped authentication on requests the interceptor believed were guarded. With the
     * interceptor now failing closed by default, that disagreement decides whether a request is
     * authenticated at all.
     */
    @Test
    void doFilterInternal_appliesProtectionUnderANonEmptyContextPath() throws Exception {
        SessionRecord session = sessionRecord();
        when(sessionStore.getByAccessToken("access-token-123")).thenReturn(Optional.of(session));
        when(aclResolver.resolve(session.principalNpub(), session.principalPubkey()))
                .thenReturn(AclDecision.allowed(List.of("merchant"), List.of("read")));

        NapSessionFilter filter = new NapSessionFilter(
                sessionStore, aclResolver, "merchant_session",
                List.of("/internal/v1/merchants"), Duration.ofMinutes(5)
        );

        MockHttpServletRequest request =
                new MockHttpServletRequest("POST", "/app/internal/v1/merchants/test/suspend");
        request.setContextPath("/app");
        request.setCookies(new Cookie("merchant_session", "access-token-123"));

        AtomicReference<Authentication> captured = new AtomicReference<>();
        filter.doFilterInternal(request, new MockHttpServletResponse(), (req, res) ->
                captured.set(SecurityContextHolder.getContext().getAuthentication()));

        // The prefix matches only once the context path is stripped, so an authentication
        // being present is what proves the filter treated this as protected.
        assertThat(captured.get()).isNotNull();
        assertThat(captured.get().isAuthenticated()).isTrue();
    }

    private SessionRecord sessionRecord() {
        long now = java.time.Instant.now().getEpochSecond();
        return SessionRecord.create(
                "session-123",
                "challenge-123",
                "access-token-123",
                "npub1test",
                "a".repeat(64),
                List.of("merchant"),
                List.of("read"),
                now,
                now + 3_600
        );
    }
}
