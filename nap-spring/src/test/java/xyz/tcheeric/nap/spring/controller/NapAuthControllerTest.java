package xyz.tcheeric.nap.spring.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import xyz.tcheeric.nap.core.AuthFailureResponse;
import xyz.tcheeric.nap.core.AuthInitResponse;
import xyz.tcheeric.nap.core.AuthSuccessResponse;
import xyz.tcheeric.nap.core.SessionRecord;
import xyz.tcheeric.nap.core.SessionStore;
import xyz.tcheeric.nap.server.IssueChallengeInput;
import xyz.tcheeric.nap.server.IssueChallengeResult;
import xyz.tcheeric.nap.server.NapServer;
import xyz.tcheeric.nap.server.VerifyCompletionInput;
import xyz.tcheeric.nap.server.VerifyCompletionOutcome;
import xyz.tcheeric.nap.server.store.InMemorySessionStore;
import xyz.tcheeric.nap.spring.config.NapProperties;
import xyz.tcheeric.nap.spring.filter.NapServletFilter;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentCaptor.forClass;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Verifies auth completion, session sliding/reason-typed 401 (spec 006), and logout cookie clear.
 */
class NapAuthControllerTest {

    private final NapServer napServer = mock(NapServer.class);
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final SessionStore sessionStore = new InMemorySessionStore();
    private final NapProperties properties = new NapProperties(
            true,
            "https://account.imani.casa",
            60,     // challengeTtlSeconds
            3600,   // sessionTtlSeconds (legacy)
            900,    // sessionIdleTtlSeconds (spec 006 — 15 min)
            43200,  // sessionAbsoluteTtlSeconds (spec 006 — 12 h)
            30,     // resultCacheTtlSeconds
            60,     // maxClockSkewSeconds
            600,    // stepUpTtlSeconds
            0,      // refreshTtlSeconds — refresh is opt-in
            300,    // aclRefreshIntervalSeconds
            null,   // rateLimitEnabled — compact ctor defaults these
            0,      // rateLimitWindowSeconds
            0,      // rateLimitMaxPerWindow
            null,   // maxOutstandingChallengesPerNpub
            null,   // maxOutstandingChallengesPerIp
            null,   // maxFailuresPerChallenge
            null,   // minAuthResponseMillis
            null,   // responseJitterMillis
            0,      // maxBodyBytes
            List.of("/internal/v1/merchants"),
            new NapProperties.CookieProperties("merchant_session", true, true, "Lax", "/", "", 43200)
    );

    private NapAuthController controller() {
        return new NapAuthController(napServer, sessionStore, properties, objectMapper);
    }

    @Test
    void complete_usesBodyProofWhenAuthorizationHeaderIsMissing() {
        String requestBody = """
                {"challenge_id":"challenge-123","proof":"Nostr legacy-proof"}
                """;
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/auth/complete");
        request.setAttribute(NapServletFilter.RAW_BODY_ATTRIBUTE, requestBody.getBytes());
        MockHttpServletResponse response = new MockHttpServletResponse();

        long now = 1_700_000_000L;
        SessionRecord session = SessionRecord.create(
                "session-1", "challenge-123", "access-token",
                "npub1test", "a".repeat(64),
                List.of("merchant"), List.of("read"),
                now, now, now + 900, now + 43200
        );
        when(napServer.verifyCompletion(any())).thenReturn(VerifyCompletionOutcome.success(session));
        when(napServer.toPublicAuthSuccess(session)).thenReturn(new AuthSuccessResponse(
                "ok", session.accessToken(), "Bearer",
                session.expiresAt(), session.absoluteExpiryAt(),
                new AuthSuccessResponse.Principal(session.principalNpub(), session.principalPubkey()),
                session.roles(), session.permissions()
        ));

        Object body = controller().complete(request, response).getBody();

        var captor = forClass(VerifyCompletionInput.class);
        verify(napServer).verifyCompletion(captor.capture());
        VerifyCompletionInput completionInput = captor.getValue();
        assertThat(completionInput.authorization()).isEqualTo("Nostr legacy-proof");
        assertThat(completionInput.method()).isEqualTo("POST");
        assertThat(completionInput.url()).isEqualTo("https://account.imani.casa/api/v1/auth/complete");
        assertThat(completionInput.rawBody()).isEqualTo(requestBody.getBytes());
        assertThat(response.getCookie("merchant_session")).isNotNull();
        assertThat(body).isNotNull();
    }

    @Test
    void init_validNpub_returnsSuccess() {
        AuthInitResponse initResponse = new AuthInitResponse(
                "challenge-1", "nip98-challenge", "https://account.imani.casa/api/v1/auth/complete",
                "NIP-98", 1_700_000_000L, 1_700_000_060L
        );
        when(napServer.issueChallenge(any(IssueChallengeInput.class)))
                .thenReturn(new IssueChallengeResult.Success(initResponse));

        ResponseEntity<?> response = controller().init(Map.of("npub", "npub1testpubkey"), new MockHttpServletRequest());

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody()).isNotNull();
    }

    @Test
    void init_missingNpubAndPubkey_returnsBadRequest() {
        ResponseEntity<?> response = controller().init(Map.of(), new MockHttpServletRequest());
        assertThat(response.getStatusCode().value()).isEqualTo(400);
    }

    @Test
    void complete_malformedBody_returnsBadRequest() {
        when(napServer.verifyCompletion(any())).thenReturn(VerifyCompletionOutcome.malformed());

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/auth/complete");
        request.setAttribute(NapServletFilter.RAW_BODY_ATTRIBUTE, "{}".getBytes());
        MockHttpServletResponse servletResponse = new MockHttpServletResponse();

        ResponseEntity<?> response = controller().complete(request, servletResponse);

        assertThat(response.getStatusCode().value()).isEqualTo(400);
    }

    @Test
    void complete_failure_returnsUnauthorized() {
        when(napServer.verifyCompletion(any()))
                .thenReturn(new VerifyCompletionOutcome.Failure(
                        xyz.tcheeric.nap.core.NapErrorCode.NAP_COMPLETE_INVALID_SIGNATURE, false));
        when(napServer.toPublicAuthFailure())
                .thenReturn(new NapServer.PublicFailureResponse(401, AuthFailureResponse.authenticationFailed()));

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/auth/complete");
        request.setAttribute(NapServletFilter.RAW_BODY_ATTRIBUTE, "{}".getBytes());
        MockHttpServletResponse servletResponse = new MockHttpServletResponse();

        ResponseEntity<?> response = controller().complete(request, servletResponse);

        assertThat(response.getStatusCode().value()).isEqualTo(401);
    }

    // -----------------------------------------------------------------
    // /auth/session — spec-006 sliding-window + reason-typed 401
    // -----------------------------------------------------------------

    @Test
    void checkSession_noCookie_returns401WithReasonInvalid() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/auth/session");

        ResponseEntity<?> response = controller().checkSession(request);

        assertThat(response.getStatusCode().value()).isEqualTo(401);
        @SuppressWarnings("unchecked")
        Map<String, Object> body = (Map<String, Object>) response.getBody();
        assertThat(body).containsEntry("error", "session_ended");
        assertThat(body).containsEntry("reason", "invalid");
    }

    @Test
    void checkSession_unknownCookie_returns401WithReasonInvalid() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/auth/session");
        request.setCookies(new Cookie("merchant_session", "does-not-exist"));

        ResponseEntity<?> response = controller().checkSession(request);

        assertThat(response.getStatusCode().value()).isEqualTo(401);
        @SuppressWarnings("unchecked")
        Map<String, Object> body = (Map<String, Object>) response.getBody();
        assertThat(body).containsEntry("reason", "invalid");
    }

    @Test
    void checkSession_expiredSession_returns401WithReasonExpired() {
        long past = Instant.now().getEpochSecond() - 1_000;
        SessionRecord expired = SessionRecord.create(
                "sid-expired", "chal", "token",
                "npub", "b".repeat(64),
                List.of(), List.of(),
                past - 3600, past - 3600, past - 600, past - 600
        );
        sessionStore.createForChallenge(expired);

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/auth/session");
        request.setCookies(new Cookie("merchant_session", "sid-expired"));

        ResponseEntity<?> response = controller().checkSession(request);

        assertThat(response.getStatusCode().value()).isEqualTo(401);
        @SuppressWarnings("unchecked")
        Map<String, Object> body = (Map<String, Object>) response.getBody();
        assertThat(body).containsEntry("reason", "expired");
    }

    @Test
    void checkSession_returnsCrossImplementationShapeWithoutLeakingTheToken() {
        long now = Instant.now().getEpochSecond();
        SessionRecord active = SessionRecord.create(
                "sid-shape", "chal-s", "token-secret",
                "npub1example", "d".repeat(64),
                List.of("merchant"), List.of("voucher:issue"),
                now - 60, now - 60, now + 300, now + 43200
        );
        sessionStore.createForChallenge(active);

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/auth/session");
        request.setCookies(new Cookie("merchant_session", "sid-shape"));

        ResponseEntity<?> response = controller().checkSession(request);

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        @SuppressWarnings("unchecked")
        Map<String, Object> body = (Map<String, Object>) response.getBody();

        // The shape @imani/nap-client-web reads: toSessionState() dereferences
        // response.principal.pubkey, so a missing `principal` breaks resume().
        assertThat(body).containsEntry("status", "ok");
        assertThat(body).containsEntry("roles", List.of("merchant"));
        assertThat(body).containsEntry("permissions", List.of("voucher:issue"));
        @SuppressWarnings("unchecked")
        Map<String, Object> principal = (Map<String, Object>) body.get("principal");
        assertThat(principal).containsEntry("npub", "npub1example");
        assertThat(principal).containsEntry("pubkey", "d".repeat(64));

        // Retained for existing JVM consumers — the change is additive.
        assertThat(body).containsEntry("pubkey", "d".repeat(64));
        assertThat(body).containsKey("absolute_expiry_at");

        // The session id is an HttpOnly cookie; echoing a credential into the body
        // would make it readable by script.
        assertThat(body).doesNotContainKey("access_token");
        assertThat(body).doesNotContainKey("step_up_token");
    }

    @Test
    void checkSession_validSession_slidesIdleWindowAndReturnsPubkey() {
        long now = Instant.now().getEpochSecond();
        long issuedAt = now - 60;            // session 1 minute old
        long lastActivity = issuedAt;
        long oldIdleExpiry = issuedAt + 300; // expires in ~4 more minutes under old window
        long absoluteExpiry = issuedAt + 43200;
        SessionRecord active = SessionRecord.create(
                "sid-active", "chal-a", "token-a",
                "npub-a", "c".repeat(64),
                List.of("merchant"), List.of("read"),
                issuedAt, lastActivity, oldIdleExpiry, absoluteExpiry
        );
        sessionStore.createForChallenge(active);

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/auth/session");
        request.setCookies(new Cookie("merchant_session", "sid-active"));

        ResponseEntity<?> response = controller().checkSession(request);

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        @SuppressWarnings("unchecked")
        Map<String, Object> body = (Map<String, Object>) response.getBody();
        assertThat(body).containsEntry("pubkey", "c".repeat(64));
        assertThat(body).containsEntry("absolute_expiry_at", absoluteExpiry);
        // expires_at must have slid FORWARD past the original window and also
        // not exceed the absolute cap.
        long newExpiresAt = ((Number) body.get("expires_at")).longValue();
        assertThat(newExpiresAt).isGreaterThan(oldIdleExpiry);
        assertThat(newExpiresAt).isLessThanOrEqualTo(absoluteExpiry);

        // The store must reflect the slide.
        SessionRecord after = sessionStore.getBySessionId("sid-active").orElseThrow();
        assertThat(after.lastActivityAt()).isGreaterThanOrEqualTo(now);
        assertThat(after.expiresAt()).isEqualTo(newExpiresAt);
    }

    @Test
    void checkSession_slide_isCappedByAbsoluteExpiry() {
        long now = Instant.now().getEpochSecond();
        // Session whose absolute cap is only 2 minutes in the future, but idleTtl
        // is 15 min. The slide MUST NOT extend expiresAt past absoluteExpiryAt.
        long absoluteExpiry = now + 120;
        SessionRecord narrow = SessionRecord.create(
                "sid-narrow", "chal-n", "token-n",
                "npub-n", "d".repeat(64),
                List.of(), List.of(),
                now - 3600, now - 60, now + 60, absoluteExpiry
        );
        sessionStore.createForChallenge(narrow);

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/auth/session");
        request.setCookies(new Cookie("merchant_session", "sid-narrow"));

        ResponseEntity<?> response = controller().checkSession(request);

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        @SuppressWarnings("unchecked")
        Map<String, Object> body = (Map<String, Object>) response.getBody();
        long newExpiresAt = ((Number) body.get("expires_at")).longValue();
        assertThat(newExpiresAt).isEqualTo(absoluteExpiry);
    }

    // -----------------------------------------------------------------
    // /auth/logout
    // -----------------------------------------------------------------

    @Test
    void logout_clearsCookieAndRevokesSession() {
        long now = Instant.now().getEpochSecond();
        SessionRecord live = SessionRecord.create(
                "sid-live", "chal-l", "token-l",
                "npub-l", "e".repeat(64),
                List.of(), List.of(),
                now - 60, now - 60, now + 900, now + 43200
        );
        sessionStore.createForChallenge(live);

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/auth/logout");
        request.setCookies(new Cookie("merchant_session", "sid-live"));
        MockHttpServletResponse response = new MockHttpServletResponse();

        ResponseEntity<Void> result = controller().logout(request, response);

        assertThat(result.getStatusCode().value()).isEqualTo(204);
        Cookie cookie = response.getCookie("merchant_session");
        assertThat(cookie).isNotNull();
        assertThat(cookie.getMaxAge()).isEqualTo(0);
        // Session is revoked in the store — subsequent getBySessionId filters it out.
        assertThat(sessionStore.getBySessionId("sid-live")).isEmpty();
    }
}
