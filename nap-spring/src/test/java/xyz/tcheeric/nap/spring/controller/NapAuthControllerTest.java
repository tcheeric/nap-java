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
import xyz.tcheeric.nap.core.NapErrorCode;
import xyz.tcheeric.nap.core.SessionRecord;
import xyz.tcheeric.nap.core.SessionStore;
import xyz.tcheeric.nap.server.IssueChallengeInput;
import xyz.tcheeric.nap.server.IssueChallengeResult;
import xyz.tcheeric.nap.server.NapServer;
import xyz.tcheeric.nap.server.RefreshSessionInput;
import xyz.tcheeric.nap.server.RefreshSessionOutcome;
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
    private final NapProperties properties =
            propertiesWith(new NapProperties.CookieProperties("merchant_session", true, true, "Lax", "/", "", 43200));

    private static NapProperties propertiesWith(NapProperties.CookieProperties cookie) {
        return new NapProperties(
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
            cookie
        );
    }

    private NapAuthController controller() {
        return controller(properties);
    }

    private NapAuthController controller(NapProperties props) {
        return new NapAuthController(napServer, sessionStore, props, objectMapper);
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
    // /auth/refresh
    // -----------------------------------------------------------------

    /**
     * A failed refresh must leave the session cookie alone. The endpoint needs neither a cookie
     * nor an Authorization header to reach the failure branch, so clearing there would let any
     * cross-site POST to /auth/refresh log out every visitor holding a live session.
     */
    @Test
    void refresh_failure_returns401ButLeavesTheSessionCookieAlone() {
        when(napServer.refreshSession(any()))
                .thenReturn(RefreshSessionOutcome.failure(NapErrorCode.NAP_REFRESH_UNKNOWN_TOKEN));
        when(napServer.toPublicAuthFailure())
                .thenReturn(new NapServer.PublicFailureResponse(401, AuthFailureResponse.authenticationFailed()));

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/auth/refresh");
        request.setCookies(new Cookie("merchant_session", "sid-live"));
        MockHttpServletResponse response = new MockHttpServletResponse();

        ResponseEntity<?> result = controller().refresh(request, response);

        assertThat(result.getStatusCode().value()).isEqualTo(401);
        assertThat(response.getCookie("merchant_session")).isNull();
    }

    @Test
    void refresh_success_renewsTheCookie() {
        long now = Instant.now().getEpochSecond();
        SessionRecord rotated = SessionRecord.create(
                "sid-rotated", "chal-r", "access-2",
                "npub-r", "f".repeat(64),
                List.of("merchant"), List.of("read"),
                now - 60, now, now + 900, now + 43200
        );
        when(napServer.refreshSession(any())).thenReturn(new RefreshSessionOutcome.Success(rotated));
        when(napServer.toPublicAuthSuccess(rotated)).thenReturn(new AuthSuccessResponse(
                "ok", rotated.accessToken(), "Bearer",
                rotated.expiresAt(), rotated.absoluteExpiryAt(),
                new AuthSuccessResponse.Principal(rotated.principalNpub(), rotated.principalPubkey()),
                rotated.roles(), rotated.permissions()
        ));

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/auth/refresh");
        request.addHeader("Authorization", "Bearer refresh-1");
        MockHttpServletResponse response = new MockHttpServletResponse();

        ResponseEntity<?> result = controller().refresh(request, response);

        assertThat(result.getStatusCode().value()).isEqualTo(200);
        Cookie cookie = response.getCookie("merchant_session");
        assertThat(cookie).isNotNull();
        assertThat(cookie.getValue()).isEqualTo("sid-rotated");
        assertThat(cookie.getMaxAge()).isEqualTo(43200);

        var captor = forClass(RefreshSessionInput.class);
        verify(napServer).refreshSession(captor.capture());
        assertThat(captor.getValue().refreshToken()).isEqualTo("refresh-1");
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

    /**
     * A browser matches a deletion against name + domain + path, and drops a Set-Cookie whose
     * SameSite it disagrees with. A clear that omits either attribute leaves the cookie in the
     * jar: logout returns 204 and the user is still logged in.
     */
    @Test
    void logout_clearedCookieCarriesTheAttributesTheSetWroteWith() {
        NapProperties domainScoped = propertiesWith(
                new NapProperties.CookieProperties("merchant_session", true, true, "Lax", "/", ".imani.casa", 43200));

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/auth/logout");
        request.setCookies(new Cookie("merchant_session", "sid-gone"));
        MockHttpServletResponse response = new MockHttpServletResponse();

        controller(domainScoped).logout(request, response);

        Cookie cookie = response.getCookie("merchant_session");
        assertThat(cookie).isNotNull();
        assertThat(cookie.getMaxAge()).isEqualTo(0);
        assertThat(cookie.getDomain()).isEqualTo(".imani.casa");
        assertThat(cookie.getPath()).isEqualTo("/");
        assertThat(cookie.getAttribute("SameSite")).isEqualTo("Lax");
        assertThat(cookie.getSecure()).isTrue();
        assertThat(cookie.isHttpOnly()).isTrue();
    }

    /**
     * The test above pins the clear against a known config, which is what caught the
     * regression. This one pins the invariant behind it: the set and the clear may differ
     * on value and max-age and on nothing else. Both go through {@code sessionCookie()}
     * today, so it cannot fail — it fails the day someone reintroduces a bespoke
     * {@code setCookie}, which is the only way this bug comes back.
     */
    @Test
    void setAndClearCookiesDifferOnlyInValueAndMaxAge() {
        NapProperties domainScoped = propertiesWith(
                new NapProperties.CookieProperties("merchant_session", true, true, "Strict", "/app", ".imani.casa", 43200));
        NapAuthController controller = controller(domainScoped);

        long now = Instant.now().getEpochSecond();
        SessionRecord session = SessionRecord.create(
                "sid-sym", "chal-sym", "token-sym",
                "npub-sym", "f".repeat(64),
                List.of(), List.of(),
                now, now, now + 900, now + 43200
        );
        when(napServer.verifyCompletion(any())).thenReturn(VerifyCompletionOutcome.success(session));
        when(napServer.toPublicAuthSuccess(session)).thenReturn(new AuthSuccessResponse(
                "ok", session.accessToken(), "Bearer",
                session.expiresAt(), session.absoluteExpiryAt(),
                new AuthSuccessResponse.Principal(session.principalNpub(), session.principalPubkey()),
                session.roles(), session.permissions()
        ));

        MockHttpServletRequest completeRequest = new MockHttpServletRequest("POST", "/api/v1/auth/complete");
        completeRequest.setAttribute(NapServletFilter.RAW_BODY_ATTRIBUTE,
                "{\"challenge_id\":\"chal-sym\",\"proof\":\"Nostr p\"}".getBytes());
        MockHttpServletResponse completeResponse = new MockHttpServletResponse();
        controller.complete(completeRequest, completeResponse);

        MockHttpServletRequest logoutRequest = new MockHttpServletRequest("POST", "/api/v1/auth/logout");
        logoutRequest.setCookies(new Cookie("merchant_session", "sid-sym"));
        MockHttpServletResponse logoutResponse = new MockHttpServletResponse();
        controller.logout(logoutRequest, logoutResponse);

        Cookie set = completeResponse.getCookie("merchant_session");
        Cookie cleared = logoutResponse.getCookie("merchant_session");
        assertThat(set).isNotNull();
        assertThat(cleared).isNotNull();

        assertThat(cleared.getName()).isEqualTo(set.getName());
        assertThat(cleared.getDomain()).isEqualTo(set.getDomain());
        assertThat(cleared.getPath()).isEqualTo(set.getPath());
        assertThat(cleared.getAttribute("SameSite")).isEqualTo(set.getAttribute("SameSite"));
        assertThat(cleared.getSecure()).isEqualTo(set.getSecure());
        assertThat(cleared.isHttpOnly()).isEqualTo(set.isHttpOnly());

        // The two that must differ, or the clear would be a renewal.
        assertThat(set.getMaxAge()).isEqualTo(43200);
        assertThat(cleared.getMaxAge()).isEqualTo(0);
        assertThat(cleared.getValue()).isEmpty();
    }
}
