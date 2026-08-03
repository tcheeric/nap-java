package xyz.tcheeric.nap.spring.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import xyz.tcheeric.nap.core.NapErrorCode;
import xyz.tcheeric.nap.core.SessionRecord;
import xyz.tcheeric.nap.core.SessionStore;
import xyz.tcheeric.nap.server.*;
import xyz.tcheeric.nap.spring.config.NapProperties;
import xyz.tcheeric.nap.spring.filter.NapServletFilter;

import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * NAP v2 authentication endpoints: init, complete, session, logout.
 *
 * <p>{@code GET /api/v1/auth/session} implements the spec-006 sliding-window
 * contract: on success it advances the session's {@code last_activity_at} and
 * returns {@code {pubkey, expires_at, absolute_expiry_at}}. On failure it
 * returns {@code 401 {error, reason}} with {@code reason=expired|invalid}.
 */
@RestController
@RequestMapping("/api/v1/auth")
public class NapAuthController {

    private static final Logger log = LoggerFactory.getLogger(NapAuthController.class);

    private final NapServer napServer;
    private final SessionStore sessionStore;
    private final NapProperties properties;
    private final ObjectMapper objectMapper;

    public NapAuthController(NapServer napServer, SessionStore sessionStore,
                             NapProperties properties, ObjectMapper objectMapper) {
        this.napServer = napServer;
        this.sessionStore = sessionStore;
        this.properties = properties;
        this.objectMapper = objectMapper;
    }

    @PostMapping("/init")
    public ResponseEntity<?> init(@RequestBody Map<String, String> body, HttpServletRequest request) {
        String npub = body.get("npub");
        String pubkey = body.get("pubkey");

        if ((npub == null || npub.isBlank()) && (pubkey == null || pubkey.isBlank())) {
            return ResponseEntity.badRequest()
                    .body(Map.of("status", "error", "message", "npub or pubkey is required"));
        }

        String authUrl = properties.externalBaseUrl() + "/api/v1/auth/complete";

        IssueChallengeResult result = napServer.issueChallenge(new IssueChallengeInput(
                npub != null ? npub : pubkey, authUrl, "POST", request.getRemoteAddr()));

        return switch (result) {
            case IssueChallengeResult.Success s -> ResponseEntity.ok(Map.of(
                    "challenge_id", s.value().challengeId(),
                    "challenge", s.value().challenge(),
                    "auth_url", s.value().authUrl(),
                    "auth_method", s.value().authMethod(),
                    "issued_at", s.value().issuedAt(),
                    "expires_at", s.value().expiresAt()
            ));
            case IssueChallengeResult.Failure f when f.code() == NapErrorCode.NAP_INIT_RATE_LIMITED ->
                    rateLimited(f.retryAfterSeconds());
            case IssueChallengeResult.Failure f -> ResponseEntity.badRequest()
                    .body(Map.of("status", "error", "code", f.code().name()));
        };
    }

    /**
     * {@code step_up} is read from the signed body, not the query string — see
     * {@link xyz.tcheeric.nap.core.AuthCompleteRequest}.
     */
    @PostMapping("/complete")
    public ResponseEntity<?> complete(HttpServletRequest request, HttpServletResponse response) {

        byte[] rawBody = (byte[]) request.getAttribute(NapServletFilter.RAW_BODY_ATTRIBUTE);
        if (rawBody == null) {
            return ResponseEntity.badRequest()
                    .body(Map.of("status", "error", "message", "Request body not captured"));
        }

        String authUrl = properties.externalBaseUrl() + "/api/v1/auth/complete";
        String authorization = resolveAuthorization(request, rawBody);

        VerifyCompletionOutcome outcome = napServer.verifyCompletion(new VerifyCompletionInput(
                authorization, "POST", authUrl, rawBody, request.getRemoteAddr()));

        return switch (outcome) {
            case VerifyCompletionOutcome.Success s -> {
                setCookie(response, s.session().sessionId());
                var successResponse = napServer.toPublicAuthSuccess(s.session());
                yield ResponseEntity.ok(successResponse);
            }
            // Rate limiting is not an authentication failure, and hiding it behind one only
            // makes clients retry harder.
            case VerifyCompletionOutcome.Failure f when f.code() == NapErrorCode.NAP_COMPLETE_RATE_LIMITED ->
                    rateLimited(f.retryAfterSeconds());
            case VerifyCompletionOutcome.Failure f -> {
                log.warn("nap_complete_failed code={}", f.code());
                yield ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(napServer.toPublicAuthFailure().body());
            }
            case VerifyCompletionOutcome.MalformedRequest m ->
                    ResponseEntity.badRequest()
                            .body(Map.of("status", "error", "message", "bad request"));
        };
    }

    private static ResponseEntity<?> rateLimited(Integer retryAfterSeconds) {
        var builder = ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS);
        if (retryAfterSeconds != null) {
            builder.header("Retry-After", String.valueOf(retryAfterSeconds));
        }
        return builder.body(Map.of("status", "error", "message", "rate limited"));
    }

    /**
     * Validate the session cookie, slide its idle window, and return the
     * pubkey + expiries. On any failure return {@code 401} with a typed
     * {@code reason} so the client can display the correct end-reason copy.
     */
    @GetMapping("/session")
    public ResponseEntity<?> checkSession(HttpServletRequest request) {
        String sessionId = extractCookie(request);
        if (sessionId == null) {
            return sessionEnded("invalid");
        }

        SessionRecord record = sessionStore.getBySessionId(sessionId).orElse(null);
        if (record == null) {
            return sessionEnded("invalid");
        }
        if (record.revokedAt() != null) {
            return sessionEnded("invalid");
        }

        long now = Instant.now().getEpochSecond();
        if (record.expiresAt() <= now || record.absoluteExpiryAt() <= now) {
            return sessionEnded("expired");
        }

        // Slide the idle window: advance last_activity_at to `now` and bump
        // expires_at forward to `now + idleTtl`, capped at absolute_expiry_at.
        long idleTtl = properties.sessionIdleTtlSeconds();
        long newExpiresAt = Math.min(now + idleTtl, record.absoluteExpiryAt());
        sessionStore.touch(record.sessionId(), now, newExpiresAt);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", "ok");
        // `principal`, `roles` and `permissions` are the cross-implementation shape the
        // browser client reads (toSessionState reads response.principal.pubkey). `pubkey`
        // is retained alongside it so existing JVM consumers keep working — an additive
        // change rather than a rename.
        body.put("pubkey", record.principalPubkey());
        Map<String, Object> principal = new LinkedHashMap<>();
        principal.put("npub", record.principalNpub());
        principal.put("pubkey", record.principalPubkey());
        body.put("principal", principal);
        body.put("roles", record.roles() == null ? List.of() : record.roles());
        body.put("permissions", record.permissions() == null ? List.of() : record.permissions());
        body.put("expires_at", newExpiresAt);
        body.put("absolute_expiry_at", record.absoluteExpiryAt());

        // Deliberately no access_token: the session id lives in an HttpOnly cookie, and
        // echoing a credential into a JSON body would make it readable by script.
        return ResponseEntity.ok(body);
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletRequest request, HttpServletResponse response) {
        String sessionId = extractCookie(request);
        if (sessionId != null) {
            sessionStore.revokeBySessionId(sessionId, Instant.now().getEpochSecond());
            log.info("nap_logout");
        }
        clearCookie(response);
        return ResponseEntity.noContent().build();
    }

    private ResponseEntity<Map<String, Object>> sessionEnded(String reason) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "session_ended", "reason", reason));
    }

    private void setCookie(HttpServletResponse response, String sessionId) {
        var cookieProps = properties.cookie();
        Cookie cookie = new Cookie(cookieProps.name(), sessionId);
        cookie.setHttpOnly(cookieProps.httpOnly());
        cookie.setSecure(cookieProps.secure());
        cookie.setPath(cookieProps.path());
        cookie.setMaxAge(cookieProps.maxAgeSeconds());
        cookie.setAttribute("SameSite", cookieProps.sameSite());
        if (cookieProps.domain() != null && !cookieProps.domain().isBlank()) {
            cookie.setDomain(cookieProps.domain());
        }
        response.addCookie(cookie);
    }

    private void clearCookie(HttpServletResponse response) {
        var cookieProps = properties.cookie();
        Cookie cookie = new Cookie(cookieProps.name(), "");
        cookie.setHttpOnly(cookieProps.httpOnly());
        cookie.setSecure(cookieProps.secure());
        cookie.setPath(cookieProps.path());
        cookie.setMaxAge(0);
        response.addCookie(cookie);
    }

    private String extractCookie(HttpServletRequest request) {
        if (request.getCookies() == null) return null;
        return Arrays.stream(request.getCookies())
                .filter(c -> properties.cookie().name().equals(c.getName()))
                .map(Cookie::getValue)
                .findFirst()
                .orElse(null);
    }

    private String resolveAuthorization(HttpServletRequest request, byte[] rawBody) {
        String header = request.getHeader("Authorization");
        if (header != null && !header.isBlank()) {
            return header;
        }

        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> body = objectMapper.readValue(rawBody, Map.class);
            Object proof = body.get("proof");
            if (proof instanceof String proofValue && !proofValue.isBlank()) {
                return proofValue;
            }
        } catch (Exception ignored) {
            // Raw-body validation happens in NapServer; fallback extraction is best effort.
        }
        return null;
    }
}
