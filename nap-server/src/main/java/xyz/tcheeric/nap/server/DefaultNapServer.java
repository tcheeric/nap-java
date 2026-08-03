package xyz.tcheeric.nap.server;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import xyz.tcheeric.nap.core.*;
import xyz.tcheeric.nap.core.ChallengeStore;
import xyz.tcheeric.nap.core.RedeemParams;
import xyz.tcheeric.nap.core.RedeemResult;
import xyz.tcheeric.nap.core.SessionStore;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.OptionalInt;

/**
 * Default NAP server implementation matching the TypeScript reference.
 */
final class DefaultNapServer implements NapServer {

    private static final Logger log = LoggerFactory.getLogger(DefaultNapServer.class);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private final NapServerOptions options;

    DefaultNapServer(NapServerOptions options) {
        this.options = options;
    }

    @Override
    public IssueChallengeResult issueChallenge(IssueChallengeInput input) {
        // Padded in a finally so a store outage answers on the same schedule as a refusal:
        // an unpadded 500 next to padded 401s is itself a distinguishable response.
        long startedAtNanos = System.nanoTime();
        IssueChallengeResult result = null;
        try {
            // Counted before anything can reject the request: a total that only sees
            // well-formed calls cannot be the denominator for the failure rate.
            count(NapCounter.AUTH_INIT_TOTAL);
            result = issueChallengeUnpadded(input);
            countOutcome(result instanceof IssueChallengeResult.Failure f ? f.code() : null);
            return result;
        } finally {
            if (!isRateLimited(result, NapErrorCode.NAP_INIT_RATE_LIMITED)) {
                padAuthResponse(startedAtNanos);
            }
        }
    }

    private IssueChallengeResult issueChallengeUnpadded(IssueChallengeInput input) {
        if (input.authUrl() == null || input.authUrl().isBlank()) {
            return IssueChallengeResult.failure(NapErrorCode.NAP_INIT_INTERNAL);
        }

        RateLimitDecision rateLimit = checkRateLimit(
                RateLimitKey.init(boundedNpub(input.npub()), input.clientIp()));
        if (!rateLimit.allowed()) {
            log.warn("nap_init_rate_limited npub={}", input.npub());
            return IssueChallengeResult.rateLimited(
                    NapErrorCode.NAP_INIT_RATE_LIMITED, rateLimit.retryAfterSeconds());
        }

        String pubkey = decodeNpub(input.npub());
        if (pubkey == null) {
            return IssueChallengeResult.failure(NapErrorCode.NAP_INIT_INVALID_NPUB);
        }

        long now = options.clock().instant().getEpochSecond();

        String exceeded = findExceededOutstandingCap(input.npub(), input.clientIp(), now);
        if (exceeded != null) {
            // Reported as rate limiting rather than a distinct code: the cap exists to bound
            // storage, and telling the caller which dimension they hit tells them how to
            // spread the load to evade it.
            log.warn("nap_init_rate_limited npub={} cap={}", input.npub(), exceeded);
            // The oldest outstanding challenge expires within one TTL at the latest, which is
            // when a slot frees up — so that is the honest Retry-After.
            return IssueChallengeResult.rateLimited(
                    NapErrorCode.NAP_INIT_RATE_LIMITED, options.challengeTtlSeconds());
        }

        String challengeId = base64Url(randomBytes(12));
        String challenge = base64Url(randomBytes(32));

        ChallengeRecord record = ChallengeRecord.issued(
                challengeId, challenge, input.npub(), pubkey,
                input.authUrl(), input.authMethod() != null ? input.authMethod() : "POST",
                now, now + options.challengeTtlSeconds(), input.clientIp()
        );

        try {
            options.challengeStore().create(record);
        } catch (Exception e) {
            log.error("Failed to store challenge: {}", e.getMessage(), e);
            return IssueChallengeResult.failure(NapErrorCode.NAP_INIT_INTERNAL);
        }

        return new IssueChallengeResult.Success(new AuthInitResponse(
                record.challengeId(), record.challenge(),
                record.authUrl(), record.authMethod(),
                record.issuedAt(), record.expiresAt()
        ));
    }

    @Override
    public VerifyCompletionOutcome verifyCompletion(VerifyCompletionInput input) {
        long startedAtNanos = System.nanoTime();
        VerifyCompletionOutcome outcome = null;
        try {
            count(NapCounter.AUTH_COMPLETE_TOTAL);
            outcome = verifyCompletionUnpadded(input);
            // A malformed request never reached a decision, so it is counted in the total and
            // nowhere else — folding it into the failure counter would make a broken client
            // read as an authentication problem.
            if (!(outcome instanceof VerifyCompletionOutcome.MalformedRequest)) {
                countOutcome(outcome instanceof VerifyCompletionOutcome.Failure f ? f.code() : null);
            }
            return outcome;
        } finally {
            if (!isRateLimited(outcome, NapErrorCode.NAP_COMPLETE_RATE_LIMITED)) {
                padAuthResponse(startedAtNanos);
            }
        }
    }

    private VerifyCompletionOutcome verifyCompletionUnpadded(VerifyCompletionInput input) {
        if (input.rawBody() == null) {
            return VerifyCompletionOutcome.malformed();
        }

        // RFC §13.4(1): reject malformed requests before touching challenge state.
        AuthCompleteRequest body = parseAuthCompleteRequest(input.rawBody());
        if (body == null) {
            return VerifyCompletionOutcome.malformed();
        }

        RateLimitDecision rateLimit = checkRateLimit(
                RateLimitKey.complete(null, input.clientIp()));
        if (!rateLimit.allowed()) {
            log.warn("nap_complete_rate_limited challenge_id={}", body.challengeId());
            return VerifyCompletionOutcome.rateLimited(
                    NapErrorCode.NAP_COMPLETE_RATE_LIMITED, rateLimit.retryAfterSeconds());
        }

        long now = options.clock().instant().getEpochSecond();

        var proof = Nip98Validator.verifyNip98Completion(new VerifyNip98CompletionInput(
                input.authorization(), input.method(), input.url(),
                body, input.rawBody(), now, options.maxClockSkewSeconds()
        ));

        if (proof instanceof Nip98Validator.Nip98ValidationResult.Failure f) {
            return VerifyCompletionOutcome.failure(f.code());
        }

        var verified = ((Nip98Validator.Nip98ValidationResult.Success) proof).value();

        // Second check, now that the request has proved who it is. The pre-proof check above
        // has only clientIp, and an adapter behind an untrusted proxy is told to report none —
        // which left the one endpoint that runs a Schnorr verify per call with no bound at
        // all. Counting the proved pubkey costs an attacker one signature per counted request.
        //
        // No clientIp on this key: the pre-proof check already spent the address's budget for
        // this request, and counting it twice would halve the configured per-address rate —
        // unevenly, since a request rejected before the proof only spends it once.
        RateLimitDecision provenRateLimit = checkRateLimit(
                RateLimitKey.complete(verified.event().pubkey(), null));
        if (!provenRateLimit.allowed()) {
            log.warn("nap_complete_rate_limited pubkey={} challenge_id={}",
                    verified.event().pubkey(), body.challengeId());
            return VerifyCompletionOutcome.rateLimited(
                    NapErrorCode.NAP_COMPLETE_RATE_LIMITED, provenRateLimit.retryAfterSeconds());
        }

        var challenge = options.challengeStore().get(verified.challengeId()).orElse(null);
        if (challenge == null) {
            return VerifyCompletionOutcome.failure(NapErrorCode.NAP_COMPLETE_UNKNOWN_CHALLENGE);
        }

        VerifyCompletionOutcome replayOutcome = resolveReplayOutcome(challenge, verified.event().id(), now);
        if (replayOutcome != null) {
            return replayOutcome;
        }

        if (challenge.expiresAt() < now || challenge.state() == ChallengeState.EXPIRED) {
            return VerifyCompletionOutcome.failure(NapErrorCode.NAP_COMPLETE_EXPIRED_CHALLENGE);
        }

        // RFC §13.4(3): a challenge that burned through its failure budget is dead even
        // though it has not expired yet.
        if (challenge.state() == ChallengeState.FAILED_TERMINAL) {
            return VerifyCompletionOutcome.failure(NapErrorCode.NAP_COMPLETE_FAILED_TERMINAL);
        }

        // Principal first, and deliberately without spending budget. Whoever signed this proof
        // is not the principal the challenge was issued to, so letting them count failures
        // would let anyone holding a victim's challenge_id burn it to failed_terminal with
        // proofs from their own key. Only the principal can spend their own budget.
        if (!challenge.pubkey().equals(verified.event().pubkey())) {
            return VerifyCompletionOutcome.failure(NapErrorCode.NAP_COMPLETE_PRINCIPAL_MISMATCH);
        }

        // Past this point the request is addressing a live challenge we loaded, matched, and
        // proved ownership of, so failures count against that challenge's budget
        // (RFC §13.4(2)). A wrong challenge_id cannot burn down another principal's live
        // challenge, and neither can a right one signed by the wrong key.
        if (!challenge.challenge().equals(verified.challenge())) {
            recordChallengeFailure(challenge.challengeId(), now);
            return VerifyCompletionOutcome.failure(NapErrorCode.NAP_COMPLETE_CHALLENGE_MISMATCH);
        }

        if (!Nip98Validator.validateChallengeBoundCreatedAt(
                verified.event().createdAt(),
                challenge.issuedAt(), challenge.expiresAt(),
                options.lowerBoundGraceSeconds(), options.upperBoundGraceSeconds())) {
            recordChallengeFailure(challenge.challengeId(), now);
            return VerifyCompletionOutcome.failure(NapErrorCode.NAP_COMPLETE_CREATED_AT_OUT_OF_RANGE);
        }

        // An ACL denial is deterministic, not a guessing attack, so it does not spend budget.
        AclDecision aclDecision = options.aclResolver().resolve(challenge.npub(), challenge.pubkey());
        if (!aclDecision.allowed()) {
            return VerifyCompletionOutcome.failure(NapErrorCode.NAP_COMPLETE_ACL_DENIED);
        }

        if (!options.eventReplayGuard().tryAcquire(verified.event().id())) {
            log.warn("nap_complete_replay_detected event_id={} challenge_id={}",
                    verified.event().id(), challenge.challengeId());
            return VerifyCompletionOutcome.failure(NapErrorCode.NAP_COMPLETE_REDEEMED_CHALLENGE);
        }

        long absoluteExpiryAt = now + options.sessionAbsoluteTtlSeconds();
        long idleExpiresAt = Math.min(now + options.sessionIdleTtlSeconds(), absoluteExpiryAt);
        // A step-up is a full re-authentication: the caller proved key control again, just
        // now, so the resulting session carries a short-lived token. The flag is signed (it
        // lives in the hashed body), so it cannot be added in transit to mint a token the
        // user never asked for.
        String stepUpToken = body.stepUp() ? base64Url(randomBytes(32)) : null;
        Long stepUpExpiresAt = body.stepUp() ? now + options.stepUpTtlSeconds() : null;
        // Refresh is opt-in: no TTL configured means no refresh credential is minted at all,
        // and /auth/refresh has nothing to accept.
        int refreshTtl = options.refreshTtlSeconds();
        String refreshToken = refreshTtl > 0 ? base64Url(randomBytes(32)) : null;
        Long refreshExpiresAt = refreshTtl > 0 ? now + refreshTtl : null;
        SessionRecord session = options.sessionStore().createForChallenge(new SessionRecord(
                base64Url(randomBytes(24)),
                challenge.challengeId(),
                base64Url(randomBytes(32)),
                challenge.npub(), challenge.pubkey(),
                aclDecision.roles(), aclDecision.permissions(),
                now, now, idleExpiresAt, absoluteExpiryAt,
                null, stepUpToken, stepUpExpiresAt,
                refreshToken, refreshExpiresAt, null
        ));

        RedeemResult redeemResult = options.challengeStore().redeem(challenge.challengeId(), new RedeemParams(
                verified.event().id(), session.sessionId(),
                now, now + options.resultCacheTtlSeconds()
        ));

        if (redeemResult == RedeemResult.REDEEMED) {
            count(NapCounter.CHALLENGE_REDEEMED_TOTAL);
            return VerifyCompletionOutcome.success(session);
        }

        if (redeemResult == RedeemResult.EXPIRED) {
            return VerifyCompletionOutcome.failure(NapErrorCode.NAP_COMPLETE_EXPIRED_CHALLENGE);
        }

        if (redeemResult == RedeemResult.NOT_FOUND) {
            return VerifyCompletionOutcome.failure(NapErrorCode.NAP_COMPLETE_UNKNOWN_CHALLENGE);
        }

        // ALREADY_REDEEMED — check retry safety
        var redeemedChallenge = options.challengeStore().get(challenge.challengeId()).orElse(null);
        if (redeemedChallenge != null
                && verified.event().id().equals(redeemedChallenge.redeemedEventId())
                && redeemedChallenge.redeemedSessionId() != null
                && (redeemedChallenge.resultCacheUntil() == null || redeemedChallenge.resultCacheUntil() >= now)) {
            var existingSession = options.sessionStore().getBySessionId(redeemedChallenge.redeemedSessionId());
            if (existingSession.isPresent()) {
                // Not a second redemption: RFC §13.3 makes the cached answer the correct one,
                // so a climbing retry rate is a client bug worth seeing apart from a login rate.
                count(NapCounter.CHALLENGE_RETRY_HIT_TOTAL);
                return VerifyCompletionOutcome.success(existingSession.get());
            }
            return VerifyCompletionOutcome.failure(NapErrorCode.NAP_COMPLETE_INTERNAL);
        }

        return VerifyCompletionOutcome.failure(NapErrorCode.NAP_COMPLETE_REDEEMED_CHALLENGE);
    }

    @Override
    public RefreshSessionOutcome refreshSession(RefreshSessionInput input) {
        long startedAtNanos = System.nanoTime();
        RefreshSessionOutcome outcome = null;
        try {
            outcome = refreshSessionUnpadded(input);
            countOutcome(outcome instanceof RefreshSessionOutcome.Failure f ? f.code() : null);
            return outcome;
        } finally {
            if (!(outcome instanceof RefreshSessionOutcome.Failure f
                    && f.code() == NapErrorCode.NAP_REFRESH_RATE_LIMITED)) {
                padAuthResponse(startedAtNanos);
            }
        }
    }

    private RefreshSessionOutcome refreshSessionUnpadded(RefreshSessionInput input) {
        SessionStore store = options.sessionStore();

        // Answered exactly like an unknown token. Whether a deployment offers refresh at all is
        // not something an anonymous caller needs confirmed, and the options builder already
        // refuses the misconfiguration that would make this the interesting branch.
        if (options.refreshTtlSeconds() <= 0 || !store.supportsRefreshTokens()) {
            return RefreshSessionOutcome.failure(NapErrorCode.NAP_REFRESH_UNKNOWN_TOKEN);
        }

        RateLimitDecision rateLimit = checkRateLimit(RateLimitKey.refresh(input.clientIp()));
        if (!rateLimit.allowed()) {
            log.warn("nap_refresh_rate_limited");
            return RefreshSessionOutcome.rateLimited(
                    NapErrorCode.NAP_REFRESH_RATE_LIMITED, rateLimit.retryAfterSeconds());
        }

        String presented = input.refreshToken();
        if (presented == null || presented.isBlank()) {
            return RefreshSessionOutcome.failure(NapErrorCode.NAP_REFRESH_UNKNOWN_TOKEN);
        }

        SessionRecord session = store.getByRefreshToken(presented).orElse(null);
        if (session == null) {
            return RefreshSessionOutcome.failure(NapErrorCode.NAP_REFRESH_UNKNOWN_TOKEN);
        }

        long now = options.clock().instant().getEpochSecond();

        // Checked before expiry and revocation: a replay is worth acting on whatever else is
        // wrong with the session, and reporting it as merely expired would hide the only
        // signal that a token leaked.
        if (constantTimeEquals(session.previousRefreshToken(), presented)) {
            store.revokeBySessionId(session.sessionId(), now);
            log.warn("nap_refresh_reused session_id={} pubkey={}",
                    session.sessionId(), session.principalPubkey());
            return RefreshSessionOutcome.failure(NapErrorCode.NAP_REFRESH_REUSED);
        }

        // A store that answered with a session holding neither the presented token nor its
        // predecessor has a broken index; treat it as no match rather than rotate a session
        // the caller has not proved anything about.
        if (!constantTimeEquals(session.refreshToken(), presented)) {
            return RefreshSessionOutcome.failure(NapErrorCode.NAP_REFRESH_UNKNOWN_TOKEN);
        }

        if (session.revokedAt() != null) {
            return RefreshSessionOutcome.failure(NapErrorCode.NAP_REFRESH_REVOKED);
        }

        if (session.refreshExpiresAt() == null || session.refreshExpiresAt() < now) {
            return RefreshSessionOutcome.failure(NapErrorCode.NAP_REFRESH_EXPIRED);
        }

        AclDecision aclDecision =
                options.aclResolver().resolve(session.principalNpub(), session.principalPubkey());
        if (!aclDecision.allowed()) {
            // Same rule as a guarded request: only a denial the resolver is certain about ends
            // every session. A resolver that could not *read* the ACL denies this refresh and
            // nothing more — the access token still expires on its own schedule, so nothing is
            // granted by waiting.
            if (aclDecision.revokeSessions()) {
                store.revokeByPrincipal(session.principalPubkey(), now);
            }
            log.warn("nap_refresh_acl_denied session_id={} reason={}",
                    session.sessionId(), aclDecision.reason());
            return RefreshSessionOutcome.failure(NapErrorCode.NAP_REFRESH_ACL_DENIED);
        }

        // The sliding cap still applies: a refresh advances the idle window but cannot push a
        // session past the absolute expiry it was created with.
        long expiresAt = Math.min(now + options.sessionIdleTtlSeconds(), session.absoluteExpiryAt());

        SessionRecord rotated = store.rotateRefreshToken(session.sessionId(), new RotateRefreshTokenParams(
                presented,
                base64Url(randomBytes(32)),
                base64Url(randomBytes(32)),
                now,
                expiresAt,
                now + options.refreshTtlSeconds(),
                aclDecision.roles(),
                aclDecision.permissions()
        )).orElse(null);

        if (rotated == null) {
            log.warn("nap_refresh_rotate_failed session_id={}", session.sessionId());
            return RefreshSessionOutcome.failure(NapErrorCode.NAP_REFRESH_INTERNAL);
        }

        return RefreshSessionOutcome.success(rotated);
    }

    @Override
    public AuthSuccessResponse toPublicAuthSuccess(SessionRecord session) {
        return new AuthSuccessResponse(
                "ok",
                session.accessToken(), "Bearer", session.expiresAt(), session.absoluteExpiryAt(),
                new AuthSuccessResponse.Principal(session.principalNpub(), session.principalPubkey()),
                session.roles(), session.permissions(),
                session.stepUpToken(), session.stepUpExpiresAt(),
                session.refreshToken(), session.refreshExpiresAt()
        );
    }

    /** Null-tolerant and length-independent only past the null check — both sides are tokens. */
    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        return java.security.MessageDigest.isEqual(
                a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }

    private void count(NapCounter counter) {
        try {
            options.metrics().increment(counter);
        } catch (RuntimeException e) {
            // A metrics backend being down is not a reason to stop authenticating.
            log.debug("metrics increment failed: {}", e.getMessage());
        }
    }

    /**
     * The three outcome counters follow the outcome alone; the code-specific ones name a
     * particular failure. {@code NAP_COMPLETE_MISSING_PAYLOAD} is deliberately not counted as a
     * payload mismatch: nothing was compared, so calling it a mismatch would blur a client that
     * omits the tag with one whose body was rewritten in transit — the very thing the counter
     * is watched for.
     */
    private void countOutcome(NapErrorCode code) {
        if (code == null) {
            count(NapCounter.AUTH_SUCCESS_TOTAL);
            return;
        }

        count(code == NapErrorCode.NAP_INIT_RATE_LIMITED
                || code == NapErrorCode.NAP_COMPLETE_RATE_LIMITED
                || code == NapErrorCode.NAP_REFRESH_RATE_LIMITED
                ? NapCounter.AUTH_RATE_LIMITED_TOTAL
                : NapCounter.AUTH_FAILURE_TOTAL);

        switch (code) {
            case NAP_COMPLETE_EXPIRED_CHALLENGE -> count(NapCounter.CHALLENGE_EXPIRED_TOTAL);
            // The NIP-98 `u` tag *is* the audience.
            case NAP_COMPLETE_URL_MISMATCH -> count(NapCounter.AUDIENCE_MISMATCH_TOTAL);
            case NAP_COMPLETE_PAYLOAD_MISMATCH -> count(NapCounter.PAYLOAD_MISMATCH_TOTAL);
            default -> { }
        }
    }

    @Override
    public PublicFailureResponse toPublicAuthFailure() {
        return new PublicFailureResponse(401, AuthFailureResponse.authenticationFailed());
    }

    private RateLimitDecision checkRateLimit(RateLimitKey key) {
        RateLimiter limiter = options.rateLimiter();
        return limiter == null ? RateLimitDecision.allow() : limiter.check(key);
    }

    /** A bech32 npub is 63 characters. */
    private static final int MAX_NPUB_KEY_LENGTH = 128;

    /**
     * The npub is unvalidated at the point the limiter counts it — decoding happens later — so
     * an oversized one would become a map key an attacker chose the size of. Dropping the
     * dimension rather than truncating keeps two distinct npubs from sharing a budget; the
     * request is still counted against the caller's address.
     */
    private static String boundedNpub(String npub) {
        return npub != null && npub.length() <= MAX_NPUB_KEY_LENGTH ? npub : null;
    }

    private static boolean isRateLimited(IssueChallengeResult result, NapErrorCode code) {
        return result instanceof IssueChallengeResult.Failure failure && failure.code() == code;
    }

    private static boolean isRateLimited(VerifyCompletionOutcome outcome, NapErrorCode code) {
        return outcome instanceof VerifyCompletionOutcome.Failure failure && failure.code() == code;
    }

    /**
     * RFC §17.4: bound outstanding challenges per principal and per caller address.
     *
     * <p>Returns the exceeded dimension, or {@code null}. Skipped entirely when the store does
     * not implement {@code countOutstanding} — a store that cannot count cannot cap, and
     * failing closed here would break every existing custom store.
     *
     * <p>The per-npub count is scoped to the caller's address when there is one. {@code /auth/init}
     * is unauthenticated and npubs are public, so a cap counting one npub across all addresses
     * is an account-lockout primitive: fill a stranger's ten slots and they cannot log in until
     * the challenges expire. Scoping by address costs nothing in storage terms — the per-address
     * cap already bounds what any one caller can accumulate.
     */
    private String findExceededOutstandingCap(String npub, String clientIp, long now) {
        int perNpub = options.maxOutstandingChallengesPerNpub();
        if (perNpub > 0) {
            OutstandingChallengeFilter filter = clientIp != null
                    ? OutstandingChallengeFilter.forNpubAtClientIp(npub, clientIp, now)
                    : OutstandingChallengeFilter.forNpub(npub, now);
            OptionalInt count = options.challengeStore().countOutstanding(filter);
            if (count.isPresent() && count.getAsInt() >= perNpub) {
                return "npub";
            }
        }

        int perIp = options.maxOutstandingChallengesPerIp();
        if (perIp > 0 && clientIp != null) {
            OptionalInt count = options.challengeStore()
                    .countOutstanding(OutstandingChallengeFilter.forClientIp(clientIp, now));
            if (count.isPresent() && count.getAsInt() >= perIp) {
                return "ip";
            }
        }

        return null;
    }

    /**
     * RFC §13.4: cap failures per challenge. The public response is the same 401 either way;
     * this only moves the challenge to {@code failed_terminal} and says so in the log.
     */
    private void recordChallengeFailure(String challengeId, long now) {
        int maxFailures = options.maxFailuresPerChallenge();
        if (maxFailures <= 0) {
            return;
        }

        RecordChallengeFailureResult result =
                options.challengeStore().recordFailure(challengeId, now, maxFailures);
        if (result != null && result.state() == ChallengeState.FAILED_TERMINAL) {
            log.warn("nap_complete_failed_terminal challenge_id={} failure_count={}",
                    challengeId, result.failureCount());
        }
    }

    /**
     * RFC §15: hold every auth response to a fixed floor plus jitter.
     *
     * <p>The generic 401 hides <em>which</em> check failed; latency did not — a request
     * rejected before the signature check returns measurably sooner than one that ran a
     * Schnorr verify. Jitter alone would not close it (it hides samples, not the mean), so
     * the floor does the work.
     *
     * <p>Not applied to a rate-limited response. A 429 is already distinguishable by its status
     * code, so padding buys no cover there — it only hands a caller who is <em>already</em> over
     * the limit a free hold on a request thread for the floor's duration, which is the
     * amplification the limiter exists to prevent.
     */
    private void padAuthResponse(long startedAtNanos) {
        int floor = options.minAuthResponseMillis();
        int jitterRange = options.responseJitterMillis();
        if (floor <= 0 && jitterRange <= 0) {
            return;
        }

        int jitter = jitterRange > 0 ? randomBytes(1)[0] & 0xFF : 0;
        if (jitterRange > 0) {
            jitter %= jitterRange + 1;
        }

        long elapsedMillis = (System.nanoTime() - startedAtNanos) / 1_000_000L;
        long remaining = floor + jitter - elapsedMillis;
        if (remaining > 0) {
            try {
                Thread.sleep(remaining);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private AuthCompleteRequest parseAuthCompleteRequest(byte[] rawBody) {
        try {
            var node = OBJECT_MAPPER.readTree(new String(rawBody, StandardCharsets.UTF_8));
            String challengeId = node.path("challenge_id").asText(null);
            if (challengeId == null || challengeId.isEmpty()) {
                return null;
            }
            // Reject a non-boolean step_up rather than coercing it: the flag is inside the
            // hashed body, so anything but true/false is a client bug or a probe.
            JsonNode stepUp = node.path("step_up");
            if (!stepUp.isMissingNode() && !stepUp.isNull() && !stepUp.isBoolean()) {
                return null;
            }
            return new AuthCompleteRequest(challengeId, stepUp.asBoolean(false));
        } catch (Exception e) {
            return null;
        }
    }

    private VerifyCompletionOutcome resolveReplayOutcome(ChallengeRecord challenge, String eventId, long now) {
        if (challenge.state() != ChallengeState.REDEEMED && challenge.redeemedEventId() == null) {
            return null;
        }

        if (eventId.equals(challenge.redeemedEventId())
                && challenge.redeemedSessionId() != null
                && (challenge.resultCacheUntil() == null || challenge.resultCacheUntil() >= now)) {
            var existingSession = options.sessionStore().getBySessionId(challenge.redeemedSessionId());
            if (existingSession.isPresent()) {
                count(NapCounter.CHALLENGE_RETRY_HIT_TOTAL);
                return VerifyCompletionOutcome.success(existingSession.get());
            }
            return VerifyCompletionOutcome.failure(NapErrorCode.NAP_COMPLETE_INTERNAL);
        }

        return VerifyCompletionOutcome.failure(NapErrorCode.NAP_COMPLETE_REDEEMED_CHALLENGE);
    }

    private String decodeNpub(String npub) {
        try {
            if (npub == null || npub.isBlank()) {
                return null;
            }
            // Accept raw hex pubkey (64-char hex string) in addition to bech32 npub
            if (!npub.startsWith("npub1")) {
                if (npub.length() == 64 && npub.matches("[0-9a-fA-F]+")) {
                    return npub.toLowerCase();
                }
                return null;
            }
            String hex = nostr.crypto.bech32.Bech32.fromBech32(npub);
            if (hex == null || hex.length() != 64) {
                return null;
            }
            return hex;
        } catch (Exception e) {
            log.debug("Failed to decode npub: {}", e.getMessage());
            return null;
        }
    }

    private byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        options.random().nextBytes(bytes);
        return bytes;
    }

    private String base64Url(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
