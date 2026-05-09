package xyz.tcheeric.nap.server;

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
import java.util.List;

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
        if (input.authUrl() == null || input.authUrl().isBlank()) {
            return new IssueChallengeResult.Failure(
                    NapErrorCode.NAP_INIT_INTERNAL,
                    NapErrorCode.NAP_INIT_INTERNAL.isRetryable());
        }

        String pubkey = decodeNpub(input.npub());
        if (pubkey == null) {
            return new IssueChallengeResult.Failure(
                    NapErrorCode.NAP_INIT_INVALID_NPUB,
                    NapErrorCode.NAP_INIT_INVALID_NPUB.isRetryable());
        }

        long now = options.clock().instant().getEpochSecond();
        String challengeId = base64Url(randomBytes(12));
        String challenge = base64Url(randomBytes(32));

        ChallengeRecord record = ChallengeRecord.issued(
                challengeId, challenge, input.npub(), pubkey,
                input.authUrl(), input.authMethod() != null ? input.authMethod() : "POST",
                now, now + options.challengeTtlSeconds()
        );

        try {
            options.challengeStore().create(record);
        } catch (Exception e) {
            log.error("Failed to store challenge: {}", e.getMessage(), e);
            return new IssueChallengeResult.Failure(
                    NapErrorCode.NAP_INIT_INTERNAL,
                    NapErrorCode.NAP_INIT_INTERNAL.isRetryable());
        }

        return new IssueChallengeResult.Success(new AuthInitResponse(
                record.challengeId(), record.challenge(),
                record.authUrl(), record.authMethod(),
                record.issuedAt(), record.expiresAt()
        ));
    }

    @Override
    public VerifyCompletionOutcome verifyCompletion(VerifyCompletionInput input) {
        if (input.rawBody() == null) {
            return VerifyCompletionOutcome.malformed();
        }

        AuthCompleteRequest body = parseAuthCompleteRequest(input.rawBody());
        if (body == null) {
            return VerifyCompletionOutcome.malformed();
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

        if (!challenge.challenge().equals(verified.challenge())) {
            return VerifyCompletionOutcome.failure(NapErrorCode.NAP_COMPLETE_CHALLENGE_MISMATCH);
        }

        if (!challenge.pubkey().equals(verified.event().pubkey())) {
            return VerifyCompletionOutcome.failure(NapErrorCode.NAP_COMPLETE_PRINCIPAL_MISMATCH);
        }

        if (!Nip98Validator.validateChallengeBoundCreatedAt(
                verified.event().createdAt(),
                challenge.issuedAt(), challenge.expiresAt(),
                options.lowerBoundGraceSeconds(), options.upperBoundGraceSeconds())) {
            return VerifyCompletionOutcome.failure(NapErrorCode.NAP_COMPLETE_CREATED_AT_OUT_OF_RANGE);
        }

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
        SessionRecord session = options.sessionStore().createForChallenge(SessionRecord.create(
                base64Url(randomBytes(24)),
                challenge.challengeId(),
                base64Url(randomBytes(32)),
                challenge.npub(), challenge.pubkey(),
                aclDecision.roles(), aclDecision.permissions(),
                now, now, idleExpiresAt, absoluteExpiryAt
        ));

        RedeemResult redeemResult = options.challengeStore().redeem(challenge.challengeId(), new RedeemParams(
                verified.event().id(), session.sessionId(),
                now, now + options.resultCacheTtlSeconds()
        ));

        if (redeemResult == RedeemResult.REDEEMED) {
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
                return VerifyCompletionOutcome.success(existingSession.get());
            }
            return VerifyCompletionOutcome.failure(NapErrorCode.NAP_COMPLETE_INTERNAL);
        }

        return VerifyCompletionOutcome.failure(NapErrorCode.NAP_COMPLETE_REDEEMED_CHALLENGE);
    }

    @Override
    public AuthSuccessResponse toPublicAuthSuccess(SessionRecord session) {
        return new AuthSuccessResponse(
                "ok",
                session.accessToken(), "Bearer", session.expiresAt(), session.absoluteExpiryAt(),
                new AuthSuccessResponse.Principal(session.principalNpub(), session.principalPubkey()),
                session.roles(), session.permissions()
        );
    }

    @Override
    public PublicFailureResponse toPublicAuthFailure() {
        return new PublicFailureResponse(401, AuthFailureResponse.authenticationFailed());
    }

    private AuthCompleteRequest parseAuthCompleteRequest(byte[] rawBody) {
        try {
            var node = OBJECT_MAPPER.readTree(new String(rawBody, StandardCharsets.UTF_8));
            String challengeId = node.path("challenge_id").asText(null);
            if (challengeId == null || challengeId.isEmpty()) {
                return null;
            }
            return new AuthCompleteRequest(challengeId);
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
