package xyz.tcheeric.nap.it;

import nostr.crypto.bech32.Bech32;
import nostr.crypto.bech32.Bech32Prefix;
import nostr.crypto.schnorr.Schnorr;
import org.junit.jupiter.api.Test;
import xyz.tcheeric.nap.client.NapProofBuilder;
import xyz.tcheeric.nap.core.AuthInitResponse;
import xyz.tcheeric.nap.core.NapErrorCode;
import xyz.tcheeric.nap.core.SessionRecord;
import xyz.tcheeric.nap.server.*;
import xyz.tcheeric.nap.server.store.InMemoryChallengeStore;
import xyz.tcheeric.nap.server.store.InMemorySessionStore;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HexFormat;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Covers the RFC §§13.4/15/17 hardening added for parity with the TypeScript server:
 * body-carried {@code step_up}, the per-challenge failure budget, 429 with {@code Retry-After},
 * the outstanding-challenge caps, and the challenge-TTL ceiling.
 */
class NapServerHardeningTest {

    private static final HexFormat HEX = HexFormat.of();
    private static final String AUTH_URL = "https://example.com/auth/complete";

    private final long now = Instant.now().getEpochSecond();
    private final Clock clock = Clock.fixed(Instant.ofEpochSecond(now), ZoneOffset.UTC);

    private final byte[] privKey = newPrivateKey();
    private final String privKeyHex = HEX.formatHex(privKey);
    private final String pubKeyHex = HEX.formatHex(schnorrPubKey(privKey));
    private final String npub = Bech32.toBech32(Bech32Prefix.NPUB, pubKeyHex);

    private NapServerOptions.Builder options() {
        return NapServerOptions.builder()
                .challengeStore(new InMemoryChallengeStore())
                .sessionStore(new InMemorySessionStore())
                .aclResolver(new AllowAllAclResolver())
                .clock(clock)
                .challengeTtlSeconds(60)
                .sessionTtlSeconds(3600)
                // The floor is a production defence, not a test one — it would add ~100 ms per
                // call here and every assertion below is about the outcome, not the timing.
                .minAuthResponseMillis(0)
                .responseJitterMillis(0);
    }

    // ---------------------------------------------------------------- step_up

    @Test
    void stepUpInTheSignedBody_mintsAShortLivedToken() {
        NapServer server = NapServer.create(options().stepUpTtlSeconds(600).build());
        AuthInitResponse issued = issue(server);

        var outcome = complete(server, issued.challengeId(), issued.challenge(), true);

        assertThat(outcome).isInstanceOf(VerifyCompletionOutcome.Success.class);
        SessionRecord session = ((VerifyCompletionOutcome.Success) outcome).session();
        assertThat(session.stepUpToken()).isNotBlank();
        assertThat(session.stepUpExpiresAt()).isEqualTo(now + 600);
        assertThat(server.toPublicAuthSuccess(session).stepUpToken()).isEqualTo(session.stepUpToken());
    }

    @Test
    void withoutStepUp_noTokenIsMinted() {
        NapServer server = NapServer.create(options().build());
        AuthInitResponse issued = issue(server);

        var outcome = complete(server, issued.challengeId(), issued.challenge(), false);

        SessionRecord session = ((VerifyCompletionOutcome.Success) outcome).session();
        assertThat(session.stepUpToken()).isNull();
        assertThat(session.stepUpExpiresAt()).isNull();
        assertThat(server.toPublicAuthSuccess(session).stepUpToken()).isNull();
    }

    @Test
    void nonBooleanStepUp_isRejectedRatherThanCoerced() {
        NapServer server = NapServer.create(options().build());
        AuthInitResponse issued = issue(server);
        byte[] rawBody = ("{\"challenge_id\":\"" + issued.challengeId() + "\",\"step_up\":\"yes\"}")
                .getBytes(StandardCharsets.UTF_8);

        var outcome = server.verifyCompletion(new VerifyCompletionInput(
                proof(issued.challengeId(), issued.challenge(), rawBody),
                "POST", AUTH_URL, rawBody, null));

        assertThat(outcome).isInstanceOf(VerifyCompletionOutcome.MalformedRequest.class);
    }

    // -------------------------------------------------------- failure budget

    @Test
    void challengeDiesAfterItsFailureBudgetIsSpent() {
        NapServer server = NapServer.create(options().maxFailuresPerChallenge(3).build());
        AuthInitResponse issued = issue(server);

        for (int attempt = 1; attempt <= 3; attempt++) {
            var outcome = complete(server, issued.challengeId(), "wrong-challenge-" + attempt, false);
            assertThat(failureCode(outcome))
                    .as("attempt %d spends budget rather than terminating early", attempt)
                    .isEqualTo(NapErrorCode.NAP_COMPLETE_CHALLENGE_MISMATCH);
        }

        // Budget spent: even the correct proof is refused now, and with a distinct code so the
        // audit log says why. The public 401 is unchanged either way.
        var afterBudget = complete(server, issued.challengeId(), issued.challenge(), false);
        assertThat(failureCode(afterBudget)).isEqualTo(NapErrorCode.NAP_COMPLETE_FAILED_TERMINAL);
    }

    // ------------------------------------------------------------ 429 / caps

    @Test
    void rateLimiterDenial_surfacesRetryAfterOnBothEndpoints() {
        RateLimiter alwaysDenied = key -> RateLimitDecision.denied(7);
        NapServer server = NapServer.create(options().rateLimiter(alwaysDenied).build());

        var init = server.issueChallenge(new IssueChallengeInput(npub, AUTH_URL, "POST", "203.0.113.7"));
        assertThat(init).isInstanceOf(IssueChallengeResult.Failure.class);
        var initFailure = (IssueChallengeResult.Failure) init;
        assertThat(initFailure.code()).isEqualTo(NapErrorCode.NAP_INIT_RATE_LIMITED);
        assertThat(initFailure.retryAfterSeconds()).isEqualTo(7);

        byte[] rawBody = "{\"challenge_id\":\"whatever\"}".getBytes(StandardCharsets.UTF_8);
        var completeOutcome = server.verifyCompletion(new VerifyCompletionInput(
                "Nostr aGk=", "POST", AUTH_URL, rawBody, "203.0.113.7"));
        var completeFailure = (VerifyCompletionOutcome.Failure) completeOutcome;
        assertThat(completeFailure.code()).isEqualTo(NapErrorCode.NAP_COMPLETE_RATE_LIMITED);
        assertThat(completeFailure.retryAfterSeconds()).isEqualTo(7);
    }

    @Test
    void inMemoryRateLimiterDeniesOncePerWindowBudgetIsSpent() {
        NapServer server = NapServer.create(options()
                .rateLimiter(InMemoryRateLimiter.create(60, 2, clock))
                .build());

        assertThat(server.issueChallenge(initInput()).isSuccess()).isTrue();
        assertThat(server.issueChallenge(initInput()).isSuccess()).isTrue();

        var third = (IssueChallengeResult.Failure) server.issueChallenge(initInput());
        assertThat(third.code()).isEqualTo(NapErrorCode.NAP_INIT_RATE_LIMITED);
        assertThat(third.retryAfterSeconds()).isPositive();
    }

    @Test
    void outstandingChallengesPerNpubAreCapped() {
        NapServer server = NapServer.create(options()
                .maxOutstandingChallengesPerNpub(2)
                .rateLimiter(null)   // deliberate: this test is about the cap, not the window
                .build());

        assertThat(server.issueChallenge(initInput()).isSuccess()).isTrue();
        assertThat(server.issueChallenge(initInput()).isSuccess()).isTrue();

        var third = (IssueChallengeResult.Failure) server.issueChallenge(initInput());
        assertThat(third.code()).isEqualTo(NapErrorCode.NAP_INIT_RATE_LIMITED);
    }

    @Test
    void challengeTtlAboveTheRfcCeilingIsRejectedAtConstruction() {
        assertThatThrownBy(() -> options().challengeTtlSeconds(3600).build())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("challengeTtlSeconds");
    }

    // ------------------------------------------------------------- fixtures

    private IssueChallengeInput initInput() {
        return new IssueChallengeInput(npub, AUTH_URL, "POST", "203.0.113.7");
    }

    private AuthInitResponse issue(NapServer server) {
        return ((IssueChallengeResult.Success) server.issueChallenge(initInput())).value();
    }

    private VerifyCompletionOutcome complete(NapServer server, String challengeId,
                                             String challengeSecret, boolean stepUp) {
        String json = stepUp
                ? "{\"challenge_id\":\"" + challengeId + "\",\"step_up\":true}"
                : "{\"challenge_id\":\"" + challengeId + "\"}";
        byte[] rawBody = json.getBytes(StandardCharsets.UTF_8);
        return server.verifyCompletion(new VerifyCompletionInput(
                proof(challengeId, challengeSecret, rawBody), "POST", AUTH_URL, rawBody, null));
    }

    private String proof(String challengeId, String challengeSecret, byte[] rawBody) {
        return new NapProofBuilder()
                .privateKey(privKeyHex)
                .pubkey(pubKeyHex)
                .url(AUTH_URL)
                .method("POST")
                .challenge(challengeSecret)
                .challengeId(challengeId)
                .body(rawBody)
                .createdAt(now)
                .buildAuthorizationHeader();
    }

    private static byte[] newPrivateKey() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        return key;
    }

    private static byte[] schnorrPubKey(byte[] privKey) {
        try {
            return Schnorr.genPubKey(privKey);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static NapErrorCode failureCode(VerifyCompletionOutcome outcome) {
        return ((VerifyCompletionOutcome.Failure) outcome).code();
    }
}
