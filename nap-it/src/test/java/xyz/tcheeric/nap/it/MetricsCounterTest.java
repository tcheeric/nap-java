package xyz.tcheeric.nap.it;

import nostr.crypto.bech32.Bech32;
import nostr.crypto.bech32.Bech32Prefix;
import nostr.crypto.schnorr.Schnorr;
import org.junit.jupiter.api.Test;
import xyz.tcheeric.nap.client.NapProofBuilder;
import xyz.tcheeric.nap.server.*;
import xyz.tcheeric.nap.server.store.InMemoryChallengeStore;
import xyz.tcheeric.nap.server.store.InMemorySessionStore;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.EnumMap;
import java.util.HexFormat;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * The RFC §19.3 counters, over a real exchange rather than a stubbed outcome.
 *
 * <p>What is actually being pinned here is what {@code auth_success_total} <em>means</em>. It
 * has to mean the same thing as in the TypeScript implementation, where issuing a challenge
 * emits no success audit event and so never reaches the counter — otherwise one name measures
 * "completions" on one side and "inits + completions" on the other, and the failure rate
 * computed from them is a different number depending on which server answered.
 */
class MetricsCounterTest {

    private static final HexFormat HEX = HexFormat.of();
    private static final String AUTH_URL = "https://example.com/auth/complete";

    private final RecordingMetrics metrics = new RecordingMetrics();

    @Test
    void issuingAChallengeCountsTheInitTotalAndNothingElse() throws Exception {
        long now = Instant.now().getEpochSecond();
        NapServer server = server(now);

        var keys = new Keys();
        server.issueChallenge(new IssueChallengeInput(keys.npub, AUTH_URL));

        assertThat(metrics.count(NapCounter.AUTH_INIT_TOTAL)).isEqualTo(1);
        assertThat(metrics.count(NapCounter.AUTH_SUCCESS_TOTAL)).isZero();
        assertThat(metrics.count(NapCounter.AUTH_FAILURE_TOTAL)).isZero();
    }

    @Test
    void completingCountsTheSuccessAndTheRedemption() throws Exception {
        long now = Instant.now().getEpochSecond();
        NapServer server = server(now);
        var keys = new Keys();

        var challenge = ((IssueChallengeResult.Success)
                server.issueChallenge(new IssueChallengeInput(keys.npub, AUTH_URL))).value();
        var outcome = server.verifyCompletion(completion(challenge, keys, now));

        assertThat(outcome.isSuccess()).isTrue();
        assertThat(metrics.count(NapCounter.AUTH_INIT_TOTAL)).isEqualTo(1);
        assertThat(metrics.count(NapCounter.AUTH_COMPLETE_TOTAL)).isEqualTo(1);
        // One, not two: the init that preceded it is not an authentication.
        assertThat(metrics.count(NapCounter.AUTH_SUCCESS_TOTAL)).isEqualTo(1);
        assertThat(metrics.count(NapCounter.CHALLENGE_REDEEMED_TOTAL)).isEqualTo(1);
        assertThat(metrics.count(NapCounter.CHALLENGE_RETRY_HIT_TOTAL)).isZero();
    }

    /** RFC §13.3: the replay gets the cached session, and it is counted apart from a redemption. */
    @Test
    void aRetriedCompletionCountsAsARetryHitNotASecondRedemption() throws Exception {
        long now = Instant.now().getEpochSecond();
        NapServer server = server(now);
        var keys = new Keys();

        var challenge = ((IssueChallengeResult.Success)
                server.issueChallenge(new IssueChallengeInput(keys.npub, AUTH_URL))).value();
        var input = completion(challenge, keys, now);
        server.verifyCompletion(input);
        server.verifyCompletion(input);

        assertThat(metrics.count(NapCounter.CHALLENGE_REDEEMED_TOTAL)).isEqualTo(1);
        assertThat(metrics.count(NapCounter.CHALLENGE_RETRY_HIT_TOTAL)).isEqualTo(1);
        assertThat(metrics.count(NapCounter.AUTH_SUCCESS_TOTAL)).isEqualTo(2);
    }

    /** A metrics backend being down is not a reason to stop authenticating. */
    @Test
    void aThrowingRecorderDoesNotFailTheRequest() throws Exception {
        long now = Instant.now().getEpochSecond();
        NapServer server = NapServer.create(baseOptions(now)
                .metrics(counter -> { throw new IllegalStateException("collector is down"); })
                .build());
        var keys = new Keys();

        assertThatCode(() -> {
            var challenge = ((IssueChallengeResult.Success)
                    server.issueChallenge(new IssueChallengeInput(keys.npub, AUTH_URL))).value();
            assertThat(server.verifyCompletion(completion(challenge, keys, now)).isSuccess()).isTrue();
        }).doesNotThrowAnyException();
    }

    private NapServer server(long now) {
        return NapServer.create(baseOptions(now).metrics(metrics).build());
    }

    private static NapServerOptions.Builder baseOptions(long now) {
        return NapServerOptions.builder()
                .challengeStore(new InMemoryChallengeStore())
                .sessionStore(new InMemorySessionStore())
                .aclResolver(new AllowAllAclResolver())
                .clock(Clock.fixed(Instant.ofEpochSecond(now), ZoneOffset.UTC))
                .challengeTtlSeconds(60)
                .sessionTtlSeconds(3600)
                .minAuthResponseMillis(0)
                .responseJitterMillis(0);
    }

    private static VerifyCompletionInput completion(
            xyz.tcheeric.nap.core.AuthInitResponse challenge, Keys keys, long now) throws Exception {
        byte[] rawBody = ("{\"challenge_id\":\"" + challenge.challengeId() + "\"}")
                .getBytes(StandardCharsets.UTF_8);
        String authorization = new NapProofBuilder()
                .privateKey(keys.privKeyHex)
                .pubkey(keys.pubKeyHex)
                .url(AUTH_URL)
                .method("POST")
                .challenge(challenge.challenge())
                .challengeId(challenge.challengeId())
                .body(rawBody)
                .createdAt(now)
                .buildAuthorizationHeader();
        return new VerifyCompletionInput(authorization, "POST", AUTH_URL, rawBody);
    }

    private static final class Keys {
        private final String privKeyHex;
        private final String pubKeyHex;
        private final String npub;

        Keys() throws Exception {
            byte[] privKey = new byte[32];
            new SecureRandom().nextBytes(privKey);
            this.privKeyHex = HEX.formatHex(privKey);
            this.pubKeyHex = HEX.formatHex(Schnorr.genPubKey(privKey));
            this.npub = Bech32.toBech32(Bech32Prefix.NPUB, pubKeyHex);
        }
    }

    private static final class RecordingMetrics implements MetricsRecorder {
        private final Map<NapCounter, AtomicInteger> counts = new EnumMap<>(NapCounter.class);

        @Override
        public void increment(NapCounter counter) {
            counts.computeIfAbsent(counter, key -> new AtomicInteger()).incrementAndGet();
        }

        int count(NapCounter counter) {
            var value = counts.get(counter);
            return value == null ? 0 : value.get();
        }
    }
}
