package xyz.tcheeric.nap.it;

import nostr.crypto.bech32.Bech32;
import nostr.crypto.bech32.Bech32Prefix;
import nostr.crypto.schnorr.Schnorr;
import org.junit.jupiter.api.Test;
import xyz.tcheeric.nap.client.NapProofBuilder;
import xyz.tcheeric.nap.core.AuthSuccessResponse;
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

/**
 * Login mints a refresh token and that token rotates — the whole RFC §14.1 path over a real
 * NIP-98 exchange, so the two halves are known to fit together and not merely to work apart.
 */
class RefreshRoundTripTest {

    private static final HexFormat HEX = HexFormat.of();
    private static final String AUTH_URL = "https://example.com/auth/complete";

    @Test
    void loginMintsARefreshTokenThatRotates() throws Exception {
        long now = Instant.now().getEpochSecond();
        NapServer server = NapServer.create(NapServerOptions.builder()
                .challengeStore(new InMemoryChallengeStore())
                .sessionStore(new InMemorySessionStore())
                .aclResolver(new AllowAllAclResolver())
                .clock(Clock.fixed(Instant.ofEpochSecond(now), ZoneOffset.UTC))
                .challengeTtlSeconds(60)
                .sessionTtlSeconds(3600)
                .refreshTtlSeconds(86400)
                .minAuthResponseMillis(0)
                .responseJitterMillis(0)
                .build());

        byte[] privKey = new byte[32];
        new SecureRandom().nextBytes(privKey);
        String privKeyHex = HEX.formatHex(privKey);
        String pubKeyHex = HEX.formatHex(Schnorr.genPubKey(privKey));
        String npub = Bech32.toBech32(Bech32Prefix.NPUB, pubKeyHex);

        var challenge = ((IssueChallengeResult.Success)
                server.issueChallenge(new IssueChallengeInput(npub, AUTH_URL))).value();

        byte[] rawBody = ("{\"challenge_id\":\"" + challenge.challengeId() + "\"}")
                .getBytes(StandardCharsets.UTF_8);
        String authorization = new NapProofBuilder()
                .privateKey(privKeyHex)
                .pubkey(pubKeyHex)
                .url(AUTH_URL)
                .method("POST")
                .challenge(challenge.challenge())
                .challengeId(challenge.challengeId())
                .body(rawBody)
                .createdAt(now)
                .buildAuthorizationHeader();

        SessionRecord session = ((VerifyCompletionOutcome.Success) server.verifyCompletion(
                new VerifyCompletionInput(authorization, "POST", AUTH_URL, rawBody))).session();

        assertThat(session.refreshToken()).isNotBlank();
        assertThat(session.refreshExpiresAt()).isEqualTo(now + 86400);
        assertThat(session.previousRefreshToken()).isNull();

        AuthSuccessResponse body = server.toPublicAuthSuccess(session);
        assertThat(body.refreshToken()).isEqualTo(session.refreshToken());
        assertThat(body.refreshExpiresAt()).isEqualTo(session.refreshExpiresAt());

        var refreshed = server.refreshSession(
                new RefreshSessionInput(session.refreshToken(), "1.2.3.4"));

        assertThat(refreshed.isSuccess()).isTrue();
        SessionRecord rotated = ((RefreshSessionOutcome.Success) refreshed).session();
        assertThat(rotated.sessionId()).isEqualTo(session.sessionId());
        assertThat(rotated.accessToken()).isNotEqualTo(session.accessToken());
        assertThat(rotated.refreshToken()).isNotEqualTo(session.refreshToken());
        assertThat(rotated.previousRefreshToken()).isEqualTo(session.refreshToken());
    }
}
