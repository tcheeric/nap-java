package xyz.tcheeric.nap.it;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import nostr.crypto.bech32.Bech32;
import nostr.crypto.bech32.Bech32Prefix;
import nostr.crypto.schnorr.Schnorr;
import org.junit.jupiter.api.Test;
import xyz.tcheeric.nap.client.NapProofBuilder;
import xyz.tcheeric.nap.core.NapErrorCode;
import xyz.tcheeric.nap.server.*;
import xyz.tcheeric.nap.server.store.InMemoryChallengeStore;
import xyz.tcheeric.nap.server.store.InMemorySessionStore;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.HexFormat;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The NIP-98 signature must bind the fields the validator inspects, not merely the event id
 * the caller presents.
 *
 * <p>Without recomputing the id from the canonical serialization, a Schnorr verify over the
 * presented id proves only that the key signed <em>some</em> event — and every other field is
 * read from the same caller-supplied JSON. Any note the victim ever published to a relay could
 * then be re-dressed as a completion for a challenge the attacker opened, since {@code
 * /auth/init} is unauthenticated and will name any npub asked of it.
 *
 * <p>This forged exactly that way and was issued a session before {@code Nip98Validator}
 * recomputed the id.
 */
class SignatureBindingTest {

    private static final HexFormat HEX = HexFormat.of();
    private static final String AUTH_URL = "https://example.com/auth/complete";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void aSignatureOverAnotherEventCannotCompleteAChallenge() throws Exception {
        long now = Instant.now().getEpochSecond();
        NapServer server = NapServer.create(NapServerOptions.builder()
                .challengeStore(new InMemoryChallengeStore())
                .sessionStore(new InMemorySessionStore())
                .aclResolver(new AllowAllAclResolver())
                .clock(Clock.fixed(Instant.ofEpochSecond(now), ZoneOffset.UTC))
                .minAuthResponseMillis(0)
                .responseJitterMillis(0)
                .build());

        // The victim's key. The attacker never sees it.
        byte[] victimPriv = new byte[32];
        new SecureRandom().nextBytes(victimPriv);
        String victimPub = HEX.formatHex(Schnorr.genPubKey(victimPriv));
        String victimNpub = Bech32.toBech32(Bech32Prefix.NPUB, victimPub);

        // The attacker opens a challenge naming the victim — /auth/init is unauthenticated.
        var challenge = ((IssueChallengeResult.Success)
                server.issueChallenge(new IssueChallengeInput(victimNpub, AUTH_URL))).value();

        // The only victim material the attacker holds: one event the victim signed and
        // published, e.g. a kind-1 note off any relay. Simulated here by signing a decoy
        // through the normal builder and keeping ONLY its id/pubkey/sig.
        byte[] decoyBody = "{\"unrelated\":true}".getBytes(StandardCharsets.UTF_8);
        String decoyHeader = new NapProofBuilder()
                .privateKey(HEX.formatHex(victimPriv))
                .pubkey(victimPub)
                .url("https://somewhere.else/whatever")
                .method("GET")
                .challenge("unrelated-challenge")
                .challengeId("unrelated-id")
                .body(decoyBody)
                .createdAt(now - 5)
                .buildAuthorizationHeader();
        ObjectNode decoy = (ObjectNode) MAPPER.readTree(
                Base64.getDecoder().decode(decoyHeader.substring("Nostr ".length())));

        // Forge: keep the victim's id + sig, rewrite every other field into a completion
        // for the challenge the attacker just opened.
        byte[] body = ("{\"challenge_id\":\"" + challenge.challengeId() + "\"}")
                .getBytes(StandardCharsets.UTF_8);
        ObjectNode forged = MAPPER.createObjectNode();
        forged.put("id", decoy.get("id").asText());     // victim's real event id
        forged.put("pubkey", victimPub);
        forged.put("sig", decoy.get("sig").asText());   // victim's real signature over it
        forged.put("created_at", now);
        forged.put("kind", 27235);
        forged.put("content", "");
        var tags = forged.putArray("tags");
        tags.addArray().add("u").add(AUTH_URL);
        tags.addArray().add("method").add("POST");
        tags.addArray().add("payload").add(sha256Hex(body));
        tags.addArray().add("challenge").add(challenge.challenge());
        tags.addArray().add("challenge_id").add(challenge.challengeId());

        String authorization = "Nostr " + Base64.getEncoder().encodeToString(
                MAPPER.writeValueAsBytes(forged));

        var outcome = server.verifyCompletion(
                new VerifyCompletionInput(authorization, "POST", AUTH_URL, body));

        assertThat(outcome).isInstanceOf(VerifyCompletionOutcome.Failure.class);
        assertThat(((VerifyCompletionOutcome.Failure) outcome).code())
                .isEqualTo(NapErrorCode.NAP_COMPLETE_INVALID_SIGNATURE);
    }

    private static String sha256Hex(byte[] bytes) throws Exception {
        return HEX.formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }
}
