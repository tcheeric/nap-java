package xyz.tcheeric.nap.it;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import xyz.tcheeric.nap.core.AuthCompleteRequest;
import xyz.tcheeric.nap.core.ChallengeRecord;
import xyz.tcheeric.nap.core.ChallengeState;
import xyz.tcheeric.nap.core.Nip98Validator;
import xyz.tcheeric.nap.core.VerifyNip98CompletionInput;
import xyz.tcheeric.nap.server.AllowAllAclResolver;
import xyz.tcheeric.nap.server.NapServer;
import xyz.tcheeric.nap.server.NapServerOptions;
import xyz.tcheeric.nap.server.VerifyCompletionInput;
import xyz.tcheeric.nap.server.VerifyCompletionOutcome;
import xyz.tcheeric.nap.server.store.InMemoryChallengeStore;
import xyz.tcheeric.nap.server.store.InMemorySessionStore;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * The official NAP v2 test vectors (RFC §20.3), run against the JVM implementation.
 *
 * <p>The fixtures are generated in the TypeScript repository and consumed by both
 * implementations — that is what makes "wire-compatible" checkable rather than asserted. A
 * failure here is a real divergence: the two implementations disagree about the same bytes.
 *
 * <p>Error codes are part of each vector. If this implementation returns a different code for
 * the same input, that is a divergence to fix or to specify — not something to map away here.
 *
 * <p>Skipped when the sibling checkout is absent, following the same rule as
 * {@link TypeScriptClientInteropTest}: a missing sibling repo is a workstation without the
 * fixtures, not a broken build. Point {@code -Dnap.test-vectors.dir} elsewhere to override.
 */
class OfficialTestVectorsTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final HexFormat HEX = HexFormat.of();

    private static Path vectorDir() {
        String override = System.getProperty("nap.test-vectors.dir");
        return override != null
                ? Path.of(override)
                : Path.of(System.getProperty("user.home"), "IdeaProjects", "nap",
                        "packages", "nap-core", "test-vectors");
    }

    private static JsonNode load(String file) throws Exception {
        Path path = vectorDir().resolve(file);
        assumeTrue(Files.exists(path), "test vectors not available at " + path);
        return MAPPER.readTree(Files.readString(path));
    }

    @Test
    void payloadHashVectors() throws Exception {
        JsonNode vectors = load("payload-hash.json");

        for (JsonNode testCase : vectors.get("cases")) {
            String name = testCase.get("name").asText();
            byte[] body = testCase.get("body").asText().getBytes(StandardCharsets.UTF_8);
            assertThat(sha256Hex(body))
                    .as("payload hash: %s", name)
                    .isEqualTo(testCase.get("sha256").asText());
        }
    }

    /** Decidable by the NIP-98 header validator alone — no challenge store involved. */
    @Test
    void nip98Vectors() throws Exception {
        JsonNode vectors = load("nip98.json");

        for (JsonNode testCase : vectors.get("cases")) {
            String name = testCase.get("name").asText();
            JsonNode request = testCase.get("request");
            byte[] rawBody = request.get("body").asText().getBytes(StandardCharsets.UTF_8);

            var result = Nip98Validator.verifyNip98Completion(new VerifyNip98CompletionInput(
                    testCase.get("authorization").asText(),
                    request.get("method").asText(),
                    request.get("url").asText(),
                    completeRequest(rawBody),
                    rawBody,
                    testCase.get("now").asLong(),
                    NapServerOptions.DEFAULT_MAX_CLOCK_SKEW_SECONDS
            ));

            JsonNode expected = testCase.get("expect");
            if (expected.get("ok").asBoolean()) {
                assertThat(result)
                        .as("nip98: %s", name)
                        .isInstanceOf(Nip98Validator.Nip98ValidationResult.Success.class);
            } else {
                assertThat(result)
                        .as("nip98: %s", name)
                        .isInstanceOf(Nip98Validator.Nip98ValidationResult.Failure.class);
                var failure = (Nip98Validator.Nip98ValidationResult.Failure) result;
                assertThat(failure.code().name())
                        .as("nip98: %s", name)
                        .isEqualTo(expected.get("code").asText());
            }
        }
    }

    /**
     * Cases that need challenge state. Each runs its steps in order against <em>one</em> server
     * instance with the clock pinned to the step's {@code now}; {@code same_session_as_step}
     * names an earlier step whose session this one must equal — returning a second distinct
     * session fails the vector just as an error would (RFC §13.3).
     */
    @Test
    void flowVectors() throws Exception {
        JsonNode vectors = load("flow.json");

        for (JsonNode testCase : vectors.get("cases")) {
            String name = testCase.get("name").asText();
            JsonNode steps = testCase.get("steps");

            var challengeStore = new InMemoryChallengeStore();
            challengeStore.create(challengeRecord(testCase.get("challenge")));

            var clock = new MutableClock(steps.get(0).get("now").asLong());
            NapServer server = NapServer.create(NapServerOptions.builder()
                    .challengeStore(challengeStore)
                    .sessionStore(new InMemorySessionStore())
                    .aclResolver(new AllowAllAclResolver())
                    .clock(clock)
                    .minAuthResponseMillis(0)
                    .responseJitterMillis(0)
                    .build());

            List<String> sessionIds = new ArrayList<>();

            for (JsonNode step : steps) {
                clock.set(step.get("now").asLong());
                JsonNode request = step.get("request");

                VerifyCompletionOutcome outcome = server.verifyCompletion(new VerifyCompletionInput(
                        step.get("authorization").asText(),
                        request.get("method").asText(),
                        request.get("url").asText(),
                        request.get("body").asText().getBytes(StandardCharsets.UTF_8),
                        null
                ));

                JsonNode expected = step.get("expect");
                if (!expected.get("ok").asBoolean()) {
                    assertThat(outcome)
                            .as("flow: %s", name)
                            .isInstanceOf(VerifyCompletionOutcome.Failure.class);
                    assertThat(((VerifyCompletionOutcome.Failure) outcome).code().name())
                            .as("flow: %s", name)
                            .isEqualTo(expected.get("code").asText());
                    sessionIds.add(null);
                    continue;
                }

                assertThat(outcome)
                        .as("flow: %s", name)
                        .isInstanceOf(VerifyCompletionOutcome.Success.class);
                var session = ((VerifyCompletionOutcome.Success) outcome).session();
                sessionIds.add(session.sessionId());

                JsonNode sameAs = expected.get("same_session_as_step");
                if (sameAs != null && !sameAs.isNull()) {
                    assertThat(session.sessionId())
                            .as("flow: %s — must reuse the session from step %d", name, sameAs.asInt())
                            .isEqualTo(sessionIds.get(sameAs.asInt()));
                }
            }
        }
    }

    /**
     * Built field by field rather than through Jackson: {@code state} is lower-case on the wire
     * and upper-case in {@link ChallengeState}, and spelling that out here keeps the mapping
     * visible instead of resting on a naming strategy.
     */
    private static ChallengeRecord challengeRecord(JsonNode node) {
        return new ChallengeRecord(
                node.get("challenge_id").asText(),
                node.get("challenge").asText(),
                node.get("npub").asText(),
                node.get("pubkey").asText(),
                node.get("auth_url").asText(),
                node.get("auth_method").asText(),
                node.get("issued_at").asLong(),
                node.get("expires_at").asLong(),
                ChallengeState.fromWireValue(node.get("state").asText()),
                null, null, null
        );
    }

    private static AuthCompleteRequest completeRequest(byte[] rawBody) throws Exception {
        JsonNode node = MAPPER.readTree(rawBody);
        return new AuthCompleteRequest(
                node.path("challenge_id").asText(null),
                node.path("step_up").asBoolean(false));
    }

    private static String sha256Hex(byte[] bytes) throws Exception {
        return HEX.formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    /** A clock the vectors can pin per step. */
    private static final class MutableClock extends Clock {
        private volatile long epochSecond;

        MutableClock(long epochSecond) {
            this.epochSecond = epochSecond;
        }

        void set(long value) {
            this.epochSecond = value;
        }

        @Override
        public ZoneId getZone() {
            return ZoneId.of("UTC");
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return Instant.ofEpochSecond(epochSecond);
        }
    }
}
