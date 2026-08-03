package xyz.tcheeric.nap.it;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import nostr.crypto.bech32.Bech32;
import nostr.crypto.bech32.Bech32Prefix;
import org.junit.jupiter.api.Test;
import xyz.tcheeric.nap.server.*;
import xyz.tcheeric.nap.server.store.InMemoryChallengeStore;
import xyz.tcheeric.nap.server.store.InMemorySessionStore;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HexFormat;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Verifies the real TypeScript @imani/nap-client-http package can authenticate against the Java NAP server.
 */
class TypeScriptClientInteropTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final HexFormat HEX = HexFormat.of();

    private static String generatePrivateKeyHex() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        return HEX.formatHex(key);
    }

    private static String derivePubkeyHex(String privateKeyHex) {
        try {
            byte[] privKey = HEX.parseHex(privateKeyHex);
            byte[] pubKey = nostr.crypto.schnorr.Schnorr.genPubKey(privKey);
            return HEX.formatHex(pubKey);
        } catch (Exception e) {
            throw new RuntimeException("Failed to derive pubkey", e);
        }
    }

    // Authenticates against the Java server by spawning the real TypeScript client package through tsx
    @Test
    void typescriptClientAuthenticatesAgainstJavaServer() throws Exception {
        Path napRoot = Path.of(System.getProperty("user.home"), "IdeaProjects", "nap");
        Path tsxBinary = napRoot.resolve("node_modules/.bin/tsx");
        assumeTrue(Files.exists(tsxBinary), "tsx toolchain not available — skipping interop test");

        String privateKeyHex = generatePrivateKeyHex();
        String pubkeyHex = derivePubkeyHex(privateKeyHex);
        String npub = Bech32.toBech32(Bech32Prefix.NPUB, pubkeyHex);

        NapServer server = NapServer.create(NapServerOptions.builder()
                .challengeStore(new InMemoryChallengeStore())
                .sessionStore(new InMemorySessionStore())
                .aclResolver(new AllowAllAclResolver())
                .challengeTtlSeconds(60)
                .sessionTtlSeconds(3600)
                .clock(Clock.fixed(Instant.ofEpochSecond(1_710_000_000L), ZoneOffset.UTC))
                .build());

        try (NapHttpTestServer httpServer = NapHttpTestServer.start(server)) {
            try (InputStream scriptStream = getClass().getResourceAsStream("/ts/tsClientInterop.ts")) {
                assertThat(scriptStream).isNotNull();

                Path interopScript = Files.createTempFile(napRoot, "nap-interop-", ".ts");
                Files.writeString(
                        interopScript,
                        new String(scriptStream.readAllBytes(), StandardCharsets.UTF_8),
                        StandardCharsets.UTF_8
                );

                try {
                    Map<String, Object> body = runClient(
                            tsxBinary, interopScript, napRoot, httpServer.baseUrl(), privateKeyHex, false);
                    assertThat(body.get("status")).isEqualTo("ok");
                    assertThat(((Map<?, ?>) body.get("principal")).get("pubkey")).isEqualTo(pubkeyHex);
                    assertThat(((Map<?, ?>) body.get("principal")).get("npub")).isEqualTo(npub);
                    // NON_NULL: an ordinary completion must not carry the field at all.
                    assertThat(body).doesNotContainKey("step_up_token");

                    // The TS client puts step_up inside the signed body; the Java server reads it
                    // from there. This is the assertion that fails if either side moves the flag.
                    Map<String, Object> steppedUp = runClient(
                            tsxBinary, interopScript, napRoot, httpServer.baseUrl(), privateKeyHex, true);
                    assertThat(steppedUp.get("step_up_token")).isInstanceOf(String.class);
                    assertThat((String) steppedUp.get("step_up_token")).isNotBlank();
                    assertThat(steppedUp.get("step_up_expires_at")).isNotNull();
                } finally {
                    Files.deleteIfExists(interopScript);
                }
            }
        }
    }

    /** Runs the real TS client once and returns the parsed {@code /auth/complete} response body. */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> runClient(Path tsxBinary, Path script, Path workingDir,
                                                 String baseUrl, String privateKeyHex, boolean stepUp)
            throws IOException, InterruptedException {
        Process process = new ProcessBuilder(
                tsxBinary.toString(), script.toString(), baseUrl, privateKeyHex,
                stepUp ? "step-up" : "plain")
                .directory(workingDir.toFile())
                .redirectErrorStream(true)
                .start();

        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
        assertThat(process.waitFor())
                .withFailMessage("TypeScript client process failed: %s", output)
                .isZero();

        Map<String, Object> response = MAPPER.readValue(output, Map.class);
        assertThat(response.get("status")).isEqualTo(200);
        return (Map<String, Object>) response.get("body");
    }

    private static final class NapHttpTestServer implements AutoCloseable {
        private final HttpServer server;
        private final NapServer napServer;
        private final String baseUrl;

        private NapHttpTestServer(HttpServer server, NapServer napServer, String baseUrl) {
            this.server = server;
            this.napServer = napServer;
            this.baseUrl = baseUrl;
        }

        static NapHttpTestServer start(NapServer napServer) throws IOException {
            HttpServer server = HttpServer.create(new InetSocketAddress(0), 0);
            String baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
            NapHttpTestServer wrapper = new NapHttpTestServer(server, napServer, baseUrl);
            server.createContext("/auth/init", wrapper::handleInit);
            server.createContext("/auth/complete", wrapper::handleComplete);
            server.start();
            return wrapper;
        }

        String baseUrl() {
            return baseUrl;
        }

        private void handleInit(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendJson(exchange, 405, Map.of("status", "error", "message", "method not allowed"));
                return;
            }

            @SuppressWarnings("unchecked")
            Map<String, Object> body = MAPPER.readValue(readBody(exchange), Map.class);
            String npub = String.valueOf(body.get("npub"));
            var result = napServer.issueChallenge(new IssueChallengeInput(npub, baseUrl + "/auth/complete"));

            if (result instanceof IssueChallengeResult.Success success) {
                sendJson(exchange, 200, success.value());
                return;
            }

            sendJson(exchange, 400, Map.of("status", "error", "message", "bad request"));
        }

        private void handleComplete(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendJson(exchange, 405, Map.of("status", "error", "message", "method not allowed"));
                return;
            }

            String authorization = exchange.getRequestHeaders().getFirst("Authorization");
            byte[] rawBody = readBody(exchange);
            URI requestUri = exchange.getRequestURI();
            String url = baseUrl + requestUri.getPath();
            var result = napServer.verifyCompletion(new VerifyCompletionInput(
                    authorization,
                    exchange.getRequestMethod(),
                    url,
                    rawBody
            ));

            if (result instanceof VerifyCompletionOutcome.Success success) {
                sendJson(exchange, 200, napServer.toPublicAuthSuccess(success.session()));
                return;
            }

            sendJson(exchange, 401, napServer.toPublicAuthFailure().body());
        }

        private static byte[] readBody(HttpExchange exchange) throws IOException {
            try (InputStream inputStream = exchange.getRequestBody()) {
                return inputStream.readAllBytes();
            }
        }

        private static void sendJson(HttpExchange exchange, int status, Object body) throws IOException {
            byte[] payload = MAPPER.writeValueAsBytes(body);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(status, payload.length);
            exchange.getResponseBody().write(payload);
            exchange.close();
        }

        @Override
        public void close() {
            server.stop(0);
        }
    }
}
