package xyz.tcheeric.nap.it;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import nostr.crypto.bech32.Bech32;
import nostr.crypto.bech32.Bech32Prefix;
import nostr.crypto.schnorr.Schnorr;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.postgresql.ds.PGSimpleDataSource;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.testcontainers.containers.PostgreSQLContainer;
import xyz.tcheeric.nap.client.NapProofBuilder;
import xyz.tcheeric.nap.core.AclDecision;
import xyz.tcheeric.nap.core.SessionRecord;
import xyz.tcheeric.nap.jdbc.JdbcChallengeStore;
import xyz.tcheeric.nap.jdbc.JdbcSessionStore;
import xyz.tcheeric.nap.server.AclResolver;
import xyz.tcheeric.nap.server.NapServer;
import xyz.tcheeric.nap.server.NapServerOptions;
import xyz.tcheeric.nap.spring.config.NapProperties;
import xyz.tcheeric.nap.spring.controller.NapAuthController;
import xyz.tcheeric.nap.spring.filter.NapServletFilter;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.Statement;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@code GET /auth/session} answers the ACL as it stands now, over a real login persisted in
 * PostgreSQL (imani-wallet#114).
 *
 * <p>The failure this guards: a merchant whose stall record reached the ACL a second after their
 * login was stored as a customer, and every later {@code /auth/session} read that row back, so a
 * reload never helped. Each step here goes through the production pieces: a NIP-98 login against
 * {@link NapServer}, the session written by {@link JdbcSessionStore} under the published
 * migrations, and the read through the same {@link NapAuthController} the auto-configuration
 * builds.
 */
class SessionAclLiveIT {

    private static final String AUTH_URL = "https://example.com/api/v1/auth/complete";
    private static final String COOKIE = "session";
    private static final HexFormat HEX = HexFormat.of();

    private static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");
    private static PGSimpleDataSource dataSource;

    private final AtomicReference<AclDecision> acl = new AtomicReference<>();
    private final AtomicReference<RuntimeException> aclFault = new AtomicReference<>();
    private final AclResolver resolver = (npub, pubkey) -> {
        RuntimeException fault = aclFault.get();
        if (fault != null) {
            throw fault;
        }
        return acl.get();
    };

    private NapServer server;
    private JdbcSessionStore sessions;
    private NapAuthController controller;

    @BeforeAll
    static void startDatabase() throws Exception {
        POSTGRES.start();
        dataSource = new PGSimpleDataSource();
        dataSource.setUrl(POSTGRES.getJdbcUrl());
        dataSource.setUser(POSTGRES.getUsername());
        dataSource.setPassword(POSTGRES.getPassword());
        try (Connection c = dataSource.getConnection(); Statement s = c.createStatement()) {
            for (String migration : List.of("V1__create_nap_tables.sql", "V2__nap_security_hardening.sql",
                    "V3__sliding_window_and_refresh_tokens.sql")) {
                s.execute(migration(migration));
            }
        }
    }

    @AfterAll
    static void stopDatabase() {
        POSTGRES.stop();
    }

    @BeforeEach
    void wire() {
        acl.set(customer());
        aclFault.set(null);
        sessions = new JdbcSessionStore(dataSource);
        server = NapServer.create(NapServerOptions.builder()
                .challengeStore(new JdbcChallengeStore(dataSource))
                .sessionStore(sessions)
                .aclResolver(resolver)
                .challengeTtlSeconds(60)
                .sessionIdleTtlSeconds(900)
                .sessionAbsoluteTtlSeconds(43200)
                .minAuthResponseMillis(0)
                .responseJitterMillis(0)
                .build());
        controller = new NapAuthController(server, sessions, properties(), new ObjectMapper(),
                null, null, null, resolver);
    }

    /** The #114 sequence: login lands before the stall record, the ACL catches up, resume sees it. */
    @Test
    void aMerchantWhoLoggedInAsACustomerIsAMerchantOnTheNextSessionRead() throws Exception {
        String token = login();
        assertThat(sessions.getByAccessToken(token).orElseThrow().permissions())
                .as("the login-time row: the race lost")
                .containsExactly("wallet:read");

        acl.set(merchant());

        Map<String, Object> body = session(token, 200);
        assertThat(body).containsEntry("roles", List.of("merchant"));
        assertThat(body).containsEntry("permissions", List.of("wallet:read", "coupon:issue"));
    }

    /** The other direction: a stall closed mid-session stops offering issuance on the next read. */
    @Test
    void aMerchantWhoClosesTheirStallLosesIssuanceOnTheNextSessionRead() throws Exception {
        acl.set(merchant());
        String token = login();
        assertThat(session(token, 200)).containsEntry("permissions", List.of("wallet:read", "coupon:issue"));

        acl.set(customer());

        assertThat(session(token, 200)).containsEntry("permissions", List.of("wallet:read"));
    }

    /** An ACL that cannot be read keeps the session (and slides it) but grants nothing. */
    @Test
    void anUnreadableAclKeepsTheSessionAndGrantsNothing() throws Exception {
        acl.set(merchant());
        String token = login();
        long expiresBefore = sessions.getByAccessToken(token).orElseThrow().expiresAt();

        aclFault.set(new IllegalStateException("acl store down"));
        Thread.sleep(1100);

        Map<String, Object> body = session(token, 200);
        assertThat(body).containsEntry("permissions", List.of());
        assertThat(body).containsEntry("roles", List.of());
        SessionRecord after = sessions.getByAccessToken(token).orElseThrow();
        assertThat(after.revokedAt()).isNull();
        assertThat(after.expiresAt()).isGreaterThan(expiresBefore);

        aclFault.set(null);
        assertThat(session(token, 200))
                .as("restored as soon as the ACL answers again")
                .containsEntry("permissions", List.of("wallet:read", "coupon:issue"));
    }

    /** A suspension ends the session in the store, not only in this response. */
    @Test
    void aSuspensionEndsTheSession() throws Exception {
        acl.set(merchant());
        String token = login();

        acl.set(AclDecision.denied("suspended", true));

        assertThat(session(token, 401)).containsEntry("reason", "invalid");
        assertThat(sessions.getByAccessToken(token)).as("revoked in the store").isEmpty();
        acl.set(merchant());
        assertThat(session(token, 401)).containsEntry("reason", "invalid");
    }

    // -----------------------------------------------------------------

    private static AclDecision customer() {
        return AclDecision.allowed(List.of("customer"), List.of("wallet:read"));
    }

    private static AclDecision merchant() {
        return AclDecision.allowed(List.of("merchant"), List.of("wallet:read", "coupon:issue"));
    }

    /** A full NIP-98 login through the controller; returns the cookie it set. */
    private String login() throws Exception {
        byte[] privKey = new byte[32];
        new SecureRandom().nextBytes(privKey);
        String privKeyHex = HEX.formatHex(privKey);
        String pubKeyHex = HEX.formatHex(Schnorr.genPubKey(privKey));
        String npub = Bech32.toBech32(Bech32Prefix.NPUB, pubKeyHex);

        ResponseEntity<?> init = controller.init(Map.of("npub", npub), new MockHttpServletRequest());
        assertThat(init.getStatusCode().value()).isEqualTo(200);
        @SuppressWarnings("unchecked")
        Map<String, Object> challenge = (Map<String, Object>) init.getBody();
        String challengeId = (String) challenge.get("challenge_id");

        byte[] rawBody = ("{\"challenge_id\":\"" + challengeId + "\"}").getBytes(StandardCharsets.UTF_8);
        String authorization = new NapProofBuilder()
                .privateKey(privKeyHex)
                .pubkey(pubKeyHex)
                .url(AUTH_URL)
                .method("POST")
                .challenge((String) challenge.get("challenge"))
                .challengeId(challengeId)
                .body(rawBody)
                .createdAt(java.time.Instant.now().getEpochSecond())
                .buildAuthorizationHeader();

        MockHttpServletRequest complete = new MockHttpServletRequest("POST", "/api/v1/auth/complete");
        complete.addHeader("Authorization", authorization);
        complete.setAttribute(NapServletFilter.RAW_BODY_ATTRIBUTE, rawBody);
        MockHttpServletResponse response = new MockHttpServletResponse();
        ResponseEntity<?> result = controller.complete(complete, response);
        assertThat(result.getStatusCode().value()).isEqualTo(200);
        return response.getCookie(COOKIE).getValue();
    }

    private Map<String, Object> session(String token, int expectedStatus) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/auth/session");
        request.setCookies(new Cookie(COOKIE, token));
        ResponseEntity<?> response = controller.checkSession(request);
        assertThat(response.getStatusCode().value()).isEqualTo(expectedStatus);
        @SuppressWarnings("unchecked")
        Map<String, Object> body = (Map<String, Object>) response.getBody();
        return body;
    }

    private static NapProperties properties() {
        return new NapProperties(
                true, "https://example.com",
                60, 3600, 900, 43200, 30, 60, 600, 0, 300,
                null, 0, 0, null, null, null, 0, 0, 0,
                List.of(),
                List.of("/api/v1/private"),
                false,
                false,
                new NapProperties.CookieProperties(COOKIE, true, true, "Lax", "/", "", 43200));
    }

    private static String migration(String name) throws IOException {
        try (InputStream in = JdbcSessionStore.class.getResourceAsStream("/db/migration/" + name)) {
            if (in == null) {
                throw new IllegalStateException("migration not on the classpath: " + name);
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
