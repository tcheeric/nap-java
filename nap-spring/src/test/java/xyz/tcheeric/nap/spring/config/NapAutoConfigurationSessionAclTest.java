package xyz.tcheeric.nap.spring.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import xyz.tcheeric.nap.core.AclDecision;
import xyz.tcheeric.nap.core.SessionRecord;
import xyz.tcheeric.nap.server.NapServer;
import xyz.tcheeric.nap.server.store.InMemorySessionStore;
import xyz.tcheeric.nap.spring.controller.NapAuthController;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * The auto-configured {@link NapAuthController} answers {@code /auth/session} through the
 * application's {@link xyz.tcheeric.nap.server.AclResolver} (imani-wallet#114).
 *
 * <p>The controller's own tests prove the behaviour when it has a resolver. This proves the
 * deployments that never construct one by hand, which is all of them, actually get it: a
 * controller built without the resolver silently keeps serving the login-time row.
 */
class NapAutoConfigurationSessionAclTest {

    @Test
    void theAutoConfiguredControllerResolvesSessionGrantsThroughTheApplicationsResolver() {
        var store = new InMemorySessionStore();
        long now = Instant.now().getEpochSecond();
        store.createForChallenge(SessionRecord.create(
                "sid-auto", "chal-auto", "token-auto", "npub-auto", "a".repeat(64),
                List.of("customer"), List.of(),
                now, now, now + 300, now + 43200));

        NapAuthController controller = new NapAutoConfiguration().napAuthController(
                mock(NapServer.class), store, properties(),
                (npub, pubkey) -> AclDecision.allowed(List.of("merchant"), List.of("coupon:issue")),
                new ObjectMapper(), none(), none(), none());

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/auth/session");
        request.setCookies(new Cookie("session", "token-auto"));
        ResponseEntity<?> response = controller.checkSession(request);

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        @SuppressWarnings("unchecked")
        Map<String, Object> body = (Map<String, Object>) response.getBody();
        assertThat(body).containsEntry("roles", List.of("merchant"));
        assertThat(body).containsEntry("permissions", List.of("coupon:issue"));
    }

    @SuppressWarnings("unchecked")
    private static <T> ObjectProvider<T> none() {
        ObjectProvider<T> provider = mock(ObjectProvider.class);
        return provider;
    }

    private static NapProperties properties() {
        return new NapProperties(
                true, "https://account.imani.casa",
                60, 3600, 900, 43200, 30, 60, 600, 0, 300,
                null, 0, 0, null, null, null, null, null, 0,
                List.of(),
                List.of("/internal/v1/merchants"),
                false,
                false,
                new NapProperties.CookieProperties("session", true, true, "Lax", "/", "", 43200));
    }
}
