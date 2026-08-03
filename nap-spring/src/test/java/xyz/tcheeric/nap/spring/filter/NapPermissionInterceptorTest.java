package xyz.tcheeric.nap.spring.filter;

import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.method.HandlerMethod;
import xyz.tcheeric.nap.core.SessionRecord;
import xyz.tcheeric.nap.server.acl.PermissionDefinition;
import xyz.tcheeric.nap.server.acl.PermissionRegistry;
import xyz.tcheeric.nap.spring.annotation.RequiresPermission;
import xyz.tcheeric.nap.spring.annotation.RequiresRole;
import xyz.tcheeric.nap.spring.annotation.RequiresStepUp;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies @RequiresPermission endpoints are rejected when the authenticated principal lacks the required authority.
 */
class NapPermissionInterceptorTest {

    private final NapPermissionInterceptor interceptor = new NapPermissionInterceptor();

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void preHandle_returnsForbiddenWhenPermissionIsMissing() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(
                new TestingAuthenticationToken("merchant", null, "read")
        );
        HandlerMethod handlerMethod = new HandlerMethod(new TestController(),
                TestController.class.getDeclaredMethod("adminEndpoint"));
        var request = new org.springframework.mock.web.MockHttpServletRequest("POST", "/internal/v1/merchants/test/suspend");
        var response = new org.springframework.mock.web.MockHttpServletResponse();

        boolean allowed = interceptor.preHandle(request, response, handlerMethod);

        assertThat(allowed).isFalse();
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
    }

    @Test
    void preHandle_allowsRequestWhenPermissionMatches() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(
                new TestingAuthenticationToken("merchant", null, "admin")
        );
        HandlerMethod handlerMethod = new HandlerMethod(new TestController(),
                TestController.class.getDeclaredMethod("adminEndpoint"));
        var request = new org.springframework.mock.web.MockHttpServletRequest("POST", "/internal/v1/merchants/test/suspend");
        var response = new org.springframework.mock.web.MockHttpServletResponse();

        boolean allowed = interceptor.preHandle(request, response, handlerMethod);

        assertThat(allowed).isTrue();
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
    }

    @Test
    void preHandle_allowsRequestWhenRoleMatches() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(
                new TestingAuthenticationToken("merchant", null, "ROLE_MERCHANT")
        );
        HandlerMethod handlerMethod = new HandlerMethod(new TestController(),
                TestController.class.getDeclaredMethod("staffEndpoint"));
        var request = new org.springframework.mock.web.MockHttpServletRequest("GET", "/staff");
        var response = new org.springframework.mock.web.MockHttpServletResponse();

        boolean allowed = interceptor.preHandle(request, response, handlerMethod);

        assertThat(allowed).isTrue();
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
    }

    @Test
    void preHandle_allowsAnyOfTheDeclaredRoles() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(
                new TestingAuthenticationToken("merchant", null, "ROLE_OWNER")
        );
        HandlerMethod handlerMethod = new HandlerMethod(new TestController(),
                TestController.class.getDeclaredMethod("eitherRoleEndpoint"));
        var request = new org.springframework.mock.web.MockHttpServletRequest("GET", "/either");
        var response = new org.springframework.mock.web.MockHttpServletResponse();

        boolean allowed = interceptor.preHandle(request, response, handlerMethod);

        assertThat(allowed).isTrue();
    }

    @Test
    void preHandle_returnsForbiddenWhenRoleIsMissing() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(
                new TestingAuthenticationToken("viewer", null, "ROLE_VIEWER")
        );
        HandlerMethod handlerMethod = new HandlerMethod(new TestController(),
                TestController.class.getDeclaredMethod("staffEndpoint"));
        var request = new org.springframework.mock.web.MockHttpServletRequest("GET", "/staff");
        var response = new org.springframework.mock.web.MockHttpServletResponse();

        boolean allowed = interceptor.preHandle(request, response, handlerMethod);

        assertThat(allowed).isFalse();
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
    }

    @Test
    void preHandle_returnsUnauthorizedForRoleGuardWithoutAuthentication() throws Exception {
        HandlerMethod handlerMethod = new HandlerMethod(new TestController(),
                TestController.class.getDeclaredMethod("staffEndpoint"));
        var request = new org.springframework.mock.web.MockHttpServletRequest("GET", "/staff");
        var response = new org.springframework.mock.web.MockHttpServletResponse();

        boolean allowed = interceptor.preHandle(request, response, handlerMethod);

        assertThat(allowed).isFalse();
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
    }

    @Test
    void preHandle_requiresBothWhenPermissionAndRoleAreDeclared() throws Exception {
        // Holds the role but not the permission: both must pass.
        SecurityContextHolder.getContext().setAuthentication(
                new TestingAuthenticationToken("merchant", null, "ROLE_MERCHANT")
        );
        HandlerMethod handlerMethod = new HandlerMethod(new TestController(),
                TestController.class.getDeclaredMethod("bothEndpoint"));
        var request = new org.springframework.mock.web.MockHttpServletRequest("GET", "/both");
        var response = new org.springframework.mock.web.MockHttpServletResponse();

        boolean allowed = interceptor.preHandle(request, response, handlerMethod);

        assertThat(allowed).isFalse();
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
    }

    // --- step-up (RFC §10.3) ---

    @Test
    void preHandle_returnsForbiddenForStepUpGuardWithoutAToken() throws Exception {
        authenticateWithStepUp(null, null);
        var response = new MockHttpServletResponse();

        boolean allowed = interceptor.preHandle(
                new MockHttpServletRequest("POST", "/sensitive"), response, stepUpHandler());

        assertThat(allowed).isFalse();
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
    }

    @Test
    void preHandle_allowsStepUpGuardWithAMatchingToken() throws Exception {
        authenticateWithStepUp("step-up-token", Instant.now().getEpochSecond() + 600);
        var request = new MockHttpServletRequest("POST", "/sensitive");
        request.addHeader(NapPermissionInterceptor.STEP_UP_TOKEN_HEADER, "step-up-token");
        var response = new MockHttpServletResponse();

        assertThat(interceptor.preHandle(request, response, stepUpHandler())).isTrue();
    }

    @Test
    void preHandle_returnsForbiddenForAWrongStepUpToken() throws Exception {
        authenticateWithStepUp("step-up-token", Instant.now().getEpochSecond() + 600);
        var request = new MockHttpServletRequest("POST", "/sensitive");
        request.addHeader(NapPermissionInterceptor.STEP_UP_TOKEN_HEADER, "step-up-toke");
        var response = new MockHttpServletResponse();

        boolean allowed = interceptor.preHandle(request, response, stepUpHandler());

        assertThat(allowed).isFalse();
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
    }

    @Test
    void preHandle_returnsForbiddenForAnExpiredStepUpToken() throws Exception {
        // The token is right; it is simply past its TTL. A step-up is a statement about how
        // recently the key was proved, so an old one is worth no more than none.
        authenticateWithStepUp("step-up-token", Instant.now().getEpochSecond() - 1);
        var request = new MockHttpServletRequest("POST", "/sensitive");
        request.addHeader(NapPermissionInterceptor.STEP_UP_TOKEN_HEADER, "step-up-token");
        var response = new MockHttpServletResponse();

        boolean allowed = interceptor.preHandle(request, response, stepUpHandler());

        assertThat(allowed).isFalse();
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
    }

    @Test
    void preHandle_bindsAClassLevelStepUpDeclaration() throws Exception {
        // Declared on the controller, not the method — the same reach @RequiresPermission and
        // @RequiresRole have.
        authenticateWithStepUp(null, null);
        var response = new MockHttpServletResponse();
        HandlerMethod handlerMethod = new HandlerMethod(new StepUpController(),
                StepUpController.class.getDeclaredMethod("inheritsStepUpFromTheClass"));

        boolean allowed = interceptor.preHandle(
                new MockHttpServletRequest("POST", "/class-level"), response, handlerMethod);

        assertThat(allowed).isFalse();
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
    }

    @Test
    void preHandle_requiresStepUpForARegistryPermissionThatDeclaresIt() throws Exception {
        // No @RequiresStepUp at the call site: the registry says the permission needs one, and
        // that is enough. Otherwise the annotation has to be remembered everywhere the
        // permission is used, and one forgotten site is the whole guard.
        var registry = PermissionRegistry.of(
                "test",
                List.of(new PermissionDefinition("wallet:withdraw", "Withdraw funds", true)),
                List.of(),
                null);
        var registryInterceptor = new NapPermissionInterceptor(registry);
        authenticateWithStepUp(null, null, "wallet:withdraw");
        var response = new MockHttpServletResponse();
        HandlerMethod handlerMethod = new HandlerMethod(new WalletController(),
                WalletController.class.getDeclaredMethod("withdraw"));

        boolean allowed = registryInterceptor.preHandle(
                new MockHttpServletRequest("POST", "/withdraw"), response, handlerMethod);

        assertThat(allowed).isFalse();
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
    }

    @Test
    void preHandle_allowsARegistryStepUpPermissionOnceSteppedUp() throws Exception {
        var registry = PermissionRegistry.of(
                "test",
                List.of(new PermissionDefinition("wallet:withdraw", "Withdraw funds", true)),
                List.of(),
                null);
        var registryInterceptor = new NapPermissionInterceptor(registry);
        authenticateWithStepUp("fresh", Instant.now().getEpochSecond() + 600, "wallet:withdraw");
        var request = new MockHttpServletRequest("POST", "/withdraw");
        request.addHeader(NapPermissionInterceptor.STEP_UP_TOKEN_HEADER, "fresh");
        HandlerMethod handlerMethod = new HandlerMethod(new WalletController(),
                WalletController.class.getDeclaredMethod("withdraw"));

        assertThat(registryInterceptor.preHandle(request, new MockHttpServletResponse(), handlerMethod))
                .isTrue();
    }

    private HandlerMethod stepUpHandler() throws NoSuchMethodException {
        return new HandlerMethod(new TestController(),
                TestController.class.getDeclaredMethod("stepUpEndpoint"));
    }

    private static void authenticateWithStepUp(String stepUpToken, Long stepUpExpiresAt,
                                               String... permissions) {
        long now = Instant.now().getEpochSecond();
        SessionRecord session = new SessionRecord(
                "session-id", "challenge-id", "access-token", "npub1test", "pubkeyhex",
                List.of(), List.of(permissions),
                now, now, now + 3600, now + 43200,
                null, stepUpToken, stepUpExpiresAt);
        SecurityContextHolder.getContext().setAuthentication(
                new NapSessionFilter.NapAuthenticationToken(session));
    }

    @RequiresStepUp
    private static class StepUpController {

        public void inheritsStepUpFromTheClass() {
        }
    }

    /** No step-up annotation anywhere: the registry is the only thing that can require it. */
    private static class WalletController {

        @RequiresPermission("wallet:withdraw")
        public void withdraw() {
        }
    }

    private static class TestController {

        @RequiresPermission("admin")
        public void adminEndpoint() {
        }

        @RequiresStepUp
        public void stepUpEndpoint() {
        }

        @RequiresRole("merchant")
        public void staffEndpoint() {
        }

        @RequiresRole({"admin", "owner"})
        public void eitherRoleEndpoint() {
        }

        @RequiresPermission("admin")
        @RequiresRole("merchant")
        public void bothEndpoint() {
        }
    }
}
