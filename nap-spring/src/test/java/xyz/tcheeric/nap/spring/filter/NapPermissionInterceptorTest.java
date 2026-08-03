package xyz.tcheeric.nap.spring.filter;

import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.method.HandlerMethod;
import xyz.tcheeric.nap.spring.annotation.RequiresPermission;
import xyz.tcheeric.nap.spring.annotation.RequiresRole;

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

    private static class TestController {

        @RequiresPermission("admin")
        public void adminEndpoint() {
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
