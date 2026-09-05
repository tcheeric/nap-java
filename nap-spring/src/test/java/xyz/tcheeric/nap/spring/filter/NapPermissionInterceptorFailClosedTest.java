package xyz.tcheeric.nap.spring.filter;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.method.HandlerMethod;
import xyz.tcheeric.nap.spring.annotation.PublicEndpoint;
import xyz.tcheeric.nap.spring.annotation.RequiresSession;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A handler with no NAP annotation is reachable by anyone. That is the documented default and it
 * is defensible: the adapter cannot know which endpoints are meant to be public. What is not
 * defensible is that it is also the outcome of forgetting, so a new handler added to a protected
 * controller is exposed with nothing in the diff to show for it.
 *
 * <p>{@code nap.require-annotation-on-protected-paths} makes the declaration mandatory inside
 * {@code nap.protected-path-prefixes}. These tests pin that the default is unchanged, that the
 * opt-in refuses an undeclared handler, and that a genuinely public one can still say so.
 */
class NapPermissionInterceptorFailClosedTest {

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @SuppressWarnings("unused")
    static final class Handlers {
        public void undeclared() { }

        @RequiresSession
        public void declared() { }

        @PublicEndpoint("health checks must answer before a session exists")
        public void deliberatelyPublic() { }
    }

    /** Default behaviour must not change: this mode can only break a working application. */
    @Test
    void undeclaredHandlerIsAllowedByDefault() throws Exception {
        NapPermissionInterceptor interceptor = new NapPermissionInterceptor();

        MockHttpServletResponse response = new MockHttpServletResponse();
        assertTrue(interceptor.preHandle(request("/internal/v1/merchants/42"), response,
                handler("undeclared")));
        assertEquals(200, response.getStatus());
    }

    @Test
    void undeclaredHandlerIsAllowedWhenOptInIsOff() throws Exception {
        NapPermissionInterceptor interceptor =
                new NapPermissionInterceptor(null, List.of("/internal/v1/merchants"), false);

        assertTrue(interceptor.preHandle(request("/internal/v1/merchants/42"),
                new MockHttpServletResponse(), handler("undeclared")));
    }

    /** The regression this mode exists for. */
    @Test
    void undeclaredHandlerUnderProtectedPrefixIsRefusedWhenOptInIsOn() throws Exception {
        NapPermissionInterceptor interceptor =
                new NapPermissionInterceptor(null, List.of("/internal/v1/merchants"), true);

        MockHttpServletResponse response = new MockHttpServletResponse();
        assertFalse(interceptor.preHandle(request("/internal/v1/merchants/42"), response,
                handler("undeclared")));
        assertEquals(500, response.getStatus(),
                "an endpoint that never stated its access policy is a wiring bug, not a 401: "
                        + "no credential the caller could present would change the outcome");
    }

    @Test
    void handlerOutsideProtectedPrefixIsUnaffected() throws Exception {
        NapPermissionInterceptor interceptor =
                new NapPermissionInterceptor(null, List.of("/internal/v1/merchants"), true);

        assertTrue(interceptor.preHandle(request("/api/v1/auth/init"),
                new MockHttpServletResponse(), handler("undeclared")),
                "the mandate covers protected prefixes only; /api/v1/auth must stay reachable");
    }

    @Test
    void publicEndpointAnnotationOptsOut() throws Exception {
        NapPermissionInterceptor interceptor =
                new NapPermissionInterceptor(null, List.of("/internal/v1/merchants"), true);

        MockHttpServletResponse response = new MockHttpServletResponse();
        assertTrue(interceptor.preHandle(request("/internal/v1/merchants/health"), response,
                handler("deliberatelyPublic")),
                "a public endpoint must remain expressible, in the source rather than by omission");
        assertEquals(200, response.getStatus());
    }

    /** An annotated handler still goes down the normal path: unauthenticated means 401. */
    @Test
    void declaredHandlerStillRejectsUnauthenticatedWith401() throws Exception {
        NapPermissionInterceptor interceptor =
                new NapPermissionInterceptor(null, List.of("/internal/v1/merchants"), true);

        MockHttpServletResponse response = new MockHttpServletResponse();
        assertFalse(interceptor.preHandle(request("/internal/v1/merchants/42"), response,
                handler("declared")));
        assertEquals(401, response.getStatus(),
                "a declared handler with no session is a caller error, distinct from a wiring bug");
    }

    @Test
    void contextPathIsStrippedBeforePrefixMatching() throws Exception {
        NapPermissionInterceptor interceptor =
                new NapPermissionInterceptor(null, List.of("/internal/v1/merchants"), true);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setContextPath("/gateway");
        request.setRequestURI("/gateway/internal/v1/merchants/42");

        MockHttpServletResponse response = new MockHttpServletResponse();
        assertFalse(interceptor.preHandle(request, response, handler("undeclared")),
                "deploying under a context path must not silently disable the mandate");
        assertEquals(500, response.getStatus());
    }

    @Test
    void nonHandlerMethodRequestsPassThrough() throws Exception {
        NapPermissionInterceptor interceptor =
                new NapPermissionInterceptor(null, List.of("/internal/v1/merchants"), true);

        // Static resources resolve to a ResourceHttpRequestHandler, not a HandlerMethod.
        assertTrue(interceptor.preHandle(request("/internal/v1/merchants/logo.png"),
                new MockHttpServletResponse(), new Object()));
    }

    private static MockHttpServletRequest request(String uri) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI(uri);
        return request;
    }

    private static HandlerMethod handler(String method) throws NoSuchMethodException {
        return new HandlerMethod(new Handlers(), Handlers.class.getMethod(method));
    }
}
