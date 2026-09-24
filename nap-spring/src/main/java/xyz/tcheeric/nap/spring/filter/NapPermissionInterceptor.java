package xyz.tcheeric.nap.spring.filter;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.security.core.Authentication;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;
import xyz.tcheeric.nap.core.SessionRecord;
import xyz.tcheeric.nap.server.acl.PermissionRegistry;
import xyz.tcheeric.nap.spring.annotation.PublicEndpoint;
import xyz.tcheeric.nap.spring.annotation.RequiresPermission;
import xyz.tcheeric.nap.spring.annotation.RequiresRole;
import xyz.tcheeric.nap.spring.annotation.RequiresSession;
import xyz.tcheeric.nap.spring.annotation.RequiresStepUp;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Enforces {@link RequiresPermission}, {@link RequiresRole} and {@link RequiresStepUp}
 * declarations on MVC handler methods.
 *
 * <p>All present declarations are checked, and all must pass. A permission the registry marks
 * {@code stepUp} implies {@link RequiresStepUp} without the annotation having to be repeated at
 * every call site — pass a {@link PermissionRegistry} to get that.
 *
 * <h2>Handlers carrying no annotation</h2>
 *
 * <p>By default an unannotated handler is not guarded: this interceptor only rejects handlers that
 * declare a requirement. That is deliberate — an adapter cannot know which endpoints are meant to
 * be public — but it makes the safe state the one you have to remember, and a handler added to a
 * protected controller without an annotation is exposed silently, with nothing in the diff to
 * show for it.
 *
 * <p>{@code nap.require-annotation-on-protected-paths=true} inverts that within
 * {@code nap.protected-path-prefixes}: a handler under one of those prefixes must carry a NAP
 * annotation or the request is refused with {@code 500}, not {@code 401}, because an endpoint
 * whose access policy was never stated is a wiring mistake and not a caller error. Public
 * endpoints inside a protected prefix stay expressible with {@link PublicEndpoint}, which says in
 * the source what the missing annotation used to say only by omission.
 */
public class NapPermissionInterceptor implements HandlerInterceptor {

    /** Header carrying the token minted by a {@code "step_up": true} completion (RFC §10.3). */
    public static final String STEP_UP_TOKEN_HEADER = "X-Step-Up-Token";

    private final PermissionRegistry registry;
    private final List<String> protectedPathPrefixes;
    private final boolean requireAnnotationOnProtectedPaths;

    public NapPermissionInterceptor() {
        this(null);
    }

    public NapPermissionInterceptor(PermissionRegistry registry) {
        this(registry, List.of(), false);
    }

    /**
     * @param protectedPathPrefixes            paths within which an annotation is mandatory when
     *                                         {@code requireAnnotationOnProtectedPaths} is set.
     * @param requireAnnotationOnProtectedPaths fail closed on an undeclared handler rather than
     *                                          letting it through.
     */
    public NapPermissionInterceptor(PermissionRegistry registry, List<String> protectedPathPrefixes,
                                    boolean requireAnnotationOnProtectedPaths) {
        this.registry = registry;
        this.protectedPathPrefixes = protectedPathPrefixes == null ? List.of()
                : List.copyOf(protectedPathPrefixes);
        this.requireAnnotationOnProtectedPaths = requireAnnotationOnProtectedPaths;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        if (!(handler instanceof HandlerMethod handlerMethod)) {
            return true;
        }

        RequiresPermission permissionAnnotation = findAnnotation(handlerMethod);
        RequiresRole roleAnnotation = findRoleAnnotation(handlerMethod);
        RequiresStepUp stepUpAnnotation = findStepUpAnnotation(handlerMethod);
        RequiresSession sessionAnnotation = findSessionAnnotation(handlerMethod);
        if (permissionAnnotation == null && roleAnnotation == null && stepUpAnnotation == null
                && sessionAnnotation == null) {
            if (requiresExplicitDeclaration(request, handlerMethod)) {
                // 500, not 401: no credential the caller could present would help, because the
                // endpoint never said what it wants. Refusing loudly is what keeps a forgotten
                // annotation from reading as "public".
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                return false;
            }
            return true;
        }

        Authentication authentication = org.springframework.security.core.context.SecurityContextHolder
                .getContext()
                .getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return false;
        }

        Set<String> authorities = authentication.getAuthorities().stream()
                .map(org.springframework.security.core.GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());

        if (permissionAnnotation != null && !authorities.contains(permissionAnnotation.value())) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            return false;
        }

        if (roleAnnotation != null) {
            // NapAuthenticationToken maps roles to ROLE_<UPPER> authorities.
            boolean allowed = Arrays.stream(roleAnnotation.value())
                    .map(NapSessionFilter.NapAuthenticationToken::toRoleAuthority)
                    .anyMatch(authorities::contains);
            if (!allowed) {
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                return false;
            }
        }

        boolean stepUpRequired = stepUpAnnotation != null
                || (permissionAnnotation != null && registryRequiresStepUp(permissionAnnotation.value()));
        if (stepUpRequired && !hasValidStepUpToken(request, authentication)) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            return false;
        }

        return true;
    }

    /**
     * True when the handler sits under a protected prefix, declares nothing, and has not opted
     * out with {@link PublicEndpoint}.
     */
    private boolean requiresExplicitDeclaration(HttpServletRequest request, HandlerMethod handler) {
        if (!requireAnnotationOnProtectedPaths || protectedPathPrefixes.isEmpty()) {
            return false;
        }
        if (AnnotatedElementUtils.findMergedAnnotation(handler.getMethod(), PublicEndpoint.class) != null
                || AnnotatedElementUtils.findMergedAnnotation(handler.getBeanType(), PublicEndpoint.class) != null) {
            return false;
        }
        // One path helper for both, so the filter and this interceptor cannot disagree about
        // which requests fall under a protected prefix.
        String path = NapSessionFilter.pathWithinApplication(request);
        for (String prefix : protectedPathPrefixes) {
            if (prefix != null && !prefix.isBlank() && path.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    private boolean registryRequiresStepUp(String permission) {
        if (registry == null) {
            return false;
        }
        return registry.permissions().stream()
                .anyMatch(definition -> definition.key().equals(permission) && definition.stepUpRequired());
    }

    private boolean hasValidStepUpToken(HttpServletRequest request, Authentication authentication) {
        if (!(authentication instanceof NapSessionFilter.NapAuthenticationToken token)) {
            return false;
        }

        SessionRecord session = token.getSession();
        String provided = request.getHeader(STEP_UP_TOKEN_HEADER);
        if (provided == null || session.stepUpToken() == null || session.stepUpExpiresAt() == null) {
            return false;
        }
        if (session.stepUpExpiresAt() <= Instant.now().getEpochSecond()) {
            return false;
        }

        // MessageDigest.isEqual is time-constant, including on the length difference —
        // guards run outside the auth endpoints' response floor, so nothing else is
        // smoothing out a comparison that short-circuits on the first differing byte.
        return MessageDigest.isEqual(
                session.stepUpToken().getBytes(StandardCharsets.UTF_8),
                provided.getBytes(StandardCharsets.UTF_8));
    }

    /** Method then class, like the other two — a guard declared on the controller must bind. */
    private RequiresStepUp findStepUpAnnotation(HandlerMethod handlerMethod) {
        RequiresStepUp methodAnnotation = AnnotatedElementUtils.findMergedAnnotation(
                handlerMethod.getMethod(), RequiresStepUp.class);
        if (methodAnnotation != null) {
            return methodAnnotation;
        }
        return AnnotatedElementUtils.findMergedAnnotation(
                handlerMethod.getBeanType(), RequiresStepUp.class);
    }

    private RequiresRole findRoleAnnotation(HandlerMethod handlerMethod) {
        RequiresRole methodAnnotation = AnnotatedElementUtils.findMergedAnnotation(
                handlerMethod.getMethod(), RequiresRole.class);
        if (methodAnnotation != null) {
            return methodAnnotation;
        }
        return AnnotatedElementUtils.findMergedAnnotation(
                handlerMethod.getBeanType(), RequiresRole.class);
    }

    /**
     * Carries no check of its own beyond the authentication gate above — declaring it is the
     * whole point, since a handler declaring nothing is never gated at all.
     */
    private RequiresSession findSessionAnnotation(HandlerMethod handlerMethod) {
        RequiresSession methodAnnotation = AnnotatedElementUtils.findMergedAnnotation(
                handlerMethod.getMethod(), RequiresSession.class);
        if (methodAnnotation != null) {
            return methodAnnotation;
        }
        return AnnotatedElementUtils.findMergedAnnotation(
                handlerMethod.getBeanType(), RequiresSession.class);
    }

    private RequiresPermission findAnnotation(HandlerMethod handlerMethod) {
        RequiresPermission methodAnnotation = AnnotatedElementUtils.findMergedAnnotation(
                handlerMethod.getMethod(), RequiresPermission.class);
        if (methodAnnotation != null) {
            return methodAnnotation;
        }
        return AnnotatedElementUtils.findMergedAnnotation(
                handlerMethod.getBeanType(), RequiresPermission.class);
    }
}
