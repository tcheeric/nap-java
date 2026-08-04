package xyz.tcheeric.nap.spring.filter;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.security.core.Authentication;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;
import xyz.tcheeric.nap.core.SessionRecord;
import xyz.tcheeric.nap.server.acl.PermissionRegistry;
import xyz.tcheeric.nap.spring.annotation.RequiresPermission;
import xyz.tcheeric.nap.spring.annotation.RequiresRole;
import xyz.tcheeric.nap.spring.annotation.RequiresSession;
import xyz.tcheeric.nap.spring.annotation.RequiresStepUp;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Enforces {@link RequiresPermission}, {@link RequiresRole} and {@link RequiresStepUp}
 * declarations on MVC handler methods.
 *
 * <p>All present declarations are checked, and all must pass. A permission the registry marks
 * {@code stepUp} implies {@link RequiresStepUp} without the annotation having to be repeated at
 * every call site — pass a {@link PermissionRegistry} to get that.
 */
public class NapPermissionInterceptor implements HandlerInterceptor {

    /** Header carrying the token minted by a {@code "step_up": true} completion (RFC §10.3). */
    public static final String STEP_UP_TOKEN_HEADER = "X-Step-Up-Token";

    private final PermissionRegistry registry;

    public NapPermissionInterceptor() {
        this(null);
    }

    public NapPermissionInterceptor(PermissionRegistry registry) {
        this.registry = registry;
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
