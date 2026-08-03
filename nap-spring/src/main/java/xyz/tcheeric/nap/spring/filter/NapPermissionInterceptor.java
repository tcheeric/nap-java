package xyz.tcheeric.nap.spring.filter;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.security.core.Authentication;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;
import xyz.tcheeric.nap.spring.annotation.RequiresPermission;
import xyz.tcheeric.nap.spring.annotation.RequiresRole;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Enforces {@link RequiresPermission} and {@link RequiresRole} declarations on MVC handler
 * methods.
 *
 * <p>Both are checked when both are present, and both must pass.
 */
public class NapPermissionInterceptor implements HandlerInterceptor {

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        if (!(handler instanceof HandlerMethod handlerMethod)) {
            return true;
        }

        RequiresPermission permissionAnnotation = findAnnotation(handlerMethod);
        RequiresRole roleAnnotation = findRoleAnnotation(handlerMethod);
        if (permissionAnnotation == null && roleAnnotation == null) {
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

        return true;
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
