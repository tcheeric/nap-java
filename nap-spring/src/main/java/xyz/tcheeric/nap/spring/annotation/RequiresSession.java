package xyz.tcheeric.nap.spring.annotation;

import java.lang.annotation.*;

/**
 * Marks an endpoint as requiring nothing more than a valid session — the caller is logged in.
 *
 * <p>The authentication-only guard, for handlers that are for signed-in users generally and have
 * no permission that distinguishes them. Without it the way to express that is a placeholder
 * permission granted to everyone, which puts a key in the registry that gates nothing and reads,
 * to everyone after you, as though it does.
 *
 * <p>Note that a handler carrying <em>no</em> NAP annotation is not guarded at all:
 * {@code NapSessionFilter} populates the {@code SecurityContext} on
 * {@code nap.protected-path-prefixes} but lets an unauthenticated request through, and
 * {@code NapPermissionInterceptor} only rejects handlers that declare a requirement. A prefix in
 * {@code nap.protected-path-prefixes} therefore means "authenticate here if you can", not
 * "login required" — this annotation is how a handler says the latter.
 *
 * <p>On a controller class it covers every handler in it, matching {@code @RequiresPermission},
 * {@code @RequiresRole} and {@code @RequiresStepUp}.
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface RequiresSession {
}
