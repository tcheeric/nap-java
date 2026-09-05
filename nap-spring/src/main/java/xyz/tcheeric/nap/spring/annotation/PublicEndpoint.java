package xyz.tcheeric.nap.spring.annotation;

import java.lang.annotation.*;

/**
 * Marks a handler as deliberately reachable without a session.
 *
 * <p>Only meaningful under {@code nap.require-annotation-on-protected-paths=true}, where a handler
 * inside {@code nap.protected-path-prefixes} must state its access policy. This is how it states
 * "none".
 *
 * <p>It carries no enforcement of its own: with the default configuration an unannotated handler is
 * already reachable, and this annotation changes nothing about that. What it changes is the
 * reading. Absence of an annotation is ambiguous between "public on purpose" and "someone forgot",
 * and a reviewer cannot tell which from the diff. This makes the first case say so, which leaves
 * the second case as the only unannotated one.
 *
 * @see RequiresSession for the opposite declaration, authentication with no particular permission
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface PublicEndpoint {

    /** Why this endpoint is public, for the reviewer who finds it later. */
    String value() default "";
}
