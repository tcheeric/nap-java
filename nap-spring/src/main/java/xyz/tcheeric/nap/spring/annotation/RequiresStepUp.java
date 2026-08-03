package xyz.tcheeric.nap.spring.annotation;

import java.lang.annotation.*;

/**
 * Marks an endpoint as requiring a step-up re-authentication token.
 *
 * <p>On a controller class it covers every handler in it, matching
 * {@code @RequiresPermission} and {@code @RequiresRole}.
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface RequiresStepUp {
}
