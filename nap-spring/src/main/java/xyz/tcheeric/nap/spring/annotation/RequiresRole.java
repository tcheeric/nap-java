package xyz.tcheeric.nap.spring.annotation;

import java.lang.annotation.*;

/**
 * Marks an endpoint as requiring membership of one of the named NAP roles.
 *
 * <p><strong>Prefer {@link RequiresPermission}.</strong> A role is a named set of
 * permissions — {@code RoleDefinition} is {@code (key, description, permissions)} and the
 * ACL resolver expands roles into the session's permission list at login — so every role
 * check is expressible as a permission check. The two differ in which direction change
 * flows: a guard naming a permission absorbs a new role through one registry edit, while a
 * guard naming a role must itself be edited at every site that should also accept the new
 * role. The registry exists to centralise that mapping, and role guards route around it.
 * The failure is silent: the new role holds every permission it needs and the route still
 * refuses it.
 *
 * <p>Reach for this where the role, not a capability, is the thing being authorised —
 * break-glass and staff-only routes are the usual cases. See RFC §15.1.
 *
 * <p>Multiple values are <em>any-of</em>: {@code @RequiresRole({"admin", "owner"})} admits a
 * session holding either. Stacking annotations is not an option on a single handler, so
 * disjunction has to be expressed here.
 *
 * <p>Role membership carries the same freshness constraint as permissions: where roles are
 * resolved once at login, a revoked role remains effective until the session ends.
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface RequiresRole {
    String[] value();
}
