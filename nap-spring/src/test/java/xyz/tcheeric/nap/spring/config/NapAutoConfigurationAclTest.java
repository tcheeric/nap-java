package xyz.tcheeric.nap.spring.config;

import org.junit.jupiter.api.Test;
import xyz.tcheeric.nap.core.AclDecision;
import xyz.tcheeric.nap.server.AclResolver;
import xyz.tcheeric.nap.server.AllowAllAclResolver;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The auto-configuration must not hand out authorization by default (#30).
 *
 * <p>The previous default {@link AllowAllAclResolver} authorized every principal who could prove
 * key control, and nothing reported it. An operator wired NAP, logged in with their own key, saw
 * a session, and shipped, with the authorization layer a silent no-op.
 *
 * <p>Exercised against the bean method directly rather than through a Spring context: this module
 * does not depend on spring-boot-test, and adding that dependency to assert a two-branch guard
 * would cost more than it proves. The {@code @ConditionalOnMissingBean} half (an application's own
 * resolver wins) is Spring's behaviour and not this class's to re-test.
 */
class NapAutoConfigurationAclTest {

    private final NapAutoConfiguration autoConfiguration = new NapAutoConfiguration();

    @Test
    void refusesToBuildAResolverWithoutAnExplicitOptIn() {
        assertThatThrownBy(() -> autoConfiguration.aclResolver(propertiesWithAllowAll(null)))
                .isInstanceOf(IllegalStateException.class)
                // The message has to name the property and the escape hatch, since the whole
                // problem was that the previous behaviour was invisible.
                .hasMessageContaining("nap.allow-all-principals")
                .hasMessageContaining("AclResolver");
    }

    @Test
    void refusesWhenTheOptInIsExplicitlyFalse() {
        assertThatThrownBy(() -> autoConfiguration.aclResolver(propertiesWithAllowAll(false)))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void buildsAllowAllWhenItIsAskedForExplicitly() {
        AclResolver resolver = autoConfiguration.aclResolver(propertiesWithAllowAll(true));

        assertThat(resolver).isInstanceOf(AllowAllAclResolver.class);

        // Still allow-all, which is the point: the behaviour is unchanged, only the way you
        // arrive at it is.
        AclDecision decision = resolver.resolve("npub1anyone", "a".repeat(64));
        assertThat(decision.allowed()).isTrue();
        assertThat(decision.roles()).isEmpty();
        assertThat(decision.permissions()).isEmpty();
    }

    private static NapProperties propertiesWithAllowAll(Boolean allowAllPrincipals) {
        return new NapProperties(
                true, "https://account.imani.casa",
                60, 3600, 900, 43200, 30, 60, 600, 0, 300,
                null, 0, 0, null, null, null, null, null, 0,
                List.of(),
                List.of("/internal/v1/merchants"),
                false,
                allowAllPrincipals,
                new NapProperties.CookieProperties("session", true, true, "Lax", "/", "", 43200));
    }
}
