package xyz.tcheeric.nap.spring.config;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.ConfigurationPropertySource;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Binding-level tests for the session cookie attributes.
 *
 * <p>These go through {@link Binder} rather than calling the record constructor, because the
 * defect they cover only existed under binding. {@code httpOnly} and {@code secure} were
 * primitive {@code boolean}, so Spring materialised them as {@code false} whenever any sibling
 * property was present, while a hand-constructed {@code NapProperties} took the all-absent
 * branch and looked correct. A unit test that never bound anything would have agreed with the
 * broken code.
 */
class NapCookiePropertiesTest {

    private static NapProperties bind(Map<String, Object> properties) {
        ConfigurationPropertySource source = new MapConfigurationPropertySource(properties);
        return new Binder(source).bind("nap", NapProperties.class).get();
    }

    @Test
    @DisplayName("cookie section absent entirely: HttpOnly and Secure are on")
    void defaultsWhenCookieSectionAbsent() {
        NapProperties properties = bind(Map.of("nap.session-ttl-seconds", "900"));

        assertTrue(properties.cookie().httpOnly());
        assertTrue(properties.cookie().secure());
        assertEquals("Lax", properties.cookie().sameSite());
    }

    @Test
    @DisplayName("an unrelated cookie property does not silently clear HttpOnly and Secure")
    void unrelatedCookiePropertyKeepsSecurityAttributes() {
        // The regression. Naming the cookie is the most ordinary reason to touch this section,
        // and it used to strip both protections from the session credential.
        NapProperties properties = bind(Map.of("nap.cookie.name", "merchant_session"));

        assertTrue(properties.cookie().httpOnly(), "HttpOnly must survive a partial cookie config");
        assertTrue(properties.cookie().secure(), "Secure must survive a partial cookie config");
        assertEquals("merchant_session", properties.cookie().name());
    }

    @Test
    @DisplayName("setting only the domain keeps HttpOnly and Secure")
    void domainOnlyKeepsSecurityAttributes() {
        NapProperties properties = bind(Map.of("nap.cookie.domain", "example.test"));

        assertTrue(properties.cookie().httpOnly());
        assertTrue(properties.cookie().secure());
        assertEquals("example.test", properties.cookie().domain());
    }

    @Test
    @DisplayName("an explicit false is still honoured")
    void explicitFalseIsRespected() {
        // The fix must not become an override. Local development over http has to be able to
        // turn Secure off deliberately, otherwise the browser withholds the cookie and the
        // operator's only remaining route is to stop using the property.
        Map<String, Object> config = new HashMap<>();
        config.put("nap.cookie.secure", "false");
        config.put("nap.cookie.http-only", "false");

        NapProperties properties = bind(config);

        assertFalse(properties.cookie().secure());
        assertFalse(properties.cookie().httpOnly());
    }

    @Test
    @DisplayName("maxAge defaulting does not discard the security attributes on the way through")
    void maxAgeDefaultingPreservesSecurityAttributes() {
        // NapProperties rebuilds CookieProperties to fill in maxAge. That copy passes every
        // other field positionally, so it is a second place the attributes could be dropped.
        NapProperties properties = bind(Map.of(
                "nap.session-absolute-ttl-seconds", "3600",
                "nap.cookie.name", "merchant_session"
        ));

        assertEquals(3600, properties.cookie().maxAgeSeconds());
        assertTrue(properties.cookie().httpOnly());
        assertTrue(properties.cookie().secure());
    }
}
