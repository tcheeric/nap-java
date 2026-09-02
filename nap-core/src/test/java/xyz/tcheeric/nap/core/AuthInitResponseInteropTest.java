package xyz.tcheeric.nap.core;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Wire compatibility of {@code /auth/init} with the TypeScript implementation.
 *
 * <p>RFC §24.3 permits additive fields, but a field is only additive if the other
 * implementation tolerates it. Both halves of that are tested here, because both were broken:
 *
 * <ul>
 *   <li>Reading: Jackson's default is to throw on an unknown property, so a Java client failed
 *       with {@code UnrecognizedPropertyException} the moment a TypeScript server began
 *       advertising {@code supported_extensions}.</li>
 *   <li>Writing: a record component serialises as {@code null} by default, and the TypeScript
 *       field is optional ({@code supported_extensions?: string[]}) with <em>absence</em>
 *       meaning "the server makes no claim". Sending an explicit null violates that type and
 *       reads as a claim to any client testing for the key rather than its value.</li>
 * </ul>
 */
class AuthInitResponseInteropTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void readsAResponseFromAServerThatAdvertisesExtensions() throws Exception {
        String json = """
                {"challenge_id":"c1","challenge":"abc",
                 "auth_url":"https://api.example.com/auth/complete","auth_method":"POST",
                 "issued_at":1710000000,"expires_at":1710000060,
                 "supported_extensions":["voucher-acl/1"]}""";

        AuthInitResponse parsed = mapper.readValue(json, AuthInitResponse.class);

        assertThat(parsed.challengeId()).isEqualTo("c1");
        assertThat(parsed.supportedExtensions()).containsExactly("voucher-acl/1");
    }

    @Test
    void readsAResponseFromAServerThatPredatesTheField() throws Exception {
        // Absence means "makes no claim", not "supports nothing". A client must treat null as
        // unknown and try, or every server older than the field is locked out of extensions it
        // may well support.
        String json = """
                {"challenge_id":"c1","challenge":"abc",
                 "auth_url":"https://api.example.com/auth/complete","auth_method":"POST",
                 "issued_at":1710000000,"expires_at":1710000060}""";

        assertThat(mapper.readValue(json, AuthInitResponse.class).supportedExtensions()).isNull();
    }

    @Test
    void toleratesAFieldThisVersionHasNeverHeardOf() throws Exception {
        // The general property, not just the one field that broke. Whatever §24.3 adds next
        // must not take this client down.
        String json = """
                {"challenge_id":"c1","challenge":"abc",
                 "auth_url":"https://api.example.com/auth/complete","auth_method":"POST",
                 "issued_at":1710000000,"expires_at":1710000060,
                 "some_field_from_the_future":{"nested":true}}""";

        assertThat(mapper.readValue(json, AuthInitResponse.class).challengeId()).isEqualTo("c1");
    }

    @Test
    void omitsTheExtensionsFieldRatherThanSendingNull() throws Exception {
        AuthInitResponse response = new AuthInitResponse(
                "c1", "abc", "https://api.example.com/auth/complete", "POST", 1L, 2L);

        assertThat(mapper.writeValueAsString(response)).doesNotContain("supported_extensions");
    }

    @Test
    void emitsTheFieldWhenThereIsSomethingToAdvertise() throws Exception {
        AuthInitResponse response = new AuthInitResponse(
                "c1", "abc", "https://api.example.com/auth/complete", "POST", 1L, 2L,
                List.of("voucher-acl/1"));

        assertThat(mapper.writeValueAsString(response))
                .contains("\"supported_extensions\":[\"voucher-acl/1\"]");
    }

    @Test
    void roundTripsThroughTheSixArgumentForm() throws Exception {
        // The six-argument constructor is kept so an additive protocol field does not become a
        // breaking API change for callers with nothing to advertise -- which is every caller
        // today.
        AuthInitResponse original = new AuthInitResponse(
                "c1", "abc", "https://api.example.com/auth/complete", "POST", 1L, 2L);

        AuthInitResponse parsed =
                mapper.readValue(mapper.writeValueAsString(original), AuthInitResponse.class);

        assertThat(parsed).isEqualTo(original);
    }
}
