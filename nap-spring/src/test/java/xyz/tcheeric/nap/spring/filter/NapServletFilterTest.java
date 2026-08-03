package xyz.tcheeric.nap.spring.filter;

import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The raw-body capture the NIP-98 payload hash depends on, and the cap that bounds it.
 */
class NapServletFilterTest {

    private static final String COMPLETE_PATH = "/api/v1/auth/complete";

    @Test
    void doFilterInternal_capturesTheRawBodyOnTheCompletePath() throws Exception {
        String body = "{\"challenge_id\":\"abc\"}";
        MockHttpServletRequest request = completeRequest(body);
        MockFilterChain chain = new MockFilterChain();

        new NapServletFilter(COMPLETE_PATH).doFilter(request, new MockHttpServletResponse(), chain);

        assertThat((byte[]) request.getAttribute(NapServletFilter.RAW_BODY_ATTRIBUTE))
                .isEqualTo(body.getBytes(StandardCharsets.UTF_8));
        // Downstream still gets to read the body: the wrapper replays the captured bytes,
        // which is the whole reason the filter exists rather than a plain read.
        assertThat(chain.getRequest()).isNotNull();
        assertThat(chain.getRequest().getInputStream().readAllBytes())
                .isEqualTo(body.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void doFilterInternal_rejectsABodyOverTheCap() throws Exception {
        // A valid completion body is ~40 bytes; the cap bounds what an anonymous caller can
        // make the server buffer and hash per request (RFC §17.4).
        MockHttpServletRequest request = completeRequest("x".repeat(2048));
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        new NapServletFilter(COMPLETE_PATH, 1024).doFilter(request, response, chain);

        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE);
        assertThat(chain.getRequest()).isNull();
        assertThat(request.getAttribute(NapServletFilter.RAW_BODY_ATTRIBUTE)).isNull();
    }

    @Test
    void doFilterInternal_acceptsABodyExactlyAtTheCap() throws Exception {
        // Off-by-one guard: the filter reads one byte past the cap to detect an overflow, so
        // the boundary case is the one that would break if that read were miscounted.
        MockHttpServletRequest request = completeRequest("x".repeat(1024));
        MockHttpServletResponse response = new MockHttpServletResponse();

        new NapServletFilter(COMPLETE_PATH, 1024)
                .doFilter(request, response, new MockFilterChain());

        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
        assertThat((byte[]) request.getAttribute(NapServletFilter.RAW_BODY_ATTRIBUTE)).hasSize(1024);
    }

    @Test
    void doFilterInternal_leavesOtherPathsAlone() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/auth/init");
        request.setContent("{\"npub\":\"npub1test\"}".getBytes(StandardCharsets.UTF_8));

        new NapServletFilter(COMPLETE_PATH)
                .doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        assertThat(request.getAttribute(NapServletFilter.RAW_BODY_ATTRIBUTE)).isNull();
    }

    private static MockHttpServletRequest completeRequest(String body) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", COMPLETE_PATH);
        request.setContent(body.getBytes(StandardCharsets.UTF_8));
        return request;
    }
}
