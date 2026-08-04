package xyz.tcheeric.nap.spring.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;

/**
 * Captures raw request body bytes on the /auth/complete path for NIP-98 payload hash verification.
 *
 * <p>Only activates on the auth complete path to avoid memory pressure from body buffering
 * on high-throughput endpoints.
 *
 * <p>The auto-configuration deliberately does not register this filter, so the application does,
 * and the cap has to be passed at that site:
 *
 * <pre>{@code
 * @Bean
 * FilterRegistrationBean<NapServletFilter> napServletFilter(NapProperties properties) {
 *     var registration = new FilterRegistrationBean<>(
 *             new NapServletFilter("/auth/complete", properties.maxBodyBytes()));
 *     registration.setOrder(Ordered.HIGHEST_PRECEDENCE);
 *     return registration;
 * }
 * }</pre>
 *
 * <p>There is deliberately no constructor that defaults the cap. One used to exist, and a
 * registration that took it silently ignored {@code nap.max-body-bytes} — a deployment that
 * tightened the cap ran on 1024 anyway, and one that raised it 413'd bodies it had configured
 * itself to accept, both without a word. The compiler is the check now.
 */
public class NapServletFilter extends OncePerRequestFilter {

    public static final String RAW_BODY_ATTRIBUTE = "nap.raw.body";

    /**
     * A valid {@code /auth/complete} body is ~40 bytes. The cap (RFC §17.4) bounds what an
     * anonymous caller can make the server buffer and hash per request.
     *
     * <p>This is what {@code nap.max-body-bytes} falls back to when unset, not a default this
     * filter applies on its own — see {@link xyz.tcheeric.nap.spring.config.NapProperties}.
     */
    public static final int DEFAULT_MAX_BODY_BYTES = 1024;

    private final String completePath;
    private final int maxBodyBytes;

    public NapServletFilter(String completePath, int maxBodyBytes) {
        this.completePath = completePath;
        this.maxBodyBytes = maxBodyBytes;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                     FilterChain filterChain) throws ServletException, IOException {
        if (request.getRequestURI().endsWith(completePath)) {
            // Read one byte past the cap so an oversized body is detected without buffering it.
            byte[] body = request.getInputStream().readNBytes(maxBodyBytes + 1);
            if (body.length > maxBodyBytes) {
                response.setStatus(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE);
                return;
            }
            request.setAttribute(RAW_BODY_ATTRIBUTE, body);
            filterChain.doFilter(new CachedBodyRequestWrapper(request, body), response);
        } else {
            filterChain.doFilter(request, response);
        }
    }

    private static class CachedBodyRequestWrapper extends HttpServletRequestWrapper {
        private final byte[] body;

        CachedBodyRequestWrapper(HttpServletRequest request, byte[] body) {
            super(request);
            this.body = body;
        }

        @Override
        public jakarta.servlet.ServletInputStream getInputStream() {
            ByteArrayInputStream bais = new ByteArrayInputStream(body);
            return new jakarta.servlet.ServletInputStream() {
                @Override public int read() { return bais.read(); }
                @Override public boolean isFinished() { return bais.available() == 0; }
                @Override public boolean isReady() { return true; }
                @Override public void setReadListener(jakarta.servlet.ReadListener listener) {}
            };
        }

        @Override
        public BufferedReader getReader() {
            return new BufferedReader(new InputStreamReader(getInputStream()));
        }
    }
}
