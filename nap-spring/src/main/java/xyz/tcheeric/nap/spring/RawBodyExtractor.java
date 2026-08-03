package xyz.tcheeric.nap.spring;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Produces the exact bytes the NIP-98 {@code payload} tag hashes (RFC §20.2).
 *
 * <p>{@code payload} is {@code sha256(rawBody)}, so this must return the bytes as they
 * arrived. Anything that re-serialises the parsed body — a filter that round-trips JSON for
 * logging, a converter that reads the stream first — produces different bytes and fails
 * every completion with {@code NAP_COMPLETE_PAYLOAD_MISMATCH}.
 *
 * <p>Returns {@code null} when no raw body was captured. That is a wiring error rather than
 * a client error and is reported as one, instead of being folded into the uniform 401.
 *
 * <p>The default reads the attribute {@code NapServletFilter} stores. Bind one only when an
 * application captures the bytes somewhere else.
 */
@FunctionalInterface
public interface RawBodyExtractor {

    byte[] extract(HttpServletRequest request);
}
