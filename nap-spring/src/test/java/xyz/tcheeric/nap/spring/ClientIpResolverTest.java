package xyz.tcheeric.nap.spring;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

/**
 * The rate limiter counts against a client address, and this class decides what that address is.
 *
 * <p>Two failure modes sit either side of the correct answer, and a fix for one is the other:
 *
 * <ul>
 *   <li>Trust nothing and behind a proxy every caller is the proxy, so they share a bucket and the
 *       limit becomes a lockout an attacker triggers for everybody.</li>
 *   <li>Trust {@code X-Forwarded-For} from anyone and a caller mints a fresh bucket per request,
 *       so the limit is gone.</li>
 * </ul>
 *
 * <p>These tests pin both walls.
 */
class ClientIpResolverTest {

    @Test
    void remoteAddrReportsThePeer() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("203.0.113.7");

        assertEquals("203.0.113.7", ClientIpResolver.remoteAddr().resolve(request));
    }

    @Test
    void remoteAddrIgnoresForwardedHeader() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("203.0.113.7");
        request.addHeader("X-Forwarded-For", "198.51.100.9");

        assertEquals("203.0.113.7", ClientIpResolver.remoteAddr().resolve(request),
                "the default must never read a header the caller controls");
    }

    /**
     * The forgery wall. An untrusted caller sending its own X-Forwarded-For must not be able to
     * pick its own bucket, or it evades the limit entirely by varying the header per request.
     */
    @Test
    void forwardedHeaderFromAnUntrustedPeerIsIgnored() {
        ClientIpResolver resolver = ClientIpResolver.forwardedFor(List.of("10.0.0.1"));

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("203.0.113.7");           // direct caller, not our proxy
        request.addHeader("X-Forwarded-For", "1.2.3.4"); // self-asserted

        assertEquals("203.0.113.7", resolver.resolve(request),
                "a header relayed by an untrusted peer must be discarded");
    }

    @Test
    void forgedBucketsCollapseToOneWhenPeerIsUntrusted() {
        ClientIpResolver resolver = ClientIpResolver.forwardedFor(List.of("10.0.0.1"));

        String first = resolveWith(resolver, "203.0.113.7", "1.1.1.1");
        String second = resolveWith(resolver, "203.0.113.7", "2.2.2.2");

        assertEquals(first, second,
                "one attacker varying the header must not obtain two rate-limit buckets");
    }

    /**
     * The lockout wall, and the reason this class exists. Two clients behind the same trusted
     * proxy must resolve to different addresses, or they share a bucket.
     */
    @Test
    void distinctClientsBehindATrustedProxyGetDistinctIdentities() {
        ClientIpResolver resolver = ClientIpResolver.forwardedFor(List.of("10.0.0.1"));

        String alice = resolveWith(resolver, "10.0.0.1", "198.51.100.10");
        String bob = resolveWith(resolver, "10.0.0.1", "198.51.100.11");

        assertEquals("198.51.100.10", alice);
        assertEquals("198.51.100.11", bob);
        assertNotEquals(alice, bob,
                "getRemoteAddr() returned the proxy for both, collapsing them into one bucket");
    }

    /**
     * Right-to-left is the whole trust argument: the rightmost entry was written by the closest
     * hop. A client that prepends fake entries must not shift the answer.
     */
    @Test
    void prependedEntriesFromTheClientAreDiscarded() {
        ClientIpResolver resolver = ClientIpResolver.forwardedFor(List.of("10.0.0.1"));

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("10.0.0.1");
        // The client sent "1.2.3.4, 9.9.9.9"; the proxy appended what it actually saw.
        request.addHeader("X-Forwarded-For", "1.2.3.4, 9.9.9.9, 198.51.100.10");

        assertEquals("198.51.100.10", resolver.resolve(request),
                "only the entry the trusted hop observed may be believed");
    }

    @Test
    void walksBackThroughChainedTrustedProxies() {
        ClientIpResolver resolver = ClientIpResolver.forwardedFor(List.of("10.0.0.1", "10.0.0.2"));

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("10.0.0.1");
        request.addHeader("X-Forwarded-For", "198.51.100.10, 10.0.0.2");

        assertEquals("198.51.100.10", resolver.resolve(request),
                "each trusted hop is skipped until the first address none of them wrote");
    }

    @Test
    void emptyTrustListDegradesToPeer() {
        ClientIpResolver resolver = ClientIpResolver.forwardedFor(List.of());

        assertEquals("203.0.113.7", resolveWith(resolver, "203.0.113.7", "1.2.3.4"),
                "trusting no proxy must behave exactly like remoteAddr()");
    }

    @Test
    void missingOrBlankHeaderFallsBackToPeer() {
        ClientIpResolver resolver = ClientIpResolver.forwardedFor(List.of("10.0.0.1"));

        MockHttpServletRequest noHeader = new MockHttpServletRequest();
        noHeader.setRemoteAddr("10.0.0.1");
        assertEquals("10.0.0.1", resolver.resolve(noHeader));

        MockHttpServletRequest blank = new MockHttpServletRequest();
        blank.setRemoteAddr("10.0.0.1");
        blank.addHeader("X-Forwarded-For", "   ");
        assertEquals("10.0.0.1", resolver.resolve(blank));
    }

    @Test
    void allHopsTrustedMeansTheClientWasNeverRecorded() {
        ClientIpResolver resolver = ClientIpResolver.forwardedFor(List.of("10.0.0.1", "10.0.0.2"));

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("10.0.0.1");
        request.addHeader("X-Forwarded-For", "10.0.0.2");

        assertEquals("10.0.0.1", resolver.resolve(request),
                "falling back to the peer is honest when no client address was observed");
    }

    @Test
    void trustListIgnoresBlankEntriesAndSurroundingWhitespace() {
        // A trailing comma in config must not add "" to the trust set, which would otherwise
        // match nothing but is still worth not carrying around.
        ClientIpResolver resolver =
                ClientIpResolver.forwardedFor(java.util.Arrays.asList(" 10.0.0.1 ", "", null));

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("10.0.0.1");
        request.addHeader("X-Forwarded-For", " 198.51.100.10 ");

        assertEquals("198.51.100.10", resolver.resolve(request));
    }

    private static String resolveWith(ClientIpResolver resolver, String peer, String forwarded) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr(peer);
        request.addHeader("X-Forwarded-For", forwarded);
        return resolver.resolve(request);
    }
}
