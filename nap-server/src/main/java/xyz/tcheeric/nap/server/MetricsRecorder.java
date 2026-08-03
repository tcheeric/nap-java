package xyz.tcheeric.nap.server;

/**
 * Pluggable counter sink (RFC §19.3).
 *
 * <p>Deliberately counters only, and deliberately not a log sink: the values a NAP server
 * would otherwise have to hand a metrics backend — {@code npub}, {@code challenge_id},
 * {@code session_id} — are per-request identifiers, and a label carrying one is unbounded
 * cardinality. §19.2 forbids exporting several of them at all, so this interface offers
 * nowhere to put them.
 *
 * <p>{@link #increment} is called on the request path, so it must not block or throw. The
 * server swallows failures rather than let them fail a login: a metrics backend being down
 * is not a reason to stop authenticating.
 *
 * <p>Defaults to {@link #noop()}, which costs one null check per counted event.
 */
@FunctionalInterface
public interface MetricsRecorder {

    void increment(NapCounter counter);

    static MetricsRecorder noop() {
        return counter -> { };
    }
}
