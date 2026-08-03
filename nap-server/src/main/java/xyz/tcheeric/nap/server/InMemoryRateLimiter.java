package xyz.tcheeric.nap.server;

import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Single-process fixed-window rate limiter (RFC §17.1).
 *
 * <p>Enough to stop a single client hammering {@code /auth/init}, but the counters live in one
 * process: behind more than one instance each gets its own budget, so the effective rate is the
 * configured one multiplied by the instance count. Multi-instance deployments want a shared
 * backend behind the same {@link RateLimiter} interface.
 *
 * <p>The {@code pubkey} and {@code clientIp} dimensions are counted separately and all of them —
 * one proved principal cycling addresses is still capped, and so is one address cycling
 * principals. The {@code npub} dimension is counted per address instead of globally, because on
 * {@code /auth/init} it is an unproved, public identifier: a global budget for it locks the owner
 * out rather than bounding an attacker, who would simply pick another npub.
 */
public final class InMemoryRateLimiter implements RateLimiter {

    public static final int DEFAULT_WINDOW_SECONDS = 60;
    public static final int DEFAULT_MAX_PER_WINDOW = 30;

    private final int windowSeconds;
    private final int maxPerWindow;
    private final Clock clock;
    private final Map<String, Window> windows = new ConcurrentHashMap<>();
    private final AtomicLong lastPrunedAt = new AtomicLong(Long.MIN_VALUE);

    private InMemoryRateLimiter(int windowSeconds, int maxPerWindow, Clock clock) {
        this.windowSeconds = windowSeconds;
        this.maxPerWindow = maxPerWindow;
        this.clock = clock;
    }

    public static InMemoryRateLimiter create() {
        return create(DEFAULT_WINDOW_SECONDS, DEFAULT_MAX_PER_WINDOW, Clock.systemUTC());
    }

    public static InMemoryRateLimiter create(int windowSeconds, int maxPerWindow, Clock clock) {
        return new InMemoryRateLimiter(windowSeconds, maxPerWindow, clock);
    }

    @Override
    public RateLimitDecision check(RateLimitKey key) {
        long now = clock.instant().getEpochSecond();
        prune(now);

        List<String> identifiers = new ArrayList<>(3);
        if (key.npub() != null) {
            // Scoped to the address when there is one. The npub on /auth/init is unproved and
            // public, so a budget counting one npub across all addresses is an account-lockout
            // primitive — spend a stranger's thirty requests and they cannot log in. It also
            // caps nothing an attacker cannot sidestep by generating another npub, which costs
            // them nothing. The address dimension below is what actually bounds a flood.
            identifiers.add(key.clientIp() != null
                    ? key.scope() + ":npub:" + key.npub() + "@" + key.clientIp()
                    : key.scope() + ":npub:" + key.npub());
        }
        if (key.pubkey() != null) {
            identifiers.add(key.scope() + ":pubkey:" + key.pubkey());
        }
        if (key.clientIp() != null) {
            identifiers.add(key.scope() + ":ip:" + key.clientIp());
        }
        if (identifiers.isEmpty()) {
            return RateLimitDecision.allow();
        }

        // Every dimension is counted, not just up to the first rejection: an early return
        // would leave the other counters under-counted and let a caller who is already
        // blocked on one dimension build headroom on the others.
        RateLimitDecision worst = RateLimitDecision.allow();
        for (String identifier : identifiers) {
            RateLimitDecision decision = hit(identifier, now);
            if (!decision.allowed()) {
                worst = decision;
            }
        }
        return worst;
    }

    private RateLimitDecision hit(String identifier, long now) {
        Window window = windows.compute(identifier, (id, existing) -> {
            if (existing == null || now - existing.startedAt >= windowSeconds) {
                return new Window(now, 1);
            }
            return new Window(existing.startedAt, existing.count + 1);
        });

        if (window.count > maxPerWindow) {
            return RateLimitDecision.denied(
                    (int) Math.max(1, window.startedAt + windowSeconds - now));
        }
        return RateLimitDecision.allow();
    }

    /**
     * Sweep expired windows so a caller who is gone stops costing memory. Amortised to one
     * pass per clock tick — the map is only ever read through {@link #hit}, which starts a
     * fresh window for an expired entry anyway, so pruning is housekeeping, not correctness.
     */
    private void prune(long now) {
        long previous = lastPrunedAt.get();
        if (now <= previous || !lastPrunedAt.compareAndSet(previous, now)) {
            return;
        }
        windows.values().removeIf(window -> now - window.startedAt >= windowSeconds);
    }

    private record Window(long startedAt, int count) {
    }
}
