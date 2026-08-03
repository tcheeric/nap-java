package xyz.tcheeric.nap.core;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

/**
 * Body of {@code POST /auth/complete}.
 *
 * <p>{@code step_up} lives here rather than in the query string because the body
 * is covered by the NIP-98 {@code payload} hash: in transit the flag can neither
 * be added to mint a token the user never asked for, nor stripped to downgrade a
 * step-up to an ordinary login. It also keeps the signed {@code u} tag
 * query-free, and therefore equal to the audience the server computes (RFC §11).
 */
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record AuthCompleteRequest(String challengeId, boolean stepUp) {

    public AuthCompleteRequest(String challengeId) {
        this(challengeId, false);
    }
}
