package xyz.tcheeric.nap.server;

import xyz.tcheeric.nap.core.AuthFailureResponse;
import xyz.tcheeric.nap.core.AuthSuccessResponse;
import xyz.tcheeric.nap.core.SessionRecord;

public interface NapServer {

    IssueChallengeResult issueChallenge(IssueChallengeInput input);

    VerifyCompletionOutcome verifyCompletion(VerifyCompletionInput input);

    /**
     * Exchange a refresh token for a fresh access token (RFC §14.1).
     *
     * <p>Rotating: every call retires the presented token and issues a new one, so a stolen
     * token is usable at most once before the theft becomes visible. What makes it visible is
     * that the retired token stays recognisable — presenting it again means two parties hold
     * the lineage, and since the server cannot tell which one is the thief, the session is
     * revoked and both must sign in again.
     *
     * <p>The ACL is re-read on every refresh. A refresh mints a new access token good for the
     * full session TTL, so trusting the login-time snapshot would let a principal suspended an
     * hour ago keep extending their access indefinitely — which is the one thing short
     * access-token lifetimes exist to prevent.
     */
    RefreshSessionOutcome refreshSession(RefreshSessionInput input);

    AuthSuccessResponse toPublicAuthSuccess(SessionRecord session);

    PublicFailureResponse toPublicAuthFailure();

    record PublicFailureResponse(int status, AuthFailureResponse body) {
    }

    static NapServer create(NapServerOptions options) {
        return new DefaultNapServer(options);
    }
}
