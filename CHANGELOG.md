# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Wire and behavioural parity with the TypeScript workspace's unreleased security
hardening. A TS client asking for a step-up, or reading a 429, now works against a
Java server; before this it did not.

### Added

- **Pluggable rate limiting** (RFC §17.1). `RateLimiter` is `{ check(RateLimitKey) }`,
  where the key carries the scope (`init` / `complete`), npub, proved pubkey, and caller
  address. `InMemoryRateLimiter` is a single-process fixed-window implementation; behind
  N instances the effective rate is N× the configured one, so multi-instance deployments
  want a shared backend behind the same interface. **On by default** — the response floor
  below holds every unauthenticated request open, which without a limiter is a concurrency
  amplifier rather than a timing defence. `.rateLimiter(null)`, or
  `nap.rate-limit-enabled=false`, opts out deliberately. `NapAuthController` maps
  `NAP_INIT_RATE_LIMITED` / `NAP_COMPLETE_RATE_LIMITED` to **429 with `Retry-After`**
  rather than the usual 401 — rate limiting is not an authentication failure, and hiding
  it behind one only makes clients retry harder.

  `/auth/complete` is checked twice: once on caller address before the proof, and again
  on the proved pubkey after it. The first check has nothing to key on when an adapter
  reports no address, which would otherwise leave the one endpoint that runs a Schnorr
  verify per call unbounded.
- **Outstanding-challenge caps** (RFC §17.4). `maxOutstandingChallengesPerNpub`
  (default 10) and `maxOutstandingChallengesPerIp` (default 30) bound how many unredeemed,
  unexpired challenges one principal or address may hold. Exceeding either returns
  `NAP_INIT_RATE_LIMITED` — a distinct code would tell the caller how to spread load to
  evade the cap.
- **Challenge failure budget** (RFC §13.4). `maxFailuresPerChallenge` (default 5) moves a
  challenge to `failed_terminal`, after which further attempts get the new
  `NAP_COMPLETE_FAILED_TERMINAL`. Counted only for proof failures after the challenge is
  loaded and matched, so a wrong `challenge_id` cannot burn down another principal's live
  challenge, and an ACL denial — deterministic, not a guessing attack — does not spend it.
- **Response timing floor** (RFC §15). `minAuthResponseMillis` (default 100) and
  `responseJitterMillis` (default 25) hold every auth response to a fixed floor plus
  jitter, including the path where the store throws — an unpadded 500 next to padded 401s
  is itself a distinguishable response. The generic 401 hides which check failed; latency
  did not. Jitter alone would not close it (it hides samples, not the mean), so the floor
  does the work. Set `.minAuthResponseMillis(0)` in tests.
- **Request body limit** (RFC §17.4). `NapServletFilter` caps `/auth/complete` at
  **1 kB** and answers 413 above it, reading one byte past the cap so an oversized body is
  detected without being buffered. A valid body is ~40 bytes. `nap.max-body-bytes` carries
  the value to the application's own filter registration — the auto-configuration
  deliberately does not register the filter, since a second registration would consume the
  request body twice.
- **`AclDecision.revokeSessions`**, gating mass revocation. `NapSessionFilter` ends the
  session on an ACL denial only when the resolver sets it — `RegistryAclResolver` does so
  for `suspended` and nothing else. A resolver that answers "denied" because it could not
  *read* the ACL (a lagging replica, a row mid-rewrite) denies the one request and no
  more; the alternative turns a transient store problem into a forced NIP-98 re-login for
  everyone.
- `ChallengeStore.countOutstanding()` and `ChallengeStore.recordFailure()`, implemented by
  the in-memory and JDBC stores. Both are `default` methods, so existing custom stores
  keep compiling.
- `clientIp` on `IssueChallengeInput` and `VerifyCompletionInput`; `NapAuthController`
  passes `request.getRemoteAddr()`.

### Changed

- **Step-up moved from `?step_up=true` to the request body**, matching the TypeScript
  change. `AuthCompleteRequest` carries `stepUp`, so the flag is covered by the NIP-98
  `payload` hash and can no longer be added in transit to mint a token the user never
  asked for, nor stripped to downgrade a step-up to an ordinary login. It also keeps the
  signed `u` tag query-free and therefore equal to the audience the server computes, which
  RFC §11 requires. A non-boolean `step_up` is rejected rather than coerced.

  The resulting session carries `step_up_token` / `step_up_expires_at`
  (`stepUpTtlSeconds`, default 600), now emitted by `toPublicAuthSuccess()` and persisted
  by `JdbcSessionStore` — which was dropping both columns on insert.
- **`NapPermissionInterceptor` enforces step-up**, via `@RequiresStepUp` or a permission
  the registry marks `stepUpRequired`, so it need not be repeated at every call site.
  Tokens compare with `MessageDigest.isEqual`; guards run outside the auth endpoints'
  response floor, so a comparison that short-circuits on the first differing byte had
  nothing smoothing it out.
- **`challengeTtlSeconds` is now validated** (RFC §10.1). `NapServerOptions.build()`
  throws for a value outside `1..60` instead of silently issuing a non-conformant
  challenge; a longer TTL widens the window in which a captured proof is replayable.
  A deployment that had set it above 60 will now fail to start.
- `AclDecision.denied(reason)` retains the reason. It was accepted and discarded.
- **The per-npub budgets are scoped to the caller address.** Both the outstanding-challenge
  cap (RFC §17.4) and `InMemoryRateLimiter`'s `npub` dimension now count per address rather
  than globally. An npub is public and `/auth/init` is unauthenticated, so a global
  per-npub budget was a lockout primitive: anyone could spend a stranger's and keep them
  from logging in. The per-address cap already bounds total storage, which is what the cap
  is for. The `pubkey` dimension keeps a global budget — it only appears once a NIP-98
  proof has established the caller holds the key. New
  `OutstandingChallengeFilter.forNpubAtClientIp(npub, clientIp, now)`.
- **`/auth/complete` spends the caller address's budget once per request.** The post-proof
  limiter check no longer repeats `clientIp`, which was halving the configured per-address
  rate and unevenly: a request rejected before the proof cost one, a request that got
  through cost two.
- **A rate-limited response is no longer padded** to `minAuthResponseMillis`. A 429 is
  already distinguishable by its status code, so the floor hid nothing there and only gave
  a caller who was over the limit a free hold on a request thread — the amplification the
  limiter exists to prevent. The 401 paths are padded exactly as before.
- **`@RequiresStepUp` is allowed on a controller class**, matching `@RequiresPermission`
  and `@RequiresRole`; `NapPermissionInterceptor` looks at the method and then the bean
  type. Previously class-level use failed to compile.
- **A suspended principal loses every session, not just the requesting one.**
  `NapSessionFilter` calls `revokeByPrincipal` where it called `revokeBySessionId`, which
  is what its javadoc already promised and what the TypeScript filter does.

### Fixed

- **A challenge's failure budget can no longer be spent by anyone but its principal**
  (RFC §13.4). The challenge-value check ran before the principal check, so a proof signed
  by any key could burn a challenge to `failed_terminal`. A `challenge_id` is not a secret
  — it travels in the clear and the client hands it back — so anyone who had seen one
  could deny the rightful holder their login. `NAP_COMPLETE_PRINCIPAL_MISMATCH` now
  returns without touching the counter.
- **The outstanding-challenge cap now sends `Retry-After`.** It denied with a plain
  failure, so the adapter emitted a 429 with no header and a caller who legitimately hit
  the cap could only guess. It now reports the challenge TTL, which is when a slot frees.
- **An oversized npub is dropped from the rate-limit key** rather than used as a map key.
  It reaches the limiter before `decodeNpub` has looked at it, so it is still arbitrary
  caller input at that point. Dropped, not truncated: truncation would let two distinct
  npubs share one budget.
- `V2__nap_security_hardening.sql` declares `client_ip` as `TEXT`. A bounded `VARCHAR(64)`
  would turn an over-long value from the adapter's trust policy into a 500 on `/auth/init`.

### Migration

- **JDBC users must run `V2__nap_security_hardening.sql`** before deploying: it adds
  `client_ip` and `failure_count` to `nap_challenges` plus two partial indexes on
  `state = 'issued'`. The indexes are not optional in practice — `countOutstanding()`
  runs on every `/auth/init`.
- **Rate limiting is now on by default.** Deployments wanting the previous unlimited
  behaviour must say so with `nap.rate-limit-enabled=false`. The default is a
  single-process in-memory limiter at 30 requests per identifier per 60 s — behind a load
  balancer that is 30 × N.
- **`POST /auth/complete` no longer reads `?step_up=true`.** Clients must move the flag
  into the signed body. A client that keeps sending the query parameter gets an ordinary
  session with no step-up token, not an error.
- **Custom `AclResolver` implementations must set `revokeSessions` on denials** that
  should end the principal's sessions. Without it a denial blocks the request but leaves
  sessions alive until they expire.
- **Custom `ChallengeStore` implementations keep compiling**, but one that does not
  override `countOutstanding()` / `recordFailure()` silently skips the corresponding cap.
  A store that cannot count cannot cap.

## [0.2.0] - 2026-08-03

### Added

- `@RequiresRole` annotation and interceptor support, guarding a handler on role
  membership. Values are any-of — `@RequiresRole({"admin", "owner"})` admits a session
  holding either — since a handler cannot stack the annotation. Where both
  `@RequiresPermission` and `@RequiresRole` are present, both must pass.
  Documented as the second choice: a role is a named set of permissions, so a
  permission guard absorbs a new role through one registry edit where a role guard
  must be edited at every site (RFC §15.1).
- `GET /auth/session` now returns `status`, `principal` (`npub`, `pubkey`), `roles`,
  and `permissions`, matching the shape the TypeScript browser client reads.

### Changed

- `NapSessionFilter.NapAuthenticationToken.toRoleAuthority` widened from private to
  public, so the interceptor resolves `@RequiresRole` through the same role-to-authority
  mapping that populated the authorities rather than duplicating the prefix and casing.

### Fixed

- **`@imani/nap-client-web` could not resume a session against a Java server.** Its
  `toSessionState()` dereferences `response.principal.pubkey`, and `GET /auth/session`
  returned only `pubkey`, `expires_at`, and `absolute_expiry_at`. The added fields are
  additive: `pubkey` and `absolute_expiry_at` are retained, so existing JVM consumers
  are unaffected.

### Security

- Added a regression test asserting `GET /auth/session` returns neither `access_token`
  nor `step_up_token`. The behaviour was already correct; the test prevents a future
  change from echoing a credential into a JSON body, where script could read it. The
  session id is carried in an HttpOnly cookie.

## [0.1.1] - 2026-05-09

Initial published release of the Java NAP v2 implementation: `nap-core`, `nap-server`,
`nap-jdbc`, `nap-client`, `nap-spring`, and the `nap-it` integration suite.

[Unreleased]: https://github.com/tcheeric/nap-java/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/tcheeric/nap-java/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/tcheeric/nap-java/releases/tag/v0.1.1
