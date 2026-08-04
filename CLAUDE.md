# CLAUDE.md

Guidance for Claude Code in this repository. Read `README.md` first for module layout,
endpoints, and configuration — this file only covers what that doesn't.

## Build

```bash
mvn -q test      # unit tests
mvn -q verify    # + nap-it (Docker required for Testcontainers)
```

## Layering

`nap-core → nap-server → {nap-jdbc, nap-spring}`, one-way. Keep the core modules
framework-agnostic; anything that imports Spring or `jakarta.servlet` belongs in `nap-spring`.
An abstraction that exists so `nap-server` can stay framework-free (`AclResolver`,
`RateLimiter`, `MetricsRecorder`, `EventReplayGuard`) is load-bearing, not speculative.

## Cross-implementation compatibility

`nap` (sibling repo at `../nap`, `@imani/nap-*`) is the TypeScript implementation of the same
protocol. **The two must stay wire-compatible: a protocol change here needs the matching change
there, or clients break across implementations.**

`docs/NAP-v2-RFC.md` **in the `nap` repo** is the single source of truth — this repo carries no
copy. `docs/NAP-INTEGRATION-GUIDE.md` there records where each implementation diverges.

Before touching the HTTP surface:

- **`GET /api/v1/auth/session` is a shared contract.** The browser client's `toSessionState()`
  dereferences `response.principal.pubkey`, so `principal`, `roles`, and `permissions` must be
  present. This repo also returns `pubkey` and `absolute_expiry_at`, which TypeScript does not
  — additive fields are fine, missing ones are not.
- **Never echo `access_token` from `/auth/session`.** The session id is an HttpOnly cookie;
  putting a credential in a JSON body makes it readable by script.
- **Java-only, additive, safe**: sliding idle window, `absolute_expiry_at`, typed 401 reasons
  (`invalid` / `expired`). The TypeScript client branches on the 401 status, not the body.

## Protocol invariants

Treat these as contracts, not implementation details — tests in `nap-it` and
`NapServerHardeningTest` exist because each one was once wrong:

- **Uniform failures.** Auth failures return one 401 body regardless of which check failed,
  padded to `minAuthResponseMillis` plus jitter. Which check failed is the attacker's question.
  Rate limiting is the deliberate exception — it returns 429 so clients back off.
- **Refresh rotation.** A refresh retires the presented token and re-reads the ACL. A failed
  refresh must not clear the session cookie (a cross-site POST would otherwise log everyone
  out).
- **Cookie set and clear go through the same builder.** A browser matches a deletion on
  name + domain + path; a clear that omits `domain` leaves the cookie in place.
- **`@RequiresPermission` over `@RequiresRole`.** RFC §15.1 and the annotation javadoc: role
  guards invert the direction of change and fail silently when a new role is added.

## Spring gotchas

- Auto-configuration is gated on `nap.enabled=true` and deliberately does **not** register
  `NapServletFilter` / `NapSessionFilter` — the application does. Neither has a defaulting
  constructor, so a missed setting is a compile error rather than a config value silently
  never applied. Don't "helpfully" add filter beans or defaulting constructors back.
- `NapProperties` uses boxed fields where `0` is a meaningful value (caps disabled, padding off
  in tests) and unboxed `int` with a `<= 0 means unset` convention elsewhere. Keep that split.

## Schema

`nap-jdbc` migrations are additive and published: `V1` → `V3`. Change the schema by adding
`V4`, never by editing an existing migration — deployments have already run them.
