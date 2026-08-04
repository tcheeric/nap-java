# NAP Java

Java implementation of the **Nostr Authentication Protocol (NAP) v2** — challenge/response
login with a NIP-98 signed event, server-side sessions, rotating refresh tokens, and
role/permission ACLs. Framework-agnostic core, optional Spring Boot adapter.

Requires Java 21. Current version: `0.5.0`.

## Modules

| Module | What's in it |
| --- | --- |
| `nap-core` | Protocol types, NIP-98 validation, `ChallengeStore` / `SessionStore` / `AclStore` interfaces. No framework. |
| `nap-server` | `NapServer` — challenge issuance, completion verification, refresh rotation. Rate limiting, replay guard, permission registry, in-memory stores. |
| `nap-jdbc` | JDBC-backed stores + Flyway migrations (`V1`–`V3`). |
| `nap-client` | `NapProofBuilder` — builds NIP-98 proofs (used by tests and JVM clients). |
| `nap-spring` | Auto-configuration, `/api/v1/auth/*` controller, servlet filters, `@RequiresPermission`. |
| `nap-it` | Integration tests: round trips, official test vectors, TypeScript client interop, Postgres via Testcontainers. |

Dependency direction is one-way: `core → server → {jdbc, spring}`. Nothing below `nap-spring`
knows about Spring.

## HTTP surface (`nap-spring`)

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/v1/auth/init` | Issue a challenge for an `npub`/`pubkey`. |
| `POST` | `/api/v1/auth/complete` | Verify the NIP-98 proof, set the session cookie. |
| `POST` | `/api/v1/auth/refresh` | Rotate a refresh token (`Authorization: Bearer …`). Opt-in via `nap.refresh-ttl-seconds`. |
| `GET` | `/api/v1/auth/session` | Validate the cookie, slide the idle window, return principal + expiries. |
| `POST` | `/api/v1/auth/logout` | Revoke the session and clear the cookie. |

Auth failures return a uniform `401` — which check failed is not disclosed. Rate limiting
returns `429` with `Retry-After`.

## Spring Boot setup

```xml
<dependency>
  <groupId>xyz.tcheeric</groupId>
  <artifactId>nap-spring</artifactId>
  <version>0.5.0</version>
</dependency>
```

```yaml
nap:
  enabled: true                      # auto-configuration is off unless this is true
  external-base-url: https://example.com
  session-idle-ttl-seconds: 900      # sliding window
  session-absolute-ttl-seconds: 43200
  refresh-ttl-seconds: 0             # 0 = refresh disabled
  protected-path-prefixes: [/api/v1/merchant]
  cookie:
    name: merchant_session
```

Auto-configuration supplies `NapServer`, in-memory stores, an `AllowAllAclResolver`, the
controller, and the permission interceptor — each `@ConditionalOnMissingBean`, so supplying
your own `SessionStore` (e.g. `JdbcSessionStore`) replaces it.

**The two filters are not auto-registered** — a second registration would consume the request
body twice. Register them yourself and pass the settings; there are no defaulting constructors:

```java
new NapServletFilter("/auth/complete", properties.maxBodyBytes()); // suffix match on the URI
new NapSessionFilter(sessionStore, aclResolver, properties.cookie().name(),
                     properties.protectedPathPrefixes(),
                     Duration.ofSeconds(properties.aclRefreshIntervalSeconds()));
```

Guard endpoints with `@RequiresPermission` (preferred), `@RequiresRole`, `@RequiresStepUp`, or
`@RequiresSession` when the endpoint is for signed-in users generally and no permission
distinguishes them.

**A handler that declares none of these is not guarded.** `NapSessionFilter` populates the
`SecurityContext` on `nap.protected-path-prefixes` but lets unauthenticated requests through, and
the interceptor only rejects handlers that declare a requirement — so a protected prefix means
"authenticate here if you can", not "login required". `@RequiresSession` is how a handler says
the latter.

## Persistence

`nap-jdbc` expects the migrations in `nap-jdbc/src/main/resources/db/migration`. Run all three
— `V3` adds the sliding-window and refresh-token columns the session store reads.

## Build

```bash
mvn -q test      # unit tests
mvn -q verify    # + integration tests (Docker required for Testcontainers)
```

## Specification

The protocol spec lives in the sibling `nap` repo: `docs/NAP-v2-RFC.md`. That repo also holds
the TypeScript implementation of the same protocol — the two must stay wire-compatible.
