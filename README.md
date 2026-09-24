# NAP Java

Java implementation of the **Nostr Authentication Protocol (NAP) v2** — challenge/response
login with a NIP-98 signed event, server-side sessions, rotating refresh tokens, and
role/permission ACLs. Framework-agnostic core, optional Spring Boot adapter.

Requires Java 21. Current version: `0.6.2`.

Versions are managed by `imani-bom`; consumers that import it should omit the
version entirely. 0.6.0 added the authorization layer (`AclResolver`,
`PermissionRegistry`, `RoleDefinition`, and the `@RequiresPermission` /
`@RequiresRole` / `@RequiresSession` guards), which 0.1.x does not have.

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
  <version>0.6.2</version>
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
  trusted-proxies: []                # see "Rate limiting behind a proxy" below
  cookie:
    name: merchant_session
```

**You must supply an `AclResolver` bean.** There is no default. The auto-configuration used to
fall back to `AllowAllAclResolver`, which authorizes every principal who can prove key control,
and nothing reported it: you wire NAP, log in with your own key, see a session, and ship with the
authorization layer a no-op. Supply `RegistryAclResolver` (or your own), or set
`nap.allow-all-principals: true` to ask for the old behaviour deliberately.

```java
@Bean
AclResolver aclResolver(AclStore aclStore) {
    return RegistryAclResolver.create(myPermissionRegistry, aclStore, /* autoProvision */ false);
}
```

Auto-configuration supplies `NapServer`, in-memory stores, the controller, and the permission
interceptor — each `@ConditionalOnMissingBean`, so supplying your own `SessionStore` (e.g.
`JdbcSessionStore`) replaces it.

**The in-memory stores are for development.** They are the default because they need no
configuration, and they log a warning at startup saying so. Sessions are lost on restart and are
not shared between instances, which makes revocation per-node: `revokeByPrincipal()` on a
suspension reaches only the instance that served the request, and the principal keeps working
everywhere else until their session expires. Use `JdbcSessionStore` for anything multi-instance.

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

**A handler that declares none of these is refused inside a protected prefix.**
`NapSessionFilter` populates the `SecurityContext` on `nap.protected-path-prefixes` but lets
unauthenticated requests through, and the interceptor is what enforces. Since a handler under a
protected prefix that declares nothing would otherwise be served to anyone,
`nap.require-annotation-on-protected-paths` **defaults to `true`**: an undeclared handler there is
refused with `500` (a wiring bug, not a caller error, so no credential would help). Genuinely
public endpoints stay expressible with `@PublicEndpoint("why")`, which states in the source what
omission used to state only by accident.

Set it to `false` to restore the previous behaviour, where an unannotated handler is public. That
is the configuration in which forgetting an annotation exposes an endpoint with nothing in the
diff to show for it, so prefer `@PublicEndpoint`.

## Rate limiting behind a proxy

The rate limiter counts against a client address, and by default that is `getRemoteAddr()` — the
TCP peer. That is correct only when the client *is* the peer. Behind a reverse proxy the peer is
the proxy, identical for every caller, so the whole client dimension collapses into one bucket:
the first `rate-limit-max-per-window` requests exhaust it and everyone else is refused. An
attacker gets that denial of service for free, and it looks like the limiter working.

Reading `X-Forwarded-For` unconditionally is worse — any caller sets the header themselves and
mints a fresh bucket per request — so the deployment has to say which hops it trusts:

```yaml
nap:
  trusted-proxies: [10.0.0.1]   # addresses of YOUR proxies, not a CIDR of the internet
```

The resolver then walks `X-Forwarded-For` right to left and takes the first address none of those
proxies wrote, which is the first one a hop you trust actually observed. Anything more involved
(PROXY protocol, a CDN header) is a `ClientIpResolver` bean.

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
