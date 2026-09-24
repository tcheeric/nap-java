# Upgrading

## 0.8.0 to 0.9.0

Three changes alter behaviour at runtime. Two of them can take an application down at
startup or serve `500`s from handlers that worked yesterday, so read this before deploying
rather than after.

Nothing here needs a database migration. The work is configuration and one unavoidable
logout.

### Before you deploy

Run through these in order. Each is a thing you can check now, on the running system, in
less time than the rollback would take.

**1. Supply an `AclResolver`, or opt in to allowing everyone (#30).**

Auto-configuration used to fall back to `AllowAllAclResolver` in silence, so an application
that never declared one authorised every authenticated principal for everything and gave no
sign of it. Startup now fails instead.

If you have a resolver bean, nothing changes. If you were relying on the old default, say
so explicitly:

```yaml
nap:
  allow-all-principals: true
```

That property exists so the permissive case is a sentence in your configuration rather than
an accident of what you left out. Prefer a real resolver where you can.

**2. Audit handlers under `nap.protected-path-prefixes` (#29).**

`nap.require-annotation-on-protected-paths` now defaults to `true`. A handler under a
protected prefix that carries no NAP annotation is refused with a `500` rather than served
to anyone. A `500` rather than a `403` because the condition is a wiring mistake in the
application, not a decision about the caller: nobody is authorised to reach a handler whose
access rules were never stated.

This only bites if `protected-path-prefixes` is non-empty. If it is, list the handlers
underneath it and give each one an annotation. A genuinely public endpoint says so:

```java
@PublicEndpoint
@GetMapping("/api/health")
public Health health() { ... }
```

To stage the change, set `nap.require-annotation-on-protected-paths: false`, deploy, fix
what the logs show, then remove the property. Leaving it `false` permanently puts you back
where you started, where a new unannotated endpoint is public and nothing says so.

**3. Expect every signed-in user to be logged out once (#27).**

The session cookie now carries the access token rather than the session id. Cookies minted
by 0.8.0 no longer authenticate, so every live session ends the moment the new version
serves traffic. Users log in again with NIP-98 and it does not recur.

There is no compatibility window on offer. Accepting both formats would mean continuing to
accept the session id as a bearer credential, which is the vulnerability being closed.
Schedule accordingly: a quiet hour costs less than the same logout at peak.

**4. Check your `nap.cookie.*` block.**

If you set any property under `nap.cookie`, 0.8.0 silently dropped `HttpOnly` and `Secure`
from the session cookie. That is fixed, and the fix is the safe direction, but it means the
cookie now carries `Secure` where it previously did not, and a browser will not send a
`Secure` cookie over plain `http://`.

Any environment serving over `http` needs to say so:

```yaml
nap:
  cookie:
    secure: false
```

Production should terminate TLS instead.

### Deploying alongside `nap` (TypeScript)

The two implementations now agree on the wire: both put the access token in the cookie and
authenticate with `getByAccessToken()`. Before 0.9.0 they did not, so a cookie minted by one
server could not be presented to the other.

If both run against one session store, deploy `nap-java` 0.9.0 and `nap` 0.11.0 together.
A mixed fleet mid-rollout will reject cookies issued by the other side, which looks like
users being logged out at random rather than once.

### Rolling back

Rolling back to 0.8.0 logs everyone out a second time, for the same reason the upgrade did,
and reopens the session-id-as-credential exposure. If you roll back, treat any session id
that reached a log during the 0.9.0 window as a credential that was written down.

### Verifying afterwards

```bash
curl -si https://your-host/auth/session | grep -i set-cookie
```

You want `HttpOnly`, `Secure`, and a `SameSite` on that line. If `Secure` is missing and you
did not set `nap.cookie.secure: false` on purpose, the configuration is not being read from
where you think it is.
