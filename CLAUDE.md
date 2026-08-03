# CLAUDE.md

This file provides guidance to Claude Code when working with code in this repository.

## Project Overview

`nap-java` is the standalone Java NAP v2 library extracted from gateway session-management code.

## Build Commands

```bash
mvn -q test
mvn -q verify
```

## Module Structure

```text
nap-java/
├── nap-core
├── nap-server
├── nap-jdbc
├── nap-client
├── nap-spring
└── nap-it
```

## Design Notes

- Keep the core modules framework-agnostic.
- Spring-specific behavior belongs in `nap-spring`.
- Treat challenge/session semantics as protocol contracts.

## Cross-Implementation Compatibility

`nap` (sibling repo, `@imani/nap-*`) is the TypeScript implementation of the same
protocol. **The two must stay wire-compatible: a protocol change here needs the
matching change there, or clients break across implementations.**

The specification is `docs/NAP-v2-RFC.md` **in the `nap` repo** — this repo carries
no copy, so it is the single source of truth for both. `docs/NAP-INTEGRATION-GUIDE.md`
there records where each implementation diverges from it.

Compatibility notes worth knowing before touching the HTTP surface:

- **`GET /auth/session` response is a shared contract.** The browser client's
  `toSessionState()` dereferences `response.principal.pubkey`, so `principal`,
  `roles`, and `permissions` must be present. This repo also returns `pubkey` and
  `absolute_expiry_at`, which the TypeScript side does not — additive fields are
  fine, missing ones are not.
- **Never echo `access_token` from `/auth/session`.** The session id is an HttpOnly
  cookie; putting a credential in a JSON body makes it readable by script.
- **Features this implementation has and TypeScript does not**: sliding idle window,
  `absolute_expiry_at`, and typed 401 reasons (`invalid` / `expired`). These are
  additive and safe — the TypeScript client only branches on the 401 status, not the
  body.
- **`@RequiresPermission` over `@RequiresRole`.** See RFC §15.1 and the annotation's
  javadoc: role guards invert the direction of change and fail silently when a new
  role is added.
