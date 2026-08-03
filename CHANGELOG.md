# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
