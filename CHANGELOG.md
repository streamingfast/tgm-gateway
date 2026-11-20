# Change log

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). See [MAINTAINERS.md](./MAINTAINERS.md)
for instructions to keep up to date.

## Unreleased

* Add `github.com/streamingfast/dhttp` (head) dependency and bump `dgrpc` to head, which upgrades OpenTelemetry modules.

* `tgm` authenticator now rejects requests when the jwt-issuer deterministically denies a JWT reissue (any 4xx except 429: disabled/revoked API key, disabled organization, unknown key, expired JWT) with `PermissionDenied` (403) or `Unauthenticated` (other 4xx), instead of silently continuing with the old token. Fail-open is kept only when the issuer is unavailable (network error, timeout, 5xx, 429) or replies 200 with an invalid token.

* Metering emitter shutdown lines (`received shutdown signal`, `waiting for event flush to complete`, `event flushed`, `sending last events`) and session pool `borrowed worker` are now logged at `Debug`. Substreams tier2 creates an emitter per job, so the four shutdown lines fired for every job.

* `tgm` authenticator now sets the `x-auth-method`, `x-auth-jwt-lifetime-bucket`, `x-auth-jwt-iat` and `x-auth-jwt-exp` trusted headers (JWT details reflect the token presented by the client, not the reissued one, and are absent for API key requests). Adds the `auth_payment_gateway_auth_counter` metric.

* Bump `github.com/streamingfast/dauth` for the new `x-auth-*` trusted header constants.

## v0.0.1

* Multiple rename of `User` to `Organization`, simple rename, should be easy to spot them on upgrade and simply change the name, all behavior remain the same.