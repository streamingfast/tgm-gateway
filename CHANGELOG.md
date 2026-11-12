# Change log

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html). See [MAINTAINERS.md](./MAINTAINERS.md)
for instructions to keep up to date.

## Unreleased

* Metering emitter shutdown lines (`received shutdown signal`, `waiting for event flush to complete`, `event flushed`, `sending last events`) and session pool `borrowed worker` are now logged at `Debug`. Substreams tier2 creates an emitter per job, so the four shutdown lines fired for every job.

* `tgm` authenticator now sets the `x-auth-method`, `x-auth-jwt-lifetime-bucket`, `x-auth-jwt-iat` and `x-auth-jwt-exp` trusted headers (JWT details reflect the token presented by the client, not the reissued one, and are absent for API key requests). Adds the `auth_payment_gateway_auth_counter` metric.

* Bump `github.com/streamingfast/dauth` for the new `x-auth-*` trusted header constants.

## v0.0.1

* Multiple rename of `User` to `Organization`, simple rename, should be easy to spot them on upgrade and simply change the name, all behavior remain the same.