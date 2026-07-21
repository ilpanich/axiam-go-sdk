# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0-alpha15] - 2026-07-21

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha12.

## [1.0.0-alpha12] - 2026-07-19

### Fixed

- Supply organization context for login/refresh (CONTRACT §5.1) (#11)

## [1.0.0-alpha11] - 2026-07-18

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha10.

## [1.0.0-alpha10] - 2026-07-18

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha9.

## [Unreleased]

### Added

- gRPC `GetUserInfo` (CONTRACT.md §1.1, contract 1.3). The new
  `axiamgrpc.NewUserInfoClient(conn, refreshFn)` wraps the committed
  `axiam.v1.UserInfoService` stub and exposes `GetUserInfo(ctx) (UserInfo, error)`,
  the low-latency gRPC counterpart of the server's REST `GET /oauth2/userinfo`
  endpoint. It reuses the **same** gRPC channel and auth + `x-tenant-id`
  interceptor as `CheckAccess`, sends an empty request (identity is derived
  server-side from the bearer token), maps terminal gRPC statuses through the
  shared §2 taxonomy helper, and drives the same single-flight refresh with a
  one-shot retry on `UNAUTHENTICATED` (§9). The returned `UserInfo` carries the
  always-present `Sub`/`TenantID`/`OrgID` plus the scope-gated optional
  `Email`/`PreferredUsername` (`*string`, nil when absent). Vendored
  `proto/axiam/v1/userinfo.proto` and the committed
  `internal/gen/axiam/v1/userinfo*.pb.go` stubs were added; `CONTRACT.md` was
  re-synced to contract 1.3.

- Client-certificate / mutual-TLS (mTLS) support (CONTRACT.md §6.1). The new
  `axiam.WithClientCertificate(certPEM, keyPEM []byte)` option configures a
  PEM X.509 identity (cert chain + PKCS#8/PKCS#1 private key) that the SDK
  presents on **both** the REST transport and any gRPC channel of the same
  logical client. An invalid cert/key pair is a construction-time error from
  `NewClient`, matching `WithCustomCA`. The private key is held behind the
  `Sensitive` type and never logged/displayed, with no public getter.
  Presenting a client certificate never relaxes server verification (the
  TLS-1.3 floor and strict `RootCAs` behavior are unchanged). The gRPC entry
  point `axiamgrpc.NewTLSCredentials` now accepts the same client cert/key
  PEMs as additional (optional) arguments so the identity is applied over
  gRPC too.

### Added

- Declarative authorization helpers (CONTRACT.md §11): `middleware.RequireAuth`,
  `middleware.RequireAccess`, and `middleware.RequireRole` add a per-route
  authorization layer on top of the existing §10 `middleware.Middleware` guard,
  along with `middleware.ResourceFromPath`/`middleware.StaticResource` resource
  resolvers and the `middleware.AccessChecker` interface. `RequireAccess` fails
  closed (503) on any transport failure while calling the authz endpoint and
  never caches decisions.
- `Client.CheckAccessAs` — additive alongside the existing `CheckAccess`,
  performs an authorization check on behalf of an explicit subject id so the
  new middleware helpers can check the request's authenticated user rather
  than the application's own client session.
- Extended the `examples/middleware-guard` example with a `RequireAccess`-
  protected `GET /docs/{id}` route.

## [1.0.0-alpha] - 2026-07-15

First alpha release of the official Go client SDK for AXIAM. This is an early,
pre-production preview published via the Go module proxy for evaluation and
feedback — the public API may still change before the beta and stable releases.

### Added

- REST client covering the AXIAM API surface (authentication, authorization
  checks, tenant/user/role/resource management).
- gRPC client for low-latency authorization checks (generated stubs committed
  and drift-checked against the protos).
- HTTP middleware guard for protecting application routes.
- Strict TLS by default with no certificate-verification bypass surface.
- Runnable examples, including the middleware-guard integration.

[1.0.0-alpha]: https://github.com/ilpanich/axiam-go-sdk/releases/tag/v1.0.0-alpha
