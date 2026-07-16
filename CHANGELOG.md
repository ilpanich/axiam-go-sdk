# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
