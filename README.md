# axiam SDK (Go)

[![CI](https://github.com/ilpanich/axiam-go-sdk/actions/workflows/sdk-ci-go.yml/badge.svg?branch=main)](https://github.com/ilpanich/axiam-go-sdk/actions/workflows/sdk-ci-go.yml)
[![Coverage Status](https://coveralls.io/repos/github/ilpanich/axiam-go-sdk/badge.svg?branch=main)](https://coveralls.io/github/ilpanich/axiam-go-sdk?branch=main)
[![Go Reference](https://pkg.go.dev/badge/github.com/ilpanich/axiam-go-sdk.svg)](https://pkg.go.dev/github.com/ilpanich/axiam-go-sdk)
[![Go Report Card](https://goreportcard.com/badge/github.com/ilpanich/axiam-go-sdk)](https://goreportcard.com/report/github.com/ilpanich/axiam-go-sdk)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Official Go client SDK for [AXIAM](https://github.com/ilpanich/axiam) — Access eXtended Identity and Authorization Management.

## Package identity

- **Go module:** `github.com/ilpanich/axiam-go-sdk`
- **Version tags:** `vX.Y.Z`
- **API docs:** [pkg.go.dev/github.com/ilpanich/axiam-go-sdk](https://pkg.go.dev/github.com/ilpanich/axiam-go-sdk)
- **License:** Apache-2.0

## Contract conformance

This SDK conforms to CONTRACT.md §1–§11 (including §6.1 mTLS).

See [`CONTRACT.md`](./CONTRACT.md) for the full cross-language behavioral contract.

## Status

Implemented (Phase 18). REST client (login/MFA/refresh/logout, authz
check/can/batch-check), gRPC client, AMQP consumer with HMAC verification,
local JWKS verification, and `net/http` middleware are all available. Five
runnable examples live under [`examples/`](./examples).

## Installation

```bash
go get github.com/ilpanich/axiam-go-sdk@latest
```

Or pin an explicit release:

```bash
go get github.com/ilpanich/axiam-go-sdk@vX.Y.Z
```

```go
import axiam "github.com/ilpanich/axiam-go-sdk"
```

## Usage

### Login + MFA (§1, §5)

```go
client, err := axiam.NewClient(baseURL, tenantSlug) // tenantSlug is required — no default tenant (§5)
if err != nil {
	// handle error
}

result, err := client.Login(ctx, email, password)
if err != nil {
	// handle error
}
if result.MFARequired {
	completed, err := client.VerifyMfa(ctx, result.MFAToken, totpCode)
	// ...
}
```

See [`examples/login-mfa`](./examples/login-mfa).

### REST authorization checks — CheckAccess / Can / BatchCheck (§1)

```go
allowed, reason, err := client.CheckAccess(ctx, "resource:read", resourceID)
canWrite, err := client.Can(ctx, "resource:write", resourceID)
results, err := client.BatchCheck(ctx, []axiam.AccessCheck{
	{Action: "resource:read", ResourceID: resourceID},
})
```

See [`examples/authz-check`](./examples/authz-check).

### gRPC authorization checks (§1, §5, §9)

```go
creds, err := axiamgrpc.NewTLSCredentials(nil, nil, nil) // strict TLS; arg 1 is an optional custom CA PEM for dev servers (§6)
conn, err := axiamgrpc.NewGRPCClient(target, creds, interceptor)
authzClient := axiamgrpc.NewAuthzClient(conn, refreshFn)

allowed, denyReason, err := authzClient.CheckAccess(ctx, axiamgrpc.CheckAccessRequest{
	TenantID: tenantID, SubjectID: subjectID, Action: "resource:read", ResourceID: resourceID,
})
```

See [`examples/grpc-checkaccess`](./examples/grpc-checkaccess).

### mTLS / client certificates (§6.1)

AXIAM can authenticate IoT devices and service accounts by mutual TLS: the
client presents an X.509 identity certificate (signed by the tenant's
organization CA) that the server binds to a service account. Configure the
client identity with `WithClientCertificate` — it is applied to **both** the
REST and gRPC transports of the same logical client, and it **never** relaxes
server verification (it is additive to `WithCustomCA`/§6, and the TLS-1.3
floor and strict `RootCAs` behavior are unchanged).

```go
// PEM cert chain + PEM private key (PKCS#8 or PKCS#1).
client, err := axiam.NewClient(baseURL, tenantSlug,
	axiam.WithCustomCA(serverCAPEM),                 // trust the server's CA (§6)
	axiam.WithClientCertificate(certPEM, keyPEM),    // present our identity (§6.1)
)

// The same identity over gRPC — pass the SAME cert chain + key:
creds, err := axiamgrpc.NewTLSCredentials(serverCAPEM, certPEM, keyPEM)
```

mTLS is opt-in: omitting `WithClientCertificate` leaves the default
bearer-cookie behavior unchanged. The private key is secret material (§7) —
it is held behind the SDK's `Sensitive` type and never appears in any log,
error, or display output, and there is no public getter for it.

### AMQP consumer with HMAC verification (§8)

```go
handler := func(ctx context.Context, event amqp.Event) error {
	// process event.Fields — hmac_signature has already been verified and removed
	return nil // Ack; return amqp.ErrDrop for a poison message (Nack, no requeue)
}
err := amqp.Consume(ctx, ch, queue, signingKey, handler)
```

See [`examples/amqp-consumer`](./examples/amqp-consumer).

### `net/http` middleware (§10)

```go
verifier, err := axiam.NewJWKSVerifier(ctx, baseURL, nil)
guarded := middleware.Middleware(verifier, tenantSlug)(mux)

// inside a handler:
user, ok := middleware.UserFromContext(r.Context())
```

See [`examples/middleware-guard`](./examples/middleware-guard).

### Declarative authorization helpers (§11)

On top of the §10 `Middleware` guard, `middleware.RequireAuth`,
`middleware.RequireAccess`, and `middleware.RequireRole` add a per-route
authorization layer (CONTRACT.md §11). Go has no macro/annotation/decorator
facility, so these are per-route `http.Handler` wrappers under the same
canonical `require_auth` / `require_access` / `require_role` vocabulary every
other AXIAM SDK uses. They run strictly *after* the §10 guard — they never
extract or verify a token themselves, only consuming the identity
`Middleware` already injected — and they perform no decision caching: every
request re-checks.

```go
verifier, err := axiam.NewJWKSVerifier(ctx, baseURL, nil)
client, err := axiam.NewClient(baseURL, tenantSlug) // *axiam.Client satisfies middleware.AccessChecker

mux := http.NewServeMux()

// GET /docs/{id} requires the authenticated caller to pass a
// "documents:read" check for the {id} resolved from the path.
mux.Handle("/docs/{id}", middleware.RequireAccess(
	client, "documents:read", middleware.ResourceFromPath("id"),
)(docHandler))

// A route that only needs an authenticated identity, no resource check.
mux.Handle("/whoami", middleware.RequireAuth()(whoamiHandler))

// A cheap, LOCAL role check — no server round-trip, and NOT a substitute
// for RequireAccess's resource-level check.
mux.Handle("/admin", middleware.RequireRole("admin")(adminHandler))

guarded := middleware.Middleware(verifier, tenantSlug)(mux) // §10 guard wraps the whole mux
```

The check is always made for the **request's** authenticated user
(`subject_id`), never the application's own client session — this is why
`RequireAccess` takes a `middleware.AccessChecker` (satisfied by
`*axiam.Client`'s additive `CheckAccessAs` method) rather than reusing
`CheckAccess` directly. A resource id that can't be resolved (missing path
value, empty `StaticResource`, or a failing custom `ResourceResolver`) is a
400, never a silent allow. A transport failure while calling the authz
endpoint fails **closed** with 503 — it is never treated as an allow.

See [`examples/middleware-guard`](./examples/middleware-guard) (the `GET
/docs/{id}` route).

## Versioning

Releases are tagged `vX.Y.Z`. Pushing such a tag triggers the module-publish CI
job, which verifies the tag was cut from `main` and asks proxy.golang.org to
fetch it; pull-request events never trigger publish.

There is no registry upload step — for Go, the git tag *is* the release, and
`go get` resolves it through the module proxy. API docs appear automatically on
pkg.go.dev once the proxy has seen the tag.
