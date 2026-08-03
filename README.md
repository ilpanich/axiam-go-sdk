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

This SDK conforms to CONTRACT.md §1–§13 (including §6.1 mTLS).

See [`CONTRACT.md`](./CONTRACT.md) for the full cross-language behavioral contract.

## Status

Implemented (Phase 18). REST client (login/MFA/refresh/logout, authz
check/can/batch-check), gRPC client (authz check/batch-check plus
`GetUserInfo`), AMQP consumer with HMAC verification, local JWKS verification,
`net/http` middleware, OIDC/SSO relying-party helpers (§12 — "Login with
AXIAM"), and a webhook-signature verifier (§13) are all available. Six
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
// tenantSlug is required — no default tenant (§5). Login and Refresh also
// require organization context (§5.1) — a tenant slug is only unique within
// an organization — so pass the org via WithOrgSlug (or WithOrgID for a UUID);
// a login without it is rejected with 400 "must provide org_id or org_slug".
client, err := axiam.NewClient(baseURL, tenantSlug, axiam.WithOrgSlug(orgSlug))
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

### gRPC userinfo — GetUserInfo (§1.1)

`GetUserInfo` is the low-latency gRPC counterpart of the server's REST
`GET /oauth2/userinfo` endpoint (CONTRACT.md §1.1). It invokes
`axiam.v1.UserInfoService/GetUserInfo` on the **same** gRPC channel and shares
the same auth + `x-tenant-id` interceptor as `CheckAccess`; the request is
empty (identity is derived server-side from the bearer token) and it drives the
same single-flight refresh + one-shot retry on `UNAUTHENTICATED` (§9).

```go
userInfoClient := axiamgrpc.NewUserInfoClient(conn, refreshFn) // same conn as NewAuthzClient

info, err := userInfoClient.GetUserInfo(ctx)
// info.Sub, info.TenantID, info.OrgID are always present.
// info.Email / info.PreferredUsername are *string — non-nil only when the
// access token carries the "email" / "profile" scope respectively.
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

### Webhook signature verification (§13)

```go
// r.Body MUST be read into raw bytes and passed to Verify UNMODIFIED — never
// re-serialize a parsed JSON body, since that changes key order/whitespace
// and breaks the MAC.
body, err := io.ReadAll(r.Body)
if err != nil {
	http.Error(w, "failed to read body", http.StatusBadRequest)
	return
}

event, err := webhook.Verify(axiam.Sensitive(webhookSecret), r.Header.Get("X-Axiam-Signature"), body)
if err != nil {
	http.Error(w, "invalid webhook signature", http.StatusUnauthorized)
	return
}

// Dedup at-least-once retries using the X-Axiam-Delivery header (not part of
// the MAC — keep a short-lived seen-set keyed on it).
deliveryID := r.Header.Get("X-Axiam-Delivery")
_ = deliveryID

// event.Type, event.Body are now safe to use.
switch event.Type {
case "user.created":
	// ...
}
w.WriteHeader(http.StatusOK)
```

`webhook.Verify` defaults to a ±300-second freshness window (override with
`webhook.WithTolerance`) and returns a `*webhook.VerifyError` (matchable via
`errors.Is(err, webhook.ErrVerify)`) on any failure — never a signature value,
in either the returned error or any log output.

### `net/http` middleware (§10)

```go
verifier, err := axiam.NewJWKSVerifier(ctx, baseURL, nil)
guarded := middleware.Middleware(verifier, tenantSlug)(mux)

// inside a handler:
user, ok := middleware.UserFromContext(r.Context())
```

See [`examples/middleware-guard`](./examples/middleware-guard).

#### Local verification (§10.1)

`Middleware` applies the complete CONTRACT.md §10.1 **minimum
local-verification set** on every request. Each rule fails closed — a required
claim that is absent, unparseable, or of the wrong JSON type is a rejection,
never a skipped check:

| # | Claim | What the guard does |
|---|---|---|
| 1 | signature | Verified against the org JWKS with `alg` pinned to `EdDSA` **before** any key lookup, so `alg: none` and HS-family confusion are rejected without ever consulting a key. |
| 2 | `exp` | **Required.** No `exp`, or a non-numeric `exp`, is rejected. An absent `exp` is a permanent credential, not an absent constraint. |
| 3 | `nbf` | Honoured when present; an `nbf` in the future is rejected. An absent `nbf` is valid. |
| 4 | `tenant_id` | **Required and asserted** against the configured tenant. An absent claim — or a guard constructed with an empty tenant — is rejected. The JWKS is organization-wide, so a valid signature alone never bounds a token to a tenant. |
| 5 | `iss` | Checked **only** when `WithExpectedIssuer` is configured. Unset by default. |
| 6 | `aud` | Checked **only** when `WithExpectedAudience` is configured. Unset by default. |
| 7 | clock skew | `axiam.ClockSkewLeeway` — a named 60-second constant applied to rules 2 and 3. Deliberately **not** operator-configurable. |

`iss` and `aud` are conditional and default to unset; this SDK hardcodes no
issuer or audience. Configure them when your deployment has an expectation to
assert — a guard fronting a user-facing resource server should generally
expect `axiam:user`:

```go
guarded := middleware.Middleware(verifier, tenantSlug,
	middleware.WithExpectedIssuer("https://axiam.example.com"),
	middleware.WithExpectedAudience("axiam:user"),
)(mux)
```

`JWKSVerifier.VerifySignatureOnlyUnchecked` is the raw signature-only
primitive §10.1 permits for integrators implementing their own policy. **It is
not a guard**: it checks no claim at all, so an expired token, a token with no
`exp`, and a token minted for a *different tenant* under the same org-wide
JWKS all verify successfully. Use `VerifyAccessToken` (which `Middleware`
wraps) unless you are implementing rules 2–7 yourself.

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

### OIDC / SSO relying-party helpers — "Login with AXIAM" (§12)

`*axiam.Client` exposes the nine canonical CONTRACT.md §12 operations for
building an OIDC relying party against AXIAM's own OIDC provider, driving
its `client_credentials` service-account grant, introspecting/revoking
tokens, and stepping through the upstream-IdP federation endpoints:

| Operation | Wire call | Purpose |
|---|---|---|
| `OidcDiscover(ctx)` | `GET /.well-known/openid-configuration` | Fetch and cache the discovery document (≥5 min TTL, single-flight per client). |
| `OidcBegin(configuration, params)` | *(none — pure local computation)* | Build the authorization URL with a CSPRNG `state`/`nonce` and an S256 PKCE challenge. |
| `OidcExchange(ctx, params)` | `POST /oauth2/token` (`authorization_code`) | Exchange a code for a token set, validating the ID token in full. |
| `OidcRefresh(ctx, params)` | `POST /oauth2/token` (`refresh_token`) | Refresh an `OidcTokenSet` under a single-flight guard. |
| `LoginClientCredentials(ctx, params)` | `POST /oauth2/token` (`client_credentials`) | Service-account machine-to-machine login. |
| `Introspect(ctx, params)` | `POST /oauth2/introspect` | RFC 7662 token introspection. |
| `Revoke(ctx, params)` | `POST /oauth2/revoke` | RFC 7009 token revocation (idempotent). |
| `SsoStart(ctx, params)` | `POST /api/v1/auth/federation/oidc/start` | Step 1 of upstream-IdP SSO. |
| `SsoComplete(ctx, params)` | `POST /api/v1/auth/federation/oidc/callback` | Step 2: establishes the session via `Set-Cookie`. |

Configure the relying party's client credentials at construction time —
`client_id` is needed for every grant and for §12.4's audience check, so it
lives on the `Client`, never a per-call argument:

```go
client, err := axiam.NewClient(baseURL, tenantSlug,
	axiam.WithOidcClientID("my-app"),
	axiam.WithOidcClientSecret(clientSecret), // omit for a public client
)
```

**The caller owns the login state — the SDK stores nothing.** `OidcBegin`
returns `AuthorizationRequest{URL, State, Nonce, CodeVerifier}` and touches
no store; persist `State`, `Nonce` and `CodeVerifier` in your own session (or
via the optional `axiam.OidcStateStore` / `axiam.NewMemoryOidcStateStore`)
and pass `Nonce` + `CodeVerifier` back into `OidcExchange` yourself:

```go
configuration, err := client.OidcDiscover(ctx)
request, err := client.OidcBegin(configuration, axiam.OidcBeginParams{
	RedirectURI: redirectURI,
	Scope:       "openid profile email",
})
// ...persist request.State / request.Nonce / request.CodeVerifier, then...
http.Redirect(w, r, request.URL, http.StatusFound)

// on the callback, after checking the returned `state` matches:
tokens, err := client.OidcExchange(ctx, axiam.OidcExchangeParams{
	Code: code, CodeVerifier: request.CodeVerifier, Nonce: request.Nonce,
	RedirectURI: redirectURI, TenantID: tenantID,
})
fmt.Println(tokens.IDClaims.Sub) // the validated ID-token subject
```

`middleware.OidcLoginHandler` / `middleware.OidcCallbackHandler` wrap that
same sequence as two `http.Handler`s, using an `axiam.OidcStateStore` to
bridge the login and callback requests:

```go
store := axiam.NewMemoryOidcStateStore(0) // 10-minute TTL, single-use consume
opts := middleware.OidcLoginOptions{
	Client: client, Store: store, RedirectURI: redirectURI, Scope: "openid profile",
	OnSuccess: func(w http.ResponseWriter, r *http.Request, tokens axiam.OidcTokenSet, entry axiam.OidcStateEntry) {
		// establish YOUR OWN application session here — the SDK never does.
	},
}
mux.Handle("/login", middleware.OidcLoginHandler(opts))
mux.Handle("/auth/callback", middleware.OidcCallbackHandler(opts))
```

`access_token`, `refresh_token`, `id_token`, `client_secret` and
`code_verifier` are all `Sensitive` (§7/§12.5) — including while a
`code_verifier` sits inside an `AuthorizationRequest` or an `OidcStateStore`
entry. `state` and `nonce` are not secrets and are plain strings. PKCE is
**S256-only**: `plain` is not implemented anywhere in this SDK. `OidcRefresh`
runs under its own single-flight guard so concurrent callers share one wire
call; `OidcExchange`/`OidcRefresh` validate any `id_token` against the full
CONTRACT.md §12.4 checklist (`EdDSA`-only, issuer/audience/time/nonce) and
discard the WHOLE token set — access and refresh token included — on any
failure. An `OAuth2ErrorResponse` from `/oauth2/*` surfaces as
`*axiam.OAuthProtocolError`, a sub-type of `*axiam.AuthError` (existing
`errors.Is(err, axiam.ErrAuth)` / `errors.As(err, &authErr)` handling keeps
matching it unchanged); a 401 from `Introspect`/`Revoke` never enters the §9
refresh guard.

See [`examples/oidc-login`](./examples/oidc-login).

## Versioning

Releases are tagged `vX.Y.Z`. Pushing such a tag triggers the module-publish CI
job, which verifies the tag was cut from `main` and asks proxy.golang.org to
fetch it; pull-request events never trigger publish.

There is no registry upload step — for Go, the git tag *is* the release, and
`go get` resolves it through the module proxy. API docs appear automatically on
pkg.go.dev once the proxy has seen the tag.
