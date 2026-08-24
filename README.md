# axiam SDK (Go)

[![CI](https://github.com/ilpanich/axiam-go-sdk/actions/workflows/sdk-ci-go.yml/badge.svg?branch=main)](https://github.com/ilpanich/axiam-go-sdk/actions/workflows/sdk-ci-go.yml)
[![Coverage Status](https://coveralls.io/repos/github/ilpanich/axiam-go-sdk/badge.svg?branch=main)](https://coveralls.io/github/ilpanich/axiam-go-sdk?branch=main)
[![Go Reference](https://pkg.go.dev/badge/github.com/ilpanich/axiam-go-sdk.svg)](https://pkg.go.dev/github.com/ilpanich/axiam-go-sdk)
[![Go Report Card](https://goreportcard.com/badge/github.com/ilpanich/axiam-go-sdk)](https://goreportcard.com/report/github.com/ilpanich/axiam-go-sdk)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Official Go client SDK for [AXIAM](https://github.com/ilpanich/axiam) — Access eXtended Identity and Authorization Management.

**Platform documentation:** <https://ilpanich.github.io/axiam/> — getting started, the authorization model, the OAuth2/OIDC surface, and the operations guides. This README covers the SDK; the site covers the server it talks to.

## Package identity

- **Go module:** `github.com/ilpanich/axiam-go-sdk`
- **Version tags:** `vX.Y.Z`
- **API docs:** [pkg.go.dev/github.com/ilpanich/axiam-go-sdk](https://pkg.go.dev/github.com/ilpanich/axiam-go-sdk)
- **License:** Apache-2.0
- **Go:** `1.26` minimum (`axiam.MinGoVersion`) — see [Supported Go versions](#supported-go-versions)

## Contract conformance

This SDK conforms to CONTRACT.md §1–§13 and §12.7, §14, §15, §17, §19, §20, §21, §22, §23,
§24, §25, §26 (including §6.1 mTLS).

§12.7, §14, §15, §20, §22, §23, §24, §25 and §26 are named rather than folded into the
range because they landed after this SDK already claimed §1–§13: widening the range
silently would turn a statement that was true when written into a different claim
without anyone editing it.

See [`CONTRACT.md`](./CONTRACT.md) for the full cross-language behavioral contract.

## Status

Implemented (Phase 18). REST client (login/MFA/refresh/logout, authz
check/can/batch-check), gRPC client (authz check/batch-check plus
`GetUserInfo`), AMQP consumer with HMAC verification, local JWKS verification,
`net/http` middleware, OIDC/SSO relying-party helpers (§12 — "Login with
AXIAM"), a webhook-signature verifier (§13), the reactor runtime (§22 —
`ReactorServe`) and the OPAQUE login path (§23 — `LoginOpaque`) are all
available. Runnable examples live under
[`examples/`](./examples).

## Installation

**Requires Go 1.26 or later.** That is a step up from the 1.25 this module used
to need, and it comes from `github.com/bytemare/opaque` — the RFC 9807
implementation the OPAQUE login path binds (see [OPAQUE](#opaque-contractmd-23)
for why this SDK depends on one at all rather than shipping its own).

The alternative was pinning an older release of that library to keep the 1.25
floor, and it is worth saying why that was refused: the last version compatible
with 1.25 predates RFC 9807's publication by more than two years, so it
implements a CFRG draft. Trading a verified byte-for-byte interoperability with
the AXIAM server for a lower minimum Go version would be trading the thing that
actually matters for the thing that looks tidier.

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

## Supported Go versions

| | Version | Why this one |
|---|---|---|
| **Floor** | 1.26 | The `go` directive in `go.mod`, and the reason for it is above: `github.com/bytemare/opaque` needs it. Exported as `axiam.MinGoVersion`. |
| **Newest** | 1.27 | The current release (2026-08-19). |

Go supports exactly the two most recent majors, so that pair is not a sample
of the supported range — it **is** the supported range, with nothing in
between to interpolate.

**The module is built against the floor, and runs on the newest.** CI proves
each separately: the gating matrix in `sdk-ci-go.yml` runs `build`, `vet` and
the full test suite on **1.26.7 and on 1.27.0**. The floor leg is what keeps
the `go.mod` directive honest — a 1.27-only stdlib call compiles clean on the
newest leg and then breaks every consumer who took the module at its declared
word. `govulncheck` runs once, on the floor leg, since the floor is the oldest
stdlib any consumer will be using.

`axiam.MinGoVersion` exposes the floor as a readable constant. The toolchain
enforces the `go` directive at build time, but a consumer cannot read it back
at run time — `debug.ReadBuildInfo` reports the toolchain that produced the
binary and the module graph, never a dependency's declared language version.
`version_policy_test.go` asserts the constant, the `go` directive and the CI
matrix all still agree, so the constant cannot go stale.

See [`examples/version-compatibility`](./examples/version-compatibility) for a
runnable preflight built on it.

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

### Reactors — AMQP extension actors (CONTRACT.md §22)

A **reactor** is an external process that subscribes to named hook events on the AXIAM
bus and answers back — allow, deny, or a field-allow-listed mutation — inside a timeout
the server declared. Zitadel Actions and Keycloak SPIs solve the same problem by loading
third-party code *into* the authorization server; a reactor stays outside it, reachable
only through a signed reply schema the server validates before it believes a word of it.

```go
err := amqp.ReactorServe(ctx,
    // §8b: amqps:// only, optional CA bundle, no verification-skip switch anywhere.
    amqp.AMQPSDialer("amqps://broker.example:5671", amqp.WithReactorCABundle(caPEM)),
    amqp.ReactorConfig{
        TenantID:   tenantID,
        ReactorID:  reactorID, // the queue name is derived from it; the SERVER declared it
        SigningKey: subkey,    // the tenant AMQP subkey from the management API (§8.1)
    },
    func(ctx context.Context, ev amqp.ReactorEvent) (amqp.ReactorAnswer, error) {
        switch ev.Event {
        case amqp.ReactorEventTokenPreIssue:
            // `ext.` is the COMPLETE allow-list for this event.
            return amqp.ReactorMutate(map[string]string{"ext.department": "eng"}), nil
        case amqp.ReactorEventLoginPostAuth:
            if fraudulent(ev) {
                return amqp.ReactorDeny("embargoed region"), nil
            }
            return amqp.ReactorAllow(), nil // or ReactorAllowWithStepUp()
        }
        return amqp.ReactorAllow(), nil
    },
)
```

#### Binding handlers per event — `ReactorMux` (§22.14)

The switch above is the shape every multi-event reactor grows, and it has two failure
modes that cost nothing to remove. `ReactorMux` is §22.14's declarative form for Go — pure
sugar over the same `ReactorServe`, in the spirit of the §11 declarative authorization
helpers:

```go
handler, err := amqp.NewReactorMux().
    On(amqp.ReactorEventTokenPreIssue, enrichToken).
    On(amqp.ReactorEventLoginPostAuth, screenLogin).
    Handler()
if err != nil {
    return err // every rejected binding at once, not one per run
}
err = amqp.ReactorServe(ctx, dialer, cfg, handler)
```

- **A misspelled event is refused when you bind it**, not discovered as an event that
  never fires. `ReactorMux` accepts only names in the §22.5 registry — which is also why
  it refuses the three hot-path operations §22.7 excludes: they are in no registry row.
- **An unbound event abstains** — no reply, `failure_policy` decides (§22.8). A `default:`
  arm returning `ReactorAllow()` answers on behalf of code that never ran, which is how an
  operator's `fail_closed` setting gets defeated from inside the library (§22.10 rule 2).
- A duplicate binding is an error rather than a silent overwrite, and `mux.Events()` feeds
  `amqp.ReactorDefaultFailurePolicy` so you can see what an unreachable reactor costs
  before you go live.

It adds no transport, no verification and no signing: it produces exactly the
`ReactorHandler` `ReactorServe` already takes, and a handler's own error or panic reaches
the runtime unchanged so nothing is published.

`ReactorServe` verifies every delivery **before** the handler sees it — key version, MAC,
freshness, nonce, in that order — then signs the reply with the same tenant subkey. §8's
HMAC runs in **both directions** here: a reply is an instruction to change a token or
refuse a login, so an unsigned or stale one is not a weak reply, it is not a reply at all.

Five things this runtime does that are easy to get wrong, and are asserted against the
server-generated vectors in
[`amqp/testdata/reactor_v2_reference_vectors.json`](amqp/testdata/reactor_v2_reference_vectors.json)
rather than documented and hoped for:

- **`hmac_signature` is serialized as `null` inside a reactor body**, not omitted the way
  §8's own two message types omit it. This is the single most likely place to produce a
  MAC that never verifies, in either direction.
- **`reason`, `patch` and `require_mfa` are omitted when absent/false.** A reply that
  serializes `"require_mfa": false` produces different canonical bytes and a different MAC.
- **A patch is sent unfiltered.** One forbidden key rejects the *whole* patch server-side,
  and this SDK will not quietly drop `sub` to rescue the rest — that would leave you
  believing a field was set when it was dropped.
- **A handler that fails publishes nothing.** No synthesized `allow`: the registration's
  `failure_policy` decides, which is what the operator configured. `login.post_auth`
  defaults to `fail_closed`.
- **It never declares an exchange, a queue or a binding.** The server declares the
  per-reactor queue from the registration. A reactor that could bind could bind itself to
  `*.token.pre_issue` and read another tenant's issuance events.

The event registry, its per-event mutable-field allow-lists and §22.8's strictest-wins
failure-policy composition are mirrored locally (`amqp.ReactorEvents()`,
`amqp.ReactorDefaultFailurePolicy(events)`) because the delivery path validates against
them with no network available; `GET /api/v1/reactors/events` serves the live copy.

**Not hookable, and not offered anywhere in this SDK:** the hot-path decision operations
(the authorization check, the batch check and token introspection) are absent from the
registry by design — §22.7 writes this as a MUST NOT because a reactor round-trip is
milliseconds and the check path's budget is microseconds. An application that needs
external input on an authorization decision writes a **deny grant**, which the engine
evaluates in the hot path at hot-path cost.

`timeout_ms` reaches the handler both as `ev.Timeout` and as the handler context's
deadline, so a handler that honours `ctx` sheds load instead of answering into a closed
window. Telemetry (§19) is available via `WithReactorTelemetryHook` — and worth wiring,
because a `fail_open` timeout produces `allow` *and* an audit record, so reactor health
must never be inferred from the outcome alone.

See [`examples/reactor`](./examples/reactor).

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

### Device authorization grant (CONTRACT.md §14)

RFC 8628 — signing in a device that cannot show a browser: a TV, a CLI, a
headless commissioning tool.

```go
tokens, err := client.DeviceLogin(ctx, axiam.DeviceLoginParams{
    OnUserCode: func(a axiam.DeviceAuthorization) error {
        // Called BEFORE the first poll. Display it however the device can —
        // screen, QR code, e-ink panel. The SDK never prints it for you.
        fmt.Printf("visit %s and enter %s\n", a.VerificationURI, a.UserCode)
        return nil
    },
})
```

`DeviceAuthorize` and `DevicePoll` are also exported, for an application driving
its own loop. The polling rules are where implementations go wrong:

- **`slow_down` raises the interval permanently.** An SDK that backs off for one
  round and returns to the original interval will be told to slow down again,
  forever.
- **`access_denied` and `expired_token` stay distinct.** A human said no, versus
  nobody answered — the only information the device can act on.
- **Polling stops at `ExpiresIn`**, even if the server has not yet said
  `expired_token`.
- **A `5xx` mid-poll is not terminal.** A server restart must not lose a grant
  the user has already approved.

`DeviceCode` is `Sensitive`; `UserCode` deliberately is not — it exists to be
read aloud, and wrapping it would defeat the one thing it is for.
`DeviceAuthorize` sends no `client_secret` and does not refuse a `Client` built
without one. Returning an error from `OnUserCode` aborts before any polling, and
`ctx` cancellation is honoured *between* polls rather than only during them.

Per §14.3 rule 4, the token set is returned; `AdoptAsCredential` is the same
opt-in flag `LoginClientCredentials` uses. See
[`examples/device-login`](./examples/device-login).

### Token exchange (CONTRACT.md §15)

RFC 8693 — a service holding a user's token exchanging it for a *narrower* one
before calling the next service.

```go
exchanged, err := client.TokenExchange(ctx, axiam.TokenExchangeParams{
    SubjectToken:     axiam.Sensitive(userToken),
    SubjectTokenType: axiam.SubjectTokenTypeAccessToken, // required, no default
    Scopes:           []string{"orders:read"},
    Audience:         "orders-service",
})
```

Most of what this method does is refuse to be helpful:

- **No default `SubjectTokenType`.** It is required (§15.1). Which kind of token
  you hold is something only you know, so the SDK will not pick — an empty value
  fails client-side rather than sending a type you did not choose.
- **No default `ActorToken`.** Leaving it zero asks for *impersonation*; the SDK
  will not quietly substitute the client's own session token and turn that into
  a delegation.
- **No auto-narrowing after `invalid_scope`.** The server refuses rather than
  silently narrowing precisely so the caller finds out here.
- **No refresh token, ever** — `ExchangedToken` has no such field. Re-run the
  exchange.
- **No adoption**, and no flag to enable it. A MUST NOT, where
  `LoginClientCredentials` and `DeviceLogin` adoption is a MAY.

See [`examples/token-exchange`](./examples/token-exchange).

#### External-IdP subject tokens (CONTRACT.md §15.7)

The same method exchanges a token minted by a **trusted external IdP** — a
partner's Entra, Okta or Keycloak — for an AXIAM token scoped to what the
resolved AXIAM user may actually do. There is no separate operation:

```go
exchanged, err := client.TokenExchange(ctx, axiam.TokenExchangeParams{
    SubjectToken:     axiam.Sensitive(partnerToken),
    SubjectTokenType: axiam.SubjectTokenTypeJWT, // named, never guessed
    Scopes:           []string{"read:orders"},
    Audience:         "https://orders.internal",
})
```

- **`SubjectTokenType` is yours to state, and is required.** The SDK never
  decodes the subject token to pick it, and never overrides what you named.
  There is no default: leaving it empty fails client-side with no wire call
  (§15.1), because a default would be the SDK choosing for you.
- **No actor token.** Delegation across a trust boundary is unsupported in v1;
  sending one is `invalid_request`, which the SDK will not work around by
  dropping it and re-sending.
- **One refusal is distinguishable.** `invalid_grant` whose description is
  `the subject token's issuer is not configured for token exchange` means *fix
  the AXIAM trust configuration*. Every other `invalid_grant` means *fix your
  token*, and is deliberately generic.
- **Forward the result as-is.** It carries an `ext_exchange` claim naming the
  partner issuer; never strip it, and never read it as an authorization input.
  It also cannot be exchanged again — exchanges do not compose.

See [`examples/external-token-exchange`](./examples/external-token-exchange)
and the operator guide, `docs/api/federated-token-exchange.md`.

### UMA 2.0 — Protection API and ticket grant (CONTRACT.md §20)

The resource-server side of User-Managed Access: register what you guard, ask
the authorization server what a caller would need, and redeem the resulting
ticket.

```go
// A PAT is a client-credentials token carrying `uma_protection` — never a user
// token, and never this client's own session (§20.2 rule 1).
session, _ := client.LoginClientCredentials(ctx, axiam.LoginClientCredentialsParams{
    Scope: axiam.UmaProtectionScope,
})
pat := session.AccessToken

resource, _ := client.UmaRegisterResource(ctx, pat, axiam.ResourceSet{
    Name: "invoice-7", Type: "document", ResourceScopes: []string{"view"},
})

// The returned ID IS the AXIAM resource id — no translation step.
ticket, _ := client.UmaRequestTicket(ctx, pat, []axiam.RequestedPermission{
    {ResourceID: resource.ID, ResourceScopes: []string{"view"}},
})

w.Header().Set("WWW-Authenticate", axiam.UmaChallengeHeader("invoices", issuer, ticket))
```

…and on the client side, having caught that `401`:

```go
challenge, ok := axiam.UmaParseChallenge(resp.Header.Get("WWW-Authenticate"))
if ok {
    rpt, err := client.UmaExchangeTicket(ctx, axiam.UmaExchangeTicketParams{
        Ticket: challenge.Ticket, ClaimToken: axiam.Sensitive(usersAccessToken),
    })
}
```

The rules this surface exists to enforce:

- **A ticket is never retried** — not on `5xx`, not on a timeout, not on
  `invalid_grant`. It is the one documented exception to §16's retry policy,
  and a security rule rather than a performance one: the ticket is consumed
  *before* the exchange is evaluated, so a failed exchange has already spent it
  and a retry is a *second redemption*. Under concurrency that is exactly the
  redemption a server whose storage engine the SDK cannot attest may admit twice
  ([`ilpanich/axiam#302`](https://github.com/ilpanich/axiam/issues/302)).
  On failure, request a **new** ticket.
- **`UmaParseChallenge` does not exchange what it parsed.** The `as_uri` names
  an authorization server you have not necessarily chosen to trust;
  auto-exchanging would send the requesting party's `claim_token` to whatever
  host answered the `401`.
- **`ClaimToken` is required, never defaulted.** It is the only channel that
  names the requesting party — defaulting it to your own PAT would mint an RPT
  for *you*. An empty one is refused client-side, so the ticket stays unspent.
- **No auto-narrowing on `access_denied`.** A partial grant is refused whole;
  whether two-of-three permissions is useful is your application's judgement,
  not the SDK's.
- **The RPT is never adopted** as this client's credential, and
  `RequestingPartyToken` has no refresh-token field.
- **`UmaUpdateResource` replaces the scope list rather than merging it**, so
  omitting a scope removes it. There is no read-modify-write.

#### Emitting the challenge from the §11 guard

`middleware.WithUmaChallenge` wires the emit half into `RequireAccess`, so you
do not hand-roll the mint-and-format on every denial:

```go
challenger := &middleware.UmaChallenger{
    Realm: "invoices", ASURI: configuration.Issuer, PAT: pat, Minter: client,
}
mux.Handle("/invoices/{invoiceID}", middleware.RequireAccess(
    client, "invoices:read", middleware.ResourceFromPath("invoiceID"),
    middleware.WithUmaChallenge(challenger),
)(http.HandlerFunc(invoiceHandler)))
// A denial now answers 403 with
//   WWW-Authenticate: UMA realm="invoices", as_uri="…", ticket="…"
```

Two properties are deliberate, and both are asserted by counting Protection API
calls rather than by inspection:

- **Opt-in.** Emitting a challenge means minting a credential. A guard that did
  that on every denial by default would put a Protection API call — and a live
  ticket — behind every unauthorized request, which is a denial-of-service
  amplifier pointed at your own authorization server. An allow mints nothing,
  and neither does a 401 or a fail-closed 503: only a *resource denial* is
  answerable with a ticket.
- **A minting failure is not an escalation.** An expired PAT or an unreachable
  Protection API still yields the plain 403 — never a 503, and never an allow.

The requested scope is the AXIAM **action**, so the ticket asks for exactly the
authority that was refused and the engine's deny rules keep applying to
whatever RPT comes back.

Both halves run end-to-end in [`examples/uma-resource-server`](examples/uma-resource-server)
and [`examples/uma-client`](examples/uma-client).

### Logout — RP-initiated and back-channel (CONTRACT.md §12.7)

`LogoutURL` builds the redirect; `VerifyLogoutToken` validates a token the OP
**pushed** to your back-channel endpoint.

```go
url, err := client.LogoutURL(ctx, axiam.LogoutURLParams{IDToken: idToken})

// …and at your registered backchannel_logout_uri:
verified, err := client.VerifyLogoutToken(ctx, logoutToken, nil)
if verified.SID != "" {
    endSession(verified.SID) // that session ONLY
}
```

The verifier is where the security weight sits — the input arrives unsolicited
and instructs you to terminate a session. It checks the signature (same JWKS
path as §12.4, which already pins EdDSA and requires a `kid`), `iss`, `aud`,
that `events` carries the back-channel-logout key (**the only thing separating a
logout token from an ID token**), that `nonce` is *absent* (its presence is how
an ID token gets replayed as one), that something is named, and freshness.

It returns `SID`/`Sub`/`JTI` rather than a bare `bool`: you have to know *which*
session to end. **Dedup on `JTI` yourself** — delivery is at-least-once, so a
valid token legitimately arrives twice; the SDK has no durable store and an
in-memory guard would silently drop a real second logout after a restart.

See [`examples/logout`](./examples/logout).

### Decision reason codes (CONTRACT.md §11 rule 9)

`AccessResult.ReasonCode` distinguishes `no_grant` ("ask an admin for access")
from `denied_by_rule` ("an admin has already decided") — opposite instructions
to the person on the other end, which is why the contract forbids collapsing
them into a bare `false`.

`CheckAccess` and `AuthzClient.CheckAccess` keep their `(bool, string, error)`
tuples, which predate the field and cannot carry it; `CheckAccessDecision` on
both returns the full result. An unrecognised code is surfaced verbatim and
never changes `Allowed`.

## WebAuthn and passkeys (CONTRACT.md §24)

A passkey ceremony is **two exchanges stacked**: one with an *authenticator*,
which needs a platform API, and one with *AXIAM*, which is four ordinary JSON
round trips. Go has no authenticator, so this SDK ships the second half.

That is not a consolation prize. A Go service completing a ceremony that ran on
an Android or iOS handset is the relying party exactly as a browser is — and
§24.6b rule 2 forbids the alternative outright: an SDK must not emulate an
authenticator in software, because a "credential" held in process memory is not
a second factor.

### The three-step shape

```go
challenge, err := client.WebauthnDiscoverableStart(ctx, nil)

// The JSON form every platform authenticator API takes (§24.6a) — the exact
// string Android's CreatePublicKeyCredentialRequest and a browser's
// parseCreationOptionsFromJSON() both want.
requestJSON, err := challenge.RequestJSON()
responseJSON := yourDeviceChannel(requestJSON)

session, err := client.WebauthnDiscoverableFinish(
    ctx, challenge.StateToken, responseJSON,   // the platform's string, verbatim
)
```

The client is authenticated when that returns — §24.3 rule 1 is not a "MAY
adopt". `WebauthnRegisterStart`/`Finish` and
`WebauthnAuthenticateStart`/`Finish` follow the same shape, for enrolling a
credential and for a passkey used as a second factor after `Login` answered
`MFARequired`.

Every `*Finish` takes `any`: a `string`, a `json.RawMessage`, `[]byte`, or a
value to marshal. Requiring a caller to unmarshal a platform response into a
struct this SDK immediately re-marshals is three chances to corrupt a signed
buffer in service of nothing — a string passes through as raw JSON without
touching a Go type.

### What the SDK will not do

**It never adjusts an option.** The server generates the challenge and chooses
`residentKey`, `userVerification`, the attestation conveyance, the exclusion list
and the timeout; this SDK carries all of it through unchanged and posts the
answer back unchanged. Not because those fields are hard — because they are not,
and relaxing `userVerification` to `"preferred"` because a test authenticator
kept prompting weakens a ceremony the server believes it configured. The server
cannot catch it: an assertion produced under weaker options is a valid assertion.

**It never parses `StateToken`.** It is opaque, it is `Sensitive`, and it goes
straight back to the matching `*Finish`.

### Classifying a device's failure

Every platform reports a ceremony failure as one opaque type whose only
machine-readable part is a name — so a handset can relay just that name, and a
Go service can turn it into the same five outcomes a browser would see:

```go
failure := axiam.ClassifyWebauthnError(nameRelayedByTheDevice)
if failure == axiam.WebauthnAlreadyRegistered {
    // the only outcome whose remedy is "use a different device"
}
show(axiam.WebauthnErrorMessage(failure))
```

`WebauthnCancelled` covers **both** an explicit refusal and a silent timeout. The
WebAuthn spec deliberately refuses to distinguish them, because telling a website
which one happened leaks whether an authenticator was present — so the copy does
not accuse anyone of cancelling, and the distinction must not be recovered by
timing the call.

### Two error rows that are not the generic mapping

- A **`403` on `WebauthnRegisterFinish`** is the tenant's attestation policy
  refusing *this authenticator* — an AAGUID that is not allow-listed, a missing
  FIDO certification, a revoked status — not a permission problem with the user.
  The policy message survives into the `*AuthzError`, because it is the only way
  the person holding the key learns a different one would work. This is the one
  place the SDK's D-15 "never put a body in an error" rule bends, and it bends
  the way D-15 already permits: one **named** JSON field is decoded, exactly as
  `action`/`resource_id` already are. The raw body still never reaches an error.
- A **`503` on `WebauthnRegisterStart`** means attestation is required and the
  FIDO metadata service has no usable snapshot. A server configuration state, not
  a transient failure, and deliberately **not** retried.

Worked example: [`examples/webauthn-relying-party`](examples/webauthn-relying-party).

## Account lifecycle and MFA enrolment (CONTRACT.md §25)

§1 locks the *middle* of an account's life — `Login`, `VerifyMfa`, `Refresh`,
`Logout` all assume an account that already exists, is verified, and already has
its second factor. These nine operations are how it gets there.

```go
enrolment, err := client.MfaEnroll(ctx)
renderQR(enrolment.TotpURI)          // Sensitive: pass it, do not stringify it
enabled, err := client.MfaConfirm(ctx, codeTypedByUser)
```

`SecretBase32` and `TotpURI` are both `Sensitive`, and the URI is the one that
matters: it *is* `otpauth://…?secret=…`, so it contains the secret it sits beside.
Wrapping only the secret would have wrapped nothing — the URI is the field that
actually reaches a log, because it is the field you hand to a QR renderer.

### `Login` has a third outcome

`LoginResult` gains `MFASetupRequired` and `SetupToken`. The server has always
been able to answer `403 mfa_setup_required` for an account in a tenant that
requires MFA; it used to reach you as an `*AuthzError`, saying you lacked
permission to log in when what the server said was recoverable.

```go
result, err := client.Login(ctx, email, password)
if result.MFASetupRequired {
    enrolment, _ := client.MfaSetupEnroll(ctx, result.SetupToken)
    renderQR(enrolment.TotpURI)
    _, err = client.MfaSetupConfirm(ctx, result.SetupToken, code)  // completes the login
}
```

Additive here rather than a new type, because `LoginResult` has always been one
struct with flags rather than a discriminated union — so nothing that reads
`MFARequired` today has to change. A genuine authorization refusal is still an
`*AuthzError`: the branch is matched on the body's discriminant, not the `403`
alone.

### Email verification and password reset

```go
err := client.VerifyEmail(ctx, tokenFromLink, tenantID)
err = client.ResendVerification(ctx, email, tenantID)
err = client.RequestPasswordReset(ctx, axiam.PasswordResetRequest{Email: email})
```

`RequestPasswordReset` returns `nil` **whether or not the address exists**, and
this SDK exposes no way to tell them apart. Any signal distinguishing them —
including one inferred from timing — turns the endpoint into the account
enumeration oracle its uniform response exists to prevent.

Setting the new password takes one extra call on any tenant that might have
OPAQUE enabled, because the client has to build a registration record and cannot
know the parameters before it has a token to ask with:

```go
resetContext, err := client.PasswordResetContext(ctx, token)
// …build an OPAQUE record when resetContext.Opaque is non-nil…
err = client.ConfirmPasswordReset(ctx, axiam.PasswordResetConfirmation{
    Token: token, NewPassword: newPassword, TenantID: tenantID, Opaque: opaque,
})
```

The context discloses no identity, and a `404` covers unknown, expired and
already-consumed without distinguishing them.

Worked example: [`examples/account-lifecycle`](examples/account-lifecycle).

## Pushed authorization requests (CONTRACT.md §26)

PAR (RFC 9126) moves the authorization request off the browser: the client POSTs
`scope`, `redirect_uri`, `state` and the PKCE challenge straight to AXIAM over an
authenticated back channel and puts an opaque `request_uri` in the redirect, so
what travels through the user agent is a random string that cannot be edited into
meaning something else.

Required for a FAPI 2.0 client — `profile: "fapi2"` refuses a registration that
does not set `require_par`.

```go
configuration, _ := client.OidcDiscover(ctx)
request, _ := client.OidcBegin(configuration, axiam.OidcBeginParams{
    RedirectURI: redirectURI, Scope: "openid profile",
})

pushed, err := client.OidcPar(ctx, axiam.OidcParParams{
    Request: request, RedirectURI: redirectURI, Scope: "openid profile",
    Configuration: &configuration,
})
redirect(pushed.AuthorizationURL)

// …on the callback, unchanged by PAR:
tokens, err := client.OidcExchange(ctx, axiam.OidcExchangeParams{
    Code: code, RedirectURI: redirectURI,
    Nonce: pushed.Nonce, CodeVerifier: pushed.CodeVerifier,
})
```

`OidcBegin` still does the computing — there is no second generator for `state`,
`nonce` and PKCE — and `pushed.CodeVerifier` is the one it produced, so there is
exactly one value to keep.

Three things that are easy to get wrong:

1. **The endpoint answers `201`, not `200`.** RFC 9126 §2.2 specifies Created, and
   a success predicate written `== 200` treats every successful push as a failure.
2. **The authorization URL carries exactly `client_id` and `request_uri`.** The
   server *refuses* a request mixing a `request_uri` with inline authorization
   parameters rather than merging them, and re-adding them "for compatibility"
   restores the parameter-confusion attack the refusal prevents.
3. **`RequestURI` is single-use and short-lived.** There is nothing to retry with
   it; the safe recovery is a fresh push. `OidcPar` is correspondingly never
   retried on a `5xx` or a transport failure — it is a POST that creates state.

Worked example: [`examples/par-login`](examples/par-login).

## OPAQUE (CONTRACT.md §23)

`LoginOpaque` proves the password to the server without the password — or
anything from which it can be cheaply recovered — ever crossing the wire. The
server stores a **registration record** whose envelope is sealed under a key
the client can only reconstruct by running the password through the server's
oblivious PRF.

```go
result, err := client.LoginOpaque(ctx, "alice", password)
```

It takes the same arguments as `Login` and returns the same `LoginResult`,
MFA branch included, so switching a tenant to OPAQUE needs no change to how the
result is handled. A runnable end-to-end example, including the fallback and
the enrolment call, is in [`examples/opaque-login`](./examples/opaque-login).

### What this buys, and what it does not

OPAQUE closes holes TLS 1.3 does not:

- a TLS-terminating reverse proxy, ingress controller, CDN or service mesh
  sees every plaintext password today; under OPAQUE it sees a blinded group
  element and a MAC;
- an accidental request-body log, a heap dump or a crash reporter can no
  longer capture a plaintext password, because the server never has one;
- **a stolen record database is not offline-crackable on its own.** Recovering
  a password additionally requires the tenant's OPRF seed, which is encrypted
  at rest separately. This is the property SRP could not offer, and the main
  reason AXIAM replaced it.

It does **not** protect against a compromised AXIAM server.

### Modes

`opaque_mode` is an organization baseline a tenant may tighten:

| mode | `/auth/login` | `LoginOpaque` |
|---|---|---|
| `disabled` (default) | works | `*NetworkError` (404) |
| `optional` | works | works, and falls back to `Login` on a failed exchange |
| `required` | `*AuthzError` (`opaque_required`) | works |

- `errors.As(err, &netErr)` from `LoginOpaque` means *this tenant does not
  offer OPAQUE*, a property of the tenant rather than of any user. Fall back to
  `Login`.
- **A failed exchange is handled inside `LoginOpaque`, not by the caller**
  (CONTRACT.md §23.4 rule 7). `login/start` reports the tenant's mode, and that
  alone decides what happens when the client cannot open `KE2` — wrong
  password, unknown identity, or an account with no registration record, which
  are indistinguishable by design. Under `optional`, `LoginOpaque` retries the
  same credentials over `Login` itself and returns that call's result or error;
  under `required`, an unrecognised mode, or a server too old to send the field
  at all, it returns `*AuthError` and never touches `/auth/login`. `KE3` is
  never sent in any of those cases.
- **The caller must still not retry an `*AuthError` over `Login`.** By the time
  one reaches you the fallback has either already happened or been ruled out by
  the tenant's own policy, and `required` refuses `/auth/login` for every
  principal anyway. The example shows the shape.
- `mode` is **not** downgrade protection: a hostile server that wanted the
  plaintext could answer `404` and get the caller's fallback regardless of what
  it puts there. `required` is what closes that, server-side.

### Enrolment

The server cannot build a record — it never sees the plaintext — so one has to
be sent with any request that sets a password:

```go
enrollment, err := client.OpaqueEnrollment(ctx, newPassword)
// send `enrollment` as the request body's `opaque` field
```

One argument, where the SRP verifier this replaces took four. There is no
`identity` — a record binds to a credential identifier the server chooses, so
enrolling against an email can no longer produce something no login can satisfy
— and no group or KDF, because the server names them in its `register/start`
response and this call honours what it names.

It takes a `context.Context` because it performs that round trip: OPAQUE's
envelope is sealed under the server's oblivious PRF, so there is no offline
computation that produces a valid record. The SRP verifier needed no network at
all.

### Cost

`LoginOpaque` runs the tenant's key-stretching function: Argon2id at 19 MiB and
t=2 by default, which is tens to hundreds of milliseconds of CPU and the memory
to go with it. That cost is the point — it is what makes a stolen record
expensive to attack even by someone holding the OPRF seed. Treat the call as
blocking work; it is not something to run per request on a hot path.

### This SDK's one permitted exception, and how it is kept honest

CONTRACT.md §23.1 forbids an SDK from implementing OPAQUE. Every other SDK
binds `crates/axiam-opaque` — compiled, through WebAssembly, or through its C
ABI. Go is the single exception and uses
[`github.com/bytemare/opaque`](https://github.com/bytemare/opaque) natively.

Both halves of the justification are required: a vetted, independently
maintained RFC 9807 implementation exists for Go, **and** binding the C ABI
would force cgo on every consumer, breaking `CGO_ENABLED=0` builds and
cross-compilation. Neither reason alone would be enough.

The risk that creates is that the two implementations disagree, and "both
implement RFC 9807" is not evidence: they must agree on the OPRF, the key
schedule, the envelope, the AKE transcript **and** the key-stretching
parameters, of which only the first four are in the specification. The KSF is
where it would actually break — `opaque-ke` stretches with a 16-byte all-zero
salt and a 64-byte output, and nothing in the RFC says it must.

So it is checked rather than assumed. `opaque_interop_test.go` completes a full
registration and login against the Rust implementation's server half, asserting
the width of every message and that the envelope opens:

```bash
# in a checkout of ilpanich/axiam
cargo build -p axiam-opaque --example interop

# here
AXIAM_INTEROP_HELPER=/path/to/axiam/target/debug/examples/interop     go test -tags interop -run Interop ./...
```

CI runs it on every pull request. If it ever fails, one side moved — find out
which, rather than loosening the test.

### Zeroization

The `password` argument is a Go `string` and therefore **cannot** be
overwritten: strings are immutable and the runtime may have copied it before
this SDK ever saw it. If that matters to your threat model, keep the plaintext
in a `[]byte` you control for as long as you can and accept that the final
conversion is outside this SDK's reach. The protocol's own intermediates are
`bytemare/opaque`'s responsibility.

`OpaqueAvailable` always reports `true` here, because the Go SDK compiles the
implementation in. It is in the API because §23.2 puts it in every SDK's
vocabulary, and in the SDKs that load a native library or a WebAssembly module
it genuinely answers `false` when that artifact is absent.

## Versioning

Releases are tagged `vX.Y.Z`. Pushing such a tag triggers the module-publish CI
job, which verifies the tag was cut from `main` and asks proxy.golang.org to
fetch it; pull-request events never trigger publish.

There is no registry upload step — for Go, the git tag *is* the release, and
`go get` resolves it through the module proxy. API docs appear automatically on
pkg.go.dev once the proxy has seen the tag.

## Client quality-of-life (CONTRACT.md §16–§19)

### Retry policy (§16)

Read-only authorization checks — `CheckAccess`, `Can`, `CheckAccessAs`, `CheckAccessDecision`,
`BatchCheck` — retry transient failures under the contract's normative table: **3 attempts**
(1 initial + 2 retries), 200 ms base, 5 s cap, **full jitter** (uniform over `[0, backoff]`),
and `Retry-After` honored as a **floor**.

> **This changed in D5.** The previous policy used a 100 ms base, `backoff *= 2` with **no cap
> and no jitter**, and ignored `Retry-After` entirely. Uncapped, the wait was bounded by
> nothing but the attempt count; unjittered, every client that saw the same outage retried at
> the same instant — the thundering herd the backoff is supposed to prevent.

Only failures that could plausibly succeed on a second attempt are retried: transport errors,
`408`, `429`, `5xx`. A `401` or `403` is an answer, not a transport failure, and surfaces after
exactly one attempt. Nothing that changes server state is ever retried. A cancelled context
wins over a pending backoff.

```go
// Turn it off if you own your own retry layer — you know your deadline, this SDK doesn't.
client, err := axiam.NewClient(baseURL, "acme", axiam.WithRetryDisabled())
```

There is deliberately no option for the attempt cap, base delay or delay cap: §16.1 forbids
raising them, and eleven SDKs agreeing on one table is the point.

### Deterministic shutdown (§18)

`client.Close()` releases the client's local resources and closes idle connections. It is
idempotent, satisfies `io.Closer`, and any call afterwards returns a `*NetworkError` naming the
cause rather than silently reconnecting.

**`Close` does not log out.** It never reaches the network. The server-side session
deliberately outlives the `Client` value — that is what lets a process restart and resume — so
a `Close` that logged out would silently end every user's session on each deploy. Call `Logout`
first if ending the session is what you want.

### Telemetry hooks (§19)

Wire metrics without this module depending on any metrics library:

```go
client, err := axiam.NewClient(baseURL, "acme", axiam.WithTelemetryHook(
    func(e axiam.TelemetryEvent) {
        switch ev := e.(type) {
        case axiam.RequestEndEvent:
            histogram.Record(ctx, ev.Duration.Seconds(), /* labels */)
        case axiam.RetryEvent:
            counter.Add(ctx, 1, /* labels */)
        }
    },
))
```

- **A hook that panics cannot fail the operation that fired it** — and in Go an unrecovered
  panic would take the process down, not just the request.
- **No event payload can carry a token.** `TelemetryEvent` is a closed interface (its marker
  method is unexported) with fixed field sets — this surface exists to be shipped to a metrics
  backend.
- **Path templates, not URLs**, so a metric label cannot become a cardinality bomb.

One `RequestStartEvent`/`RequestEndEvent` pair is emitted **per attempt**, so you can count
real wire calls. See [`examples/telemetry-hook`](examples/telemetry-hook) for the
OpenTelemetry mapping.

### Decision memo (§17) — opt-in, off by default

An optional TTL-bounded cache for `CheckAccess` results. **Disabled by default**, because
§11.2 rule 6's ban on caching authorization decisions is still the default behaviour.

```go
client, err := axiam.NewClient(baseURL, "acme", axiam.WithDecisionMemoTTL(5*time.Second))
```

**What you are accepting.** The staleness bound is the TTL, in *both* directions: a grant
revoked on the server can still read as allowed for up to the TTL, and a grant just added can
still read as denied for up to the TTL.

> **Reads-your-own-writes is not guaranteed.** An admin UI that grants a role and immediately
> re-checks is the case that breaks, and it breaks silently. If that is your workload, leave
> this off.

The TTL is clamped to `MaxMemoTTL` (5 s) rather than rejected. Allows and denies are memoized
identically — asymmetric caching would leak which outcome occurred through latency. Failures
are never memoized: caching a transport error as a deny would turn a blip into a TTL-long
outage. The memo is cleared on `Login`, `VerifyMfa`, `Refresh` and `Logout`, since entries are
keyed by subject rather than by session. It is safe for concurrent use.
