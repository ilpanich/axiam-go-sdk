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

This SDK conforms to CONTRACT.md §1–§13 and §12.7, §14, §15, §17, §19, §20, §21, §22, §23 (including §6.1 mTLS).

§12.7, §14, §15, §20, §22 and §23 are named rather than folded into the range because they
landed after this SDK already claimed §1–§13: widening the range silently would
turn a statement that was true when written into a different claim without
anyone editing it.

See [`CONTRACT.md`](./CONTRACT.md) for the full cross-language behavioral contract.

## Status

Implemented (Phase 18). REST client (login/MFA/refresh/logout, authz
check/can/batch-check), gRPC client (authz check/batch-check plus
`GetUserInfo`), AMQP consumer with HMAC verification, local JWKS verification,
`net/http` middleware, OIDC/SSO relying-party helpers (§12 — "Login with
AXIAM"), a webhook-signature verifier (§13), the reactor runtime (§22 —
`ReactorServe`) and the SRP-6a login path (§23 — `LoginSrp`) are all
available. Runnable examples live under
[`examples/`](./examples).

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

## Secure Remote Password (CONTRACT.md §23)

`LoginSrp` proves the password to the server without the password — or
anything from which it can be cheaply recovered — ever crossing the wire. The
server stores a **verifier** `v = g^x mod N` instead of a password hash, and
what travels is `A` and a proof, neither of which is useful without that
verifier.

```go
result, err := client.LoginSrp(ctx, "alice", password)
```

It takes the same arguments as `Login` and returns the same `LoginResult`,
MFA branch included, so switching a tenant to SRP needs no change to how the
result is handled. A runnable end-to-end example, including the fallback and
the enrolment call, is in [`examples/srp-login`](./examples/srp-login).

### What this buys, and what it does not

SRP closes holes TLS 1.3 does not:

- a TLS-terminating reverse proxy, ingress controller, CDN or service mesh
  sees every plaintext password today; under SRP it sees `A` and `M1`;
- an accidental request-body log, a heap dump or a crash reporter can no
  longer capture a plaintext password, because the server never has one;
- a leaked verifier database still costs a full KDF evaluation per candidate
  password, exactly as a leaked Argon2id database does.

It does **not** protect against a compromised AXIAM server, and this SDK does
not claim it does.

### Tenant policy, and the two errors that are not credential failures

`srp_mode` is an organization baseline a tenant may tighten:

| mode | `/auth/login` | `LoginSrp` |
|---|---|---|
| `disabled` (default) | works | `*NetworkError` — the endpoint answers `404` |
| `optional` | works | works |
| `required` | `*AuthzError` (`srp_required`) | works |

Both of those errors are deliberately **not** `*AuthError`:

- `errors.Is(err, ErrNetwork)` from `LoginSrp` means *this tenant does not
  offer SRP*, a property of the tenant rather than of any user. Fall back to
  `Login`.
- `errors.Is(err, ErrAuthz)` from `Login` means *this tenant refuses password
  login*. The credentials were never examined. Showing "invalid username or
  password" to a user whose password is perfectly good is the failure this
  mapping exists to prevent.

`required` refuses **every** principal in the tenant, not only the enrolled
ones. Splitting the response on whether an account has a verifier would turn
`/auth/login` into an enumeration oracle costing one junk password per name.
It also means `required` locks out anyone not yet enrolled: a verifier needs
the plaintext password, and a stored Argon2id hash is not invertible, so
nobody can be enrolled retroactively. Operators turn it on last, after a
password-reset campaign.

### Enrolment

The server cannot compute a verifier, so any request that **sets** a password
has to carry one. `SrpEnrollment` produces the `srp` object for
`POST /api/v1/users`, `/auth/password/change`, `/auth/reset/confirm` and
`/admin/bootstrap`:

```go
enrolment, err := client.SrpEnrollment(axiam.SrpEnrollmentRequest{
    Identity: "alice", // the USERNAME, not an email — see below
    Password: newPassword,
    Group:    policy.SrpGroup, // from GET /api/v1/auth/me
    Kdf:      policy.SrpKdf,
})
```

`Identity` must be the account's **username**: `x` is derived over
`identity ":" password` using the identity the challenge endpoint hands back,
so a verifier enrolled against an email address can never satisfy a login.
For the same reason, **renaming a user invalidates their verifier** — the
server clears it, and the user re-enrols at their next password change.

The salt is 32 fresh bytes from `crypto/rand` on every call.

### Cost

`LoginSrp` runs the tenant's KDF: Argon2id at 19 MiB and t=2 by default, which
is tens to hundreds of milliseconds of CPU plus that memory, per login
attempt. That cost is the point — it is what makes a leaked verifier no
cheaper to attack than a leaked Argon2id hash. Size connection pools and
request timeouts accordingly; it is not a cost `Login` has.

### Cryptographic parameters

RFC 5054 Appendix A groups `rfc5054_2048`, `rfc5054_3072` and `rfc5054_4096`
(the AXIAM default), embedded as constants. A modulus is **never** accepted
from the server — a server-supplied `N` is a server-supplied trapdoor — and a
group this SDK does not recognise is refused rather than guessed.

Two deliberate divergences from RFC 5054, both AXIAM-wide:

- `H` is **SHA-256**, not SHA-1.
- `x` is a **memory-hard KDF output**, not a bare hash. RFC 5054's bare-hash
  `x` would make a leaked verifier *cheaper* to attack offline than the
  Argon2id hashes AXIAM already stores, which would make adopting SRP a net
  regression at rest.

Both KDFs are implemented: Argon2id via `golang.org/x/crypto/argon2` and
PBKDF2-HMAC-SHA256 via the standard library's `crypto/pbkdf2`. The server
dictates which, per exchange; the SDK honours what it is given and never
caches parameters across logins, because a verifier enrolled under different
costs stays valid.

### Zeroization

`x`, the derived secret, `S` and `K` are overwritten after use. The
`password` argument is a Go `string` and therefore **cannot** be: strings are
immutable and the runtime may have copied it before this SDK ever saw it. If
that matters to your threat model, keep the plaintext in a `[]byte` you
control for as long as you can and accept that the final conversion is
outside this SDK's reach.

`SrpAvailable` always reports `true` here. It is in the API because §23.1 puts
it in every SDK's vocabulary, and in PHP — the one language with no native
bignum — it genuinely answers `false`.

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
