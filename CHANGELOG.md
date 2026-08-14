# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Re-sync vendored `CONTRACT.md` to contract 1.14** — documentation only, no code change.
  §20.2 rule 6 (a permission ticket MUST NOT be retried) cited a "measured residual
  (ilpanich/axiam#302) … roughly 1 in 640" as its second reason. That residual is closed: the
  server now decides the ticket race with a transaction its storage engine arbitrates plus a
  redemption nonce read back after the commit. **The rule is unchanged, and this SDK's
  behaviour is unchanged** — `uma_exchange_ticket` stays excluded from every automatic retry
  path. What changed is the reasoning: the first reason (a spent ticket makes the retry
  useless) always stood alone, and the second now rests on what an SDK can actually know —
  it is talking to a server whose storage engine it cannot attest, and the guarantee is
  conditional on that engine being persistent.
- **BREAKING (contract 1.13): `TokenExchangeParams.SubjectTokenType` is now required.** It
  shipped optional, defaulting to `…:access_token` when empty. That satisfied §15.7's "never
  inspect the subject token" while leaving the rule it serves unenforced: an optional field with
  a default *is* a default the SDK applies whenever the caller says nothing. The guess did not
  go away, it moved into the signature. §15.1 now makes the parameter required.

  Go cannot demand a struct field at compile time, so the demand lands at the call: an empty
  `SubjectTokenType` returns an `*AuthError` **client-side, with no wire call**, naming the
  field and both constants. A test pins that no request is sent.

  **Migration** — pass what you were previously getting by silence:

  ```go
  exchanged, err := client.TokenExchange(ctx, axiam.TokenExchangeParams{
      SubjectToken:     axiam.Sensitive(userToken),
      SubjectTokenType: axiam.SubjectTokenTypeAccessToken, // <- add this
      Scopes:           []string{"orders:read"},
  })
  ```

  This closes a gap rather than opening one: `subject_token_type` has always been required *on
  the wire*, and the SDK was covering for that with a constant which stopped being the only
  legal value when X4 landed. For a caller who actually held a refresh token, the old default
  traded the `invalid_request` that names the type for a generic `invalid_grant`.

### Added

- **§15.7 external-IdP subject tokens (X4).** `TokenExchange` can now exchange a token minted
  by a trusted external IdP — a partner's Entra, Okta or Keycloak — for an AXIAM token scoped
  to what the resolved AXIAM user may actually do. No new operation: the same method, plus
  `TokenExchangeParams.SubjectTokenType` and the `SubjectTokenTypeAccessToken` /
  `SubjectTokenTypeJWT` constants.

  **The type is the caller's to name, never the SDK's to guess.** §15.7 forbids inspecting the
  subject token to pick it, because which kind of token you hold is something only you know and
  a wrong guess is the difference between a request that is refused and one that is silently
  reinterpreted. A JWT-shaped subject token does **not** change what is sent, which is asserted
  by a test. (This shipped with an `…:access_token` default; contract 1.13 removed it — see
  *Changed* below.)

  Also asserted: an `actor_token` alongside an external subject token surfaces
  `invalid_request` with no retry and no request rewriting; a refused refresh or ID token type
  is never retried as a different type; the one normative description — `the subject token's
  issuer is not configured for token exchange`, meaning *fix the AXIAM trust config* rather
  than *fix your token* — reaches the caller intact; and nothing re-exchanges an exchanged
  token, which both server paths refuse because exchanges do not compose.

  New `examples/external-token-exchange` runs the partner-token → AXIAM-token exchange at an
  API gateway, including the one error branch worth telling apart.

  `CONTRACT.md` and `openapi.json` re-synced from `ilpanich/axiam@main` (contract 1.10 → 1.12
  plus §15.7), which also brings contract 1.11's lifted §12.6 deferral, contract 1.12's
  `/oauth2/*` error rows dispatching on the `error` field at any status, and the
  `TokenExchangeTrust` schemas behind the X4 provider configuration.

- **§20.3 challenge emission from the §11 guard.** `middleware.WithUmaChallenge(*UmaChallenger)`
  makes `RequireAccess` answer a denial with a freshly minted ticket in
  `WWW-Authenticate: UMA` instead of a bare 403. `UmaChallenger` carries the realm, the
  `as_uri`, the PAT and a `UmaTicketMinter` — an interface `*Client` already satisfies, kept
  narrow for the same reason `AccessChecker` is.

  **Opt-in**, because emitting a challenge means minting a credential: a guard that did it by
  default would put a Protection API call behind every unauthorized request, which is a
  denial-of-service amplifier aimed at your own authorization server. An allow mints nothing,
  and neither does a 401 or a fail-closed 503 — only a resource denial is answerable with a
  ticket. And a **minting failure is not an escalation**: the denial still surfaces as the
  plain 403, never a 503 and never an allow. Both are asserted by counting minter calls.

  The requested scope is the AXIAM *action*, so the ticket asks for exactly the authority just
  refused and the engine's deny rules keep applying to whatever RPT comes back.

  Paired with the new `examples/uma-resource-server` and `examples/uma-client`, which run both
  halves — including the trust decision §20.3 keeps in the caller's hands rather than
  auto-exchanging against whatever host a 403 named.

- **§20 UMA 2.0 — Protection API and ticket grant.** Nine entry points:
  `UmaRegisterResource`, `UmaReadResource`, `UmaUpdateResource`, `UmaDeleteResource`,
  `UmaListResources`, `UmaRequestTicket` and `UmaExchangeTicket` on `*Client`, plus the two
  package-level challenge helpers `UmaParseChallenge` / `UmaChallengeHeader`. New types
  `ResourceSet`, `RequestedPermission`, `RptPermission`, `RequestingPartyToken`,
  `UmaExchangeTicketParams` and `UmaChallenge`.

  The load-bearing rules, all asserted in `oidc_uma_test.go`:

  - **`UmaExchangeTicket` is never retried** — not on `5xx`, not on a transport failure, not
    on `invalid_grant`. This is the one documented exception to §16, and a security rule
    rather than a performance one: the ticket is consumed *before* the exchange is evaluated,
    so a retry is a second redemption — the concurrency case whose measured residual
    `ilpanich/axiam#302` records.
  - **`UmaParseChallenge` performs no exchange.** The `as_uri` names an authorization server
    the caller has not chosen to trust.
  - **The RPT is never adopted** as the client's credential (§20.2 rule 4), and
    `RequestingPartyToken` has no refresh-token field (rule 5).
  - **`UmaUpdateResource` replaces the scope list rather than merging it** (§20.2 rule 8) —
    no read-modify-write, so omitting a scope removes it.
  - **An absent PAT or `ClaimToken` is refused client-side**, with no wire call, so a request
    that could not have succeeded never spends a ticket.

- **§19 `ConfigClampedEvent` (contract 1.9).** A clamped setting is now reported at
  construction rather than applied silently — currently the §17.1 rule 2 memo TTL
  (`WithDecisionMemoTTL`). Clamping is right; clamping *silently* is not: an operator who set
  a 60-second TTL believes their staleness bound is 60 seconds, and it is five. Nothing is
  emitted for a value already within its limit, or for the disabled default.

### Changed

- Re-vendored `CONTRACT.md` at **1.10** and `openapi.json` (the server's `/uma2/*` surface).
- The ticket grant maps its errors through `mapUmaGrantError`, which dispatches on the
  `error` field at *any* status. `access_denied` answers HTTP 403 here where RFC 8628's
  answers 400, and the shared `/oauth2` mapper gates its `OAuth2ErrorResponse` rows to
  400/401 — deliberately, so an ordinary REST 403 still maps to `*AuthzError`. Widening it
  there would have changed every other endpoint's behaviour to fix one grant, so the fix is
  contained to the grant. A body that is not an `OAuth2ErrorResponse` still falls through to
  the §2 status mapping.

## [Unreleased]

### Added

- **§18 `Client.Close()`** — idempotent, satisfies `io.Closer`, clears the memo and closes
  idle connections. Use-after-close returns a `*NetworkError` rather than silently
  reconnecting. It does **not** log out and never reaches the network: the server-side session
  outlives the `Client` value, and a `Close` that logged out would end every user's session on
  each deploy.
- **§19 telemetry hooks** — `WithTelemetryHook`, the closed `TelemetryEvent` interface
  (`RequestStartEvent`, `RequestEndEvent`, `RetryEvent`, `RefreshEvent`) and
  `examples/telemetry-hook` with the OpenTelemetry mapping. A panicking hook is recovered, and
  no event payload can carry a token. One request pair per *attempt*.
- **§17 decision memo — opt-in, off by default** — `WithDecisionMemoTTL`, clamped to
  `MaxMemoTTL` (5 s), safe for concurrent use. Allows and denies memoized identically,
  failures never memoized, cleared on any credential change.
  **Reads-your-own-writes is not guaranteed.**
- `WithRetryDisabled` (§16.6). No option for the attempt cap, base or delay cap: §16.1 forbids
  raising them.
- `NetworkError.RetryAfter`, parsed from the `Retry-After` header. Both RFC 7231 forms are
  accepted — delta-seconds and HTTP-date, the latter being what CDNs and proxies commonly send
  on 429/503. The parsed *duration* is stored, never the raw header text, so the D-04/CR-04
  redaction invariant is untouched.

### Changed

- **§16: `retryReadOnly` replaced.** The old policy used a 100 ms base, `backoff *= 2` with
  **no cap and no jitter**, and ignored `Retry-After`. It now follows the contract table: 3
  attempts, 200 ms base, 5 s cap, full jitter over `[0, backoff]`, `Retry-After` as a floor.
  Uncapped, the old wait was bounded by nothing but the attempt count; unjittered, every client
  retried in lockstep — the thundering herd a backoff exists to prevent.
- The unexported `authzRetryMaxAttempts` constant is replaced by the exported `MaxAttempts`,
  alongside `BaseDelay` and `MaxDelay`.
- Re-vendored `CONTRACT.md` at **1.8.2**. `openapi.json` unchanged — docs-only contract revs.

## [1.0.0-alpha24] - 2026-08-04

### Added

- Add HMAC-SHA256 webhook signature verifier (CONTRACT.md §13)

### Changed

- Add the §10.1 rule-8 guardrail regression tests (#29)
- Device (mTLS) tokens now carry aud=axiam:m2m (#28)
- Service accounts can use login_client_credentials (#27)
- Cover the §10.1 validation path at package level
- Bump coverallsapp/github-action from 2.3.7 to 2.3.8
- Bump the minor-patch group with 2 updates

### Fixed

- Raise the go directive to 1.25.12 to clear stdlib advisories (#26)
- Enforce the full CONTRACT §10.1 local-verification set

## [Unreleased]

### Security

- **`go` directive raised 1.25.0 → 1.25.12 (§12.6.3).** `govulncheck` reported
  **26 standard-library advisories** against this module — reproduced firsthand,
  including reachable traces through `crypto/x509`, `crypto/tls` and
  `net/http` from `buildHTTPClient`, `doRequest` and `NewVerifierForURL`. The
  cause was the `go` directive, which sets the minimum toolchain a consumer may
  build this SDK with: at `1.25.0` a consumer on exactly that toolchain got the
  vulnerable stdlib. (CI was green because `setup-go` installs a newer toolchain
  that satisfies the directive, which is precisely why the floor itself needed
  raising rather than the CI pin.)

  **Correction to the finding as written:** it recorded these as "fixed in
  go1.25.3". That is incomplete — bumping to `1.25.3` clears only 7 of the 26;
  19 remain, in advisories published later. `1.25.12` — the version CI already
  installs — takes `govulncheck` to **0 affected vulnerabilities**, verified
  firsthand.

  Consumers now need Go 1.25.12 or newer to build this module.

### Security

- **BREAKING (acceptance tightened).** Align the `net/http` guard with the new
  normative CONTRACT.md §10.1 "minimum local-verification set". Three rules
  were previously unenforced by `middleware.Middleware`:
  - **`exp` is now REQUIRED.** A token carrying **no** `exp` was accepted —
    the check read `if claims.Exp != 0 && …`, so an absent `exp` (which
    decoded to the zero value) skipped the comparison entirely and the token
    was treated as having no expiry constraint. That is a permanent
    credential, and is the `SEC-080` defect verbatim. A non-numeric `exp`
    (e.g. the JSON string `"1700000000"`) is likewise rejected rather than
    coerced.
  - **`nbf` is now honoured.** The claim was not read at all; a token whose
    `nbf` is in the future was accepted before its validity window opened.
  - **A guard constructed with an empty tenant now fails closed** explicitly,
    rather than relying on the incidental behaviour of a string comparison.

  Tokens minted by the AXIAM server are unaffected — they always carry `exp`
  and never a future `nbf`. A guard fed tokens from **another signer sharing
  the organization-wide JWKS** may start rejecting what it previously
  accepted. That is the intent of the change.

### Added

- Add `middleware.WithExpectedIssuer` and `middleware.WithExpectedAudience` —
  the CONTRACT.md §10.1 rule 5/rule 6 checks. Both are **conditional and
  default to unset**: with no expectation configured no check is performed,
  and once configured a mismatching (or absent) claim is rejected. No issuer
  or audience is hardcoded anywhere in this SDK; a guard fronting a
  user-facing resource server should generally expect `axiam:user`.
- Add `axiam.ClockSkewLeeway` — the named, bounded 60-second clock-skew
  constant applied to the `exp`/`nbf` checks (§10.1 rule 7). It is a constant
  and is deliberately not operator-configurable.
- Add `axiam.TokenValidationOptions` and
  `(*axiam.JWKSVerifier).VerifyAccessToken` — the full §10.1 verification
  entry point every guard in this SDK now routes through.
- Add the complete §10.1 required negative-test set against the real
  middleware and the real JWKS verifier (`middleware/contract_10_1_test.go`):
  expired; no `exp`; non-numeric `exp`; future `nbf`; different tenant; no
  `tenant_id`; unconfigured tenant; `alg: none`; an HS256 token bearing an
  EdDSA key id; plus issuer and audience mismatch cases.
- Add `webhook.Verify` — HMAC-SHA256 webhook-signature verification with a
  two-sided freshness window (CONTRACT.md §13, T-145)

### Changed

- **BREAKING (API).** `(*axiam.JWKSVerifier).Verify` is renamed
  `VerifySignatureOnlyUnchecked`. CONTRACT.md §10.1 permits a raw
  signature-only primitive but requires that its name "make the omission
  obvious at the call site" and that it not be the documented guard entry
  point. It checks no claim at all — an expired token, a token with no `exp`,
  and a token minted for a *different tenant* under the same org-wide JWKS all
  verify successfully. Callers wanting a guard should use `VerifyAccessToken`
  or `middleware.Middleware`.
- **BREAKING (API).** `jwks.Claims.Exp` is now `*int64` (was `int64`), and the
  struct gains `Nbf *int64`, `Issuer string` and `Audience []string`. The
  pointer is load-bearing: a plain `int64` cannot distinguish "no `exp`
  claim" from "`exp` is zero", and conflating those two is exactly what
  produced the accepted-permanent-credential bug above.
- Re-sync the vendored `CONTRACT.md` with the new normative §10.1.

## [1.0.0-alpha23] - 2026-08-02

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha21.

## [1.0.0-alpha21] - 2026-07-30

### Added

- Add OIDC/SSO relying-party helpers (CONTRACT.md §12)

### Changed

- Re-sync vendored CONTRACT.md to contract 1.6
- Re-sync vendored CONTRACT.md to contract 1.5
- Bump github.com/rabbitmq/amqp091-go
- Bump bufbuild/buf-action from 1.4.0 to 1.5.0
- Bump actions/checkout from 7.0.0 to 7.0.1

### Fixed

- Publish the discovery outcome before vacating the guard slot
- Publish the refresh outcome before vacating the guard slot

## [Unreleased]

### Fixed

- `OidcRefresh`: publish the single flight's outcome before vacating the
  in-flight slot (CONTRACT.md §9 rules 2 and 3). The slot used to be cleared
  first, so a caller arriving in the gap found it empty with no outcome
  published and started a second `refresh_token` grant — which, against
  AXIAM's single-use rotating refresh tokens, replayed a consumed token and
  failed with `invalid_grant`.
- `OidcDiscover`: apply the same publish-before-vacate ordering to the
  discovery single-flight guard (CONTRACT.md §12.3 rule 6). The success path
  was already benign — the document cache is populated under the same lock
  that vacated the slot — but the error path caches nothing, so a caller
  arriving in the gap issued a second discovery fetch. Idempotent, hence a
  spurious extra request rather than a wrong result; now unreachable.

## [1.0.0-alpha18] - 2026-07-24

### Changed

- Bump actions/setup-go from 6.5.0 to 7.0.0 (#12)
- Bump google.golang.org/grpc in the minor-patch group (#13)
- Exclude generated gRPC code from the metric; ratchet floor 93->94 (#15)

## [1.0.0-alpha16] - 2026-07-22

### Added

- Add UserInfoClient.GetUserInfo (CONTRACT §1.1)

### Changed

- Vendor userinfo.proto + regenerate stubs, re-sync CONTRACT.md to 1.3

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

- OIDC / SSO relying-party helpers (CONTRACT.md §12, contract 1.4): the nine
  canonical operations — `OidcDiscover`, `OidcBegin`, `OidcExchange`,
  `OidcRefresh`, `LoginClientCredentials`, `Introspect`, `Revoke`, `SsoStart`,
  `SsoComplete` — as new methods on the existing `*Client`, configured via the
  new `WithOidcClientID`/`WithOidcClientSecret`/`WithOidcDiscoveryTTL`/
  `WithOidcClockSkew` options. Highlights:
  - `OidcDiscover` caches the discovery document per client instance with a
    5-minute-floor TTL and single-flight de-duplication of concurrent
    fetches (§12.3 rule 6).
  - `OidcBegin` is pure local computation (no network I/O): CSPRNG
    `state`/`nonce` (32 bytes, base64url-unpadded) and an **S256-only** PKCE
    `code_verifier`/`code_challenge` pair (RFC 7636; `plain` is not
    implemented anywhere in this SDK).
  - `OidcExchange`/`OidcRefresh` validate any `id_token` against the full
    CONTRACT.md §12.4 checklist — `alg` must be exactly `EdDSA`, signature
    verified via a JWKS verifier read from the discovery document's
    `jwks_uri` (extending `internal/jwks.Verifier` with a new
    `VerifyPayload`/`NewVerifierForURL` pair rather than forking it),
    `iss`/`aud`/`exp`/`iat`/`nbf`/`nonce` checked with ≤60s clock skew — and
    discard the WHOLE token set (access and refresh token included) on any
    single failing rule, raising `*AuthError` with a stable `Reason` code
    (`invalid_alg`, `unknown_kid`, `invalid_signature`, `invalid_issuer`,
    `invalid_audience`, `token_expired`, `nonce_mismatch`).
  - A new `*OAuthProtocolError` type (embeds `AuthError`, implements
    `Unwrap() *AuthError`) surfaces an `OAuth2ErrorResponse` body from
    `/oauth2/*` — `errors.Is(err, ErrAuth)` and `errors.As(err, &authErr)`
    against the existing `*AuthError` type keep matching it unchanged. A 401
    from `Introspect`/`Revoke` never enters the existing §9 refresh guard.
  - `OidcRefresh` runs under its own single-flight guard (a dedicated
    mutex+channel instance, kept separate from the cookie-session
    `Client.guard` — the two operate on unrelated token namespaces) so N
    concurrent callers collapse into exactly one token-endpoint request.
  - `OidcStateStore` interface plus `NewMemoryOidcStateStore` (TTL clamped to
    10 minutes, single-use `Consume`, lazy sweep, no background goroutine) —
    entirely optional; the core operations never touch a store themselves.
  - `middleware.OidcLoginHandler`/`middleware.OidcCallbackHandler`
    (`net/http`) wire `OidcBegin`/`OidcExchange` and an `OidcStateStore`
    together into a ready-to-mount two-route "Login with AXIAM" flow.
  - All five §12.5 secret fields (`AccessToken`, `RefreshToken`, `IDToken`,
    the configured `client_secret`, `CodeVerifier`) are held behind the
    existing `Sensitive` type; `state`/`nonce` are plain strings (not
    secrets, per §12.3 rule 2).
  - New example: [`examples/oidc-login`](./examples/oidc-login).
  - `CONTRACT.md` re-synced to contract 1.4; this SDK's conformance
    statement is now "§1–§12".

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
