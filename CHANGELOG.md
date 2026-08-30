# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0-beta06] - 2026-08-30

### Changed

- Maintenance release — no notable changes since v1.0.0-beta05.

## [1.0.0-beta05] - 2026-08-30

### Added

- Contract 1.35, carrying 1.34 — service-account RBAC, principal tenant, tenant scope

- **Contract 1.35, which carries contract 1.34 with it.** Nothing had been
  fanned out since 1.33, so this re-vendors `CONTRACT.md`, `openapi.json` and
  `management-registry.json` across both revisions. The registry still holds
  155 operations across 24 namespaces — 1.35 changed only its `spec_digest` —
  so the eight §27 operations below arrived with 1.34 and are new here
  regardless.

- **§27: service accounts as RBAC principals** (contract 1.34) — eight
  generated operations across `management_roles.go`, `management_groups.go` and
  `management_service_accounts.go`. `UnassignFromServiceAccount` takes the same
  optional `resource_id` query parameter as the user and group unassign calls:
  omitting it removes the *global* grant specifically, not every grant of that
  role.

- **§5.2.2: the acting tenant and the principal tenant are different things**
  (contract 1.34). `LoginResult` gains `TenantID`, `PrincipalTenantID`,
  `PrincipalTenantSlug`, `OrgID` and (from §5.2.3) `ReachableTenantIDs`.
  Absent means equal — a server older than 1.34 omits them and cannot switch
  the acting tenant either, so `PrincipalTenantID` falls back to `TenantID`
  rather than to nil. Read `OrgID` from the session instead of resolving a slug
  through `GET /api/v1/organizations`, which is `super-admin`-only.

- **§5.2.3: tenant-scoped role assignments** (contract 1.35). `TenantScope`
  appears on the three assignment request bodies and on the assignment objects
  the read paths return. Omitted means unrestricted, which is what every
  assignment written before the field existed already meant.

### Fixed

- **A registration record for your own password was sealed against the wrong
  tenant.** CONTRACT.md §5.2.2 rule 2: the caller's credentials live in the
  tenant the *account* lives in, not whichever tenant the client is currently
  pointed at, and a record sealed against the acting tenant is refused with
  "the OPAQUE session was issued for a different tenant".

  `OpaqueEnrollment` had one behaviour for a method documented for three
  callers — user creation, change-password and reset completion — and only the
  first of those wants the acting tenant. It keeps that behaviour; the new
  `OpaqueEnrollmentForSelf` seals against `PrincipalTenantID` and is what a
  self-service password change must call.

  The two collapse to the same request for every ordinary principal, so this
  only bit an organization-level account that had switched tenant.

### Note on `X-Tenant-ID` vs `X-Axiam-Tenant`

CONTRACT.md §5.2.2 and §5.2.3 name the acting-tenant header `X-Tenant-ID`, but
the AXIAM server reads **`X-Axiam-Tenant`** (`ACTIVE_TENANT_HEADER` in
`crates/axiam-api-rest/src/extractors/auth.rs`), as do its own tests, the admin
UI, and the `openapi.json` vendored alongside that contract. The server never
reads `X-Tenant-ID` at all.

Documentation updated here names `X-Axiam-Tenant`, because a tenant switch sent
under the other name is not refused — it is ignored, and the request quietly
acts on the principal's own tenant instead. The discrepancy has been reported
upstream; this SDK's existing `X-Tenant-ID` sends are left as they are, being
out of scope for a contract re-vendor.

### Unchanged, deliberately

- **§5.2.3 rule 1 needed no code here.** `tenant_scope: []` is refused with
  `400`, and Go is the one language in this fan-out where the natural encoding
  already does the right thing: `encoding/json`'s `omitempty` drops a
  zero-length slice as readily as a nil one. `TestAnEmptyTenantScopeNeverReachesTheWire`
  pins that rather than proving a fix — switching the field to a pointer, or
  dropping `omitempty`, would silently put the refused shape back on the wire.

## [1.0.0-beta04] - 2026-08-28

### Changed

- Pin actions by digest, re-vendor contract 1.33, document the provenance posture

- **CONTRACT 1.32 — signing in an organization-level principal (§5.2.1).**
  `CONTRACT.md`, `openapi.json` and `management-registry.json` re-vendored from
  the AXIAM server, where the same bug class had made an organization-level
  administrator unable to sign in at all (ilpanich/axiam#388).

  Naming no tenant now resolves the organization's own reserved scope on
  `/auth/login`, `/auth/opaque/login/start`, `/auth/opaque/register/start` and
  `/auth/webauthn/authenticate/discoverable/start`. That reserved tenant's slug
  is `organization`, so this SDK reaches it through the ordinary constructor:

  ```go
  axiam.NewClient(baseURL, "organization", axiam.WithOrgSlug("globex"))
  ```

  Prefer that over omitting the tenant: §5 rule 2 still requires one on the
  `X-Tenant-ID` header of every request after the login.

### Fixed

- Pass toolchain: stable to the digest-pinned rust-toolchain action

- Refuse a whitespace-only tenantSlug, not just an empty one

- **`NewClient` now refuses a whitespace-only `tenantSlug`, not just an empty
  one** (CONTRACT.md §5, §5.2.1 rule 2). `tenantSlug == ""` let `"   "` through,
  and a slug of spaces is exactly as much of a tenant as none at all.

  It matters because nothing can carry a blank slug: the server resolves
  nothing, and on `/auth/opaque/login/start` it fails on the workspace *before*
  the tenant's OPAQUE mode is read — so the `404` of §23.4 rule 10 never
  arrives, this SDK has no fallback to take, and sign-in fails even against a
  tenant with OPAQUE **disabled**, answered as "invalid credentials".

## [1.0.0-beta02] - 2026-08-28

### Added

- Contract 1.31 — list search, the truthful resend, organization scope

- Implement CONTRACT §27 — the management API

- **CONTRACT 1.31 — the AXIAM server PR #383 surface.** `CONTRACT.md`,
  `openapi.json` and `management-registry.json` re-vendored, and the six things
  they describe implemented.

  - **`Search` on all twenty paginated management operations** (§27.4 rule 4).
    A third field on `PageRequest`, not a third argument on twenty generated
    `List` methods, plus an `axiam.Matching(n, term)` constructor beside
    `axiam.Limited(n)`:

    ```go
    page, err := client.Users().List(ctx, axiam.Matching(50, "ada"))
    all, err  := client.Users().ListAll(ctx, axiam.Matching(200, "ada"))
    ```

    Putting it on the page request is what makes `ListAll` carry the term across
    the whole walk. A walk that filtered its first request and not the rest
    returns the matches followed by the unfiltered tail, which from the caller's
    side looks like a server bug.

    The server applies it **before** `Offset`/`Limit`, so `Page.Total` counts
    matches rather than rows. A blank or whitespace-only term is treated as
    unset and sends no `search` parameter, so a box that fires on every
    keystroke does not ask a different question once it is cleared. The server's
    length cap is deliberately **not** copied here: a client-side truncation the
    server would not have made is a silently different query.

  - **`(*Client).ResendOwnVerification`** (§25.1, §25.7) —
    `POST /api/v1/users/me/resend-verification`, for a caller signed in to the
    account it is asking about. It takes no address, and reports what happened:
    `nil` for enqueued, an `*AuthzError` for already-verified-or-ineligible, a
    `*NetworkError` for the daily limit.

    `ResendVerification` still exists and still returns `nil` whatever happens,
    because it takes an address from an anonymous caller and a truthful answer
    there is an enumeration oracle. Use the new one whenever there is a
    session — a profile page wired to the old one reports success while doing
    nothing, which is the defect the pair exists to separate. This SDK does not
    fall back from one to the other in either direction (§25.7 rule 2).

  - **`LoginResult.OrganizationLevel`** (§5.2) — whether the account holds
    grants that apply in every tenant of its organization. Check it before
    offering a tenant switch: an ordinary tenant principal changing
    `X-Tenant-ID` gets a `403`. `false` against a server older than contract
    1.31, which is the safe reading of absent.

  - **`Tenant.Kind` and `TenantKind`** (§27.11) — ordinary tenant or the
    organization's own scope. `nil` on a row written before that scope existed.
    Read-only: it is not on `CreateTenantRequest` or `UpdateTenantRequest`.

  - **`MtlsTrustAnchorResponse.TrustedAnchors`** (§27.11) — how many CAs the
    live listener now trusts, when it was reloaded. `nil` is **not** zero: it
    means there was no listener to ask, which is the case
    `RestartRequired: true` already reports.

  - **`Certificate.BoundServiceAccountID`** (§27.11) — the service account a
    certificate authenticates, resolved for a whole page in one query by
    `Certificates().List` and `nil` on `Certificates().Get`. The SDK does not
    issue a second request to fill it in there.

- **CONTRACT.md §27 — the management API.** 146 administrative operations across
  24 namespaces, reached as `client.<Namespace>().<Operation>(ctx, ...)`. The
  namespace handles and their models are generated from the vendored
  `management-registry.json` and `openapi.json` by
  `go run ./internal/cmd/genmanagement`; a new CI job runs that generator with
  `-check`, so a registry that moves without a regeneration fails the build
  rather than shipping a client that disagrees with the contract. The generator
  is a Go program and formats its own output with `go/format`, so it needs no
  toolchain beyond Go itself.

  The semantics the section fixes are implemented rather than approximated:
  acquiring a handle performs no I/O; `{org_id}`/`{tenant_id}` default from the
  client and are overridable per handle with `InOrg`/`ForTenant`; `Page.Total` is
  the whole set and `ListAll` walks it; a sparse update body sends only the
  fields that were set; 404/409 map to `*NotFoundError`/`*ConflictError` (both
  still matching `ErrAuthz`) and 400/422 to `*ValidationError` (still matching
  `ErrNetwork`), so existing `errors.Is` checks keep working; only `GET` is
  retried; and one-time secrets come back as `Sensitive`.

  Every `{..._id}` on the surface is a `uuid.UUID`, so §27.9's "a non-UUID
  identifier fails client-side with zero wire calls" is enforced by the type
  system rather than by a runtime check.

- **Declarative management (§27.6/§27.7).** `client.Manifest().Plan(ctx, ...)`
  reports what reconciling a `ManagementManifest` would do without writing
  anything, and `Apply` runs it, stopping at the first failure and reporting
  every step including the ones it did not attempt. Two declarative spellings:
  plain struct literals, and a fluent `NewManifest()` builder that validates at
  `Build()` time.

- **`Sensitive.Expose`** — an exported accessor for the raw value.
  `Sensitive` had only a package-internal `expose()`, which left a caller no
  documented way to read a secret the SDK hands them. That was already a gap for
  §25.3's TOTP URI, which has to reach a QR renderer, and §27.5 rule 3 makes it
  unavoidable: a certificate's private key, a SCIM provisioning token and a
  service account's client secret are returned by exactly one call and never
  again. A `string(...)` conversion always worked — `Sensitive` is a defined
  string type — so this adds no capability, it makes "a secret becomes a plain
  string here" one greppable call. The type's doc comment, which claimed there
  was no public getter, is corrected.

- **`Client.ResolvedTenantID` / `Client.ResolvedOrgID`** — exported accessors for
  the identifiers a login resolved from the access token's claims. §27 routes
  where `{tenant_id}` names the object rather than the calling context (the
  signing CAs under `CACertificates`, and the `Tenants` namespace) take that UUID
  as an ordinary argument, so callers outside this package need to read the one
  the session already knows.

- **Examples**: `management-basics`, `management-manifest`, and
  `device-mtls-provisioning` — an end-to-end IoT flow that mints a device
  certificate from the tenant's signing CA, binds it to a service account, and
  then authenticates as that device over §6.1 mutual TLS.

### Changed

- Re-vendor openapi.json and management-registry.json from axiam main (#66)

- Re-vendor the contract artifacts: spec digest + §27.10 posture (#64)

- Re-vendor CONTRACT.md, openapi.json and the §27 registry

- **Generated enum constant blocks now say they are not exhaustive.** The types
  were always open — a Go `type X string` decodes any string — but the constant
  block reads like a closed set, and a `switch` written against it silently
  assumes one. Each now carries a comment saying a `default` arm is required,
  because the next `Kind` or `Status` the server adds will arrive as itself
  rather than failing the response (§27.11 rule 1).

- Coverage floor raised from 94% to 94.4% (measured 94.5%, up from 94.1%).

### Fixed

- **`internal/cmd/genmanagement` no longer drops a projected list element.** The
  server answers `GET /api/v1/certificates` with `Certificate` plus one resolved
  graph edge, expressed as an `allOf` of the `$ref` and an anonymous object.
  Read as a whole, that composition has no name, so the registry carried a page
  with no element type and the added field reached no model. The generator now
  takes the base name through the `allOf` and folds the projection's added
  fields onto the base struct as optional pointers. (The registry-side half of
  this is AXIAM PR #386.)

## [1.0.0-alpha44] - 2026-08-25

### Changed

- Re-vendor openapi.json at alpha43 for tenant signing CAs (axiam#379)

- **Re-vendor `openapi.json` at 1.0.0-alpha43** for AXIAM server PR #379, which
  adds **tenant signing CAs**: an intermediate CA created beneath one of the
  organization's CAs and scoped to a single tenant, so a tenant's user, service
  and device certificates chain through a CA that can be revoked, rotated or
  handed to a different operator without redistributing the anchor the rest of
  the estate trusts. `CONTRACT.md` and `proto/` were untouched by that PR and are
  already current.

  This is a specification re-sync with **no SDK surface change**. CA-certificate
  administration is not part of the SDK contract — `CONTRACT.md` §1 maps no
  method onto any `/api/v1/organizations/{org_id}/...` CA route — and this SDK
  models none of the schemas below, so nothing here gains, loses, or changes a
  symbol. The spec is vendored so what this SDK is written against keeps
  describing the server it talks to.

  What moved in the spec:

  - **`POST /api/v1/organizations/{org_id}/tenants/{tenant_id}/signing-cas`**
    (`generate_intermediate`) — create a tenant signing CA under an organization
    CA, with AXIAM generating the key. Returns `GeneratedCaCertificate`; the
    private key comes back exactly once, and not at all under `vault_pki`, where
    it was born inside Vault and no API exports it.
  - **`GET .../signing-cas`** (`list_intermediates`) — a paginated list of one
    tenant's signing CAs.
  - **`POST .../signing-cas/sign-csr`** (`sign_intermediate_csr`) — the BYOK
    counterpart: sign a PKCS#10 CSR produced elsewhere, so the private key never
    reaches AXIAM at all. The response carries no `private_key_pem` because there
    is none to carry.
  - **`CaCertificate` gains two nullable fields** — `tenant_id`, the tenant a CA
    signs for, and `parent_ca_id`, the CA in the organization that signed it.
    Both are absent for an organization-level CA, which is the trust anchor and
    the only kind that existed before this change.
  - **Four new schemas**: `CreateIntermediateCa`, `CreateIntermediateCaRequest`,
    `SignIntermediateCsr` and `SignIntermediateCsrRequest`.

  The spec version moves from **1.0.0-alpha40** to **1.0.0-alpha43**; the
  intervening alpha41 and alpha42 releases changed nothing in it but that string.

## [1.0.0-alpha43] - 2026-08-24

### Added

- Build Go 1.27 alongside the 1.26 floor (#60)

- **Go 1.27 is now a CI-built toolchain.** The gating matrix runs `build`,
  `vet` and the full test suite on the floor **and** on the current release,
  rather than on the floor alone. Go supports exactly the two most recent
  majors, so those two legs are the whole supported range.

- **`axiam.MinGoVersion`** — the minimum supported Go language version as a
  readable constant, mirroring the `go` directive in `go.mod`. The toolchain
  enforces that directive at build time, but a consumer has no way to read it
  back at run time: `debug.ReadBuildInfo` reports the toolchain that produced
  the binary and the module graph, never a dependency's declared language
  version. This is the equivalent of `engines.node` or `requires-python` in the
  sibling SDKs.

- **`version_policy_test.go`** — a conformance test for the support policy.
  `MinGoVersion`, the `go` directive and the CI matrix are three declarations of
  the same fact; this fails the build when they disagree, so the exported
  constant cannot go stale against the directive it mirrors.

- **`examples/version-compatibility`** — a runnable preflight reporting the
  running toolchain against the SDK's declared range. Its useful end is the
  upper one: the toolchain refuses a below-floor build already, but nothing
  otherwise surfaces "you are running past everything with a green build".

- **A "Supported Go versions" section in the README**, stating the two claims
  separately — built against the floor, runs on the newest — with the CI
  evidence for each.

### Changed

- Bump the minor-patch group with 2 updates

- **The gating CI matrix is floor + newest (`1.26.7`, `1.27.0`)** rather than a
  single pinned toolchain. `govulncheck` runs once, on the floor leg, since the
  floor is the oldest stdlib any consumer will be using.

  `go.mod` is **unchanged** at `go 1.26`, so no consumer loses a build they had
  before.

## [1.0.0-alpha41] - 2026-08-24

### Added

- Fall back to /auth/login under an optional tenant (§23.4 rule 7)

### Changed

- Re-vendor openapi.json for the vault_pki CA custodian (axiam#368)

- Gofmt three OPAQUE files

- **Re-vendor `openapi.json`** for AXIAM server PR #368, which adds a third CA
  key custodian, `vault_pki`, having HashiCorp Vault's PKI secrets engine
  generate the CA key inside Vault and sign on AXIAM's behalf. The spec version
  is unchanged at **1.0.0-alpha40**; `CONTRACT.md` and `proto/` are untouched by
  that PR and are already current.

  This is a specification re-sync with **no SDK surface change**. CA-certificate
  administration is not part of the SDK contract — `CONTRACT.md` §1 maps no
  method onto `/api/v1/organizations/{org_id}/ca-certificates`, and this SDK
  models none of the five schemas below — so nothing here gains, loses, or
  changes a symbol. It is vendored so the spec this SDK is written against keeps
  describing the server it talks to.

  What moved in the spec:

  - `CaCertificate` gains a nullable `chain_pem`: the issuers above
    `public_cert_pem`, concatenated PEM, nearest issuer first and the root last.
    Absent for a CA that is its own root, which is every CA AXIAM generated
    before this. Present for a `vault_pki` CA, where it is the only copy of the
    root certificate anything outside Vault will ever see.
  - `CaCertificate.public_cert_pem` is now documented as the certificate that
    *signs*, which under `vault_pki` custody is the intermediate rather than the
    root beneath which it was created. The field itself is unchanged.
  - `GeneratedCaCertificate.private_key_pem` is **no longer required**. Under
    `vault_pki` custody the key is born inside Vault and no API exports it, so
    there is nothing to return. The field is omitted rather than sent as `null`,
    which keeps a client that has always read it working unchanged against every
    custodian that does produce a key.
  - `GeneratedCertificate` gains a nullable `chain_pem`, present only when the
    signer returned one — the `vault_pki` case, where the root's certificate
    exists nowhere a client could fetch it from.
  - `CreateCaCertificate` and `CreateCaCertificateRequest` gain the optional
    `issue_from_root`, `intermediate_subject` and `intermediate_validity_days`.
    All three are `vault_pki`-only and ignored by every other custodian.
    `issue_from_root` defaults to off: a root that signs only one intermediate
    can have that intermediate revoked and replaced without redistributing the
    trust anchor, and a root that signs leaves directly cannot.

- Re-vendor `CONTRACT.md` at **1.29** and `openapi.json` at **1.0.0-alpha40**.

- **A failed OPAQUE exchange now falls back to `Login` under an `optional`
  tenant** — CONTRACT.md §23.4 rule 7. `POST /api/v1/auth/opaque/login/start`
  gained an optional `mode` field carrying the tenant's `opaque_mode`, and it
  is the only thing that decides what `LoginOpaque` does when it cannot open
  `KE2` — wrong password, unknown identity, an account with no registration
  record, or a hostile endpoint, which are indistinguishable by design.

  - `"optional"`: `LoginOpaque` retries the same username and password over
    `POST /api/v1/auth/login` before reporting anything, and returns that
    call's outcome — its success on success, its error on failure. Without
    this, enabling `optional` locked out every account that had not yet set a
    password since OPAQUE was turned on, which is every account in the tenant
    on day one and the entire population `optional` exists to serve.
  - `"required"`, an unrecognised value, and **any response with no `mode`
    field** (a server older than this field): unchanged — `*AuthError`, and
    `/auth/login` is never called. Fail closed.

  `KE3` is still never sent after a failed `KE2`, in every case. `404` from
  `/auth/opaque/*` is untouched and still reports a disabled tenant as
  `*NetworkError` rather than a credential failure.

  `mode` is **not** downgrade protection and is not documented as such: a
  hostile server that wanted the plaintext could answer `404` and get the
  caller's own fallback whatever it put there. `required` is what closes that,
  server-side, by refusing `/auth/login` before examining any credential.

  **Not breaking.** `LoginOpaque`'s signature and result type are unchanged;
  what changes is that one previously-terminal failure now has a second leg
  under one tenant configuration.

## [1.0.0-alpha40] - 2026-08-23

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha39.

## [1.0.0-alpha39] - 2026-08-23

### Changed

- Re-vendor CONTRACT.md for the §14.1 anchor repair
- Re-vendor openapi.json at 1.0.0-alpha38

## [1.0.0-alpha38] - 2026-08-22

### Added

- Add WebAuthn (§24), account lifecycle (§25) and PAR (§26)

- **WebAuthn and passkeys — CONTRACT.md §24.** Six relying-party operations:
  `WebauthnRegisterStart`/`Finish`, `WebauthnAuthenticateStart`/`Finish`,
  `WebauthnDiscoverableStart`/`Finish`. Go has no authenticator, so §24.6b's
  linked-API helper is deliberately absent — §24.6b rule 2 forbids emulating
  one in software.

- **The §24.6a JSON bridge.** `WebauthnChallenge.RequestJSON()` produces the
  exact string a platform authenticator API takes, and every `*Finish` accepts
  the platform's response JSON string directly — so a service driving an
  Android or iOS client passes both directions through untouched. Plus
  `ClassifyWebauthnError` / `WebauthnErrorMessage`, which give a server-side
  caller the same five outcomes a browser sees.

- **Account lifecycle and MFA enrolment — CONTRACT.md §25.** Nine operations:
  `MfaEnroll`/`MfaConfirm`, `MfaSetupEnroll`/`MfaSetupConfirm`, `VerifyEmail`,
  `ResendVerification`, `RequestPasswordReset`, `ConfirmPasswordReset`,
  `PasswordResetContext`.

- **Pushed authorization requests — CONTRACT.md §26 (RFC 9126).** `OidcPar`,
  plus `PushedAuthorizationRequestEndpoint` on `OidcConfiguration`.

- Examples: `examples/webauthn-relying-party`, `examples/account-lifecycle`,
  `examples/par-login`.

### Changed

- Cover the §24/§25/§26 refusal paths

- Re-vendor CONTRACT.md at 1.28

- Re-vendor `CONTRACT.md`. Repairs §14.1's link to the `device_login` heading,
  which dropped a hyphen the em dash leaves behind and so rendered as a link
  that went nowhere; the same heading's other two links were already correct.
  Link target only — no normative change and no contract-version bump.

- Re-vendor `openapi.json` at **1.0.0-alpha38**. The server registered the four
  GDPR data-subject endpoints (`POST /api/v1/account/export`,
  `GET /api/v1/account/export/{token}`, `POST /api/v1/account/delete`,
  `GET /api/v1/auth/account/delete/cancel`), taking the document to 181
  operations across 121 paths. Purely additive, and no SDK surface changes with
  it: nothing in this repo is generated from the spec, so the cross-repo
  artifact-drift gate was the only thing reporting `STALE`.

- **`LoginResult` gains `MFASetupRequired` and `SetupToken`** (§25.2 rule 1). A
  tenant that requires MFA answers `403 mfa_setup_required` with a setup token
  for an account that has none; that used to arrive as an `*AuthzError`, telling
  the caller they lacked permission to log in when what the server said was
  recoverable and came with the means to recover.

  **Not breaking in Go.** `LoginResult` has always been one struct with flags
  rather than a discriminated union, so nothing that reads `MFARequired` has to
  change. A genuine authorization refusal still returns `*AuthzError`: the
  branch is matched on the body's discriminant, not the status.

- A `403` from `WebauthnRegisterFinish` now carries the tenant's attestation
  policy message on the `*AuthzError` (§24.4 rule 1). This is the one place
  D-15's "never put a body in an error" bends, and it bends the way D-15 already
  permits — one **named** JSON field is decoded, exactly as `action` and
  `resource_id` already are. The raw body still never reaches an error, and no
  other status on no other endpoint gains a message this way.

## [1.0.0-alpha37] - 2026-08-21

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha34.

## [1.0.0-alpha34] - 2026-08-21

### Added

- Replace SRP-6a with OPAQUE (RFC 9807) — CONTRACT 1.26

- `opaque_interop_test.go` (build tag `interop`) and a CI job that runs it. It
  completes a full registration and login against the Rust implementation's
  server half, asserting every message width and that the envelope opens. This
  is the price of the §23.1 exception: the two implementations must agree on
  the key-stretching salt width and output length, neither of which is in
  RFC 9807, and "both implement the RFC" is not evidence that they do.

- `workspaceBody`, extracted from `loginRequestBody`, so the password path, the
  OPAQUE login path and OPAQUE enrolment resolve org/tenant through one
  function rather than three.

### Changed

- Link to the AXIAM platform documentation site

- Re-vendor openapi.json at alpha32 (#51)

- Cover the OPAQUE happy paths, restoring the 94% coverage floor

- Require Go 1.26, as bytemare/opaque does

- **BREAKING: `LoginSrp` becomes `LoginOpaque`** — CONTRACT.md §23 is now
  OPAQUE (RFC 9807), and SRP-6a is removed from AXIAM entirely.
  - `LoginSrp` → `LoginOpaque`, `SrpEnrollment` → `OpaqueEnrollment`,
    `SrpAvailable` → `OpaqueAvailable`.
  - `OpaqueEnrollment` takes a `context.Context` and only a password. The SRP
    version took four arguments including the account's canonical username,
    and passing an email produced a verifier no login could satisfy. A record
    binds to a credential identifier the server chooses, so that mistake is not
    expressible — and a later rename no longer invalidates a credential. It
    needs the context because OPAQUE's envelope is sealed under the server's
    oblivious PRF, so enrolment is a round trip rather than an offline
    computation.
  - The `OpaqueEnrollment` struct has two fields where `SrpEnrollment` had
    seven.

- **The protocol is no longer implemented here.** `srp.go` — ~470 lines of
  modular arithmetic, RFC 5054 group constants and a hand-rolled KDF — is
  replaced by a thin wrapper over `github.com/bytemare/opaque`. Go is the one
  SDK CONTRACT §23.1 permits a native implementation, because a vetted RFC 9807
  library exists for it and binding the shared C ABI would force cgo on every
  consumer, breaking `CGO_ENABLED=0` builds.

- **The minimum Go version is now 1.26** (was 1.25). Required by
  `github.com/bytemare/opaque`. The last release of that library compatible
  with Go 1.25 dates from 2023 and predates RFC 9807's publication, so pinning
  it to keep the older floor would mean shipping a draft-era wire format that
  is not known to interoperate with the AXIAM server. CI is pinned to 1.26.7.

- Re-vendor `openapi.json` at **1.0.0-alpha32**, matching the server. The
  content was already byte-identical in every path and schema; only
  `info.version` differed, which is what the cross-repo artifact-drift gate
  reports as `STALE`.

### Removed

- The server-proof check and the cookie-discard path that went with it. RFC
  9807's AKE authenticates the server during the handshake, so opening `KE2`
  *is* the proof it holds the record. §23.3 rule 6 had to mandate an `M2`
  comparison in capitals because skipping it kept only half the protocol; there
  is now nothing to skip.

- The group-restart loop. SRP had to guess a group before the server named one
  and re-run the exchange if it guessed wrong; `KE1` does not depend on the KSF,
  so a login is always one round trip.

- `srp-test-vectors.json`, replaced by the smaller `opaque-test-vectors.json` —
  see CONTRACT §23.7 for why the fixture shrank rather than being ported.

## [1.0.0-alpha31] - 2026-08-20

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha30.

## [1.0.0-alpha30] - 2026-08-20

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha29.

## [1.0.0-alpha29] - 2026-08-20

### Added

- SRP-6a login client (CONTRACT §23) (#49)

## [1.0.0-alpha28] - 2026-08-19

### Changed

- Re-vendor openapi.json at 1.0.0-alpha27 (#48)
- Bump google.golang.org/protobuf in the minor-patch group

## [1.0.0-alpha27] - 2026-08-17

### Added

- §22.14 declarative reactor handler binding — ReactorMux

### Changed

- Re-vendor CONTRACT.md 1.23, and fix a plaintext example default
- Re-vendor openapi.json for the SCIM provisioning-token endpoints
- Re-vendor CONTRACT.md 1.22 from the server repo

## [1.0.0-alpha25] - 2026-08-16

### Added

- Ship the §22 reactor runtime — ReactorServe (R2.5)
- Extend §10.1 rule 9 for DPoP and implement §21.7.2 (#40)
- Subject_token_type is required (contract 1.13)
- §15.7 — external-IdP subject tokens at the exchange (X4)
- §20.3 — emit a UMA challenge from the §11 guard (#34)
- §20 UMA 2.0 — Protection API and ticket grant (#33)
- Report clamped settings via §19 ConfigClampedEvent (contract 1.9)
- §16 retry, §17 memo, §18 Close(), §19 telemetry (D5)
- Device grant, token exchange, logout helpers; re-vendor (D6)
- **CONTRACT.md §22 — Reactors, the AMQP extension actors (contract 1.18/1.19).**

  New `amqp.ReactorServe` (§22.10's `reactor_serve`, spelled `ReactorServe` per that
  subsection's per-language table): connect, consume the server-declared queue, verify
  every delivery, dispatch to a handler, sign and publish the reply, reconnect, and drain
  in-flight events on shutdown.

  §8's HMAC now runs in **both directions** on one exchange — the server signs the event,
  the reactor signs the reply with the same tenant subkey — with one canonicalization
  difference that costs a day if it is not stated: `hmac_signature` is serialized as
  **`null`** inside a reactor body rather than omitted as it is in §8's own two message
  types. The §22.13 vectors ship beside the §8 vectors under the same master key, tenant
  and derived subkey; `amqp/testdata/reactor_v2_reference_vectors.json` is vendored and
  the sign direction is asserted byte-for-byte against `canonical_signed_json`, including
  the omission of `reason`/`patch` when absent and of `require_mfa` when false.

  Three rules are structural rather than documented. `ReactorAllow`/`ReactorAllowWithStepUp`
  take no patch, so `allow` + `patch` cannot be spelled. `ReactorTransport` has no declare
  or bind method, so §22.1's "actors consume, they never declare topology" has no seam to
  leak through — a reactor that could bind could bind itself to another tenant's routing
  key. And a handler that returns an error or panics publishes **nothing**: no synthesized
  `allow`, because that would override the operator's `fail_closed` from inside the
  library.

  A mutation is sent **unfiltered** (§22.4 rule 1) — one forbidden key rejects the whole
  patch server-side, and dropping the offender would leave the author believing a field
  was set when it was dropped.

  §22.7's hot-path exclusion is enforced with a test rather than a comment: the three
  hot-path decision operations appear in no constant, no slice and no doc example in the
  package, asserted by a source scan.

  Also new: `amqp.ReactorEvents()` and `amqp.ReactorDefaultFailurePolicy()` (the §22.5
  registry and §22.8's strictest-wins composition, which an SDK MUST NOT reduce to "take
  the first event's default"), `amqp.ReactorQueueName`/`ReactorRoutingKey`,
  `amqp.AMQPSDialer` (§8b: `amqps://` only, optional CA bundle, no verification-skip
  switch), and a reactor telemetry surface (§19) whose event interface is closed so no
  variant can carry a secret. New example: `examples/reactor`.

  Not breaking: nothing existing moved, and `amqp.Consume` is untouched.

- **CONTRACT.md §10.1 rule 9 extended for DPoP, and §21.7.2 proof verification
  implemented (contract 1.16/1.17).**

  `Confirmation` gains `Jkt` (RFC 9449 §6.1), and `VerifyTokenBinding` applies
  the full ten-row rule against a certificate thumbprint, a verified DPoP key
  thumbprint, or **both**. A `cnf` naming both methods is a **conjunction** —
  satisfying only the more convenient one is not compliance — and a `cnf`
  naming nothing this SDK can check (including an *empty* one, which is how
  proto3 delivers an empty `CnfClaim`) is refused rather than read as unbound.
  `VerifyCertificateBinding` remains for certificate-only transports and now
  **refuses** a DPoP-bound or both-bound token rather than ignoring the half it
  cannot check.

  New `internal/dpop`, re-exported as `VerifyDPoPProof`, implements all ten
  §21.7.2 checks and returns the proof key's RFC 7638 thumbprint, so a value
  passed to `PresentedProofs.DPoPThumbprint` could only have come from a proof
  that verified. `NewInMemoryDPoPJtiStore` covers check 8 for a single process;
  the `DPoPJtiStore` argument is required, not optional, because there is no
  safe default that skips replay tracking.

  The algorithm is derived from the embedded `jwk` rather than the header (the
  test runs the real public-key-as-HMAC-secret forgery), and the `jti` is
  claimed **last**, so a stream of invalid proofs cannot burn `jti` values out
  of the store and deny service to valid ones.

  New example: `examples/sender-constrained-guard`. Not a breaking change: an
  unbound token is still accepted with no certificate and no proof, asserted
  directly by the first test in the new group.

- **CONTRACT.md §10.1 rule 9 — sender-constrained (certificate-bound) access tokens**
  (contract 1.15, RFC 8705 §3 / RFC 7800). A token carrying `cnf` is **not** a bearer
  token; accepting one without proving the caller holds the named key converts it back
  into one.
  - `jwks.Claims.Confirmation` / `jwks.Confirmation` — the decoded `cnf` claim.
  - `jwks.VerifyCertificateBinding(claims, presentedThumbprint)` — the rule. Returns
    `ErrNoClientCertificate`, `ErrCertificateBindingMismatch`, or
    `ErrUnverifiableConfirmation`; classify with `errors.Is`.
  - `jwks.CertificateThumbprintS256(der)` — RFC 8705 §3.1 `x5t#S256`: base64url,
    **unpadded**, SHA-256 over the DER certificate. Under `crypto/tls`, feed it
    `conn.ConnectionState().PeerCertificates[0].Raw`.

  **Not a breaking change, and it does not make certificates mandatory.** An *unbound*
  token is still accepted with or without a certificate — asserted directly, because the
  likeliest wrong implementation of this rule is one that starts demanding certificates
  from every caller.

  `ValidateClaims` deliberately does **not** apply rule 9: it has no transport to ask for
  a peer certificate. The thumbprint must come from the transport, never from a
  caller-settable header. A `cnf` naming an unimplemented method is **rejected**, never
  read as "unconstrained".

- **CONTRACT.md §21** — the FAPI 2.0 posture as an SDK sees it. Only rule 9 is normative
  for this SDK.
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

- Cover the reactor runtime to the repo's 94% floor (R2.5)
- Re-vendor CONTRACT.md 1.19, openapi.json and proto/ from main (R5.8) (#42)
- Contract 1.15 — §10.1 rule 9, sender-constrained access tokens (#39)
- Retire the "measured residual" justification (contract 1.14)
- Raise the go directive to 1.25.13
- Bump the Go toolchain to 1.25.13 (govulncheck)
- Re-sync to contract 1.14 (#302 closed)
- Cover the D5 paths that dropped coverage below the 94% floor
- Re-vendor `openapi.json` at 1.0.0-alpha27 — the copy was pinned at alpha26 and
  failing the cross-repo artifact-drift gate
- **Re-sync vendored `CONTRACT.md` / `openapi.json` to contract 1.15.**
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
- Re-vendored `CONTRACT.md` at **1.10** and `openapi.json` (the server's `/uma2/*` surface).
- The ticket grant maps its errors through `mapUmaGrantError`, which dispatches on the
  `error` field at *any* status. `access_denied` answers HTTP 403 here where RFC 8628's
  answers 400, and the shared `/oauth2` mapper gates its `OAuth2ErrorResponse` rows to
  400/401 — deliberately, so an ordinary REST 403 still maps to `*AuthzError`. Widening it
  there would have changed every other endpoint's behaviour to fix one grant, so the fix is
  contained to the grant. A body that is not an `OAuth2ErrorResponse` still falls through to
  the §2 status mapping.
- **§16: `retryReadOnly` replaced.** The old policy used a 100 ms base, `backoff *= 2` with
  **no cap and no jitter**, and ignored `Retry-After`. It now follows the contract table: 3
  attempts, 200 ms base, 5 s cap, full jitter over `[0, backoff]`, `Retry-After` as a floor.
  Uncapped, the old wait was bounded by nothing but the attempt count; unjittered, every client
  retried in lockstep — the thundering herd a backoff exists to prevent.
- The unexported `authzRetryMaxAttempts` constant is replaced by the exported `MaxAttempts`,
  alongside `BaseDelay` and `MaxDelay`.
- Re-vendored `CONTRACT.md` at **1.8.2**. `openapi.json` unchanged — docs-only contract revs.

### Fixed

- Close SDK-Q10 — reconcile reason/deny_reason on CheckAccess (CONTRACT.md §11.2 rule 9)
- R5.7 — F-14/F-15 conformance follow-ups (#41)

## [1.0.0-alpha24] - 2026-08-04

### Added

- Add HMAC-SHA256 webhook signature verifier (CONTRACT.md §13)
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

- Add the §10.1 rule-8 guardrail regression tests (#29)
- Device (mTLS) tokens now carry aud=axiam:m2m (#28)
- Service accounts can use login_client_credentials (#27)
- Cover the §10.1 validation path at package level
- Bump coverallsapp/github-action from 2.3.7 to 2.3.8
- Bump the minor-patch group with 2 updates
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

### Fixed

- Raise the go directive to 1.25.12 to clear stdlib advisories (#26)
- Enforce the full CONTRACT §10.1 local-verification set

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

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha9.

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
