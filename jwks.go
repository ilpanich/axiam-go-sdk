package axiam

import (
	"context"
	"net/http"

	"github.com/ilpanich/axiam-go-sdk/internal/jwks"
)

// JWKSVerifier is the public entry point for this SDK's local JWKS
// verification (CONTRACT.md §10/§10.1, D-06) — the shared local-verify
// mechanism consumed by the net/http middleware (package middleware). It is
// a thin re-export of the internal jwks.Verifier so callers outside this
// module never need to import an internal/ package directly.
//
// Use JWKSVerifier.VerifyAccessToken: it applies the complete §10.1 minimum
// local-verification set (EdDSA-pinned signature, REQUIRED exp, honoured nbf,
// asserted tenant_id, conditional iss/aud, bounded clock skew).
//
// JWKSVerifier.VerifySignatureOnlyUnchecked is the raw signature-only
// primitive §10.1 permits for integrators writing their own policy. It is NOT
// a guard: it checks no claim at all, so an expired token, a token carrying
// no exp, or a token minted for a DIFFERENT tenant under the same
// organization-wide JWKS all verify successfully. Do not build an
// authentication decision on it.
type JWKSVerifier = jwks.Verifier

// TokenValidationOptions carries the relying party's §10.1 expectations for
// JWKSVerifier.VerifyAccessToken.
//
// Tenant is required — an empty Tenant fails closed rather than accepting an
// arbitrary tenant's token (§10.1 rule 4). ExpectedIssuer and
// ExpectedAudience are optional and default to unset: an empty value means
// "no expectation configured, so no check" (§10.1 rules 5/6), never "expect
// the empty string". This SDK hardcodes no issuer or audience anywhere.
type TokenValidationOptions = jwks.ValidationOptions

// ClockSkewLeeway is the named, bounded clock-skew allowance this SDK applies
// to the exp and nbf checks (CONTRACT.md §10.1 rule 7). It is a constant and
// is deliberately NOT operator-configurable.
const ClockSkewLeeway = jwks.ClockSkewLeeway

// NewJWKSVerifier constructs a JWKSVerifier bound to {baseURL}/oauth2/jwks
// (trailing slash on baseURL trimmed before joining). hc may be nil, in
// which case a default *http.Client is used. The cache is registered but
// not eagerly populated; the first verification triggers the initial fetch.
//
// This is the exported constructor middleware.Middleware examples wire
// against — see examples/middleware-guard.
func NewJWKSVerifier(ctx context.Context, baseURL string, hc *http.Client) (*JWKSVerifier, error) {
	return jwks.NewVerifier(ctx, baseURL, hc)
}
