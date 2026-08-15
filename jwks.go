package axiam

import (
	"context"
	"net/http"

	"github.com/ilpanich/axiam-go-sdk/internal/dpop"
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

// --- CONTRACT.md §10.1 rule 9 and §21.7.2 (contract 1.16) ---------------------

// Confirmation is the RFC 7800 "cnf" claim carried by a sender-constrained
// token. Its presence changes what the token IS: it is no longer a bearer
// credential.
type Confirmation = jwks.Confirmation

// PresentedProofs carries what the caller proved about this connection and
// this request. See VerifyTokenBinding.
type PresentedProofs = jwks.PresentedProofs

// VerifyTokenBinding applies §10.1 rule 9 in full — the token's sender
// constraint against every proof the caller presented.
//
// Prefer this over VerifyCertificateBinding unless the transport genuinely
// cannot produce a DPoP thumbprint. An unbound token is accepted with no
// proofs at all, so adopting it breaks no existing deployment.
var VerifyTokenBinding = jwks.VerifyTokenBinding

// VerifyCertificateBinding applies rule 9 for certificate-bound tokens only.
//
// It REFUSES a DPoP-bound or both-bound token rather than ignoring the half it
// cannot check — that refusal is what lets this narrower entry point stay in
// the API without becoming a downgrade path.
var VerifyCertificateBinding = jwks.VerifyCertificateBinding

// CertificateThumbprintS256 computes the RFC 8705 §3.1 "x5t#S256" of a DER
// client certificate.
var CertificateThumbprintS256 = jwks.CertificateThumbprintS256

// Rule 9 sentinel errors, for guards that distinguish "nothing was presented"
// from "what was presented was wrong".
var (
	ErrUnverifiableConfirmation   = jwks.ErrUnverifiableConfirmation
	ErrNoClientCertificate        = jwks.ErrNoClientCertificate
	ErrCertificateBindingMismatch = jwks.ErrCertificateBindingMismatch
	ErrNoDPoPProof                = jwks.ErrNoDPoPProof
	ErrDPoPBindingMismatch        = jwks.ErrDPoPBindingMismatch
)

// DPoPRequest carries what VerifyDPoPProof needs about the current request.
type DPoPRequest = dpop.Request

// DPoPJtiStore is the §21.7.2 check 8 replay guard.
type DPoPJtiStore = dpop.JtiStore

// NewInMemoryDPoPJtiStore returns a single-process replay guard. Per-process,
// therefore per-instance: a multi-replica deployment needs a shared store.
var NewInMemoryDPoPJtiStore = dpop.NewInMemoryJtiStore

// VerifyDPoPProof performs all ten §21.7.2 checks and returns the proof key's
// RFC 7638 thumbprint — exactly the value PresentedProofs.DPoPThumbprint
// expects, so a guard can only pass on a thumbprint that came from a proof
// which actually verified.
var VerifyDPoPProof = dpop.VerifyProof

// DPoPIatLeeway is the "iat" freshness window, applied in both directions.
const DPoPIatLeeway = dpop.IatLeeway
