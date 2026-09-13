package axiam

import (
	"context"
	"net/http"

	"github.com/ilpanich/axiam-go-sdk/internal/dpop"
	"github.com/ilpanich/axiam-go-sdk/internal/jwks"
	"github.com/ilpanich/axiam-go-sdk/internal/revocation"
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

// --- CONTRACT.md §10.4, the session-revocation feed (contract 1.44) -----------

// RevocationFeed is a poller for one deployment's session-revocation feed
// (CONTRACT.md §10.4 — AXIAM threats T-39 and T-143).
//
// §10.2 records the gap it narrows: local verification proves a token was
// issued and has not expired, never that the session behind it still exists.
// A logout or a role removal therefore does not reach a token already in a
// caller's hands until it expires, up to fifteen minutes. A deployment that
// publishes GET /oauth2/revocations lets a guard close that to ONE POLL
// INTERVAL, for one cacheable fetch per interval rather than the round trip
// per request gRPC introspection costs.
//
// It is NOT a control. It is off unless you attach one, it is never fetched on
// the request path once warm, and it NEVER FAILS CLOSED: an unreachable feed,
// a non-200, an unparseable body or an unknown alg all behave exactly as no
// feed at all — and specifically not as an empty list, which would assert that
// nothing has been revoked and is a guard silently honouring no revocations
// while appearing to honour them. Every §10.1 rule runs first and still
// decides; the feed can only ever turn an accept into a reject.
//
// Safe for concurrent use, and meant to be shared: several guards built from
// one RevocationFeed poll once between them rather than once each.
type RevocationFeed = revocation.Feed

// NewRevocationFeed polls {baseURL}/oauth2/revocations on
// RevocationFeedDefaultPollInterval, through hc (nil means a default client).
// Attach it with JWKSVerifier.WithRevocationFeed.
//
// A deployment that does not publish the feed is not an error here — that is
// discovered on the first poll, and behaves as no feed at all from then on.
func NewRevocationFeed(hc *http.Client, baseURL string) (*RevocationFeed, error) {
	return revocation.NewFeed(hc, baseURL)
}

// RevocationEntryFor is the feed entry for a sid, as the server computes it:
// base64url without padding over the SHA-256 of the claim's EXACT string.
//
// Never a parsed-and-re-rendered UUID — the answer would then depend on this
// SDK's UUID parser rather than on the feed.
func RevocationEntryFor(sid string) string { return revocation.EntryFor(sid) }

const (
	// RevocationFeedMinPollInterval is the shortest interval a caller may
	// configure; a smaller one is clamped up to it, never refused (§10.4
	// rule 2).
	RevocationFeedMinPollInterval = revocation.MinPollInterval
	// RevocationFeedDefaultPollInterval is the interval §10.4 recommends.
	RevocationFeedDefaultPollInterval = revocation.DefaultPollInterval
	// RevocationFeedMaxEntries bounds the cached set. An over-sized document
	// is treated as unusable rather than truncated: a truncated set is a guard
	// that admits some revoked sessions and reports none.
	RevocationFeedMaxEntries = revocation.MaxEntries
)
