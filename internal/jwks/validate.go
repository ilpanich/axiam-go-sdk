package jwks

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"time"
)

// ClockSkewLeeway is the single, named, bounded clock-skew allowance applied
// to the exp and nbf checks (CONTRACT.md §10.1 rule 7 — RECOMMENDED 60 s).
//
// It is deliberately a CONSTANT and not a ValidationOptions field: §10.1
// requires the leeway to be "a named constant, not an inline literal" and
// forbids it being "operator-configurable to an unbounded value". Exposing it
// as a knob is the whole failure mode the rule exists to prevent.
const ClockSkewLeeway = 60 * time.Second

// Sentinel errors returned by ValidateClaims. Callers classify with
// errors.Is rather than by parsing error strings; the net/http middleware
// collapses all of them onto a single opaque 401 body so a rejected caller
// learns nothing about WHICH claim failed.
var (
	// ErrNoConfiguredTenant reports that the guard itself has no tenant to
	// compare against. §10.1 rule 4 makes this a fail-closed condition: an
	// unconfigured guard MUST NOT accept an arbitrary tenant's token.
	ErrNoConfiguredTenant = errors.New("jwks: no configured tenant to validate tenant_id against")
	// ErrTenantMismatch reports an absent tenant_id claim, or one that does
	// not equal the configured tenant (§10.1 rule 4).
	ErrTenantMismatch = errors.New("jwks: token tenant_id does not match the configured tenant")
	// ErrMissingExp reports a token with no exp claim at all — a permanent
	// credential, which §10.1 rule 2 requires be rejected rather than treated
	// as "no expiry constraint". This is the SEC-080 defect.
	ErrMissingExp = errors.New("jwks: token has no exp claim")
	// ErrExpired reports an exp claim in the past (beyond ClockSkewLeeway).
	ErrExpired = errors.New("jwks: token has expired")
	// ErrNotYetValid reports an nbf claim in the future (beyond
	// ClockSkewLeeway) — §10.1 rule 3.
	ErrNotYetValid = errors.New("jwks: token is not valid yet (nbf is in the future)")
	// ErrIssuerMismatch reports an iss claim that does not equal the
	// configured expected issuer (§10.1 rule 5).
	ErrIssuerMismatch = errors.New("jwks: token iss does not match the configured expected issuer")
	// ErrAudienceMismatch reports an aud claim that does not contain the
	// configured expected audience (§10.1 rule 6).
	ErrAudienceMismatch = errors.New("jwks: token aud does not contain the configured expected audience")
)

// ValidationOptions carries the relying party's expectations for
// ValidateClaims.
//
// Tenant is REQUIRED (§10.1 rule 4). ExpectedIssuer and ExpectedAudience are
// CONDITIONAL (§10.1 rules 5 and 6): the empty string means "not configured,
// so not checked" — never "expect the empty string". No issuer or audience
// value is hardcoded anywhere in this SDK.
type ValidationOptions struct {
	// Tenant is the tenant this guard serves. Empty fails closed.
	Tenant string
	// ExpectedIssuer, when non-empty, is compared against the token's iss.
	ExpectedIssuer string
	// ExpectedAudience, when non-empty, must appear in the token's aud.
	ExpectedAudience string

	// now is a testing seam only; nil means time.Now. It is unexported so it
	// can never be reached from configuration.
	now func() time.Time
}

func (o ValidationOptions) currentTime() time.Time {
	if o.now != nil {
		return o.now()
	}
	return time.Now()
}

// ValidateClaims applies CONTRACT.md §10.1 rules 2–7 to already
// signature-verified claims (rule 1 is enforced by the verifier's alg pin,
// before any key lookup).
//
// Every rule fails closed: a required claim that is absent, unparseable, or
// of the wrong JSON type is a rejection. "The claim was missing so there was
// nothing to check" is never success.
func ValidateClaims(claims Claims, opts ValidationOptions) error {
	// Rule 4 — tenant_id: REQUIRED and asserted. The JWKS trust anchor is
	// organization-wide, so a valid signature alone does not bound a token to
	// a tenant. An unconfigured guard has nothing to assert against and must
	// therefore reject rather than wave the token through.
	if opts.Tenant == "" {
		return ErrNoConfiguredTenant
	}
	if claims.TenantID == "" || claims.TenantID != opts.Tenant {
		return ErrTenantMismatch
	}

	now := opts.currentTime()

	// Rule 2 — exp: REQUIRED. Absent (or non-numeric, already rejected at
	// parse time) is a permanent credential and is rejected outright.
	if claims.Exp == nil {
		return ErrMissingExp
	}
	if !now.Add(-ClockSkewLeeway).Before(time.Unix(*claims.Exp, 0)) {
		return ErrExpired
	}

	// Rule 3 — nbf: honoured when present; absent is valid.
	if claims.Nbf != nil && now.Add(ClockSkewLeeway).Before(time.Unix(*claims.Nbf, 0)) {
		return ErrNotYetValid
	}

	// Rule 5 — iss: checked only when an expected issuer is configured.
	if opts.ExpectedIssuer != "" && claims.Issuer != opts.ExpectedIssuer {
		return ErrIssuerMismatch
	}

	// Rule 6 — aud: checked only when an expected audience is configured. An
	// absent aud can never contain the expectation, so it fails closed here
	// without a special case.
	if opts.ExpectedAudience != "" && !containsString(claims.Audience, opts.ExpectedAudience) {
		return ErrAudienceMismatch
	}

	return nil
}

func containsString(haystack []string, needle string) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}

// ErrUnverifiableConfirmation is returned when a token's "cnf" claim names a
// confirmation method this SDK cannot check.
//
// It is a REJECTION, not a pass. A cnf naming, say, a DPoP "jkt" is an
// unverifiable constraint — never an absent one. Read the other way, a
// sender-constrained token silently degrades to a bearer token the day a newer
// AXIAM issues a confirmation this SDK predates.
var ErrUnverifiableConfirmation = errors.New(
	"jwks: token carries a cnf confirmation naming a method this SDK cannot verify")

// ErrNoClientCertificate is returned when a certificate-bound token is
// presented on a connection carrying no client certificate.
var ErrNoClientCertificate = errors.New(
	"jwks: token is certificate-bound but no client certificate was presented")

// ErrCertificateBindingMismatch is returned when a certificate-bound token is
// presented with a certificate other than the one it was issued to.
// ErrNoDPoPProof is returned when a DPoP-bound token is presented without a
// verified proof (contract 1.16).
var ErrNoDPoPProof = errors.New(
	"jwks: token is DPoP-bound but no verified DPoP proof was presented")

// ErrDPoPBindingMismatch is returned when a DPoP-bound token is presented with
// a proof by a different key (contract 1.16).
var ErrDPoPBindingMismatch = errors.New(
	"jwks: token is bound to a different DPoP key than the one presented")

var ErrCertificateBindingMismatch = errors.New(
	"jwks: token is bound to a different client certificate than the one presented")

// VerifyCertificateBinding applies CONTRACT.md §10.1 rule 9 — the sender
// constraint (RFC 8705 §3 / RFC 7800, contract 1.15).
//
// presentedThumbprint is the RFC 8705 §3.1 "x5t#S256" of the peer certificate
// on THIS connection: base64url, unpadded, SHA-256 over the DER encoding.
// CertificateThumbprintS256 computes it; under crypto/tls it is
// CertificateThumbprintS256(conn.ConnectionState().PeerCertificates[0].Raw).
// Pass "" when the connection carries no client certificate.
//
// The four cases:
//
//	token's cnf              presentedThumbprint       result
//	absent                   anything                  nil (an ordinary bearer token)
//	x5t#S256                 equal                     nil
//	x5t#S256                 different, or ""          error
//	present, no x5t#S256     anything                  error
//
// The first row is why adopting this rule breaks nothing: an UNBOUND token is
// still accepted whether or not a certificate is present. Rule 9 constrains
// tokens that claim a constraint; it does not make certificates mandatory.
//
// The thumbprint must come from the transport — the TLS peer certificate, or a
// value a TRUSTED terminating proxy forwarded over a channel the application
// controls. Never from a caller-settable request header: a forgeable input
// makes the whole mechanism decorative.
func VerifyCertificateBinding(claims Claims, presentedThumbprint string) error {
	if claims.Confirmation == nil {
		return nil
	}
	if claims.Confirmation.X5tS256 == "" {
		// Includes the DPoP case: this entry point has no proof to check, so a
		// jkt-bound token is refused rather than silently downgraded.
		return ErrUnverifiableConfirmation
	}
	// A token naming BOTH methods is a conjunction (contract 1.16): this
	// function can establish one half and must not answer for the whole.
	// Refusing here is what stops "check whichever we can".
	if claims.Confirmation.Jkt != "" {
		return ErrUnverifiableConfirmation
	}
	if presentedThumbprint == "" {
		return ErrNoClientCertificate
	}
	// Constant-time. The thumbprint is usually public — it derives from a
	// certificate sent in the clear during the handshake — so this is defence
	// in depth. It matters most for a self-signed client, where the registered
	// thumbprint is the whole credential.
	if subtle.ConstantTimeCompare(
		[]byte(claims.Confirmation.X5tS256), []byte(presentedThumbprint)) != 1 {
		return ErrCertificateBindingMismatch
	}
	return nil
}

// CertificateThumbprintS256 computes the RFC 8705 §3.1 "x5t#S256" thumbprint
// of a DER client certificate: base64url-encoded SHA-256, WITHOUT padding.
//
// Unpadded is not a style choice — RFC 7515 §2 defines base64url in JOSE as
// omitting "=", and a padded value will not compare equal to what AXIAM put in
// the token.
func CertificateThumbprintS256(der []byte) string {
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// PresentedProofs carries what the caller proved about THIS connection and
// THIS request, for VerifyTokenBinding.
//
// A struct rather than two string parameters on purpose: two same-typed
// optional thumbprints are exactly the pair a positional call transposes
// silently, and transposing them would check each proof against the wrong
// confirmation.
type PresentedProofs struct {
	// CertificateThumbprint is the peer certificate's RFC 8705 "x5t#S256",
	// taken from the TLS connection or from a trusted terminating proxy over a
	// channel the application controls — NEVER from a caller-settable header,
	// which would make the whole mechanism decorative.
	CertificateThumbprint string
	// DPoPThumbprint is the "jkt" of an ALREADY VERIFIED DPoP proof.
	//
	// Supply it only after checking the proof's signature, htm, htu, iat and
	// jti for this request — dpop.VerifyProof does all ten §21.7.2 checks and
	// returns exactly this value. A thumbprint lifted off an unverified proof
	// would let a proof captured from any other endpoint authorize this one.
	DPoPThumbprint string
}

// VerifyTokenBinding applies CONTRACT.md §10.1 rule 9 in full — the token's
// sender constraint against EVERY proof the caller presented (contract 1.16).
//
// This is the complete rule, and the one to use unless the transport genuinely
// cannot produce a DPoP thumbprint.
//
// The ten cases:
//
//	token's cnf             certificate     DPoP        result
//	absent                  anything        anything    nil
//	x5t#S256                equal           ignored     nil
//	x5t#S256                different       ignored     error
//	x5t#S256                missing         ignored     error
//	jkt                     ignored         equal       nil
//	jkt                     ignored         different   error
//	jkt                     ignored         missing     error
//	both                    equal           equal       nil
//	both                    wrong/missing   —           error
//	present, names neither  anything        anything    error
//
// Two rows carry the weight. BOTH NAMED IS A CONJUNCTION: an operator who
// turned on two constraints asked for two, and satisfying the more convenient
// one is not compliance. NAMES NEITHER IS A REFUSAL: a confirmation this SDK
// cannot interpret is an unverifiable constraint, and reading it as
// "unconstrained" is the exact downgrade rule 9 exists to prevent. That
// includes an EMPTY cnf — which is also how proto3 delivers an empty CnfClaim
// over gRPC (§10.3 rule 3).
func VerifyTokenBinding(claims Claims, proofs PresentedProofs) error {
	// The fast path, and the common one. First on purpose: an unbound token is
	// accepted with no proofs at all, which is what keeps existing deployments
	// working when a guard adopts this rule.
	if claims.Confirmation == nil {
		return nil
	}
	if claims.Confirmation.NamesNothingCheckable() {
		return ErrUnverifiableConfirmation
	}

	// Each arm that applies must pass. Two independent checks rather than a
	// switch on the pair, precisely so "both named" needs no case of its own —
	// it is simply where both run.
	if expected := claims.Confirmation.X5tS256; expected != "" {
		if proofs.CertificateThumbprint == "" {
			return ErrNoClientCertificate
		}
		if subtle.ConstantTimeCompare(
			[]byte(expected), []byte(proofs.CertificateThumbprint)) != 1 {
			return ErrCertificateBindingMismatch
		}
	}

	if expected := claims.Confirmation.Jkt; expected != "" {
		if proofs.DPoPThumbprint == "" {
			return ErrNoDPoPProof
		}
		if subtle.ConstantTimeCompare(
			[]byte(expected), []byte(proofs.DPoPThumbprint)) != 1 {
			return ErrDPoPBindingMismatch
		}
	}

	return nil
}
