package jwks

import (
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
