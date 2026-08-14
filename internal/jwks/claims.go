// Package jwks implements local JWKS fetch/cache/verification via
// lestrrat-go/jwx/v3 (D-06/§10), the shared local-verify primitive consumed
// by the net/http middleware (Plan 05) and any proactive-refresh check.
package jwks

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
)

// Claims is the SDK's plain claims struct, matching the field names AXIAM
// issues in its access tokens (mirrors the Rust SDK's src/token/jwks.rs::Claims —
// mirror only, no server dependency).
//
// The time claims are pointers on purpose: CONTRACT.md §10.1 rule 2
// distinguishes "exp is absent" (a permanent credential — MUST be rejected)
// from "exp is present and in the past", and a plain int64 zero value cannot
// express that difference. Conflating the two is exactly the SEC-080 defect.
type Claims struct {
	// Subject is the user ID (UUID string) — the token's "sub" claim.
	Subject string
	// TenantID is the tenant UUID string.
	TenantID string
	// OrgID is the organization UUID string.
	OrgID string
	// Roles is parsed from the space-separated "scope" claim — AXIAM's
	// AccessTokenClaims has no roles field server-side (mirrors Rust 16-05).
	Roles []string
	// Exp is the "exp" claim (Unix seconds), or nil when the token carried no
	// exp at all. A nil Exp MUST be rejected by any guard (§10.1 rule 2);
	// ValidateClaims does so.
	Exp *int64
	// Nbf is the "nbf" claim (Unix seconds), or nil when absent. An absent
	// nbf is valid (§10.1 rule 3); an nbf in the future MUST be rejected.
	Nbf *int64
	// Issuer is the "iss" claim ("" when absent). Only checked when the guard
	// is configured with an expected issuer (§10.1 rule 5).
	Issuer string
	// Audience is the "aud" claim normalized to a slice — RFC 7519 allows
	// either a single string or an array of strings. nil when absent. Only
	// checked when the guard is configured with an expected audience
	// (§10.1 rule 6).
	Audience []string
	// Confirmation is the RFC 7800 / RFC 8705 §3.1 "cnf" claim, or nil when
	// the token carries none (§10.1 rule 9, contract 1.15).
	//
	// Its presence changes what the token IS. Without it the token is a bearer
	// credential: whoever holds it may use it. With it, the token names a key,
	// and accepting it without proving the caller holds that key converts it
	// straight back into a bearer token.
	//
	// ValidateClaims does NOT check it — it cannot, having no access to the
	// connection's peer certificate. Use VerifyCertificateBinding.
	Confirmation *Confirmation
}

// Confirmation is the RFC 7800 "cnf" claim.
//
// A struct with one optional field rather than a discriminated type: RFC 7800
// permits confirmation methods this SDK does not implement, and such a token
// must still PARSE. What it must not do is validate — see
// VerifyCertificateBinding, which refuses a confirmation it cannot check
// rather than reading it as "unconstrained".
type Confirmation struct {
	// X5tS256 is RFC 8705 §3.1's "x5t#S256": base64url (unpadded) SHA-256 of
	// the DER client certificate the token was issued to. Empty when the
	// confirmation names some other method.
	X5tS256 string
}

// rawClaims is the wire shape of the JWS payload this SDK decodes.
//
// exp/nbf/aud are held as json.RawMessage rather than concrete Go types so
// that "absent", "present but of the wrong JSON type" and "present and
// well-typed" stay distinguishable — see numericDate/audience.
type rawClaims struct {
	Sub      string          `json:"sub"`
	TenantID string          `json:"tenant_id"`
	OrgID    string          `json:"org_id"`
	Exp      json.RawMessage `json:"exp"`
	Nbf      json.RawMessage `json:"nbf"`
	Iss      string          `json:"iss"`
	Aud      json.RawMessage `json:"aud"`
	Scope    string          `json:"scope"`
	Cnf      *rawCnf         `json:"cnf"`
}

// rawCnf is the wire shape of the "cnf" claim. A pointer in rawClaims so that
// "absent" and "present but naming a method we do not implement" stay
// distinguishable — the difference decides accept-versus-reject in
// VerifyCertificateBinding, and collapsing it would be the bug.
type rawCnf struct {
	X5tS256 string `json:"x5t#S256"`
}

// parseClaims decodes a verified JWS payload into Claims, deriving Roles
// from the space-separated "scope" claim.
//
// parseClaims applies no policy — it only reports a claim that is PRESENT but
// of a JSON type the claim can never legitimately have (a string "exp", an
// object "aud", …), which is a parse failure and therefore a rejection
// (§10.1: "unparseable, or of the wrong JSON type MUST cause rejection").
// Whether an ABSENT claim is acceptable is ValidateClaims' decision.
func parseClaims(payload []byte) (Claims, error) {
	var raw rawClaims
	if err := json.Unmarshal(payload, &raw); err != nil {
		return Claims{}, fmt.Errorf("jwks: failed to parse claims: %w", err)
	}

	exp, err := numericDate(raw.Exp)
	if err != nil {
		return Claims{}, fmt.Errorf("jwks: invalid %q claim: %w", "exp", err)
	}
	nbf, err := numericDate(raw.Nbf)
	if err != nil {
		return Claims{}, fmt.Errorf("jwks: invalid %q claim: %w", "nbf", err)
	}
	aud, err := audience(raw.Aud)
	if err != nil {
		return Claims{}, fmt.Errorf("jwks: invalid %q claim: %w", "aud", err)
	}

	var roles []string
	if raw.Scope != "" {
		roles = append(roles, strings.Fields(raw.Scope)...)
	}

	return Claims{
		Subject:  raw.Sub,
		TenantID: raw.TenantID,
		OrgID:    raw.OrgID,
		Roles:    roles,
		Exp:      exp,
		Nbf:      nbf,
		Issuer:   raw.Iss,
		Audience: aud,
		Confirmation: func() *Confirmation {
			if raw.Cnf == nil {
				return nil
			}
			return &Confirmation{X5tS256: raw.Cnf.X5tS256}
		}(),
	}, nil
}

// numericDate converts a raw JSON value into a NumericDate (RFC 7519 §2: "A
// JSON numeric value"). It returns (nil, nil) when the claim is absent or
// JSON null, and an error when the claim is present but not a JSON number —
// a quoted "1700000000" is a JSON string, not a NumericDate, and is rejected
// rather than coerced (§10.1: wrong JSON type ⇒ reject).
func numericDate(raw json.RawMessage) (*int64, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return nil, nil
	}
	if trimmed[0] == '"' {
		return nil, fmt.Errorf("expected a JSON number, got a JSON string")
	}
	var seconds float64
	if err := json.Unmarshal(raw, &seconds); err != nil {
		return nil, fmt.Errorf("expected a JSON number: %w", err)
	}
	if math.IsNaN(seconds) || math.IsInf(seconds, 0) {
		return nil, fmt.Errorf("expected a finite JSON number")
	}
	// RFC 7519 permits a non-integer NumericDate; truncate toward zero, the
	// same rounding every sibling SDK applies.
	value := int64(seconds)
	return &value, nil
}

// audience normalizes the "aud" claim, which RFC 7519 §4.1.3 allows to be
// either a single StringOrURI or an array of them. Absent/null yields nil;
// any other JSON shape is an error.
func audience(raw json.RawMessage) ([]string, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return nil, nil
	}
	if trimmed[0] == '"' {
		var single string
		if err := json.Unmarshal(raw, &single); err != nil {
			return nil, err
		}
		return []string{single}, nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err != nil {
		return nil, fmt.Errorf("expected a string or an array of strings: %w", err)
	}
	return many, nil
}
