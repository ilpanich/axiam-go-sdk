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
	// Roles is the token's "roles" claim (CONTRACT.md §11.2 rule 11, contract
	// 1.68): the names of the subject's global roles in the tenant. It is read
	// from "roles" ONLY — never from "scope", which is chosen by the client
	// and says nothing about what the user holds (N15). nil when the claim is
	// absent or is not a JSON array of strings; HasRoles tells that apart from
	// an empty array.
	Roles []string
	// HasRoles reports whether the token carried a well-formed "roles" claim
	// (a JSON array of strings, possibly empty). false means the token says
	// nothing about roles — "ask for the roles scope" — whereas true with an
	// empty Roles means "the user holds none" (§11.2 rule 11 b).
	HasRoles bool
	// Scopes is the space-separated "scope" claim split on spaces (RFC 6749
	// §3.3). nil when the claim is absent or not a string. It feeds
	// require_scope and never require_role.
	Scopes []string
	// HasPurpose reports whether the token carried a "purpose" claim at all,
	// whatever its value. AXIAM puts it on the MFA challenge, MFA setup and
	// WebAuthn state tokens it signs with the access-token key, and on nothing
	// else; the access-token path refuses a token that has it (§10.1 rule 11).
	HasPurpose bool
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
	// SessionID is the OIDC Core "sid" claim ("" when absent) — the session
	// behind this token, and the only thing the §10.4 revocation feed can be
	// matched against (contract 1.44).
	//
	// Absent on every token that has no session behind it: client credentials,
	// an RPT, a token exchange. Such a token is never matched against the
	// feed, and there is deliberately no fallback to "jti" — hashing that
	// would match nothing while looking like it worked.
	SessionID string
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
	// Jkt is RFC 9449 §6.1's "jkt": the RFC 7638 SHA-256 thumbprint of the
	// DPoP public key the token was bound to (contract 1.16). Empty when the
	// confirmation names some other method.
	//
	// Both fields set is a CONJUNCTION, not a choice — see VerifyTokenBinding.
	Jkt string
}

// NamesNothingCheckable reports whether the confirmation names no method this
// SDK can verify.
//
// The distinction this method exists to preserve: such a token is an
// UNVERIFIABLE constraint, never an absent one. Reading it as "unconstrained"
// is the exact downgrade §10.1 rule 9 exists to prevent, and it is how a
// sender-constrained token silently becomes a bearer token the day a newer
// AXIAM issues a confirmation this SDK predates.
func (c *Confirmation) NamesNothingCheckable() bool {
	return c.X5tS256 == "" && c.Jkt == ""
}

// Verify applies CONTRACT.md §10.1 rule 9 to this confirmation against
// proofs, exactly as VerifyTokenBinding would applied to a Claims value
// whose only relevant field is this one — the two SHARE one implementation
// so a guard verifying locally and a client validating a gRPC
// TokenService response can never disagree about whether a token is a
// bearer token (§10.1 rule 9 detail 4, §10.3 rules 1 and 4).
//
// A nil receiver — the shape an absent CnfClaim decodes to, see
// grpc/token.go's TokenValidation.Cnf — verifies successfully with no
// proofs required: an absent confirmation means "never bound" (rule 9's
// first row), which is exactly what a nil *Confirmation, called through a
// nil-safe method, should mean.
func (c *Confirmation) Verify(proofs PresentedProofs) error {
	return VerifyTokenBinding(Claims{Confirmation: c}, proofs)
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
	Scope    json.RawMessage `json:"scope"`
	RolesRaw json.RawMessage `json:"roles"`
	Purpose  json.RawMessage `json:"purpose"`
	Sid      string          `json:"sid"`
	Cnf      *rawCnf         `json:"cnf"`
}

// rawCnf is the wire shape of the "cnf" claim. A pointer in rawClaims so that
// "absent" and "present but naming a method we do not implement" stay
// distinguishable — the difference decides accept-versus-reject in
// VerifyCertificateBinding, and collapsing it would be the bug.
type rawCnf struct {
	X5tS256 string `json:"x5t#S256"`
	Jkt     string `json:"jkt"`
}

// parseClaims decodes a verified JWS payload into Claims. Roles come from the
// "roles" claim only and Scopes from the "scope" claim only; neither is ever
// derived from the other.
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
	hasRoles := false
	if t := strings.TrimSpace(string(raw.RolesRaw)); t != "" && t != "null" {
		// A "roles" claim that is not a JSON array of strings is treated as
		// absent: it fails every require_role closed (§11.2 rule 11 b). The
		// elements are decoded as pointers because encoding/json decodes a
		// JSON null into a []string element as "" without error, which
		// would make ["admin", null] read as an array of strings.
		var parsed []*string
		if err := json.Unmarshal(raw.RolesRaw, &parsed); err == nil && parsed != nil {
			strs := make([]string, 0, len(parsed))
			for _, p := range parsed {
				if p == nil {
					strs = nil
					break
				}
				strs = append(strs, *p)
			}
			if strs != nil {
				hasRoles = true
				roles = strs
			}
		}
	}
	var scopes []string
	if t := strings.TrimSpace(string(raw.Scope)); t != "" && t[0] == '"' {
		var scope string
		if err := json.Unmarshal(raw.Scope, &scope); err == nil {
			// Split on single spaces, dropping empty entries (§11.2 rule
			// 11 d): no other whitespace separates scope tokens.
			for _, s := range strings.Split(scope, " ") {
				if s != "" {
					scopes = append(scopes, s)
				}
			}
		}
	}

	return Claims{
		Subject:    raw.Sub,
		TenantID:   raw.TenantID,
		OrgID:      raw.OrgID,
		Roles:      roles,
		HasRoles:   hasRoles,
		Scopes:     scopes,
		HasPurpose: len(raw.Purpose) > 0,
		Exp:        exp,
		Nbf:        nbf,
		Issuer:     raw.Iss,
		Audience:   aud,
		SessionID:  raw.Sid,
		Confirmation: func() *Confirmation {
			if raw.Cnf == nil {
				return nil
			}
			return &Confirmation{X5tS256: raw.Cnf.X5tS256, Jkt: raw.Cnf.Jkt}
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
	// Pointer elements: encoding/json decodes a JSON null into a []string
	// element as "" without error, which would read ["a", null] as strings.
	var many []*string
	if err := json.Unmarshal(raw, &many); err != nil {
		return nil, fmt.Errorf("expected a string or an array of strings: %w", err)
	}
	out := make([]string, 0, len(many))
	for _, a := range many {
		if a == nil {
			return nil, fmt.Errorf("expected an array of strings, got a null element")
		}
		out = append(out, *a)
	}
	return out, nil
}
