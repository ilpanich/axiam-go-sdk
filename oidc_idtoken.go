package axiam

// ID-token claim validation — CONTRACT.md §12.4, OIDC Core §3.1.3.7.
//
// The signature half of §12.4 (rules 1-2: alg allowlist, kid lookup,
// Ed25519 verification, single JWKS re-fetch) lives in
// internal/jwks.Verifier.VerifyPayload — the SAME verifier the §10
// middleware uses, extended (never forked) with a raw-payload entry point.
// This file holds rules 3-6 (issuer, audience, time, nonce) plus the
// reason-code vocabulary, so both halves are independently testable and were
// ported as one pair from the TypeScript reference.
//
// Every failure raises *AuthError carrying one of the seven stable reason
// codes below (§12.3 rule 3). Rule 7 (all-or-nothing discard) is enforced by
// the caller — toTokenSet never returns a token set whose ID token failed
// here, so access_token/refresh_token from the same response are dropped
// with it.

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ilpanich/axiam-go-sdk/internal/jwks"
)

// IDTokenFailureReason is one of the seven CONTRACT.md §12.3/§12.4 stable,
// machine-readable ID-token validation failure codes, carried on the
// resulting *AuthError's Reason field.
type IDTokenFailureReason string

// The seven §12.4 reason codes, used verbatim (contract-fixed spelling).
const (
	ReasonInvalidAlg       IDTokenFailureReason = "invalid_alg"
	ReasonUnknownKid       IDTokenFailureReason = "unknown_kid"
	ReasonInvalidSignature IDTokenFailureReason = "invalid_signature"
	ReasonInvalidIssuer    IDTokenFailureReason = "invalid_issuer"
	ReasonInvalidAudience  IDTokenFailureReason = "invalid_audience"
	ReasonTokenExpired     IDTokenFailureReason = "token_expired"
	ReasonNonceMismatch    IDTokenFailureReason = "nonce_mismatch"
)

// idTokenAlg is the only signing algorithm this SDK accepts for an ID token
// (CONTRACT.md §12.4 rule 1).
const idTokenAlg = "EdDSA"

// MaxIDTokenClockSkewSec is the CONTRACT.md §12.4 rule 5 ceiling for
// permitted ID-token clock skew: 60 seconds. WithOidcClockSkew clamps any
// larger configured value down to this ceiling; it is also the default when
// unconfigured.
const MaxIDTokenClockSkewSec = 60

// idTokenAuthError builds the *AuthError for a §12.4 failure: a stable
// machine-readable Reason plus a human-readable Message that — per §12.3
// rule 3 and §2's construction rules — never embeds the token, the client
// secret, the code verifier, or the expected nonce value.
func idTokenAuthError(reason IDTokenFailureReason, message string) *AuthError {
	return &AuthError{
		Message: fmt.Sprintf("id_token validation failed (%s): %s", reason, message),
		Reason:  string(reason),
	}
}

// mapJWKSVerifyError classifies a jwks.Verifier.VerifyPayload failure onto
// the matching §12.4 rule-1/rule-2 reason code. Never embeds the token.
func mapJWKSVerifyError(err error) error {
	switch {
	case errors.Is(err, jwks.ErrUnexpectedAlg), errors.Is(err, jwks.ErrNoSignatures):
		return idTokenAuthError(ReasonInvalidAlg, err.Error())
	case errors.Is(err, jwks.ErrUnknownKid):
		return idTokenAuthError(ReasonUnknownKid, err.Error())
	case errors.Is(err, jwks.ErrSignatureInvalid):
		return idTokenAuthError(ReasonInvalidSignature, err.Error())
	default:
		return idTokenAuthError(ReasonInvalidSignature, err.Error())
	}
}

// idTokenExpectations mirrors the TypeScript reference's IdTokenExpectations
// (§12.4 rules 3-6): what an already-signature-verified ID token is checked
// against.
type idTokenExpectations struct {
	// issuer is the authoritative issuer — always the discovery document's
	// `issuer`, never the client's own base URL (§12.3 rule 6).
	issuer string
	// clientID is the relying party's own client_id, matched against
	// aud/azp (rule 4).
	clientID string
	// nonce is the nonce returned by OidcBegin and passed back into
	// OidcExchange. Only meaningful when hasNonce is true.
	nonce string
	// hasNonce reports whether rule 6 applies. Mandatory for OidcExchange;
	// false for OidcRefresh and LoginClientCredentials, which skip rule 6
	// entirely (OIDC Core §12.2 does not require a nonce in a
	// refresh-issued ID token).
	hasNonce bool
	// clockSkewSec is the permitted clock skew in seconds for exp/iat/nbf
	// (rule 5); resolved via resolveClockSkewSec before use.
	clockSkewSec int
}

// resolveClockSkewSec clamps sec into [1, MaxIDTokenClockSkewSec], defaulting
// to the maximum when sec is zero or negative — CONTRACT.md §12.4 rule 5
// forbids configuring the skew ABOVE 60s, so a larger value is silently
// reduced rather than honoured.
func resolveClockSkewSec(sec int) int {
	if sec <= 0 || sec > MaxIDTokenClockSkewSec {
		return MaxIDTokenClockSkewSec
	}
	return sec
}

// constantTimeEquals is a constant-time string comparison, used for the
// nonce check §12.4 rule 6 requires. A length mismatch short-circuits to
// false — crypto/subtle.ConstantTimeCompare only compares equal-length
// inputs meaningfully, and a length difference is not itself secret.
func constantTimeEquals(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// IDTokenClaims is the decoded, ALREADY-VALIDATED ID-token claim set carried
// by OidcTokenSet.IDClaims (CONTRACT.md §12.1).
//
// Claim names are kept verbatim in their JWT/OIDC spelling (Iss, Sub, Aud,
// ...) rather than Go's usual field-name conventions: they are protocol
// identifiers a caller cross-references against OIDC Core. Extra preserves
// any further claim the server sends (e.g. email, preferred_username) — the
// ID token's full claim set is not enumerated by openapi.json, so unknown
// claims MUST be preserved and MUST NOT be rejected (§12.1).
type IDTokenClaims struct {
	// Iss is the issuer — matched for exact string equality against the
	// discovery document's issuer (rule 3).
	Iss string
	// Sub is the authenticated end user's stable identifier at AXIAM.
	Sub string
	// Aud is the audience — contains the relying party's client_id (rule 4).
	// May hold one or more values on the wire; always normalized to a slice
	// here.
	Aud []string
	// Exp is the expiry time (epoch seconds).
	Exp int64
	// Iat is the issued-at time (epoch seconds).
	Iat int64
	// Nbf is the not-before time (epoch seconds), when the server sends one.
	Nbf *int64
	// Nonce is the nonce echoed back from the authorization request (rule 6).
	Nonce string
	// Azp is the authorized party — required to equal client_id when Aud
	// holds multiple audiences (rule 4).
	Azp string
	// Extra preserves any claim not already modeled above (nil when none).
	Extra map[string]any
}

// wireIDTokenClaims is the JSON shape decoded from the JWS-verified ID-token
// payload. Aud is left as json.RawMessage because OIDC Core allows it to be
// either a bare string or a JSON array.
type wireIDTokenClaims struct {
	Iss   string          `json:"iss"`
	Sub   string          `json:"sub"`
	Aud   json.RawMessage `json:"aud"`
	Exp   *int64          `json:"exp"`
	Iat   *int64          `json:"iat"`
	Nbf   *int64          `json:"nbf"`
	Nonce *string         `json:"nonce"`
	Azp   string          `json:"azp"`
}

// idTokenKnownClaimKeys is used to strip the modeled claims out of the
// open/extra-claims map (extractExtraClaims).
var idTokenKnownClaimKeys = []string{"iss", "sub", "aud", "exp", "iat", "nbf", "nonce", "azp"}

// normalizeAud decodes the wire `aud` claim (a bare string OR a JSON array,
// per OIDC Core) into a slice, always.
func normalizeAud(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return []string{single}
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil {
		return many
	}
	return nil
}

func containsString(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// extractExtraClaims decodes payload into an open map and strips every
// modeled claim, returning nil rather than an empty map when nothing is
// left (§12.1 open-map preservation requirement).
func extractExtraClaims(payload []byte) map[string]any {
	var all map[string]any
	if err := json.Unmarshal(payload, &all); err != nil {
		return nil
	}
	for _, k := range idTokenKnownClaimKeys {
		delete(all, k)
	}
	if len(all) == 0 {
		return nil
	}
	return all
}

// validateIDToken performs CONTRACT.md §12.4 rules 3-6 (issuer, audience,
// time, nonce) over an already-signature-verified JWS payload, returning the
// decoded IDTokenClaims on success or the matching reason-coded *AuthError
// on the FIRST failure (rule 7's all-or-nothing discard is the caller's
// responsibility: it must never construct an OidcTokenSet from a partial
// result here).
func validateIDToken(payload []byte, exp idTokenExpectations, now time.Time) (IDTokenClaims, error) {
	var wire wireIDTokenClaims
	if err := json.Unmarshal(payload, &wire); err != nil {
		return IDTokenClaims{}, idTokenAuthError(ReasonInvalidSignature, "id_token payload is not valid JSON")
	}

	aud := normalizeAud(wire.Aud)

	// Rule 3 — exact string comparison. No normalization, no
	// trailing-slash tolerance, no prefix matching.
	if wire.Iss != exp.issuer {
		return IDTokenClaims{}, idTokenAuthError(ReasonInvalidIssuer, "iss does not equal the discovery document issuer")
	}

	// Rule 4 — aud must contain our client_id; with multiple audiences an
	// azp claim must be present and equal to it.
	if !containsString(aud, exp.clientID) {
		return IDTokenClaims{}, idTokenAuthError(ReasonInvalidAudience, "aud does not contain this client_id")
	}
	if len(aud) > 1 && wire.Azp != exp.clientID {
		return IDTokenClaims{}, idTokenAuthError(ReasonInvalidAudience, "aud holds multiple audiences and azp is absent or does not equal this client_id")
	}

	skew := int64(resolveClockSkewSec(exp.clockSkewSec))
	nowSec := now.Unix()

	// Rule 5 — exp must be in the future, iat must not be in the future,
	// nbf is honored when present; all within skew seconds. exp/iat are
	// treated as REQUIRED: a token with no expiry could never satisfy "exp
	// must be in the future", so absence is an expiry failure, not a free
	// pass (§12 port addendum item 11).
	if wire.Exp == nil {
		return IDTokenClaims{}, idTokenAuthError(ReasonTokenExpired, "exp claim is missing")
	}
	if *wire.Exp+skew <= nowSec {
		return IDTokenClaims{}, idTokenAuthError(ReasonTokenExpired, "exp is in the past")
	}
	if wire.Iat == nil {
		return IDTokenClaims{}, idTokenAuthError(ReasonTokenExpired, "iat claim is missing")
	}
	if *wire.Iat-skew > nowSec {
		return IDTokenClaims{}, idTokenAuthError(ReasonTokenExpired, "iat is in the future")
	}
	if wire.Nbf != nil && *wire.Nbf-skew > nowSec {
		return IDTokenClaims{}, idTokenAuthError(ReasonTokenExpired, "nbf is in the future")
	}

	// Rule 6 — mandatory for OidcExchange (hasNonce=true), skipped for
	// OidcRefresh/LoginClientCredentials.
	if exp.hasNonce {
		if wire.Nonce == nil || !constantTimeEquals(*wire.Nonce, exp.nonce) {
			return IDTokenClaims{}, idTokenAuthError(ReasonNonceMismatch, "nonce claim is absent or does not match the request nonce")
		}
	}

	claims := IDTokenClaims{
		Iss:   wire.Iss,
		Sub:   wire.Sub,
		Aud:   aud,
		Exp:   *wire.Exp,
		Iat:   *wire.Iat,
		Nbf:   wire.Nbf,
		Azp:   wire.Azp,
		Extra: extractExtraClaims(payload),
	}
	if wire.Nonce != nil {
		claims.Nonce = *wire.Nonce
	}
	return claims, nil
}
