package axiam

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func mustMarshal(t *testing.T, claims map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	return b
}

func baseClaims(now time.Time) map[string]any {
	return map[string]any{
		"iss":   "https://issuer.test",
		"sub":   "user-1",
		"aud":   "rp-client",
		"exp":   now.Add(5 * time.Minute).Unix(),
		"iat":   now.Unix(),
		"nonce": "expected-nonce",
	}
}

func baseExpectations() idTokenExpectations {
	return idTokenExpectations{issuer: "https://issuer.test", clientID: "rp-client", nonce: "expected-nonce", hasNonce: true}
}

func expectReason(t *testing.T, err error, want IDTokenFailureReason) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an error with reason %q, got nil", want)
	}
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("expected *AuthError, got %T: %v", err, err)
	}
	if authErr.Reason != string(want) {
		t.Fatalf("Reason = %q, want %q (message: %s)", authErr.Reason, want, authErr.Message)
	}
}

// TestValidateIDToken_HappyPath proves a well-formed, fully-matching claim
// set validates and round-trips iss/sub/aud/exp/iat/nonce.
func TestValidateIDToken_HappyPath(t *testing.T) {
	now := time.Now()
	claims, err := validateIDToken(mustMarshal(t, baseClaims(now)), baseExpectations(), now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims.Iss != "https://issuer.test" || claims.Sub != "user-1" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
	if len(claims.Aud) != 1 || claims.Aud[0] != "rp-client" {
		t.Fatalf("unexpected aud: %v", claims.Aud)
	}
	if claims.Nonce != "expected-nonce" {
		t.Fatalf("unexpected nonce: %q", claims.Nonce)
	}
}

// TestValidateIDToken_PreservesExtraClaims proves §12.1's open-map
// requirement: an unmodeled claim (e.g. email) survives into Extra rather
// than being rejected.
func TestValidateIDToken_PreservesExtraClaims(t *testing.T) {
	now := time.Now()
	claims := baseClaims(now)
	claims["email"] = "alice@example.test"
	claims["preferred_username"] = "alice"

	got, err := validateIDToken(mustMarshal(t, claims), baseExpectations(), now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Extra["email"] != "alice@example.test" {
		t.Fatalf("expected Extra[email] to be preserved, got %+v", got.Extra)
	}
	if got.Extra["preferred_username"] != "alice" {
		t.Fatalf("expected Extra[preferred_username] to be preserved, got %+v", got.Extra)
	}
}

// TestValidateIDToken_InvalidIssuer proves §12.4 rule 3: exact string
// comparison, no normalization.
func TestValidateIDToken_InvalidIssuer(t *testing.T) {
	now := time.Now()
	claims := baseClaims(now)
	claims["iss"] = "https://issuer.test/" // trailing slash must NOT be tolerated
	_, err := validateIDToken(mustMarshal(t, claims), baseExpectations(), now)
	expectReason(t, err, ReasonInvalidIssuer)
}

// TestValidateIDToken_InvalidAudience_NotPresent proves §12.4 rule 4: aud
// must contain the client_id.
func TestValidateIDToken_InvalidAudience_NotPresent(t *testing.T) {
	now := time.Now()
	claims := baseClaims(now)
	claims["aud"] = "someone-else"
	_, err := validateIDToken(mustMarshal(t, claims), baseExpectations(), now)
	expectReason(t, err, ReasonInvalidAudience)
}

// TestValidateIDToken_InvalidAudience_MultipleWithoutAzp proves §12.4 rule 4:
// multiple audiences require a matching azp.
func TestValidateIDToken_InvalidAudience_MultipleWithoutAzp(t *testing.T) {
	now := time.Now()
	claims := baseClaims(now)
	claims["aud"] = []string{"rp-client", "other-client"}
	_, err := validateIDToken(mustMarshal(t, claims), baseExpectations(), now)
	expectReason(t, err, ReasonInvalidAudience)
}

// TestValidateIDToken_MultipleAudienceWithMatchingAzp proves the converse:
// multiple audiences succeed when azp equals client_id.
func TestValidateIDToken_MultipleAudienceWithMatchingAzp(t *testing.T) {
	now := time.Now()
	claims := baseClaims(now)
	claims["aud"] = []string{"rp-client", "other-client"}
	claims["azp"] = "rp-client"
	if _, err := validateIDToken(mustMarshal(t, claims), baseExpectations(), now); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestValidateIDToken_Expired proves §12.4 rule 5: exp in the past.
func TestValidateIDToken_Expired(t *testing.T) {
	now := time.Now()
	claims := baseClaims(now)
	claims["exp"] = now.Add(-5 * time.Minute).Unix()
	_, err := validateIDToken(mustMarshal(t, claims), baseExpectations(), now)
	expectReason(t, err, ReasonTokenExpired)
}

// TestValidateIDToken_MissingExp proves exp is REQUIRED (§12 port addendum
// item 11): absence is treated as expired, not a free pass.
func TestValidateIDToken_MissingExp(t *testing.T) {
	now := time.Now()
	claims := baseClaims(now)
	delete(claims, "exp")
	_, err := validateIDToken(mustMarshal(t, claims), baseExpectations(), now)
	expectReason(t, err, ReasonTokenExpired)
}

// TestValidateIDToken_FutureIat proves a future iat maps to token_expired
// (no separate time-code exists among the seven reason codes).
func TestValidateIDToken_FutureIat(t *testing.T) {
	now := time.Now()
	claims := baseClaims(now)
	claims["iat"] = now.Add(10 * time.Minute).Unix()
	_, err := validateIDToken(mustMarshal(t, claims), baseExpectations(), now)
	expectReason(t, err, ReasonTokenExpired)
}

// TestValidateIDToken_FutureNbf proves a future nbf also maps to
// token_expired.
func TestValidateIDToken_FutureNbf(t *testing.T) {
	now := time.Now()
	claims := baseClaims(now)
	claims["nbf"] = now.Add(10 * time.Minute).Unix()
	_, err := validateIDToken(mustMarshal(t, claims), baseExpectations(), now)
	expectReason(t, err, ReasonTokenExpired)
}

// TestValidateIDToken_ClockSkewTolerance proves §12.4 rule 5's +/-60s
// default skew tolerates a small overshoot instead of failing.
func TestValidateIDToken_ClockSkewTolerance(t *testing.T) {
	now := time.Now()
	claims := baseClaims(now)
	claims["exp"] = now.Add(-30 * time.Second).Unix() // just past exp, within 60s skew
	exp := baseExpectations()
	if _, err := validateIDToken(mustMarshal(t, claims), exp, now); err != nil {
		t.Fatalf("expected the default 60s skew to tolerate a 30s overshoot, got: %v", err)
	}
}

// TestValidateIDToken_NonceMismatch proves §12.4 rule 6.
func TestValidateIDToken_NonceMismatch(t *testing.T) {
	now := time.Now()
	claims := baseClaims(now)
	claims["nonce"] = "wrong-nonce"
	_, err := validateIDToken(mustMarshal(t, claims), baseExpectations(), now)
	expectReason(t, err, ReasonNonceMismatch)
}

// TestValidateIDToken_MissingNonce proves an absent nonce claim, when one is
// expected, is also a nonce_mismatch.
func TestValidateIDToken_MissingNonce(t *testing.T) {
	now := time.Now()
	claims := baseClaims(now)
	delete(claims, "nonce")
	_, err := validateIDToken(mustMarshal(t, claims), baseExpectations(), now)
	expectReason(t, err, ReasonNonceMismatch)
}

// TestValidateIDToken_NonceSkippedForRefresh proves §12.4 rule 6 is skipped
// (hasNonce=false) for OidcRefresh/LoginClientCredentials-shaped
// expectations — no nonce claim needed at all.
func TestValidateIDToken_NonceSkippedForRefresh(t *testing.T) {
	now := time.Now()
	claims := baseClaims(now)
	delete(claims, "nonce")
	exp := idTokenExpectations{issuer: "https://issuer.test", clientID: "rp-client"} // hasNonce: false
	if _, err := validateIDToken(mustMarshal(t, claims), exp, now); err != nil {
		t.Fatalf("unexpected error when nonce rule is skipped: %v", err)
	}
}

// TestResolveClockSkewSec_ClampedToMax proves §12.4 rule 5: skew can never
// be configured ABOVE the 60s ceiling.
func TestResolveClockSkewSec_ClampedToMax(t *testing.T) {
	if got := resolveClockSkewSec(3600); got != MaxIDTokenClockSkewSec {
		t.Fatalf("resolveClockSkewSec(3600) = %d, want %d (clamped)", got, MaxIDTokenClockSkewSec)
	}
	if got := resolveClockSkewSec(0); got != MaxIDTokenClockSkewSec {
		t.Fatalf("resolveClockSkewSec(0) = %d, want default %d", got, MaxIDTokenClockSkewSec)
	}
	if got := resolveClockSkewSec(10); got != 10 {
		t.Fatalf("resolveClockSkewSec(10) = %d, want 10 (honoured verbatim within bound)", got)
	}
}
