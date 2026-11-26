package axiam

import (
	"testing"
	"time"
)

// An ID token whose `aud` array holds a null element beside the RP's own
// client_id (azp set, so the multi-audience rule passes) is not an array of
// strings and fails rule 4 (review round 1,
// item 4): it used to decode as ["rp-client", ""] and pass.
func TestValidateIDToken_AudArrayWithNullElementIsRefused(t *testing.T) {
	claims := map[string]any{
		"iss": "https://issuer.test", "sub": "u", "aud": []any{"rp-client", nil},
		"exp": 9999999999, "iat": 1, "nonce": "n", "azp": "rp-client",
	}
	_, err := validateIDToken(mustMarshal(t, claims), idTokenExpectations{issuer: "https://issuer.test", clientID: "rp-client", nonce: "n", hasNonce: true}, time.Now())
	expectReason(t, err, ReasonInvalidAudience)
}
