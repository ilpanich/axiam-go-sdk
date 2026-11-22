package jwks

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

// CONTRACT.md §10.1 rules 10-12 (contract 1.68; N14, D-7): the access-token
// path refuses a token typed as anything but an access token, a token
// carrying a `purpose` claim, and a token whose header names no `kid` (no
// single-key fallback). Every case is otherwise valid for the configured
// tenant, signed by the JWKS key, with no `aud`, against a verifier
// configured with no expected audience.

const n14Tenant = "11111111-1111-1111-1111-111111111111"

// n14Token signs payload with priv under a header carrying typ (omitted when
// empty) and kid (omitted from the header when empty).
func n14Token(t *testing.T, priv ed25519.PrivateKey, kid, typ string, payload map[string]any) []byte {
	t.Helper()
	pk, err := jwk.Import(priv)
	if err != nil {
		t.Fatalf("jwk.Import: %v", err)
	}
	if kid != "" {
		if err := pk.Set(jwk.KeyIDKey, kid); err != nil {
			t.Fatalf("set kid: %v", err)
		}
	}
	hdr := jws.NewHeaders()
	if typ != "" {
		if err := hdr.Set("typ", typ); err != nil {
			t.Fatalf("set typ: %v", err)
		}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	signed, err := jws.Sign(body, jws.WithKey(jwa.EdDSA(), pk, jws.WithProtectedHeaders(hdr)))
	if err != nil {
		t.Fatalf("jws.Sign: %v", err)
	}
	return signed
}

func n14Claims(extra map[string]any) map[string]any {
	p := map[string]any{
		"sub":       "22222222-2222-2222-2222-222222222222",
		"tenant_id": n14Tenant,
		"org_id":    "33333333-3333-3333-3333-333333333333",
		"iss":       "https://axiam.example",
		"exp":       time.Now().Add(5 * time.Minute).Unix(),
	}
	for k, v := range extra {
		p[k] = v
	}
	return p
}

func TestVerifyAccessToken_N14_RulesTenToTwelve(t *testing.T) {
	priv, pub := generateKey(t, "n14-kid")
	srv := newMutableJWKSServer(t, marshalSet(t, pub))
	v, err := NewVerifier(context.Background(), srv.Server.URL, nil)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	opts := ValidationOptions{Tenant: n14Tenant} // no expected audience

	refused := []struct {
		name string
		tok  []byte
	}{
		{"typ JWT (a pre-1.67 access token)", n14Token(t, priv, "n14-kid", "JWT", n14Claims(nil))},
		{"typ axiam-mfa-challenge+jwt", n14Token(t, priv, "n14-kid", "axiam-mfa-challenge+jwt", n14Claims(nil))},
		{"typ axiam-webauthn-state+jwt", n14Token(t, priv, "n14-kid", "axiam-webauthn-state+jwt", n14Claims(nil))},
		{"typ logout+jwt", n14Token(t, priv, "n14-kid", "logout+jwt", n14Claims(nil))},
		{"typ application/jwt", n14Token(t, priv, "n14-kid", "application/jwt", n14Claims(nil))},
		{"no kid against a one-key JWKS (rule 12: no single-key fallback)", n14Token(t, priv, "", "at+jwt", n14Claims(nil))},
		{"no kid and no typ", n14Token(t, priv, "", "", n14Claims(nil))},
		{"purpose mfa_challenge with typ at+jwt and a valid kid (rule 11)", n14Token(t, priv, "n14-kid", "at+jwt", n14Claims(map[string]any{"purpose": "mfa_challenge"}))},
		{"purpose on a token with no typ", n14Token(t, priv, "n14-kid", "", n14Claims(map[string]any{"purpose": "mfa_challenge"}))},
		{"WebAuthn shape: nil-UUID sub and purpose webauthn_authenticate_discoverable", n14Token(t, priv, "n14-kid", "at+jwt", n14Claims(map[string]any{
			"sub": "00000000-0000-0000-0000-000000000000", "purpose": "webauthn_authenticate_discoverable"}))},
		{"purpose present but null", n14Token(t, priv, "n14-kid", "at+jwt", n14Claims(map[string]any{"purpose": nil}))},
	}
	for _, tc := range refused {
		t.Run("refused/"+tc.name, func(t *testing.T) {
			if claims, err := v.VerifyAccessToken(context.Background(), tc.tok, opts); err == nil {
				t.Fatalf("expected the access-token path to refuse this token, got claims for sub %q", claims.Subject)
			}
		})
	}

	accepted := []struct {
		name string
		tok  []byte
	}{
		{"typ at+jwt", n14Token(t, priv, "n14-kid", "at+jwt", n14Claims(nil))},
		{"typ AT+JWT (case-insensitive)", n14Token(t, priv, "n14-kid", "AT+JWT", n14Claims(nil))},
		{"typ application/at+jwt", n14Token(t, priv, "n14-kid", "application/at+jwt", n14Claims(nil))},
		{"no typ that passes every other rule", n14Token(t, priv, "n14-kid", "", n14Claims(nil))},
	}
	for _, tc := range accepted {
		t.Run("accepted/"+tc.name, func(t *testing.T) {
			if _, err := v.VerifyAccessToken(context.Background(), tc.tok, opts); err != nil {
				t.Fatalf("a normal access token must verify: %v", err)
			}
		})
	}
}

// The rules apply to the access-token path ONLY: the raw primitive and the
// payload verifier shared with the ID-token and logout-token paths (§10.1
// "Scope") keep their behaviour.
func TestVerifyPayload_N14_NotAppliedToOtherTokenKinds(t *testing.T) {
	priv, pub := generateKey(t, "n14-kid")
	srv := newMutableJWKSServer(t, marshalSet(t, pub))
	v, err := NewVerifier(context.Background(), srv.Server.URL, nil)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	logout := n14Token(t, priv, "n14-kid", "logout+jwt", map[string]any{"events": map[string]any{}})
	if _, err := v.VerifyPayload(context.Background(), logout); err != nil {
		t.Fatalf("VerifyPayload must keep verifying a logout+jwt token: %v", err)
	}
}
