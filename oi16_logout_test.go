package axiam

// Server #880 and CONTRACT 1.69 §12.7.3 rule 1 / §12.7.6: a back-channel
// logout token from a 1.69 server carries exactly the header
// {"alg":"EdDSA","typ":"logout+jwt","kid":"<kid>"}, and VerifyLogoutToken
// selects the key by that kid. The tokens here are hand-assembled so the
// fixture signer adds nothing the server does not send.

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// serverShapedJWS signs claims under exactly the given protected header.
func serverShapedJWS(t *testing.T, priv ed25519.PrivateKey, header string, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	signingInput := enc([]byte(header)) + "." + enc(payload)
	return signingInput + "." + enc(ed25519.Sign(priv, []byte(signingInput)))
}

// twoKeyLogoutServer publishes two keys, the signing key NOT first, so a
// verifier that took "the first key" or "the only key" would fail.
func twoKeyLogoutServer(t *testing.T) *oidcTestServer {
	t.Helper()
	srv := newOidcTestServer(t)
	_, other := generateOidcTestKey(t, "previous-kid")
	srv.JWKSKeys = append(srv.JWKSKeys, other, srv.Pub)
	return srv
}

func TestVerifyLogoutToken_880_ServerShapedTokenAgainstATwoKeyJWKS(t *testing.T) {
	srv := twoKeyLogoutServer(t)
	header := `{"alg":"EdDSA","typ":"logout+jwt","kid":"` + srv.Kid + `"}`
	token := serverShapedJWS(t, srv.Priv, header, logoutClaims(srv, nil))

	verified, err := newLogoutClient(t, srv).VerifyLogoutToken(context.Background(), token, nil)
	if err != nil {
		t.Fatalf("a server-shaped 1.69 logout token must verify: %v", err)
	}
	if verified.SID != testLogoutSID || verified.JTI != testLogoutJTI {
		t.Fatalf("got %+v", verified)
	}
}

func TestVerifyLogoutToken_880_KidlessTokenIsUnknownKid(t *testing.T) {
	srv := twoKeyLogoutServer(t)
	// The pre-1.69 header: no kid. No single-key fallback, no trying each key.
	token := serverShapedJWS(t, srv.Priv, `{"alg":"EdDSA","typ":"logout+jwt"}`, logoutClaims(srv, nil))
	_, err := newLogoutClient(t, srv).VerifyLogoutToken(context.Background(), token, nil)
	var authErr *AuthError
	if !errors.As(err, &authErr) || authErr.Reason != string(ReasonUnknownKid) {
		t.Fatalf("a kid-less logout token must be refused as %q, got %v", ReasonUnknownKid, err)
	}

	// Also against a one-key JWKS, where a fallback would be tempting.
	one := newOidcTestServer(t)
	token = serverShapedJWS(t, one.Priv, `{"alg":"EdDSA","typ":"logout+jwt"}`, logoutClaims(one, nil))
	if _, err := newLogoutClient(t, one).VerifyLogoutToken(context.Background(), token, nil); !errors.As(err, &authErr) || authErr.Reason != string(ReasonUnknownKid) {
		t.Fatalf("a kid-less logout token must be refused as %q against a one-key JWKS too, got %v", ReasonUnknownKid, err)
	}
}

// §10.1 rules 10 and 11 stay off the logout-token and ID-token paths: the
// logout token's typ is logout+jwt, and a `purpose` claim refuses only an
// access token.
func TestVerifyLogoutAndIDToken_880_AccessTokenRulesTenAndElevenStayOff(t *testing.T) {
	srv := twoKeyLogoutServer(t)
	client := newLogoutClient(t, srv)

	withPurpose := logoutClaims(srv, map[string]any{"purpose": "mfa_challenge"})
	token := serverShapedJWS(t, srv.Priv, `{"alg":"EdDSA","typ":"logout+jwt","kid":"`+srv.Kid+`"}`, withPurpose)
	if _, err := client.VerifyLogoutToken(context.Background(), token, nil); err != nil {
		t.Fatalf("rule 11 must not apply on the logout path: %v", err)
	}

	now := time.Now().Unix()
	idClaims := map[string]any{
		"iss": srv.URL, "aud": testRPClient, "sub": "user-1",
		"iat": now, "exp": now + 300, "nonce": "n-1", "purpose": "anything",
	}
	exp := idTokenExpectations{issuer: srv.URL, clientID: testRPClient, nonce: "n-1", hasNonce: true}
	for _, typ := range []string{"JWT", "logout+jwt"} {
		id := serverShapedJWS(t, srv.Priv, `{"alg":"EdDSA","typ":"`+typ+`","kid":"`+srv.Kid+`"}`, idClaims)
		if _, err := client.verifyIDToken(context.Background(), srv.URL+"/oauth2/jwks", id, exp); err != nil {
			t.Fatalf("rules 10 and 11 must not apply on the ID-token path (typ %q, purpose present): %v", typ, err)
		}
	}
}
