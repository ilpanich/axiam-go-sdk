package axiam

// RP-initiated and back-channel logout — CONTRACT.md §12.7.
//
// The §12.7.6 required tests. The VerifyLogoutToken half carries the security
// weight: its input arrives unsolicited, from the network, and instructs the
// RP to terminate a session — so each rejection test names the attack it
// prevents rather than merely asserting an error.

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"
)

const (
	testLogoutSID = "session-abc"
	testLogoutJTI = "logout-token-jti-1"
	testIDToken   = "the-users-id-token"
	testRPClient  = "my-app"
)

// logoutClaims builds a VALID back-channel logout claim set for srv;
// overrides break exactly one §12.7.3 rule per negative test. A nil value
// deletes the claim entirely.
func logoutClaims(srv *oidcTestServer, overrides map[string]any) map[string]any {
	now := time.Now().Unix()
	claims := map[string]any{
		"iss": srv.URL,
		"aud": testRPClient,
		"iat": now,
		"exp": now + 120,
		"jti": testLogoutJTI,
		"sid": testLogoutSID,
		"sub": "user-1",
		"events": map[string]any{
			"http://schemas.openid.net/event/backchannel-logout": map[string]any{},
		},
	}
	for k, v := range overrides {
		if v == nil {
			delete(claims, k)
			continue
		}
		claims[k] = v
	}
	return claims
}

func newLogoutClient(t *testing.T, srv *oidcTestServer) *Client {
	t.Helper()
	client, err := NewClient(srv.URL, "acme", WithOidcClientID(testRPClient))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return client
}

func logoutQuery(t *testing.T, raw string) url.Values {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse logout URL: %v", err)
	}
	return u.Query()
}

// ---------------------------------------------------------------------------
// §12.7.2 LogoutURL
// ---------------------------------------------------------------------------

func TestLogoutURLUsesTheDiscoveredEndpoint(t *testing.T) {
	srv := newOidcTestServer(t)

	raw, err := newLogoutClient(t, srv).LogoutURL(context.Background(), LogoutURLParams{
		IDToken: Sensitive(testIDToken),
	})
	if err != nil {
		t.Fatalf("LogoutURL: %v", err)
	}

	// §12.7.2 rule 1: the endpoint comes from discovery. Code that builds
	// "{issuer}/oauth2/end_session" works against AXIAM and breaks against
	// every other OP the same application is pointed at.
	if !strings.HasPrefix(raw, srv.URL+"/oauth2/end_session") {
		t.Errorf("logout URL: got %q", raw)
	}
	if got := logoutQuery(t, raw).Get("id_token_hint"); got != testIDToken {
		t.Errorf("id_token_hint: got %q", got)
	}
}

func TestLogoutURLOmitsWhatWasNotSupplied(t *testing.T) {
	srv := newOidcTestServer(t)
	client := newLogoutClient(t, srv)

	bare, err := client.LogoutURL(context.Background(), LogoutURLParams{IDToken: Sensitive(testIDToken)})
	if err != nil {
		t.Fatalf("LogoutURL: %v", err)
	}
	q := logoutQuery(t, bare)
	if q.Has("post_logout_redirect_uri") || q.Has("state") {
		t.Error("§12.1: absent optional fields are omitted, never sent empty")
	}

	full, err := client.LogoutURL(context.Background(), LogoutURLParams{
		IDToken:               Sensitive(testIDToken),
		PostLogoutRedirectURI: "https://app.example.com/bye",
		State:                 "caller-generated-state",
	})
	if err != nil {
		t.Fatalf("LogoutURL: %v", err)
	}
	q = logoutQuery(t, full)
	if got := q.Get("post_logout_redirect_uri"); got != "https://app.example.com/bye" {
		t.Errorf("post_logout_redirect_uri: got %q", got)
	}
	// §12.7.2 rule 2: passed through unmodified — the SDK never invents one,
	// because the value only means something to the caller.
	if got := q.Get("state"); got != "caller-generated-state" {
		t.Errorf("state: got %q", got)
	}
}

func TestLogoutURLDoesNotPreValidateTheRedirect(t *testing.T) {
	srv := newOidcTestServer(t)

	// §12.7.2 rule 3: the allow-list lives in the client's server-side
	// registration. A client-side copy would drift and reject a URI an
	// operator had just registered, so an arbitrary URI must pass through.
	raw, err := newLogoutClient(t, srv).LogoutURL(context.Background(), LogoutURLParams{
		IDToken:               Sensitive(testIDToken),
		PostLogoutRedirectURI: "https://somewhere-else.example/x",
	})
	if err != nil {
		t.Fatalf("LogoutURL: %v", err)
	}
	if got := logoutQuery(t, raw).Get("post_logout_redirect_uri"); got != "https://somewhere-else.example/x" {
		t.Errorf("redirect was altered or rejected: %q", got)
	}
}

func TestLogoutURLErrorsWhenNoEndSessionEndpoint(t *testing.T) {
	srv := newOidcTestServer(t)
	srv.DiscoveryDoc = discoveryDocWithoutOptionalEndpoints

	_, err := newLogoutClient(t, srv).LogoutURL(context.Background(), LogoutURLParams{
		IDToken: Sensitive("super-secret-id-token"),
	})
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("want *AuthError, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "end_session_endpoint") {
		t.Errorf("error should name the missing endpoint: %q", err.Error())
	}
	if strings.Contains(err.Error(), "super-secret-id-token") {
		t.Error("the ID token must never appear in an error")
	}
}

// ---------------------------------------------------------------------------
// §12.7.3 VerifyLogoutToken
// ---------------------------------------------------------------------------

func TestVerifyLogoutTokenSurfacesSidSubAndJti(t *testing.T) {
	srv := newOidcTestServer(t)
	token := signIDTokenEdDSA(t, srv.Priv, srv.Kid, logoutClaims(srv, nil))

	verified, err := newLogoutClient(t, srv).VerifyLogoutToken(context.Background(), token, nil)
	if err != nil {
		t.Fatalf("VerifyLogoutToken: %v", err)
	}

	// Not a bare bool: the RP has to know WHICH session to end, and a verifier
	// that only says "valid" forces the caller to re-parse the token
	// themselves with none of these checks.
	if verified.SID != testLogoutSID {
		t.Errorf("SID: got %q", verified.SID)
	}
	if verified.Sub != "user-1" {
		t.Errorf("Sub: got %q", verified.Sub)
	}
	if verified.JTI != testLogoutJTI {
		t.Errorf("JTI: got %q", verified.JTI)
	}
}

func TestVerifyLogoutTokenRejectsAnIDTokenReplayedAsOne(t *testing.T) {
	// The attack rules 3 and 4 exist to stop, asserted with a real,
	// otherwise-valid ID token rather than a synthetic mutation: correctly
	// signed by a published key, right issuer and audience, unexpired. Only
	// the missing `events` and the present `nonce` distinguish it.
	srv := newOidcTestServer(t)
	now := time.Now().Unix()
	idToken := signIDTokenEdDSA(t, srv.Priv, srv.Kid, map[string]any{
		"iss":   srv.URL,
		"aud":   testRPClient,
		"sub":   "user-1",
		"iat":   now,
		"exp":   now + 300,
		"nonce": "the-request-nonce",
	})

	_, err := newLogoutClient(t, srv).VerifyLogoutToken(context.Background(), idToken, nil)
	if err == nil {
		t.Fatal("an ID token must never verify as a logout token")
	}
}

func TestVerifyLogoutTokenRejectionCases(t *testing.T) {
	now := time.Now().Unix()
	cases := []struct {
		name      string
		overrides map[string]any
		wantMatch string
		// attack names why the check exists.
		attack string
	}{
		{
			name:      "no events",
			overrides: map[string]any{"events": nil},
			wantMatch: "events",
			attack:    "without this check the whole method accepts a replayed ID token",
		},
		{
			name: "some other event",
			overrides: map[string]any{"events": map[string]any{
				"http://schemas.openid.net/event/some-other-thing": map[string]any{},
			}},
			wantMatch: "events",
			attack:    "a near-miss token must not pass on a technicality",
		},
		{
			name:      "nonce present",
			overrides: map[string]any{"nonce": "n-0S6_WzA2Mj"},
			wantMatch: "nonce",
			attack:    "Back-Channel Logout 1.0 §2.4 forbids it; presence is the ID-token-replay signature",
		},
		{
			name:      "empty nonce still rejected",
			overrides: map[string]any{"nonce": ""},
			wantMatch: "nonce",
			attack:    "an empty nonce is still a nonce — absence is what the spec requires",
		},
		{
			name:      "names neither sid nor sub",
			overrides: map[string]any{"sid": nil, "sub": nil},
			wantMatch: "identifies no session",
			attack:    "a token naming nothing cannot end anything",
		},
		{
			name:      "another client's audience",
			overrides: map[string]any{"aud": "some-other-rp"},
			wantMatch: "audience",
			attack:    "a token minted for another RP is not an instruction to this one",
		},
		{
			name:      "another issuer",
			overrides: map[string]any{"iss": "https://evil.example.com"},
			wantMatch: "issuer",
			attack:    "anyone can mint a token; only the configured OP's counts",
		},
		{
			name:      "expired",
			overrides: map[string]any{"exp": now - 600, "iat": now - 700},
			wantMatch: "expired",
			attack:    "a long-lived logout token is a replayable session-termination command",
		},
		{
			name:      "stale but unexpired",
			overrides: map[string]any{"iat": now - 86_400, "exp": now + 600},
			wantMatch: "too old",
			attack:    "a captured delivery replayed a day later is not a live one",
		},
		{
			name:      "no jti",
			overrides: map[string]any{"jti": nil},
			wantMatch: "jti",
			attack:    "without jti the RP cannot dedup at-least-once redeliveries",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newOidcTestServer(t)
			token := signIDTokenEdDSA(t, srv.Priv, srv.Kid, logoutClaims(srv, tc.overrides))

			_, err := newLogoutClient(t, srv).VerifyLogoutToken(context.Background(), token, nil)
			if err == nil {
				t.Fatalf("must be rejected — %s", tc.attack)
			}
			if !strings.Contains(err.Error(), tc.wantMatch) {
				t.Errorf("error %q should mention %q", err.Error(), tc.wantMatch)
			}
		})
	}
}

func TestVerifyLogoutTokenAcceptsSubOnlyButPrefersSid(t *testing.T) {
	srv := newOidcTestServer(t)
	client := newLogoutClient(t, srv)

	subOnly := signIDTokenEdDSA(t, srv.Priv, srv.Kid, logoutClaims(srv, map[string]any{"sid": nil}))
	verified, err := client.VerifyLogoutToken(context.Background(), subOnly, nil)
	if err != nil {
		t.Fatalf("a sub-only logout token is valid: %v", err)
	}
	if verified.SID != "" || verified.Sub != "user-1" {
		t.Errorf("got SID=%q Sub=%q", verified.SID, verified.Sub)
	}

	// With sid present the RP must end THAT session only — falling back to
	// "every session for sub" is over-reach the server itself refuses.
	both, err := client.VerifyLogoutToken(context.Background(), signIDTokenEdDSA(t, srv.Priv, srv.Kid, logoutClaims(srv, nil)), nil)
	if err != nil {
		t.Fatalf("VerifyLogoutToken: %v", err)
	}
	if both.SID != testLogoutSID {
		t.Errorf("SID: got %q", both.SID)
	}
}

func TestVerifyLogoutTokenRejectsAnUnpublishedKeyAndWrongAlg(t *testing.T) {
	srv := newOidcTestServer(t)
	client := newLogoutClient(t, srv)

	// The signature is what makes the token a statement rather than a request.
	_, rogueKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	rogue := signIDTokenEdDSA(t, rogueKey, srv.Kid, logoutClaims(srv, nil))
	if _, err := client.VerifyLogoutToken(context.Background(), rogue, nil); err == nil {
		t.Error("a token signed by an unpublished key must be rejected")
	}

	// §12.4 rule 1 discipline is shared: the JWKS verifier pins EdDSA before
	// any key lookup, so HS256 and "none" cannot even reach it.
	hs256 := signIDTokenHS256(t, logoutClaims(srv, nil))
	if _, err := client.VerifyLogoutToken(context.Background(), hs256, nil); err == nil {
		t.Error("a non-EdDSA logout token must be rejected")
	}
	none := signIDTokenNone(t, logoutClaims(srv, nil))
	if _, err := client.VerifyLogoutToken(context.Background(), none, nil); err == nil {
		t.Error("an alg:none logout token must be rejected")
	}
}

func TestVerifyLogoutTokenAcceptsARedelivery(t *testing.T) {
	// §12.7.3 rule 7. Delivery is at-least-once with retry, so a valid token
	// legitimately arrives twice — that is a retry, not an attack. An SDK that
	// dedupped internally would have no durable store and would silently drop
	// a real second logout after a restart, so JTI is surfaced for the RP to
	// dedup on and never consumed here.
	srv := newOidcTestServer(t)
	client := newLogoutClient(t, srv)
	token := signIDTokenEdDSA(t, srv.Priv, srv.Kid, logoutClaims(srv, nil))

	first, err := client.VerifyLogoutToken(context.Background(), token, nil)
	if err != nil {
		t.Fatalf("first delivery: %v", err)
	}
	second, err := client.VerifyLogoutToken(context.Background(), token, nil)
	if err != nil {
		t.Fatalf("§12.7.3 rule 7: a redelivery must still verify: %v", err)
	}
	if first != second {
		t.Errorf("redelivery produced a different result: %+v vs %+v", first, second)
	}
}

func TestVerifyLogoutTokenNeverEchoesTheToken(t *testing.T) {
	srv := newOidcTestServer(t)
	_, rogueKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	token := signIDTokenEdDSA(t, rogueKey, srv.Kid, logoutClaims(srv, nil))

	_, verifyErr := newLogoutClient(t, srv).VerifyLogoutToken(context.Background(), token, nil)
	if verifyErr == nil {
		t.Fatal("want an error")
	}
	if strings.Contains(verifyErr.Error(), token) {
		t.Error("an unverifiable logout token is exactly what a naive implementation logs")
	}
}
