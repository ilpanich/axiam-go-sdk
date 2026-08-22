package axiam

// §24 WebAuthn relying-party layer — the CONTRACT.md §24.8 test set.
//
// Every assertion maps to a named requirement in §24.8. Two are worth reading
// twice:
//
//   - TestWebauthnRegisterStartDoesNotRetry503 asserts on the REQUEST COUNT,
//     not the error type, because §24.4 rule 2 regresses the moment someone
//     tidies a retry predicate — and a type assertion would still pass.
//
//   - TestWebauthnStateTokenIsNeverParsed hands the SDK a state token that is
//     not a JWT at all. If anything decoded one, this is where it would fail.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

const (
	waStateToken     = "state-token-fixture-value-do-not-log"
	waChallengeToken = "challenge-token-fixture-do-not-log"
	waAccessToken    = "access-token-fixture-do-not-log"
	waRefreshToken   = "refresh-token-fixture-do-not-log"
	waOrgUUID        = "44444444-4444-4444-4444-444444444444"
)

// creationChallengeJSON is deliberately "unusual but valid": every optional
// field populated, so the pass-through assertion has something to catch an
// over-eager implementation dropping. A minimal fixture would prove nothing.
const creationChallengeJSON = `{
  "publicKey": {
    "challenge": "Y2hhbGxlbmdlLWJ5dGVz",
    "rp": {"id": "axiam.test", "name": "AXIAM Test"},
    "user": {"id": "dXNlci1oYW5kbGU", "name": "alice", "displayName": "Alice"},
    "pubKeyCredParams": [
      {"type": "public-key", "alg": -7},
      {"type": "public-key", "alg": -8},
      {"type": "public-key", "alg": -257}
    ],
    "timeout": 60000,
    "excludeCredentials": [
      {"id": "ZXhpc3Rpbmc", "type": "public-key", "transports": ["usb", "nfc"]}
    ],
    "authenticatorSelection": {
      "residentKey": "required",
      "requireResidentKey": true,
      "userVerification": "required"
    },
    "attestation": "direct",
    "extensions": {"credProps": true}
  }
}`

const minimalCreationChallengeJSON = `{
  "publicKey": {
    "challenge": "bWluaW1hbA",
    "rp": {"name": "AXIAM Test"},
    "user": {"id": "dQ", "name": "bob", "displayName": "Bob"},
    "pubKeyCredParams": [{"type": "public-key", "alg": -7}]
  }
}`

const discoverableChallengeJSON = `{
  "publicKey": {
    "challenge": "ZGlzY292ZXJhYmxl",
    "rpId": "axiam.test",
    "allowCredentials": [],
    "userVerification": "required"
  }
}`

// registrationResponseJSON carries an unknown key the SDK must forward rather
// than strip — the shape a platform actually produces, not a curated subset.
const registrationResponseJSON = `{
  "id": "bmV3LWNyZWQ",
  "rawId": "bmV3LWNyZWQ",
  "response": {
    "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0",
    "attestationObject": "o2NmbXRkbm9uZQ",
    "transports": ["internal"],
    "vendorSpecific": "must-survive"
  },
  "type": "public-key",
  "clientExtensionResults": {"credProps": {"rk": true}}
}`

const authenticationResponseJSON = `{
  "id": "bmV3LWNyZWQ",
  "rawId": "bmV3LWNyZWQ",
  "response": {
    "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0",
    "authenticatorData": "YXV0aC1kYXRh",
    "signature": "c2ln",
    "userHandle": "dXNlci1oYW5kbGU"
  },
  "type": "public-key",
  "clientExtensionResults": {}
}`

// waCapture records what each handler was asked, so a test can assert on the
// bytes that actually went out.
type waCapture struct {
	bodies map[string]json.RawMessage
	hits   map[string]*int32
}

func newWaCapture() *waCapture {
	return &waCapture{bodies: map[string]json.RawMessage{}, hits: map[string]*int32{}}
}

func (c *waCapture) count(path string) int32 {
	if n, ok := c.hits[path]; ok {
		return atomic.LoadInt32(n)
	}
	return 0
}

func (c *waCapture) record(path string, body json.RawMessage) {
	if _, ok := c.hits[path]; !ok {
		var n int32
		c.hits[path] = &n
	}
	atomic.AddInt32(c.hits[path], 1)
	if body != nil {
		c.bodies[path] = body
	}
}

// waServer stands up the six endpoints, with per-path overrides.
func waServer(t *testing.T, overrides map[string]http.HandlerFunc) (*httptest.Server, *waCapture) {
	t.Helper()
	capture := newWaCapture()
	token := makeAccessTokenWithOrgID(t, waOrgUUID)

	loginBody := func(w http.ResponseWriter) {
		http.SetCookie(w, &http.Cookie{Name: "axiam_access", Value: token, Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: "axiam_refresh", Value: "refresh-cookie", Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: "axiam_csrf", Value: "csrf-tok", Path: "/"})
		w.Header().Set("X-CSRF-Token", "csrf-tok")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  waAccessToken,
			"refresh_token": waRefreshToken,
			"session_id":    "33333333-3333-3333-3333-333333333333",
			"expires_in":    900,
		})
	}

	defaults := map[string]http.HandlerFunc{
		webauthnRegisterStartPath: func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"challenge":` + creationChallengeJSON + `,"state_token":"` + waStateToken + `"}`))
		},
		webauthnRegisterFinishPath: func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":              "11111111-1111-1111-1111-111111111111",
				"credential_id":   "bmV3LWNyZWQ",
				"name":            "Alice's laptop",
				"credential_type": "passkey",
				"created_at":      "2026-08-22T10:00:00Z",
			})
		},
		webauthnAuthStartPath: func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"challenge":` + discoverableChallengeJSON + `,"state_token":"` + waStateToken + `"}`))
		},
		webauthnAuthFinishPath: func(w http.ResponseWriter, r *http.Request) { loginBody(w) },
		webauthnDiscoverableStartPath: func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"challenge":` + discoverableChallengeJSON + `,"state_token":"` + waStateToken + `"}`))
		},
		webauthnDiscoverableFinishPath: func(w http.ResponseWriter, r *http.Request) { loginBody(w) },
	}
	for path, handler := range overrides {
		defaults[path] = handler
	}

	mux := http.NewServeMux()
	for path, handler := range defaults {
		p, h := path, handler
		mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) {
			var body json.RawMessage
			if r.Body != nil {
				buf := make([]byte, r.ContentLength)
				if r.ContentLength > 0 {
					_, _ = r.Body.Read(buf)
					body = json.RawMessage(buf)
				}
			}
			capture.record(p, body)
			h(w, r)
		})
	}
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server, capture
}

func waClient(t *testing.T, server *httptest.Server, opts ...Option) *Client {
	t.Helper()
	opts = append([]Option{WithOrgSlug("globex")}, opts...)
	client, err := NewClient(server.URL, "acme", opts...)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return client
}

// waSignedIn seeds the access cookie — what the SDK reads as "signed in" (§24.1).
func waSignedIn(t *testing.T, client *Client, server *httptest.Server) *Client {
	t.Helper()
	u := client.baseURL
	client.httpc.Jar.SetCookies(u, []*http.Cookie{
		{Name: "axiam_access", Value: makeAccessTokenWithOrgID(t, waOrgUUID), Path: "/"},
	})
	return client
}

func waBody(t *testing.T, capture *waCapture, path string) map[string]any {
	t.Helper()
	raw, ok := capture.bodies[path]
	if !ok {
		t.Fatalf("no request captured for %s", path)
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("captured body for %s is not JSON: %v (%s)", path, err, raw)
	}
	return body
}

// ---------------------------------------------------------------------------
// §24.0 — options and responses pass through untouched
// ---------------------------------------------------------------------------

func TestWebauthnOptionsPassThroughUnchanged(t *testing.T) {
	server, _ := waServer(t, nil)
	client := waSignedIn(t, waClient(t, server), server)

	challenge, err := client.WebauthnRegisterStart(context.Background())
	if err != nil {
		t.Fatalf("WebauthnRegisterStart: %v", err)
	}

	// Structural equality, not a spot-check of three fields: the failure mode
	// this guards is an SDK that quietly drops the one option it did not
	// recognize.
	var got, want any
	if err := json.Unmarshal(challenge.Challenge, &got); err != nil {
		t.Fatalf("challenge is not JSON: %v", err)
	}
	if err := json.Unmarshal([]byte(creationChallengeJSON), &want); err != nil {
		t.Fatalf("fixture is not JSON: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("challenge was modified in transit:\n got %#v\nwant %#v", got, want)
	}
}

func TestWebauthnSynthesizesNoOmittedField(t *testing.T) {
	server, _ := waServer(t, map[string]http.HandlerFunc{
		webauthnRegisterStartPath: func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"challenge":` + minimalCreationChallengeJSON + `,"state_token":"` + waStateToken + `"}`))
		},
	})
	client := waSignedIn(t, waClient(t, server), server)

	challenge, err := client.WebauthnRegisterStart(context.Background())
	if err != nil {
		t.Fatalf("WebauthnRegisterStart: %v", err)
	}
	requestJSON, err := challenge.RequestJSON()
	if err != nil {
		t.Fatalf("RequestJSON: %v", err)
	}
	var options map[string]any
	if err := json.Unmarshal([]byte(requestJSON), &options); err != nil {
		t.Fatalf("request JSON is not an object: %v", err)
	}
	for _, key := range []string{"authenticatorSelection", "timeout", "excludeCredentials", "attestation"} {
		if _, present := options[key]; present {
			t.Fatalf("SDK synthesized %q, which the server omitted", key)
		}
	}
}

func TestWebauthnResponseIsSentBackVerbatim(t *testing.T) {
	server, capture := waServer(t, nil)
	client := waSignedIn(t, waClient(t, server), server)

	if _, err := client.WebauthnRegisterFinish(
		context.Background(), waStateToken, "laptop", json.RawMessage(registrationResponseJSON),
	); err != nil {
		t.Fatalf("WebauthnRegisterFinish: %v", err)
	}

	sent := waBody(t, capture, webauthnRegisterFinishPath)["response"]
	var want any
	if err := json.Unmarshal([]byte(registrationResponseJSON), &want); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	if !reflect.DeepEqual(sent, want) {
		t.Fatalf("authenticator response was modified:\n got %#v\nwant %#v", sent, want)
	}
}

// ---------------------------------------------------------------------------
// §24.1 — preconditions and workspace resolution
// ---------------------------------------------------------------------------

func TestWebauthnRegisterRequiresASessionWithNoWireCall(t *testing.T) {
	server, capture := waServer(t, nil)
	client := waClient(t, server)

	if _, err := client.WebauthnRegisterStart(context.Background()); err == nil {
		t.Fatal("expected an error with no session")
	} else {
		var authErr *AuthError
		if !errors.As(err, &authErr) {
			t.Fatalf("expected *AuthError, got %T", err)
		}
	}
	// Asserted on the transport, not on the error type alone.
	if n := capture.count(webauthnRegisterStartPath); n != 0 {
		t.Fatalf("expected 0 requests, got %d", n)
	}

	if _, err := client.WebauthnRegisterFinish(
		context.Background(), waStateToken, "x", json.RawMessage(registrationResponseJSON),
	); err == nil {
		t.Fatal("expected an error with no session")
	}
	if n := capture.count(webauthnRegisterFinishPath); n != 0 {
		t.Fatalf("expected 0 requests, got %d", n)
	}
}

func TestWebauthnDiscoverableWorkspaceComesFromTheClient(t *testing.T) {
	server, capture := waServer(t, nil)
	client := waClient(t, server)

	if _, err := client.WebauthnDiscoverableStart(context.Background(), nil); err != nil {
		t.Fatalf("WebauthnDiscoverableStart: %v", err)
	}
	body := waBody(t, capture, webauthnDiscoverableStartPath)
	if body["org_slug"] != "globex" || body["tenant_slug"] != "acme" {
		t.Fatalf("workspace not filled from the client: %#v", body)
	}
	if _, present := body["challenge_token"]; present {
		// §24.2: a discoverable ceremony has no prior step to have minted one.
		t.Fatal("discoverable start must not carry a challenge_token")
	}
}

func TestWebauthnDiscoverableWorkspaceCanBeOverridden(t *testing.T) {
	server, capture := waServer(t, nil)
	client := waClient(t, server)

	_, err := client.WebauthnDiscoverableStart(context.Background(), &WebauthnWorkspace{
		OrgID:      "33333333-3333-3333-3333-333333333333",
		TenantSlug: "other",
	})
	if err != nil {
		t.Fatalf("WebauthnDiscoverableStart: %v", err)
	}
	body := waBody(t, capture, webauthnDiscoverableStartPath)
	if body["org_id"] != "33333333-3333-3333-3333-333333333333" || body["tenant_slug"] != "other" {
		t.Fatalf("override ignored: %#v", body)
	}
}

func TestWebauthnDiscoverableWithoutAnOrgRaisesClientSide(t *testing.T) {
	server, capture := waServer(t, nil)
	client, err := NewClient(server.URL, "acme")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.WebauthnDiscoverableStart(context.Background(), nil); err == nil {
		t.Fatal("expected an error with no organization")
	} else if !strings.Contains(err.Error(), "organization") {
		t.Fatalf("error should name the missing organization: %v", err)
	}
	if n := capture.count(webauthnDiscoverableStartPath); n != 0 {
		t.Fatalf("expected 0 requests, got %d", n)
	}
}

// ---------------------------------------------------------------------------
// §24.2 — two distinct flows
// ---------------------------------------------------------------------------

func TestWebauthnSecondFactorStartSendsOnlyTheChallengeToken(t *testing.T) {
	server, capture := waServer(t, nil)
	client := waClient(t, server)

	if _, err := client.WebauthnAuthenticateStart(context.Background(), waChallengeToken); err != nil {
		t.Fatalf("WebauthnAuthenticateStart: %v", err)
	}
	body := waBody(t, capture, webauthnAuthStartPath)
	if len(body) != 1 || body["challenge_token"] != waChallengeToken {
		t.Fatalf("unexpected body: %#v", body)
	}
}

func TestWebauthnDiscoverableFinishReachesItsOwnEndpoint(t *testing.T) {
	server, capture := waServer(t, nil)
	client := waClient(t, server)

	if _, err := client.WebauthnDiscoverableFinish(
		context.Background(), waStateToken, json.RawMessage(authenticationResponseJSON),
	); err != nil {
		t.Fatalf("WebauthnDiscoverableFinish: %v", err)
	}
	if capture.count(webauthnDiscoverableFinishPath) != 1 {
		t.Fatal("discoverable finish was not called")
	}
	if capture.count(webauthnAuthFinishPath) != 0 {
		t.Fatal("the username-bound endpoint must not be reached")
	}
}

// ---------------------------------------------------------------------------
// §24.3 — credential adoption
// ---------------------------------------------------------------------------

func TestWebauthnSignInAdoptsTheSession(t *testing.T) {
	server, _ := waServer(t, nil)
	client := waClient(t, server)

	if client.cookieValue(accessCookie) != "" {
		t.Fatal("client should start unauthenticated")
	}

	result, err := client.WebauthnAuthenticateFinish(
		context.Background(), waStateToken, json.RawMessage(authenticationResponseJSON),
	)
	if err != nil {
		t.Fatalf("WebauthnAuthenticateFinish: %v", err)
	}

	// The client's own state — not merely that a token came back. §24.3 rule 1
	// exists because returning a token set without adopting it would make this
	// the one way to log in that does not log you in.
	if client.cookieValue(accessCookie) == "" {
		t.Fatal("the session was not adopted")
	}
	if result.AccessToken.expose() != waAccessToken {
		t.Fatalf("access token: got %q", result.AccessToken.expose())
	}
	if result.RefreshToken.expose() != waRefreshToken {
		t.Fatalf("refresh token: got %q", result.RefreshToken.expose())
	}
	if result.ExpiresIn != 900 {
		t.Fatalf("expires_in: got %d", result.ExpiresIn)
	}
}

func TestWebauthnRegisterFinishReturnsTheCredential(t *testing.T) {
	server, _ := waServer(t, nil)
	client := waSignedIn(t, waClient(t, server), server)

	credential, err := client.WebauthnRegisterFinish(
		context.Background(), waStateToken, "Alice's laptop", json.RawMessage(registrationResponseJSON),
	)
	if err != nil {
		t.Fatalf("WebauthnRegisterFinish: %v", err)
	}
	if credential.CredentialID != "bmV3LWNyZWQ" || credential.CredentialType != "passkey" {
		t.Fatalf("unexpected credential: %#v", credential)
	}
	if credential.LastUsedAt != "" {
		t.Fatalf("a never-used credential should have no LastUsedAt: %q", credential.LastUsedAt)
	}
}

// ---------------------------------------------------------------------------
// §24.4 — error taxonomy
// ---------------------------------------------------------------------------

func TestWebauthnRegisterStartDoesNotRetry503(t *testing.T) {
	server, capture := waServer(t, map[string]http.HandlerFunc{
		webauthnRegisterStartPath: func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"message":"FIDO metadata unavailable"}`))
		},
	})
	client := waSignedIn(t, waClient(t, server), server)

	if _, err := client.WebauthnRegisterStart(context.Background()); err == nil {
		t.Fatal("expected an error on 503")
	}
	// §24.4 rule 2. Asserted on the request count: a 503 here is a server
	// CONFIGURATION state, retrying changes nothing, and this regresses
	// silently the moment the retry predicate is tidied.
	if n := capture.count(webauthnRegisterStartPath); n != 1 {
		t.Fatalf("expected exactly 1 request, got %d", n)
	}
}

func TestWebauthn403IsAnAuthorizationError(t *testing.T) {
	server, _ := waServer(t, map[string]http.HandlerFunc{
		webauthnRegisterFinishPath: func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"this security key is not FIDO certified"}`))
		},
	})
	client := waSignedIn(t, waClient(t, server), server)

	_, err := client.WebauthnRegisterFinish(
		context.Background(), waStateToken, "key", json.RawMessage(registrationResponseJSON),
	)
	var authzErr *AuthzError
	if !errors.As(err, &authzErr) {
		t.Fatalf("expected *AuthzError, got %T (%v)", err, err)
	}
	// §24.4 rule 1: the policy message is the only way the person holding the
	// key learns a different one would work.
	if !strings.Contains(err.Error(), "FIDO certified") {
		t.Fatalf("the attestation policy message was lost: %v", err)
	}
}

func TestWebauthnFailedAssertionIsAnAuthError(t *testing.T) {
	server, _ := waServer(t, map[string]http.HandlerFunc{
		webauthnAuthFinishPath: func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"message":"assertion failed"}`))
		},
	})
	client := waClient(t, server)

	_, err := client.WebauthnAuthenticateFinish(
		context.Background(), waStateToken, json.RawMessage(authenticationResponseJSON),
	)
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("expected *AuthError, got %T (%v)", err, err)
	}
}

// ---------------------------------------------------------------------------
// §24.5 — the state token is opaque, and Sensitive
// ---------------------------------------------------------------------------

func TestWebauthnStateTokenIsNeverParsed(t *testing.T) {
	server, capture := waServer(t, nil)
	client := waClient(t, server)

	// Not a JWT, not three dot-separated segments, not base64 anything. If the
	// SDK decoded state tokens at all, this would fail — which is exactly the
	// assertion §24.8 asks for.
	notAJWT := "this-is-not-a-jwt-and-never-will-be"
	if _, err := client.WebauthnAuthenticateFinish(
		context.Background(), Sensitive(notAJWT), json.RawMessage(authenticationResponseJSON),
	); err != nil {
		t.Fatalf("WebauthnAuthenticateFinish: %v", err)
	}
	if got := waBody(t, capture, webauthnAuthFinishPath)["state_token"]; got != notAJWT {
		t.Fatalf("state_token was rewritten: %v", got)
	}
}

func TestWebauthnSecretsNeverRender(t *testing.T) {
	server, _ := waServer(t, nil)
	client := waSignedIn(t, waClient(t, server), server)

	challenge, err := client.WebauthnRegisterStart(context.Background())
	if err != nil {
		t.Fatalf("WebauthnRegisterStart: %v", err)
	}
	login, err := waClient(t, server).WebauthnAuthenticateFinish(
		context.Background(), waStateToken, json.RawMessage(authenticationResponseJSON),
	)
	if err != nil {
		t.Fatalf("WebauthnAuthenticateFinish: %v", err)
	}

	rendered := []string{
		challenge.StateToken.String(),
		login.AccessToken.String(),
		login.RefreshToken.String(),
	}
	for _, format := range []string{"%v", "%+v", "%s", "%q", "%#v"} {
		rendered = append(rendered,
			fmt.Sprintf(format, challenge), fmt.Sprintf(format, login))
	}
	if marshalled, err := json.Marshal(login); err == nil {
		rendered = append(rendered, string(marshalled))
	}

	for _, secret := range []string{waStateToken, waAccessToken, waRefreshToken} {
		for _, surface := range rendered {
			if strings.Contains(surface, secret) {
				t.Fatalf("secret %q leaked into %q", secret, surface)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// §24.6a — the JSON bridge
// ---------------------------------------------------------------------------

func TestWebauthnRequestJSONRoundTrips(t *testing.T) {
	server, _ := waServer(t, nil)
	client := waSignedIn(t, waClient(t, server), server)

	challenge, err := client.WebauthnRegisterStart(context.Background())
	if err != nil {
		t.Fatalf("WebauthnRegisterStart: %v", err)
	}
	requestJSON, err := challenge.RequestJSON()
	if err != nil {
		t.Fatalf("RequestJSON: %v", err)
	}

	// The string an Android app hands to CreatePublicKeyCredentialRequest, and
	// a browser to PublicKeyCredential.parseCreationOptionsFromJSON.
	var got map[string]any
	if err := json.Unmarshal([]byte(requestJSON), &got); err != nil {
		t.Fatalf("request JSON is not an object: %v", err)
	}
	if _, present := got["publicKey"]; present {
		t.Fatal("the publicKey wrapper must not be in the platform request JSON")
	}

	var wrapper struct {
		PublicKey map[string]any `json:"publicKey"`
	}
	if err := json.Unmarshal([]byte(creationChallengeJSON), &wrapper); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	if !reflect.DeepEqual(got, wrapper.PublicKey) {
		t.Fatalf("options changed on the way through:\n got %#v\nwant %#v", got, wrapper.PublicKey)
	}
}

func TestWebauthnFinishAcceptsAPlatformResponseString(t *testing.T) {
	server, capture := waServer(t, nil)
	client := waClient(t, server)

	// A plain Go string, exactly as Android's authenticationResponseJson or a
	// browser's credential.toJSON() arrives.
	if _, err := client.WebauthnAuthenticateFinish(
		context.Background(), waStateToken, authenticationResponseJSON,
	); err != nil {
		t.Fatalf("WebauthnAuthenticateFinish: %v", err)
	}

	sent := waBody(t, capture, webauthnAuthFinishPath)["response"]
	var want any
	if err := json.Unmarshal([]byte(authenticationResponseJSON), &want); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	if !reflect.DeepEqual(sent, want) {
		t.Fatalf("the platform string was altered:\n got %#v\nwant %#v", sent, want)
	}
}

func TestWebauthnMalformedResponseStringIsRefusedBeforeAnyWireCall(t *testing.T) {
	server, capture := waServer(t, nil)
	client := waClient(t, server)

	if _, err := client.WebauthnAuthenticateFinish(
		context.Background(), waStateToken, "{not json",
	); err == nil {
		t.Fatal("expected an error on malformed response JSON")
	}
	if n := capture.count(webauthnAuthFinishPath); n != 0 {
		t.Fatalf("expected 0 requests, got %d", n)
	}
}

// ---------------------------------------------------------------------------
// §24.6b rule 5 — the classification, with no authenticator in sight
// ---------------------------------------------------------------------------

func TestClassifyWebauthnError(t *testing.T) {
	cases := map[string]WebauthnFailure{
		"NotAllowedError":    WebauthnCancelled,
		"InvalidStateError":  WebauthnAlreadyRegistered,
		"AbortError":         WebauthnTimeout,
		"NotSupportedError":  WebauthnUnsupported,
		"SecurityError":      WebauthnUnsupported,
		"SomethingElseError": WebauthnUnknown,
		// An Android CreateCredentialException or an ASAuthorizationError code
		// relayed to a Go service as a bare name (§24.6b rule 5's last line).
		"canceled": WebauthnCancelled,
		"":         WebauthnUnknown,
	}
	for name, want := range cases {
		if got := ClassifyWebauthnError(name); got != want {
			t.Fatalf("ClassifyWebauthnError(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestWebauthnAlreadyRegisteredIsDistinguishable(t *testing.T) {
	if ClassifyWebauthnError("InvalidStateError") == ClassifyWebauthnError("NotAllowedError") {
		t.Fatal("already_registered must be distinguishable from cancelled")
	}
	// The only classification whose remedy is a different device.
	if !strings.Contains(WebauthnErrorMessage(WebauthnAlreadyRegistered), "different device") {
		t.Fatal("the already_registered copy must point at a different device")
	}
	// The same name covers a silent timeout, and the spec will not say which,
	// so the copy must not accuse the user.
	if !strings.Contains(WebauthnErrorMessage(WebauthnCancelled), "cancelled or timed out") {
		t.Fatal("the cancelled copy must cover a timeout too")
	}
}
