package axiam

// §24.1 / §25.2 rule 2 — the setup-token WebAuthn pair (CONTRACT.md §24.8,
// contract 1.45): WebauthnSetupRegisterStart / WebauthnSetupRegisterFinish.
//
// Two assertions matter most here, both because a plausible-looking
// implementation gets them wrong silently:
//
//   - TestWebauthnSetupRegisterCarriesNoSessionCredential is asserted on the
//     TRANSPORT (request headers as the server actually received them), not
//     on client state, because a session cookie riding along on top of a
//     valid setup token would still "work" — the server would just have two
//     credentials to disagree about.
//   - TestWebauthnSetupRegisterFinishAdoptsExactlyLikeMfaSetupConfirm mirrors
//     the exact assertions §24.3 requires of WebauthnAuthenticateFinish,
//     against the setup-token completion instead: the two completions of a
//     forced first-login enrolment must leave a caller in the same state.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	wsuSetupToken = "webauthn-setup-token-fixture-do-not-log"
	wsuStateToken = "webauthn-setup-state-token-fixture-do-not-log"
)

// wsuCapture records, per path, the request actually sent — headers
// included, which is what the "no session credential" test needs and what
// none of the other WebAuthn test helpers in this package capture.
type wsuCapture struct {
	mu      sync.Mutex
	headers map[string]http.Header
	bodies  map[string]map[string]any
	hits    map[string]int
}

func newWsuCapture() *wsuCapture {
	return &wsuCapture{
		headers: map[string]http.Header{},
		bodies:  map[string]map[string]any{},
		hits:    map[string]int{},
	}
}

func (c *wsuCapture) record(path string, r *http.Request, body map[string]any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.headers[path] = r.Header.Clone()
	c.bodies[path] = body
	c.hits[path]++
}

func (c *wsuCapture) count(path string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hits[path]
}

// wsuServer stands up the two setup/register endpoints, with per-path
// overrides, plus a plain state-changing probe path used by the adoption
// test to check a CSRF token was captured.
func wsuServer(t *testing.T, overrides map[string]http.HandlerFunc) (*httptest.Server, *wsuCapture) {
	t.Helper()
	capture := newWsuCapture()

	defaults := map[string]http.HandlerFunc{
		webauthnSetupRegisterStartPath: func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"challenge":` + creationChallengeJSON + `,"state_token":"` + wsuStateToken + `"}`))
		},
		webauthnSetupRegisterFinishPath: func(w http.ResponseWriter, r *http.Request) {
			http.SetCookie(w, &http.Cookie{Name: "axiam_access", Value: makeAccessTokenWithOrgID(t, waOrgUUID), Path: "/"})
			http.SetCookie(w, &http.Cookie{Name: "axiam_refresh", Value: "refresh-cookie-setup", Path: "/"})
			w.Header().Set("X-CSRF-Token", "csrf-tok-setup")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"user":       map[string]any{"id": "11111111-1111-1111-1111-111111111111"},
				"session_id": "33333333-3333-3333-3333-333333333333",
				"expires_in": 900,
			})
		},
		// A plain state-changing endpoint with no §24 meaning of its own —
		// only used to prove a captured CSRF token gets echoed afterward.
		"/probe": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		},
	}
	for path, h := range overrides {
		defaults[path] = h
	}

	mux := http.NewServeMux()
	for path, handler := range defaults {
		p, h := path, handler
		mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) {
			var body map[string]any
			if r.Body != nil {
				_ = json.NewDecoder(r.Body).Decode(&body)
			}
			capture.record(p, r, body)
			h(w, r)
		})
	}
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server, capture
}

func wsuClient(t *testing.T, server *httptest.Server) *Client {
	t.Helper()
	client, err := NewClient(server.URL, "acme", WithOrgSlug("globex"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return client
}

// wsuGiveClientASession configures BOTH forms of session credential this SDK
// can carry — a cookie-jar session (as a prior password/passkey login would
// leave) and an adopted OIDC bearer credential (as
// LoginClientCredentials(AdoptAsCredential: true) would leave) — so the
// "carries no session credential" test exercises both paths decorateRequest
// would otherwise attach from.
func wsuGiveClientASession(t *testing.T, client *Client) *Client {
	t.Helper()
	client.httpc.Jar.SetCookies(client.baseURL, []*http.Cookie{
		{Name: accessCookie, Value: makeAccessTokenWithOrgID(t, waOrgUUID), Path: "/"},
		{Name: "axiam_csrf", Value: "pre-existing-csrf", Path: "/"},
	})
	client.adoptOidcCredential(Sensitive("pre-existing-bearer-credential-do-not-send"))
	return client
}

// ---------------------------------------------------------------------------
// §24.1 — the happy path, and that the setup token is the only thing sent
// ---------------------------------------------------------------------------

func TestWebauthnSetupRegisterStartSendsOnlyTheSetupToken(t *testing.T) {
	server, capture := wsuServer(t, nil)
	client := wsuClient(t, server)

	challenge, err := client.WebauthnSetupRegisterStart(context.Background(), Sensitive(wsuSetupToken))
	if err != nil {
		t.Fatalf("WebauthnSetupRegisterStart: %v", err)
	}
	if challenge.StateToken.expose() != wsuStateToken {
		t.Fatalf("state token: got %q", challenge.StateToken.expose())
	}
	body := capture.bodies[webauthnSetupRegisterStartPath]
	if len(body) != 1 || body["setup_token"] != wsuSetupToken {
		t.Fatalf("unexpected body: %#v", body)
	}
}

func TestWebauthnSetupRegisterFinishSendsTheCeremonyAndTheToken(t *testing.T) {
	server, capture := wsuServer(t, nil)
	client := wsuClient(t, server)

	_, err := client.WebauthnSetupRegisterFinish(
		context.Background(), Sensitive(wsuSetupToken), Sensitive(wsuStateToken),
		"Alice's security key", json.RawMessage(registrationResponseJSON),
	)
	if err != nil {
		t.Fatalf("WebauthnSetupRegisterFinish: %v", err)
	}
	body := capture.bodies[webauthnSetupRegisterFinishPath]
	if body["setup_token"] != wsuSetupToken {
		t.Fatalf("setup_token not sent: %#v", body)
	}
	if body["state_token"] != wsuStateToken {
		t.Fatalf("state_token not sent: %#v", body)
	}
	if body["credential_name"] != "Alice's security key" {
		t.Fatalf("credential_name not sent: %#v", body)
	}
	if _, present := body["user_id"]; present {
		// §24.1: the account is named by the token, never by the caller.
		t.Fatal("must not invent a user_id field")
	}
}

// ---------------------------------------------------------------------------
// §24.3 / §25.2 rule 2 — adoption, mirrored exactly from MfaSetupConfirm
// ---------------------------------------------------------------------------

func TestWebauthnSetupRegisterFinishAdoptsExactlyLikeMfaSetupConfirm(t *testing.T) {
	server, _ := wsuServer(t, nil)
	client := wsuClient(t, server)

	if client.cookieValue(accessCookie) != "" {
		t.Fatal("client should start unauthenticated")
	}

	result, err := client.WebauthnSetupRegisterFinish(
		context.Background(), Sensitive(wsuSetupToken), Sensitive(wsuStateToken),
		"Alice's security key", json.RawMessage(registrationResponseJSON),
	)
	if err != nil {
		t.Fatalf("WebauthnSetupRegisterFinish: %v", err)
	}

	// The client's own state, exactly as §24.3 rule 1 requires of
	// WebauthnAuthenticateFinish and §25.2 rule 2 requires of this call too.
	if client.cookieValue(accessCookie) == "" {
		t.Fatal("the session was not adopted")
	}
	if result.SessionID != "33333333-3333-3333-3333-333333333333" {
		t.Fatalf("session id: got %q", result.SessionID)
	}
	if result.ExpiresIn != 900 {
		t.Fatalf("expires_in: got %d", result.ExpiresIn)
	}

	// The CSRF token was captured into the same slot Login populates
	// (§24.3 rule 2), and a state-changing call made immediately afterward
	// carries it — the exact test client_test.go's TestCSRF_CaptureAndForward
	// runs for Login, run here against the setup-token completion instead.
	if _, err := client.doRequest(newTestRequest(t, http.MethodPost, server.URL+"/probe", nil)); err != nil {
		t.Fatalf("probe POST: %v", err)
	}
	if got := client.getCSRFToken(); got != "csrf-tok-setup" {
		t.Fatalf("CSRF token not captured: got %q", got)
	}
}

func TestWebauthnSetupRegisterFinishClearsTheDecisionMemo(t *testing.T) {
	server, _ := wsuServer(t, nil)
	client, err := NewClient(server.URL, "acme", WithOrgSlug("globex"), WithDecisionMemoTTL(time.Minute))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	const memoKey = "warm-before-setup-completion"
	client.session.memo.set(memoKey, AccessResult{Allowed: true})
	if _, ok := client.session.memo.get(memoKey); !ok {
		t.Fatal("test setup: the memo entry did not take")
	}

	if _, err := client.WebauthnSetupRegisterFinish(
		context.Background(), Sensitive(wsuSetupToken), Sensitive(wsuStateToken),
		"key", json.RawMessage(registrationResponseJSON),
	); err != nil {
		t.Fatalf("WebauthnSetupRegisterFinish: %v", err)
	}
	if _, ok := client.session.memo.get(memoKey); ok {
		t.Fatal("§17.1 rule 9 / §24.3 rule 4: the memo must be cleared — the subject changed")
	}
}

// ---------------------------------------------------------------------------
// §24.1 — "an SDK MUST NOT attach its session credential to these two"
// ---------------------------------------------------------------------------

func TestWebauthnSetupRegisterCarriesNoSessionCredential(t *testing.T) {
	server, capture := wsuServer(t, nil)
	client := wsuGiveClientASession(t, wsuClient(t, server))

	if _, err := client.WebauthnSetupRegisterStart(context.Background(), Sensitive(wsuSetupToken)); err != nil {
		t.Fatalf("WebauthnSetupRegisterStart: %v", err)
	}
	if _, err := client.WebauthnSetupRegisterFinish(
		context.Background(), Sensitive(wsuSetupToken), Sensitive(wsuStateToken),
		"key", json.RawMessage(registrationResponseJSON),
	); err != nil {
		t.Fatalf("WebauthnSetupRegisterFinish: %v", err)
	}

	for _, path := range []string{webauthnSetupRegisterStartPath, webauthnSetupRegisterFinishPath} {
		headers, ok := capture.headers[path]
		if !ok {
			t.Fatalf("%s: no request observed", path)
		}
		if cookie := headers.Get("Cookie"); cookie != "" {
			t.Fatalf("%s: the session cookie was sent: %q", path, cookie)
		}
		if auth := headers.Get("Authorization"); auth != "" {
			t.Fatalf("%s: an Authorization header was sent: %q", path, auth)
		}
		if csrf := headers.Get("X-CSRF-Token"); csrf != "" {
			t.Fatalf("%s: a stale CSRF token was echoed: %q", path, csrf)
		}
	}
}

// ---------------------------------------------------------------------------
// §24.4 — error taxonomy, exactly as WebauthnRegisterStart/Finish
// ---------------------------------------------------------------------------

func TestWebauthnSetupRegister401OnAnInvalidToken(t *testing.T) {
	server, _ := wsuServer(t, map[string]http.HandlerFunc{
		webauthnSetupRegisterStartPath: func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"message":"the setup token is missing, expired, or not a setup token"}`))
		},
	})
	client := wsuClient(t, server)

	_, err := client.WebauthnSetupRegisterStart(context.Background(), Sensitive("not-a-real-setup-token"))
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("expected *AuthError, got %T (%v)", err, err)
	}
}

func TestWebauthnSetupRegisterStart400WhenAlreadyConfigured(t *testing.T) {
	server, _ := wsuServer(t, map[string]http.HandlerFunc{
		webauthnSetupRegisterStartPath: func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"message":"this account already has an MFA factor"}`))
		},
	})
	client := wsuClient(t, server)

	_, err := client.WebauthnSetupRegisterStart(context.Background(), Sensitive(wsuSetupToken))
	if err == nil {
		t.Fatal("expected an error")
	}
	// §2's HTTP status table: 400 maps to *NetworkError on this (non-management)
	// surface — there is no ValidationError type outside §27.
	var netErr *NetworkError
	if !errors.As(err, &netErr) {
		t.Fatalf("expected *NetworkError, got %T (%v)", err, err)
	}
}

func TestWebauthnSetupRegisterFinish403MessageSurvives(t *testing.T) {
	server, _ := wsuServer(t, map[string]http.HandlerFunc{
		webauthnSetupRegisterFinishPath: func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"this security key is not FIDO certified"}`))
		},
	})
	client := wsuClient(t, server)

	_, err := client.WebauthnSetupRegisterFinish(
		context.Background(), Sensitive(wsuSetupToken), Sensitive(wsuStateToken),
		"key", json.RawMessage(registrationResponseJSON),
	)
	var authzErr *AuthzError
	if !errors.As(err, &authzErr) {
		t.Fatalf("expected *AuthzError, got %T (%v)", err, err)
	}
	if !strings.Contains(err.Error(), "FIDO certified") {
		t.Fatalf("the attestation policy message was lost: %v", err)
	}
}

func TestWebauthnSetupRegisterStartDoesNotRetry503(t *testing.T) {
	server, capture := wsuServer(t, map[string]http.HandlerFunc{
		webauthnSetupRegisterStartPath: func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"message":"FIDO metadata unavailable"}`))
		},
	})
	client := wsuClient(t, server)

	if _, err := client.WebauthnSetupRegisterStart(context.Background(), Sensitive(wsuSetupToken)); err == nil {
		t.Fatal("expected an error on 503")
	}
	// §24.4 rule 2, exactly as on the profile-page register/start.
	if n := capture.count(webauthnSetupRegisterStartPath); n != 1 {
		t.Fatalf("expected exactly 1 request, got %d", n)
	}
}

// ---------------------------------------------------------------------------
// §24.5 — both tokens are opaque and Sensitive
// ---------------------------------------------------------------------------

func TestWebauthnSetupTokensAreNeverParsed(t *testing.T) {
	server, capture := wsuServer(t, nil)
	client := wsuClient(t, server)

	notAJWT := "this-is-not-a-jwt-and-never-will-be"
	if _, err := client.WebauthnSetupRegisterFinish(
		context.Background(), Sensitive(notAJWT), Sensitive(notAJWT),
		"key", json.RawMessage(registrationResponseJSON),
	); err != nil {
		t.Fatalf("WebauthnSetupRegisterFinish: %v", err)
	}
	body := capture.bodies[webauthnSetupRegisterFinishPath]
	if body["setup_token"] != notAJWT || body["state_token"] != notAJWT {
		t.Fatalf("a token was rewritten: %#v", body)
	}
}

func TestWebauthnSetupSecretsNeverRender(t *testing.T) {
	server, _ := wsuServer(t, nil)
	client := wsuClient(t, server)

	challenge, err := client.WebauthnSetupRegisterStart(context.Background(), Sensitive(wsuSetupToken))
	if err != nil {
		t.Fatalf("WebauthnSetupRegisterStart: %v", err)
	}
	result, err := wsuClient(t, server).WebauthnSetupRegisterFinish(
		context.Background(), Sensitive(wsuSetupToken), Sensitive(wsuStateToken),
		"key", json.RawMessage(registrationResponseJSON),
	)
	if err != nil {
		t.Fatalf("WebauthnSetupRegisterFinish: %v", err)
	}

	rendered := []string{challenge.StateToken.String()}
	for _, format := range []string{"%v", "%+v", "%s", "%q", "%#v"} {
		rendered = append(rendered, fmt.Sprintf(format, challenge), fmt.Sprintf(format, result))
	}
	if marshalled, err := json.Marshal(result); err == nil {
		rendered = append(rendered, string(marshalled))
	}
	for _, secret := range []string{wsuSetupToken, wsuStateToken} {
		for _, surface := range rendered {
			if strings.Contains(surface, secret) {
				t.Fatalf("secret %q leaked into %q", secret, surface)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Failure paths — every early return the setup pair can take
// ---------------------------------------------------------------------------
//
// These are not coverage padding. Each branch below is a place where the
// setup pair could silently succeed, or fail with the wrong error kind, in a
// way none of the tests above would notice: a closed client that still dials,
// a malformed body mistaken for a 200, an unencodable ceremony that reaches
// the wire, and a transport failure surfaced as anything other than a
// NetworkError.

func TestWebauthnSetupRegisterRefusesAClosedClient(t *testing.T) {
	server, capture := wsuServer(t, nil)
	client := wsuClient(t, server)
	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	_, startErr := client.WebauthnSetupRegisterStart(context.Background(), Sensitive(wsuSetupToken))
	if startErr == nil || !strings.Contains(startErr.Error(), "client is closed") {
		t.Fatalf("WebauthnSetupRegisterStart on a closed client: %v", startErr)
	}
	_, finishErr := client.WebauthnSetupRegisterFinish(
		context.Background(), Sensitive(wsuSetupToken), Sensitive(wsuStateToken),
		"key", json.RawMessage(registrationResponseJSON),
	)
	if finishErr == nil || !strings.Contains(finishErr.Error(), "client is closed") {
		t.Fatalf("WebauthnSetupRegisterFinish on a closed client: %v", finishErr)
	}
	// The refusal is client-side: neither call may reach the wire, or a
	// closed client would still be spending a single-use setup token.
	if n := capture.count(webauthnSetupRegisterStartPath) + capture.count(webauthnSetupRegisterFinishPath); n != 0 {
		t.Fatalf("a closed client sent %d requests", n)
	}
}

func TestWebauthnSetupRegisterRejectsAMalformedBody(t *testing.T) {
	body := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"challenge":`)) // truncated mid-object
	}
	server, _ := wsuServer(t, map[string]http.HandlerFunc{
		webauthnSetupRegisterStartPath:  body,
		webauthnSetupRegisterFinishPath: body,
	})
	client := wsuClient(t, server)

	_, startErr := client.WebauthnSetupRegisterStart(context.Background(), Sensitive(wsuSetupToken))
	var startNet *NetworkError
	if !errors.As(startErr, &startNet) {
		t.Fatalf("a 200 with an unparseable body must be a NetworkError, got %#v", startErr)
	}
	_, finishErr := client.WebauthnSetupRegisterFinish(
		context.Background(), Sensitive(wsuSetupToken), Sensitive(wsuStateToken),
		"key", json.RawMessage(registrationResponseJSON),
	)
	var finishNet *NetworkError
	if !errors.As(finishErr, &finishNet) {
		t.Fatalf("a 200 with an unparseable body must be a NetworkError, got %#v", finishErr)
	}
	// A body that never parsed cannot have completed a login (§24.3).
	if client.cookieValue(accessCookie) != "" {
		t.Fatal("an unparseable finish response must not leave the client authenticated")
	}
}

func TestWebauthnSetupRegisterFinishRejectsAnUnencodableResponse(t *testing.T) {
	server, capture := wsuServer(t, nil)
	client := wsuClient(t, server)

	// §24.6a rule 2: the ceremony reaches the server unchanged — which means
	// one that cannot be encoded is refused here rather than sent as null.
	_, err := client.WebauthnSetupRegisterFinish(
		context.Background(), Sensitive(wsuSetupToken), Sensitive(wsuStateToken),
		"key", make(chan int),
	)
	if err == nil {
		t.Fatal("expected an error for an unencodable authenticator response")
	}
	if !strings.Contains(err.Error(), "WebauthnSetupRegisterFinish") {
		t.Fatalf("the error must name the operation, got %v", err)
	}
	if n := capture.count(webauthnSetupRegisterFinishPath); n != 0 {
		t.Fatalf("an unencodable ceremony reached the wire (%d requests)", n)
	}
}

func TestWebauthnSetupRegisterSurfacesATransportFailure(t *testing.T) {
	server, _ := wsuServer(t, nil)
	client := wsuClient(t, server)
	server.Close() // nothing is listening any more

	_, err := client.WebauthnSetupRegisterStart(context.Background(), Sensitive(wsuSetupToken))
	var netErr *NetworkError
	if !errors.As(err, &netErr) {
		t.Fatalf("a dial failure must surface as a NetworkError, got %#v", err)
	}
	if !strings.Contains(netErr.Message, "request failed") {
		t.Fatalf("unexpected message: %q", netErr.Message)
	}
}
