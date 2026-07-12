package axiam

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

// loginThenServe stands up an httptest server that completes a login (setting
// the access/refresh cookies for token) and then delegates every other path to
// next, returning a logged-in client wired to it.
func loginThenServe(t *testing.T, token string, next http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == loginPath {
			http.SetCookie(w, &http.Cookie{Name: accessCookie, Value: token, Path: "/"})
			http.SetCookie(w, &http.Cookie{Name: refreshCookie, Value: "refresh-tok", Path: "/"})
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"session_id": "33333333-3333-3333-3333-333333333333", "expires_in": 900})
			return
		}
		next(w, r)
	}))
	t.Cleanup(server.Close)

	client, err := NewClient(server.URL, "acme")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.Login(context.Background(), "alice@example.test", "hunter2"); err != nil {
		t.Fatalf("login: %v", err)
	}
	return client, server
}

// TestVerifyMfa_CompletesSession proves the two-phase MFA flow: a 200 on
// mfa/verify absorbs the session cookies and returns a completed LoginResult.
func TestVerifyMfa_CompletesSession(t *testing.T) {
	token := makeAccessTokenWithOrgID(t, "44444444-4444-4444-4444-444444444444")
	var gotBody mfaVerifyRequestBody
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != mfaVerifyPath {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		http.SetCookie(w, &http.Cookie{Name: accessCookie, Value: token, Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: refreshCookie, Value: "refresh-tok", Path: "/"})
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"session_id": "33333333-3333-3333-3333-333333333333", "expires_in": 900})
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "acme")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	result, err := client.VerifyMfa(context.Background(), Sensitive("challenge-token"), "123456")
	if err != nil {
		t.Fatalf("VerifyMfa: %v", err)
	}
	if result.MFARequired {
		t.Fatal("a completed verify must not report MFARequired")
	}
	if result.SessionID != "33333333-3333-3333-3333-333333333333" || result.ExpiresIn != 900 {
		t.Fatalf("session not established: %+v", result)
	}
	if gotBody.ChallengeToken != "challenge-token" || gotBody.TotpCode != "123456" {
		t.Fatalf("verify body not sent as expected: %+v", gotBody)
	}
}

func TestVerifyMfa_ErrorStatuses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"bad totp"}`))
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "acme")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.VerifyMfa(context.Background(), Sensitive("tok"), "000000")
	var authErr *AuthError
	if !isAuthError(err, &authErr) {
		t.Fatalf("expected *AuthError on 401, got %T: %v", err, err)
	}
}

func TestLogout_ClearsSessionState(t *testing.T) {
	token := makeAccessTokenWithOrgID(t, "44444444-4444-4444-4444-444444444444")
	var logoutBody logoutRequestBody
	client, _ := loginThenServe(t, token, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != logoutPath {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&logoutBody)
		w.WriteHeader(http.StatusOK)
	})

	// The session id logged out is the access token's jti claim.
	if err := client.Logout(context.Background()); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if logoutBody.SessionID != uuid.MustParse("33333333-3333-3333-3333-333333333333") {
		t.Fatalf("logout did not send the jti session id: %+v", logoutBody)
	}
	// After logout the guard is reset — no cached access token remains.
	if _, ok := client.guard.Load().CachedAccessToken(); ok {
		t.Fatal("expected the refresh guard to be reset after Logout")
	}
}

func TestLogout_NoSessionIsError(t *testing.T) {
	client, err := NewClient("https://example.test", "acme")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	err = client.Logout(context.Background())
	var authErr *AuthError
	if !isAuthError(err, &authErr) {
		t.Fatalf("expected *AuthError with no active session, got %T: %v", err, err)
	}
}

func TestLogout_ServerErrorPropagates(t *testing.T) {
	token := makeAccessTokenWithOrgID(t, "44444444-4444-4444-4444-444444444444")
	client, _ := loginThenServe(t, token, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	if err := client.Logout(context.Background()); err == nil {
		t.Fatal("expected a server 500 on logout to propagate as an error")
	}
}

func TestLogin_ErrorStatusMapping(t *testing.T) {
	cases := []struct {
		name   string
		status int
		assert func(t *testing.T, err error)
	}{
		{"401 -> AuthError", http.StatusUnauthorized, func(t *testing.T, err error) {
			var e *AuthError
			if !isAuthError(err, &e) {
				t.Fatalf("expected *AuthError, got %T", err)
			}
		}},
		{"403 -> AuthzError", http.StatusForbidden, func(t *testing.T, err error) {
			var e *AuthzError
			if !isAuthzError(err, &e) {
				t.Fatalf("expected *AuthzError, got %T", err)
			}
		}},
		{"500 -> NetworkError", http.StatusInternalServerError, func(t *testing.T, err error) {
			var e *NetworkError
			if !isNetworkError(err, &e) {
				t.Fatalf("expected *NetworkError, got %T", err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(`{"error":"x"}`))
			}))
			defer server.Close()
			client, err := NewClient(server.URL, "acme")
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			_, err = client.Login(context.Background(), "a@example.test", "pw")
			if err == nil {
				t.Fatal("expected an error")
			}
			tc.assert(t, err)
		})
	}
}

// TestLogin_MissingAccessCookieIsAuthError proves absorbSessionCookies fails
// closed: a 200 that never set axiam_access is an AuthError, not a silent
// "logged in" state.
func TestLogin_MissingAccessCookieIsAuthError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A valid session_id UUID so the success body decodes cleanly; the
		// AuthError must then come from the absent access cookie, not a decode
		// failure.
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"session_id": "33333333-3333-3333-3333-333333333333", "expires_in": 900})
	}))
	defer server.Close()
	client, err := NewClient(server.URL, "acme")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.Login(context.Background(), "a@example.test", "pw")
	var authErr *AuthError
	if !isAuthError(err, &authErr) {
		t.Fatalf("expected *AuthError when no access cookie is set, got %T: %v", err, err)
	}
}

func TestLogin_MalformedSuccessBodyIsNetworkError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not json"))
	}))
	defer server.Close()
	client, err := NewClient(server.URL, "acme")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.Login(context.Background(), "a@example.test", "pw")
	var netErr *NetworkError
	if !isNetworkError(err, &netErr) {
		t.Fatalf("expected *NetworkError on a malformed 200 body, got %T: %v", err, err)
	}
}

func TestBuildLoginBody_OrgSelectors(t *testing.T) {
	t.Run("WithOrgID sets org_id", func(t *testing.T) {
		id := uuid.MustParse("77777777-7777-7777-7777-777777777777")
		c, err := NewClient("https://example.test", "acme", WithOrgID(id))
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		body := c.buildLoginBody("a@example.test", "pw")
		if body.OrgID == nil || *body.OrgID != id || body.OrgSlug != nil {
			t.Fatalf("expected org_id set, org_slug nil: %+v", body)
		}
	})
	t.Run("WithOrgSlug sets org_slug", func(t *testing.T) {
		c, err := NewClient("https://example.test", "acme", WithOrgSlug("acme-org"))
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		body := c.buildLoginBody("a@example.test", "pw")
		if body.OrgSlug == nil || *body.OrgSlug != "acme-org" || body.OrgID != nil {
			t.Fatalf("expected org_slug set, org_id nil: %+v", body)
		}
	})
}

func TestDecodeUnverifiedClaims_Errors(t *testing.T) {
	cases := []struct {
		name  string
		token string
	}{
		{"too few segments", "aaa.bbb"},
		{"bad base64 payload", "aaa.!!!notbase64!!!.ccc"},
		{"payload not json", "aaa." + b64url("not json") + ".ccc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := decodeUnverifiedClaims(tc.token); err == nil {
				t.Fatalf("expected an error decoding %q", tc.token)
			}
		})
	}
}

func TestDeserErr_IsNetworkError(t *testing.T) {
	err := deserErr(errDummy{})
	var netErr *NetworkError
	if !isNetworkError(err, &netErr) {
		t.Fatalf("deserErr must produce a *NetworkError, got %T", err)
	}
}

type errDummy struct{}

func (errDummy) Error() string { return "dummy" }

func b64url(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

func isAuthzError(err error, target **AuthzError) bool {
	for err != nil {
		if e, ok := err.(*AuthzError); ok {
			*target = e
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

func isNetworkError(err error, target **NetworkError) bool {
	for err != nil {
		if e, ok := err.(*NetworkError); ok {
			*target = e
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
