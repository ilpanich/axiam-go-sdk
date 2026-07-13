package axiam

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// makeTokenClaims builds a syntactically-valid (unsigned-signature) JWT from an
// arbitrary claims map, so tests can drive the base64url-decode paths in
// login.go with tokens that are deliberately missing or malforming individual
// claims (tenant_id, org_id, jti). Signature verification is out of scope here.
func makeTokenClaims(t *testing.T, claims map[string]any) string {
	t.Helper()
	header, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT"})
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString(header) + "." + enc.EncodeToString(payload) + "." + enc.EncodeToString([]byte("sig"))
}

// loginWithToken logs a client in against a server whose non-login paths are
// delegated to next, using the exact access token supplied — including tokens
// that are valid enough to log in but deliberately lack a tenant_id/org_id/jti
// claim.
func loginWithToken(t *testing.T, token string, next http.HandlerFunc) *Client {
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
	return client
}

func fullClaims() map[string]any {
	return map[string]any{
		"sub":       "11111111-1111-1111-1111-111111111111",
		"tenant_id": "22222222-2222-2222-2222-222222222222",
		"org_id":    "44444444-4444-4444-4444-444444444444",
		"jti":       "33333333-3333-3333-3333-333333333333",
		"exp":       time.Now().Add(time.Hour).Unix(),
	}
}

// TestLogin_MalformedAccessTokenIsAuthError covers absorbSessionCookies'
// claim-decode failure branch: a 200 login that sets a malformed axiam_access
// cookie fails closed with an AuthError.
func TestLogin_MalformedAccessTokenIsAuthError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: accessCookie, Value: "not.a.jwt", Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: refreshCookie, Value: "refresh-tok", Path: "/"})
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
		t.Fatalf("expected *AuthError decoding a malformed access token, got %T: %v", err, err)
	}
}

// TestRefresh_NewAccessCookieCleared covers Refresh's "refresh response did not
// set axiam_access" branch: a 200 refresh that expires the access cookie leaves
// no new token to cache.
func TestRefresh_NewAccessCookieCleared(t *testing.T) {
	token := makeTokenClaims(t, fullClaims())
	client := loginWithToken(t, token, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == refreshPath {
			// Expire the access cookie so the jar drops it, leaving the
			// post-refresh access value empty.
			http.SetCookie(w, &http.Cookie{Name: accessCookie, Value: "", Path: "/", MaxAge: -1})
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"expires_in": 900})
		}
	})
	err := client.Refresh(context.Background())
	var authErr *AuthError
	if !isAuthError(err, &authErr) {
		t.Fatalf("expected *AuthError when refresh clears the access cookie, got %T: %v", err, err)
	}
}

// TestLogin_MFAChallengeMalformedBody covers the 202 branch's decode-error
// path: an MFA challenge whose body is not valid JSON is a NetworkError.
func TestLogin_MFAChallengeMalformedBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
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
		t.Fatalf("expected *NetworkError on a malformed 202 body, got %T: %v", err, err)
	}
}

// TestLogin_TransportErrorIsNetworkError covers the doRequest failure branch:
// pointing the client at a closed server surfaces a NetworkError.
func TestLogin_TransportErrorIsNetworkError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := server.URL
	server.Close() // nothing is listening now

	client, err := NewClient(url, "acme")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.Login(context.Background(), "a@example.test", "pw"); err == nil {
		t.Fatal("expected a transport error against a closed server")
	}
}

// TestVerifyMfa_MalformedSuccessBody covers VerifyMfa's 200 decode-error path.
func TestVerifyMfa_MalformedSuccessBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not json"))
	}))
	defer server.Close()
	client, err := NewClient(server.URL, "acme")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.VerifyMfa(context.Background(), Sensitive("tok"), "000000")
	var netErr *NetworkError
	if !isNetworkError(err, &netErr) {
		t.Fatalf("expected *NetworkError on malformed verify body, got %T: %v", err, err)
	}
}

// TestVerifyMfa_MissingAccessCookie covers VerifyMfa's absorbSessionCookies
// failure path: a 200 that never set axiam_access is an AuthError.
func TestVerifyMfa_MissingAccessCookie(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"session_id": "33333333-3333-3333-3333-333333333333", "expires_in": 900})
	}))
	defer server.Close()
	client, err := NewClient(server.URL, "acme")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.VerifyMfa(context.Background(), Sensitive("tok"), "123456")
	var authErr *AuthError
	if !isAuthError(err, &authErr) {
		t.Fatalf("expected *AuthError when verify sets no access cookie, got %T: %v", err, err)
	}
}

// TestVerifyMfa_TransportError covers VerifyMfa's doRequest failure branch.
func TestVerifyMfa_TransportError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := server.URL
	server.Close()
	client, err := NewClient(url, "acme")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.VerifyMfa(context.Background(), Sensitive("tok"), "000000"); err == nil {
		t.Fatal("expected a transport error against a closed server")
	}
}

// TestRefresh_NoAccessToken covers the guard clause: Refresh before any Login
// is an AuthError.
func TestRefresh_NoAccessToken(t *testing.T) {
	client, err := NewClient("https://example.test", "acme")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	err = client.Refresh(context.Background())
	var authErr *AuthError
	if !isAuthError(err, &authErr) {
		t.Fatalf("expected *AuthError with no access token, got %T: %v", err, err)
	}
}

// TestRefresh_TenantNotResolved covers the tenant-resolution guard: a token
// that logs in but carries no tenant_id claim cannot be refreshed.
func TestRefresh_TenantNotResolved(t *testing.T) {
	claims := fullClaims()
	delete(claims, "tenant_id")
	token := makeTokenClaims(t, claims)
	client := loginWithToken(t, token, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("refresh must not reach the server when tenant_id is unresolved; got %s", r.URL.Path)
	})
	err := client.Refresh(context.Background())
	var authErr *AuthError
	if !isAuthError(err, &authErr) {
		t.Fatalf("expected *AuthError when tenant_id is unresolved, got %T: %v", err, err)
	}
}

// TestRefresh_OrgNotResolved covers the org-resolution guard: a token with a
// tenant_id but no org_id (and no WithOrgID) cannot be refreshed.
func TestRefresh_OrgNotResolved(t *testing.T) {
	claims := fullClaims()
	delete(claims, "org_id")
	token := makeTokenClaims(t, claims)
	client := loginWithToken(t, token, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("refresh must not reach the server when org_id is unresolved; got %s", r.URL.Path)
	})
	err := client.Refresh(context.Background())
	var authErr *AuthError
	if !isAuthError(err, &authErr) {
		t.Fatalf("expected *AuthError when org_id is unresolved, got %T: %v", err, err)
	}
}

// TestRefresh_MalformedSuccessBody covers Refresh's 200 decode-error path.
func TestRefresh_MalformedSuccessBody(t *testing.T) {
	token := makeTokenClaims(t, fullClaims())
	client := loginWithToken(t, token, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == refreshPath {
			http.SetCookie(w, &http.Cookie{Name: accessCookie, Value: token, Path: "/"})
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("not json"))
		}
	})
	if err := client.Refresh(context.Background()); err == nil {
		t.Fatal("expected an error decoding a malformed refresh body")
	}
}

// TestRefresh_MalformedNewAccessToken covers Refresh's claim-decode failure on
// the freshly-issued access token: the refresh 200 sets a new but malformed
// axiam_access cookie.
func TestRefresh_MalformedNewAccessToken(t *testing.T) {
	token := makeTokenClaims(t, fullClaims())
	client := loginWithToken(t, token, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == refreshPath {
			http.SetCookie(w, &http.Cookie{Name: accessCookie, Value: "not.a.jwt", Path: "/"})
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"expires_in": 900})
		}
	})
	err := client.Refresh(context.Background())
	var authErr *AuthError
	if !isAuthError(err, &authErr) {
		t.Fatalf("expected *AuthError decoding a malformed refreshed token, got %T: %v", err, err)
	}
}

// TestRefresh_TransportError covers Refresh's doRequest failure branch.
func TestRefresh_TransportError(t *testing.T) {
	token := makeTokenClaims(t, fullClaims())
	// Log in against a live server, then close it so the refresh call fails.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: accessCookie, Value: token, Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: refreshCookie, Value: "refresh-tok", Path: "/"})
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"session_id": "33333333-3333-3333-3333-333333333333", "expires_in": 900})
	}))
	client, err := NewClient(server.URL, "acme")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.Login(context.Background(), "a@example.test", "pw"); err != nil {
		t.Fatalf("login: %v", err)
	}
	server.Close()
	if err := client.Refresh(context.Background()); err == nil {
		t.Fatal("expected a transport error refreshing against a closed server")
	}
}

// TestLogout_BadJTIIsAuthError covers Logout's jti-parse failure: a token that
// logs in but whose jti claim is not a UUID cannot be logged out.
func TestLogout_BadJTIIsAuthError(t *testing.T) {
	claims := fullClaims()
	claims["jti"] = "not-a-uuid"
	token := makeTokenClaims(t, claims)
	client := loginWithToken(t, token, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("logout must not reach the server with an unparseable jti; got %s", r.URL.Path)
	})
	err := client.Logout(context.Background())
	var authErr *AuthError
	if !isAuthError(err, &authErr) {
		t.Fatalf("expected *AuthError for a non-UUID jti, got %T: %v", err, err)
	}
}

// TestLogout_TransportErrorPropagates covers Logout's doRequest failure branch:
// a logged-in client whose server has gone away surfaces a transport error.
func TestLogout_TransportErrorPropagates(t *testing.T) {
	token := makeTokenClaims(t, fullClaims())
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: accessCookie, Value: token, Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: refreshCookie, Value: "refresh-tok", Path: "/"})
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"session_id": "33333333-3333-3333-3333-333333333333", "expires_in": 900})
	}))
	client, err := NewClient(server.URL, "acme")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.Login(context.Background(), "a@example.test", "pw"); err != nil {
		t.Fatalf("login: %v", err)
	}
	server.Close()
	if err := client.Logout(context.Background()); err == nil {
		t.Fatal("expected a transport error logging out against a closed server")
	}
}

// TestResolvedOrgTenantID_Branches drives the three failure branches of
// resolvedOrgTenantID directly: no access cookie, a token missing tenant_id,
// and a token whose tenant_id is not a UUID.
func TestResolvedOrgTenantID_Branches(t *testing.T) {
	t.Run("no access cookie", func(t *testing.T) {
		client, err := NewClient("https://example.test", "acme")
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		if _, ok := client.resolvedOrgTenantID(); ok {
			t.Fatal("expected ok=false with no access cookie")
		}
	})
	t.Run("token missing tenant_id", func(t *testing.T) {
		claims := fullClaims()
		delete(claims, "tenant_id")
		client := loginWithToken(t, makeTokenClaims(t, claims), func(http.ResponseWriter, *http.Request) {})
		if _, ok := client.resolvedOrgTenantID(); ok {
			t.Fatal("expected ok=false when tenant_id is absent")
		}
	})
	t.Run("token tenant_id not a UUID", func(t *testing.T) {
		claims := fullClaims()
		claims["tenant_id"] = "not-a-uuid"
		client := loginWithToken(t, makeTokenClaims(t, claims), func(http.ResponseWriter, *http.Request) {})
		if _, ok := client.resolvedOrgTenantID(); ok {
			t.Fatal("expected ok=false when tenant_id is not a UUID")
		}
	})
}
