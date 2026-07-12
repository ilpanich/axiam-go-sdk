package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func makeAccessToken(t *testing.T) string {
	t.Helper()
	header, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT"})
	payload, _ := json.Marshal(map[string]any{
		"sub":       "11111111-1111-1111-1111-111111111111",
		"tenant_id": "22222222-2222-2222-2222-222222222222",
		"org_id":    "44444444-4444-4444-4444-444444444444",
		"jti":       "33333333-3333-3333-3333-333333333333",
		"exp":       time.Now().Add(time.Hour).Unix(),
	})
	enc := base64.RawURLEncoding
	return enc.EncodeToString(header) + "." + enc.EncodeToString(payload) + "." + enc.EncodeToString([]byte("sig"))
}

// TestMain_TwoPhaseMFA drives the example through the MFA branch: login returns
// a 202 challenge, then mfa/verify completes the session — the full two-phase
// flow the example is meant to demonstrate.
func TestMain_TwoPhaseMFA(t *testing.T) {
	token := makeAccessToken(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/auth/login":
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(map[string]any{"challenge_token": "challenge-abc", "available_methods": []string{"totp"}})
		case "/api/v1/auth/mfa/verify":
			http.SetCookie(w, &http.Cookie{Name: "axiam_access", Value: token, Path: "/"})
			http.SetCookie(w, &http.Cookie{Name: "axiam_refresh", Value: "refresh-tok", Path: "/"})
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"session_id": "33333333-3333-3333-3333-333333333333", "expires_in": 900})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	t.Setenv("AXIAM_BASE_URL", srv.URL)
	t.Setenv("AXIAM_TENANT_SLUG", "acme")
	main()
}

// TestMain_LoginNoMFA drives the non-MFA branch: a 200 login completes the
// session directly, exercising the else path.
func TestMain_LoginNoMFA(t *testing.T) {
	token := makeAccessToken(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/auth/login" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		http.SetCookie(w, &http.Cookie{Name: "axiam_access", Value: token, Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: "axiam_refresh", Value: "refresh-tok", Path: "/"})
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"session_id": "33333333-3333-3333-3333-333333333333", "expires_in": 900})
	}))
	defer srv.Close()

	t.Setenv("AXIAM_BASE_URL", srv.URL)
	t.Setenv("AXIAM_TENANT_SLUG", "acme")
	main()
}
