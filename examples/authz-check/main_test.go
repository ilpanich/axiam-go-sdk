package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// makeAccessToken builds a syntactically valid (unsigned-signature) JWT whose
// payload carries the org_id/tenant_id/jti claims the SDK decodes after login.
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

// TestMain_AuthzCheckHappyPath drives the example's main() against a mock AXIAM
// server that returns a successful login and authz responses, exercising the
// CheckAccess/Can/BatchCheck surface the example demonstrates end-to-end.
func TestMain_AuthzCheckHappyPath(t *testing.T) {
	token := makeAccessToken(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/auth/login":
			http.SetCookie(w, &http.Cookie{Name: "axiam_access", Value: token, Path: "/"})
			http.SetCookie(w, &http.Cookie{Name: "axiam_refresh", Value: "refresh-tok", Path: "/"})
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"session_id": "33333333-3333-3333-3333-333333333333", "expires_in": 900})
		case "/api/v1/authz/check":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"allowed": true, "reason": ""})
		case "/api/v1/authz/check/batch":
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"results": []map[string]any{{"allowed": true}, {"allowed": false}}})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	t.Setenv("AXIAM_BASE_URL", srv.URL)
	t.Setenv("AXIAM_TENANT_SLUG", "acme")
	t.Setenv("AXIAM_EMAIL", "user@example.test")
	t.Setenv("AXIAM_PASSWORD", "hunter2")
	t.Setenv("AXIAM_RESOURCE_ID", "00000000-0000-0000-0000-000000000000")

	// Runs to completion iff every step succeeds — any error would log.Fatal.
	main()
}

// TestMain_MFARequiredShortCircuits proves the example's MFA short-circuit: a
// 202 login response prints the MFA notice and returns without calling authz.
func TestMain_MFARequiredShortCircuits(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/auth/login" {
			t.Errorf("authz must not be reached when MFA is required; got %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]any{"challenge_token": "c", "available_methods": []string{"totp"}})
	}))
	defer srv.Close()

	t.Setenv("AXIAM_BASE_URL", srv.URL)
	t.Setenv("AXIAM_TENANT_SLUG", "acme")
	main()
}
