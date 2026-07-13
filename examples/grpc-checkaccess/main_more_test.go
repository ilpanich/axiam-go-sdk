package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestMain_MFARequiredShortCircuits drives the example's main() to the MFA
// short-circuit: a 202 login response prints the MFA notice and returns before
// any gRPC transport is constructed (which would require a live endpoint). This
// covers the REST-login portion of main() end-to-end without a broker/server.
func TestMain_MFARequiredShortCircuits(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/auth/login" {
			t.Errorf("gRPC transport must not be reached when MFA is required; got %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"challenge_token":   "challenge",
			"available_methods": []string{"totp"},
		})
	}))
	defer srv.Close()

	t.Setenv("AXIAM_BASE_URL", srv.URL)
	t.Setenv("AXIAM_TENANT_SLUG", "acme")
	t.Setenv("AXIAM_EMAIL", "user@example.test")
	t.Setenv("AXIAM_PASSWORD", "hunter2")

	// Returns cleanly at the MFA branch; any failure before it would log.Fatal.
	main()
}
