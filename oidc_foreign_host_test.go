package axiam

// F-15 regression (cross-SDK OIDC/SSO conformance review; CONTRACT.md §12.1
// note 2 / §5 rule 2): X-Tenant-ID is unconditional, including on an
// /oauth2/* request built from a discovery document that legitimately
// advertises its token/introspection/revocation endpoints on a host
// different from the Client's own base URL (a proxy-fronted deployment).
// Before the fix, decorateRequest's foreign-host guard dropped the header
// there. No repo in the review had an end-to-end test proving the header
// actually reaches a real POST /oauth2/token request in this scenario —
// this is that test.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// newForeignHostOidcServers returns two servers standing in for a
// proxy-fronted AXIAM deployment: origin serves discovery (and is the
// Client's base URL), and tokenHost serves the actual /oauth2/token
// endpoint the discovery document advertises — a genuinely different host.
func newForeignHostOidcServers(t *testing.T, tokenHandler http.HandlerFunc) (origin, tokenHost *httptest.Server) {
	t.Helper()

	tokenMux := http.NewServeMux()
	tokenMux.HandleFunc("/oauth2/token", tokenHandler)
	tokenHost = httptest.NewServer(tokenMux)
	t.Cleanup(tokenHost.Close)

	originMux := http.NewServeMux()
	originMux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		doc := discoveryDoc(tokenHost.URL) // every endpoint, including TokenEndpoint, on the foreign host
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})
	origin = httptest.NewServer(originMux)
	t.Cleanup(origin.Close)

	return origin, tokenHost
}

// TestLoginClientCredentials_EmitsTenantHeaderOnForeignHostTokenEndpoint
// proves F-15 end-to-end: a real POST /oauth2/token request, issued against
// an endpoint discovery advertised on a host different from the Client's
// base URL, still carries X-Tenant-ID.
func TestLoginClientCredentials_EmitsTenantHeaderOnForeignHostTokenEndpoint(t *testing.T) {
	var gotTenantHeader, gotCSRFHeader string
	origin, _ := newForeignHostOidcServers(t, func(w http.ResponseWriter, r *http.Request) {
		gotTenantHeader = r.Header.Get("X-Tenant-ID")
		gotCSRFHeader = r.Header.Get("X-CSRF-Token")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "foreign-host-access-token",
			"token_type":   "Bearer",
			"expires_in":   900,
		})
	})

	client, err := NewClient(origin.URL, "acme-corp",
		WithOidcClientID("rp-1"), WithOidcClientSecret("rp-secret"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	if _, err := client.LoginClientCredentials(context.Background(), LoginClientCredentialsParams{
		TenantID: testTenantUUID,
	}); err != nil {
		t.Fatalf("LoginClientCredentials: %v", err)
	}

	if gotTenantHeader != "acme-corp" {
		t.Fatalf("expected X-Tenant-ID=acme-corp on the foreign-host /oauth2/token request, got %q", gotTenantHeader)
	}
	// CSRF stays host-guarded — this is not a §5 rule 2 requirement, and
	// leaking a captured CSRF token cross-host would be a real defect.
	if gotCSRFHeader != "" {
		t.Fatalf("X-CSRF-Token leaked to the foreign token host: %q", gotCSRFHeader)
	}
}
