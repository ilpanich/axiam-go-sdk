package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestMiddleware_XTenantHeaderMismatchRejected covers the header-vs-claim
// agreement branch: a signature-valid token for the configured tenant is still
// rejected (401) when an accompanying X-Tenant-ID header disagrees with the
// token's own tenant_id claim (WR-04). The header can never override the claim.
func TestMiddleware_XTenantHeaderMismatchRejected(t *testing.T) {
	priv, pubJWK := generateTestKey(t, "kid-1")
	jwksSrv := newTestJWKSServer(t, pubJWK)
	verifier := newTestVerifier(t, jwksSrv)

	mw := Middleware(verifier, testConfiguredTenant)
	rec := &recordingHandler{}
	h := mw(rec.handler())

	token := signTestToken(t, priv, "kid-1", validClaims())
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	// The header asserts a different tenant than the token's tenant_id claim.
	req.Header.Set("X-Tenant-ID", "some-other-tenant")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if rec.called {
		t.Fatal("wrapped handler must not run when X-Tenant-ID disagrees with the token claim")
	}
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 on X-Tenant-ID/claim mismatch, got %d", w.Code)
	}
}

// TestMiddleware_XTenantHeaderMatchingAllowed is the positive control: the same
// request with an X-Tenant-ID header that agrees with the token claim passes.
func TestMiddleware_XTenantHeaderMatchingAllowed(t *testing.T) {
	priv, pubJWK := generateTestKey(t, "kid-1")
	jwksSrv := newTestJWKSServer(t, pubJWK)
	verifier := newTestVerifier(t, jwksSrv)

	mw := Middleware(verifier, testConfiguredTenant)
	rec := &recordingHandler{}
	h := mw(rec.handler())

	token := signTestToken(t, priv, "kid-1", validClaims())
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Tenant-ID", testConfiguredTenant)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	if !rec.called || w.Code != http.StatusOK {
		t.Fatalf("expected 200 when X-Tenant-ID matches the claim, got code=%d called=%v", w.Code, rec.called)
	}
}
