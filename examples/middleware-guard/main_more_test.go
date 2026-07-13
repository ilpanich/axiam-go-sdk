package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"

	axiam "github.com/ilpanich/axiam-go-sdk"
	"github.com/ilpanich/axiam-go-sdk/middleware"
)

// TestProtectedHandler_ServesAuthenticatedUser drives the example's
// protectedHandler through the real middleware pipeline: a JWKS server plus a
// signed same-tenant token cause the middleware to inject a *User into the
// request context, which protectedHandler reads back and greets. This covers
// the handler's success path (the branch TestProtectedHandler_NoUser cannot
// reach). main() itself is not exercised here — it blocks in ListenAndServe.
func TestProtectedHandler_ServesAuthenticatedUser(t *testing.T) {
	const tenant = "acme"
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pubJWK, err := jwk.Import(pub)
	if err != nil {
		t.Fatalf("jwk.Import: %v", err)
	}
	if err := pubJWK.Set(jwk.KeyIDKey, "kid-1"); err != nil {
		t.Fatalf("set kid: %v", err)
	}
	if err := pubJWK.Set(jwk.AlgorithmKey, jwa.EdDSA()); err != nil {
		t.Fatalf("set alg: %v", err)
	}

	set := jwk.NewSet()
	if err := set.AddKey(pubJWK); err != nil {
		t.Fatalf("AddKey: %v", err)
	}
	jwksBody, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}

	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth2/jwks" {
			t.Errorf("unexpected JWKS path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksBody)
	}))
	defer jwksSrv.Close()

	verifier, err := axiam.NewJWKSVerifier(context.Background(), jwksSrv.URL, jwksSrv.Client())
	if err != nil {
		t.Fatalf("NewJWKSVerifier: %v", err)
	}

	// Sign a same-tenant token the middleware will accept.
	pk, err := jwk.Import(priv)
	if err != nil {
		t.Fatalf("jwk.Import priv: %v", err)
	}
	if err := pk.Set(jwk.KeyIDKey, "kid-1"); err != nil {
		t.Fatalf("set kid: %v", err)
	}
	payload, _ := json.Marshal(map[string]any{
		"sub":       "user-123",
		"tenant_id": tenant,
		"org_id":    "org-xyz",
		"exp":       time.Now().Add(time.Hour).Unix(),
		"scope":     "admin reader",
	})
	token, err := jws.Sign(payload, jws.WithKey(jwa.EdDSA(), pk))
	if err != nil {
		t.Fatalf("jws.Sign: %v", err)
	}

	guarded := middleware.Middleware(verifier, tenant)(http.HandlerFunc(protectedHandler))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+string(token))
	rec := httptest.NewRecorder()
	guarded.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for an authenticated request, got %d (%s)", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, "user-123") || !strings.Contains(body, tenant) {
		t.Fatalf("expected the greeting to name the user and tenant, got %q", body)
	}
}
