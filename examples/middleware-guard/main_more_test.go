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

// TestDocsRoute_RequireAccess drives GET /docs/{id} through both the §10
// identity middleware AND the §11 middleware.RequireAccess wrap main()
// installs on that route, against a fake authz backend — proving the two
// layers compose: an authenticated, authorized request reaches docHandler,
// while a denied one is rejected with 403 before docHandler ever runs.
func TestDocsRoute_RequireAccess(t *testing.T) {
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
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksBody)
	}))
	defer jwksSrv.Close()

	verifier, err := axiam.NewJWKSVerifier(context.Background(), jwksSrv.URL, jwksSrv.Client())
	if err != nil {
		t.Fatalf("NewJWKSVerifier: %v", err)
	}

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
	})
	token, err := jws.Sign(payload, jws.WithKey(jwa.EdDSA(), pk))
	if err != nil {
		t.Fatalf("jws.Sign: %v", err)
	}

	// A fake authz backend: allow doc-1, deny anything else — lets the same
	// test prove both the allow and deny→403 paths.
	authzSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ResourceID string `json:"resource_id"`
			SubjectID  string `json:"subject_id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.SubjectID != "user-123" {
			t.Errorf("expected subject_id %q on the wire, got %q", "user-123", body.SubjectID)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"allowed": body.ResourceID == "doc-1"})
	}))
	defer authzSrv.Close()

	client, err := axiam.NewClient(authzSrv.URL, tenant)
	if err != nil {
		t.Fatalf("axiam.NewClient: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/docs/{id}", middleware.RequireAccess(client, "documents:read", middleware.ResourceFromPath("id"))(http.HandlerFunc(docHandler)))
	guarded := middleware.Middleware(verifier, tenant)(mux)

	t.Run("allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/docs/doc-1", nil)
		req.SetPathValue("id", "doc-1")
		req.Header.Set("Authorization", "Bearer "+string(token))
		rec := httptest.NewRecorder()
		guarded.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d (%s)", rec.Code, rec.Body.String())
		}
		if body := rec.Body.String(); !strings.Contains(body, "doc-1") || !strings.Contains(body, "user-123") {
			t.Fatalf("expected the response to name the document and user, got %q", body)
		}
	})

	t.Run("denied", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/docs/doc-2", nil)
		req.SetPathValue("id", "doc-2")
		req.Header.Set("Authorization", "Bearer "+string(token))
		rec := httptest.NewRecorder()
		guarded.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d (%s)", rec.Code, rec.Body.String())
		}
	})

	t.Run("unauthenticated", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/docs/doc-1", nil)
		rec := httptest.NewRecorder()
		guarded.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d (%s)", rec.Code, rec.Body.String())
		}
	})
}
