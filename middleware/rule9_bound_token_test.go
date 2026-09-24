package middleware

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ilpanich/axiam-go-sdk/internal/jwks"
)

// ---------------------------------------------------------------------------
// CONTRACT.md §10.1 rule 9 at the guard entry point (contract 1.51 fix),
// through Middleware end to end — the Go analogue of the Rust reference's
// tests/actix_bound_token_test.rs: own certificate 200, a different one
// 401, unbound 200, jkt-bound 401.
//
// req.TLS is set directly on a manually-built *http.Request rather than
// driven over a real TLS handshake: net/http populates that same field, by
// the same route (r.TLS), for a request that actually arrived over mutual
// TLS, so a test that sets it directly exercises exactly the code path
// Middleware reads without paying for a live listener.
// ---------------------------------------------------------------------------

func generateTestCertificate(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

// requestWithPeerCertificate builds a GET request carrying an
// Authorization: Bearer token and, when cert is non-nil, a TLS connection
// state naming it as the peer certificate — exactly the shape
// net/http populates on r.TLS for a real mutual-TLS request.
func requestWithPeerCertificate(token string, cert *x509.Certificate) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	if cert != nil {
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	}
	return req
}

func TestMiddleware_Rule9_OwnCertificateAccepted(t *testing.T) {
	priv, pubJWK := generateTestKey(t, "kid-1")
	jwksSrv := newTestJWKSServer(t, pubJWK)
	verifier := newTestVerifier(t, jwksSrv)

	cert := generateTestCertificate(t, "device-1")
	thumb := jwks.CertificateThumbprintS256(cert.Raw)

	payload, err := json.Marshal(map[string]any{
		"sub": "device-1", "tenant_id": testConfiguredTenant, "org_id": "org-xyz",
		"exp": time.Now().Add(time.Hour).Unix(),
		"cnf": map[string]string{"x5t#S256": thumb},
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	token := signTestTokenRaw(t, priv, "kid-1", payload)

	h := &recordingHandler{}
	mw := Middleware(verifier, testConfiguredTenant)(h.handler())

	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, requestWithPeerCertificate(token, cert))

	if rec.Code != http.StatusOK {
		t.Fatalf("own certificate: got %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if !h.called {
		t.Fatal("expected the wrapped handler to be called")
	}
}

func TestMiddleware_Rule9_DifferentCertificateRejected(t *testing.T) {
	priv, pubJWK := generateTestKey(t, "kid-1")
	jwksSrv := newTestJWKSServer(t, pubJWK)
	verifier := newTestVerifier(t, jwksSrv)

	own := generateTestCertificate(t, "device-1")
	other := generateTestCertificate(t, "device-2")
	ownThumb := jwks.CertificateThumbprintS256(own.Raw)

	payload, err := json.Marshal(map[string]any{
		"sub": "device-1", "tenant_id": testConfiguredTenant, "org_id": "org-xyz",
		"exp": time.Now().Add(time.Hour).Unix(),
		"cnf": map[string]string{"x5t#S256": ownThumb},
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	token := signTestTokenRaw(t, priv, "kid-1", payload)

	h := &recordingHandler{}
	mw := Middleware(verifier, testConfiguredTenant)(h.handler())

	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, requestWithPeerCertificate(token, other))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("SECURITY: a DIFFERENT certificate got %d, want 401", rec.Code)
	}
	if h.called {
		t.Fatal("SECURITY: the wrapped handler must not run for a mismatched certificate")
	}
}

func TestMiddleware_Rule9_NoCertificateRejectedForABoundToken(t *testing.T) {
	priv, pubJWK := generateTestKey(t, "kid-1")
	jwksSrv := newTestJWKSServer(t, pubJWK)
	verifier := newTestVerifier(t, jwksSrv)

	cert := generateTestCertificate(t, "device-1")
	thumb := jwks.CertificateThumbprintS256(cert.Raw)

	payload, err := json.Marshal(map[string]any{
		"sub": "device-1", "tenant_id": testConfiguredTenant, "org_id": "org-xyz",
		"exp": time.Now().Add(time.Hour).Unix(),
		"cnf": map[string]string{"x5t#S256": thumb},
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	token := signTestTokenRaw(t, priv, "kid-1", payload)

	h := &recordingHandler{}
	mw := Middleware(verifier, testConfiguredTenant)(h.handler())

	rec := httptest.NewRecorder()
	// No r.TLS at all — the "behind a terminator that forwards nothing"
	// case CONTRACT.md §10.1 rule 9 normative detail 3 requires refusing.
	mw.ServeHTTP(rec, requestWithPeerCertificate(token, nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("SECURITY: a bound token with NO connection evidence got %d, want 401", rec.Code)
	}
	if h.called {
		t.Fatal("SECURITY: the wrapped handler must not run with no certificate evidence")
	}
}

func TestMiddleware_Rule9_UnboundTokenAcceptedWithOrWithoutACertificate(t *testing.T) {
	priv, pubJWK := generateTestKey(t, "kid-1")
	jwksSrv := newTestJWKSServer(t, pubJWK)
	verifier := newTestVerifier(t, jwksSrv)

	token := signTestToken(t, priv, "kid-1", validClaims())
	cert := generateTestCertificate(t, "unrelated")

	t.Run("no certificate on the connection", func(t *testing.T) {
		h := &recordingHandler{}
		mw := Middleware(verifier, testConfiguredTenant)(h.handler())
		rec := httptest.NewRecorder()
		mw.ServeHTTP(rec, requestWithPeerCertificate(token, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("an unbound token with no certificate got %d, want 200", rec.Code)
		}
	})

	t.Run("an UNRELATED certificate is present on the connection", func(t *testing.T) {
		h := &recordingHandler{}
		mw := Middleware(verifier, testConfiguredTenant)(h.handler())
		rec := httptest.NewRecorder()
		mw.ServeHTTP(rec, requestWithPeerCertificate(token, cert))
		if rec.Code != http.StatusOK {
			t.Fatalf("an unbound token must still verify even with an UNRELATED certificate present, got %d", rec.Code)
		}
	})
}

func TestMiddleware_Rule9_JktBoundTokenRejected(t *testing.T) {
	// This guard verifies no DPoP proof, so a jkt-bound token is refused
	// unconditionally — with or without a certificate on the connection.
	priv, pubJWK := generateTestKey(t, "kid-1")
	jwksSrv := newTestJWKSServer(t, pubJWK)
	verifier := newTestVerifier(t, jwksSrv)

	payload, err := json.Marshal(map[string]any{
		"sub": "user-1", "tenant_id": testConfiguredTenant, "org_id": "org-xyz",
		"exp": time.Now().Add(time.Hour).Unix(),
		"cnf": map[string]string{"jkt": "some-dpop-key-thumbprint"},
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	token := signTestTokenRaw(t, priv, "kid-1", payload)

	h := &recordingHandler{}
	mw := Middleware(verifier, testConfiguredTenant)(h.handler())

	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, requestWithPeerCertificate(token, nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("SECURITY: a jkt-bound token got %d, want 401 — this guard cannot verify DPoP proofs", rec.Code)
	}
	if h.called {
		t.Fatal("SECURITY: the wrapped handler must not run for a jkt-bound token")
	}
}
