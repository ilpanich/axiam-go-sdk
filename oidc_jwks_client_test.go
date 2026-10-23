package axiam

// C163-16: the JWKS fetch behind the OIDC relying-party helpers goes out on
// the SDK's own http.Client — its CA, its client certificate, its timeout —
// not on the JWKS library's default.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestOidcJWKSFetchPresentsTheClientsCertificate(t *testing.T) {
	pki := newMTLSPKI(t)
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(pki.caCertPEM) {
		t.Fatal("failed to build ClientCAs pool")
	}
	priv, pub := generateOidcTestKey(t, "kid-1")
	var withCert int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && len(r.TLS.PeerCertificates) == 1 &&
			r.TLS.PeerCertificates[0].Subject.CommonName == "axiam-mtls-test-client" {
			atomic.AddInt32(&withCert, 1)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(marshalOidcJWKS(t, pub))
	}))
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientCAs}
	srv.StartTLS()
	defer srv.Close()

	client, err := NewClient(srv.URL, "acme",
		WithCustomCA(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})),
		WithClientCertificate(pki.clientCertPEM, pki.clientKeyPEM),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	// A bounded context, so that a regression fails here instead of hanging.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	verifier, err := client.oidcJWKSVerifier(ctx, srv.URL+"/oauth2/jwks")
	if err != nil {
		t.Fatalf("oidcJWKSVerifier: %v", err)
	}
	token := signIDTokenEdDSA(t, priv, "kid-1", map[string]any{"sub": "u"})
	if _, err := verifier.VerifyPayload(ctx, []byte(token)); err != nil {
		t.Fatalf("VerifyPayload over mTLS: %v", err)
	}
	if atomic.LoadInt32(&withCert) == 0 {
		t.Error("the JWKS fetch did not present the SDK's client certificate")
	}
}

func TestOidcJWKSFetchHonoursTheClientsTimeout(t *testing.T) {
	// The server never answers; it reports how long the client waited before
	// giving up. The library's cache keeps retrying a failed first fetch until
	// its context ends, so the observable is the server's side of the first
	// request, not the verifier's return.
	aborted := make(chan time.Duration, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		select {
		case <-r.Context().Done():
			select {
			case aborted <- time.Since(start):
			default:
			}
		case <-time.After(30 * time.Second):
		}
	}))
	defer srv.Close()

	client, err := NewClient(srv.URL, "acme", WithTimeout(300*time.Millisecond))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	priv, _ := generateOidcTestKey(t, "kid-1")
	token := signIDTokenEdDSA(t, priv, "kid-1", map[string]any{"sub": "u"})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		if verifier, err := client.oidcJWKSVerifier(ctx, srv.URL+"/oauth2/jwks"); err == nil {
			_, _ = verifier.VerifyPayload(ctx, []byte(token))
		}
	}()
	select {
	case waited := <-aborted:
		if waited > 3*time.Second {
			t.Errorf("the client waited %v: the SDK's 300ms timeout was not applied", waited)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("the JWKS fetch was still waiting after 4s: the SDK's 300ms timeout was not applied")
	}
}
