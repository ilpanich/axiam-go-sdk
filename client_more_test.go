package axiam

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// selfSignedCAPEM produces a valid PEM-encoded self-signed certificate so the
// buildHTTPClient custom-CA success path (AppendCertsFromPEM -> RootCAs) can be
// exercised without a fixture file.
func selfSignedCAPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "axiam-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// TestNewClient_ValidCustomCA covers the custom-CA success branch: a valid PEM
// is appended to a fresh RootCAs pool and the client is constructed.
func TestNewClient_ValidCustomCA(t *testing.T) {
	client, err := NewClient("https://example.test", "acme", WithCustomCA(selfSignedCAPEM(t)))
	if err != nil {
		t.Fatalf("expected a valid custom CA to be accepted, got %v", err)
	}
	transport, ok := client.httpClient().Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil || transport.TLSClientConfig.RootCAs == nil {
		t.Fatalf("expected the custom CA to populate RootCAs, got %+v", transport)
	}
}

// TestNewClient_InvalidBaseURL covers the url.Parse error branch of NewClient.
func TestNewClient_InvalidBaseURL(t *testing.T) {
	_, err := NewClient("http://\x7f\x00/bad", "acme")
	var netErr *NetworkError
	if !isNetworkError(err, &netErr) {
		t.Fatalf("expected *NetworkError for an unparseable baseURL, got %T: %v", err, err)
	}
}

// TestWithHTTPClient_ClonesExistingTransport covers buildHTTPClient's else
// branch: when the supplied base client already carries a *http.Transport, it
// is cloned (not replaced with the default) and the SDK re-applies its own TLS
// config and jar on top.
func TestWithHTTPClient_ClonesExistingTransport(t *testing.T) {
	base := &http.Client{Transport: &http.Transport{MaxIdleConns: 7}}
	client, err := NewClient("https://example.test", "acme", WithHTTPClient(base))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	transport, ok := client.httpClient().Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", client.httpClient().Transport)
	}
	// The caller's transport setting is preserved on the clone...
	if transport.MaxIdleConns != 7 {
		t.Fatalf("expected the caller's transport to be cloned (MaxIdleConns=7), got %d", transport.MaxIdleConns)
	}
	// ...but it is a distinct instance (clone), not the caller's original.
	if transport == base.Transport {
		t.Fatal("the SDK must clone, not mutate, the caller's transport")
	}
	// And the SDK's TLS floor always wins.
	if transport.TLSClientConfig == nil {
		t.Fatal("SDK TLS config must be applied to the cloned transport")
	}
}

// TestRedirect_StopsAfterTenHops covers the CheckRedirect ceiling: a server
// that redirects to itself indefinitely is stopped after 10 hops rather than
// looping forever.
func TestRedirect_StopsAfterTenHops(t *testing.T) {
	var hits int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		http.Redirect(w, r, "/again", http.StatusFound)
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "acme")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.doRequest(newTestRequest(t, http.MethodGet, server.URL+"/", nil))
	if err == nil {
		t.Fatal("expected an error once the redirect ceiling is reached")
	}
	if hits < 10 {
		t.Fatalf("expected at least 10 redirect hops before stopping, got %d", hits)
	}
}

// TestNewRequest_InvalidMethod covers newRequest's construction-error branch: an
// invalid HTTP method token makes http.NewRequestWithContext fail, which the
// SDK wraps as a NetworkError.
func TestNewRequest_InvalidMethod(t *testing.T) {
	client, err := NewClient("https://example.test", "acme")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.newRequest(context.Background(), "BAD METHOD", "/x", nil)
	var netErr *NetworkError
	if !isNetworkError(err, &netErr) {
		t.Fatalf("expected *NetworkError for an invalid method, got %T: %v", err, err)
	}
}
