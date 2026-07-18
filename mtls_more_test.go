package axiam

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// mtlsPKI is an in-process test PKI: a CA, plus a client identity (cert +
// key, PEM-encoded) signed by that CA. Generated entirely at test time via
// crypto/x509 — no private key or certificate is ever committed (§6.1 test
// guidance).
type mtlsPKI struct {
	caCertPEM     []byte
	clientCertPEM []byte
	clientKeyPEM  []byte
}

// newMTLSPKI mints a fresh CA and a client leaf certificate signed by it.
func newMTLSPKI(t *testing.T) mtlsPKI {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "axiam-mtls-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	clientTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "axiam-mtls-test-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTmpl, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create client cert: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(clientKey)
	if err != nil {
		t.Fatalf("marshal client key: %v", err)
	}

	return mtlsPKI{
		caCertPEM:     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		clientCertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER}),
		clientKeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	}
}

// TestWithClientCertificate_EndToEndMTLS proves §6.1: a client built with
// WithCustomCA + WithClientCertificate completes a request against a server
// that REQUIRES and verifies a client certificate, while an otherwise
// identical client WITHOUT the client cert fails the TLS handshake (surfaced
// as a *NetworkError). Server verification stays strict throughout.
func TestWithClientCertificate_EndToEndMTLS(t *testing.T) {
	pki := newMTLSPKI(t)

	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(pki.caCertPEM) {
		t.Fatal("failed to build ClientCAs pool")
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{
		MinVersion: tls.VersionTLS13,
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  clientCAs,
	}
	srv.StartTLS()
	defer srv.Close()

	// The server's own leaf certificate is what the client must trust — feed
	// it to WithCustomCA so server verification stays strictly ON.
	serverCAPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})

	// With the client certificate: handshake completes, request succeeds.
	withCert, err := NewClient(srv.URL, "acme",
		WithCustomCA(serverCAPEM),
		WithClientCertificate(pki.clientCertPEM, pki.clientKeyPEM),
	)
	if err != nil {
		t.Fatalf("NewClient with client cert: %v", err)
	}
	resp, err := withCert.doRequest(newTestRequest(t, http.MethodGet, srv.URL+"/", nil))
	if err != nil {
		t.Fatalf("mTLS request should succeed with a client certificate, got %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	// Without the client certificate: the server rejects the handshake.
	noCert, err := NewClient(srv.URL, "acme", WithCustomCA(serverCAPEM))
	if err != nil {
		t.Fatalf("NewClient without client cert: %v", err)
	}
	_, err = noCert.doRequest(newTestRequest(t, http.MethodGet, srv.URL+"/", nil))
	if err == nil {
		t.Fatal("expected the handshake to fail without a client certificate")
	}
	var netErr *NetworkError
	if !isNetworkError(err, &netErr) {
		t.Fatalf("expected *NetworkError for a failed mTLS handshake, got %T: %v", err, err)
	}
}

// TestWithClientCertificate_InvalidPEM proves §6.1 rule 1: a malformed
// cert/key pair is a construction-time error returned from NewClient,
// consistent with WithCustomCA's invalid-PEM handling.
func TestWithClientCertificate_InvalidPEM(t *testing.T) {
	_, err := NewClient("https://example.test", "acme",
		WithClientCertificate([]byte("not a cert"), []byte("not a key")),
	)
	if err == nil {
		t.Fatal("expected a construction-time error for an invalid client cert/key PEM")
	}
	var netErr *NetworkError
	if !isNetworkError(err, &netErr) {
		t.Fatalf("expected *NetworkError, got %T: %v", err, err)
	}
}

// TestWithClientCertificate_Configured proves the option populates
// tls.Config.Certificates on the built transport (the identity the client
// will present), without weakening server verification.
func TestWithClientCertificate_Configured(t *testing.T) {
	pki := newMTLSPKI(t)
	client, err := NewClient("https://example.test", "acme",
		WithClientCertificate(pki.clientCertPEM, pki.clientKeyPEM),
	)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	transport, ok := client.httpClient().Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil {
		t.Fatalf("expected a TLS transport, got %+v", transport)
	}
	if len(transport.TLSClientConfig.Certificates) != 1 {
		t.Fatalf("expected exactly one client certificate to be configured, got %d",
			len(transport.TLSClientConfig.Certificates))
	}
	assertTLSVerificationEnabled(t, transport.TLSClientConfig)
}
