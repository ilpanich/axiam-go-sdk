package grpc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	axiam "github.com/ilpanich/axiam-go-sdk"
)

// TestBatchCheck_NilRefreshMapsError covers BatchCheck's post-retry error
// branch: with a nil refresh func, a non-UNAUTHENTICATED gRPC error skips the
// refresh block and is mapped through mapGRPCError.
func TestBatchCheck_NilRefreshMapsError(t *testing.T) {
	conn := &scriptedConn{errs: []error{status.Error(codes.PermissionDenied, "forbidden")}}
	_, err := NewAuthzClient(conn, nil).BatchCheck(context.Background(), []CheckAccessRequest{{Action: "read"}})
	var authzErr *axiam.AuthzError
	if err == nil {
		t.Fatal("expected an error from a PermissionDenied batch")
	}
	if _, ok := err.(*axiam.AuthzError); !ok && authzErr == nil {
		// PermissionDenied maps to AuthzError; assert the mapping ran.
		t.Fatalf("expected the gRPC error to be mapped, got %T: %v", err, err)
	}
	if conn.calls != 1 {
		t.Fatalf("expected exactly 1 RPC with a nil refresh, got %d", conn.calls)
	}
}

// TestNewTLSCredentials_ValidCustomCA covers newTLSCredentials' custom-CA
// success branch: a valid PEM populates RootCAs and yields usable credentials.
func TestNewTLSCredentials_ValidCustomCA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "axiam-grpc-test-ca"},
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
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	creds, err := NewTLSCredentials(pemBytes, nil, nil)
	if err != nil {
		t.Fatalf("expected a valid custom CA to be accepted, got %v", err)
	}
	if creds.Info().SecurityProtocol != "tls" {
		t.Fatalf("expected tls protocol, got %q", creds.Info().SecurityProtocol)
	}
}
