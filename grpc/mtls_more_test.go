package grpc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	grpclib "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	axiamv1 "github.com/ilpanich/axiam-go-sdk/internal/gen/axiam/v1"
)

// grpcMTLSPKI is an in-process test PKI for the gRPC mTLS tests: a CA, a
// server leaf (valid for 127.0.0.1), and a client identity signed by the CA.
// Nothing is committed — all material is minted at test time (§6.1).
type grpcMTLSPKI struct {
	caCertPEM     []byte
	serverCert    tls.Certificate
	clientCertPEM []byte
	clientKeyPEM  []byte
}

func newGRPCMTLSPKI(t *testing.T) grpcMTLSPKI {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "axiam-grpc-mtls-ca"},
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
	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	mkLeaf := func(cn string, eku x509.ExtKeyUsage, serial int64, withServerIP bool) (certPEM, keyPEM []byte) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate leaf key: %v", err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{eku},
		}
		if withServerIP {
			tmpl.IPAddresses = []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
			tmpl.DNSNames = []string{"localhost"}
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
		if err != nil {
			t.Fatalf("create leaf cert: %v", err)
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatalf("marshal leaf key: %v", err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
			pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	}

	serverCertPEM, serverKeyPEM := mkLeaf("axiam-grpc-server", x509.ExtKeyUsageServerAuth, 2, true)
	serverCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		t.Fatalf("build server keypair: %v", err)
	}
	clientCertPEM, clientKeyPEM := mkLeaf("axiam-grpc-client", x509.ExtKeyUsageClientAuth, 3, false)

	return grpcMTLSPKI{
		caCertPEM:     caCertPEM,
		serverCert:    serverCert,
		clientCertPEM: clientCertPEM,
		clientKeyPEM:  clientKeyPEM,
	}
}

// startMTLSServer starts a gRPC server that REQUIRES and verifies a client
// certificate against the test CA. No service is registered — the handshake
// is what these tests exercise; an authenticated RPC therefore yields
// codes.Unimplemented, while a failed handshake yields codes.Unavailable.
func startMTLSServer(t *testing.T, pki grpcMTLSPKI) string {
	t.Helper()

	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(pki.caCertPEM) {
		t.Fatal("failed to build server ClientCAs pool")
	}
	creds := credentials.NewTLS(&tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{pki.serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
	})

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpclib.NewServer(grpclib.Creds(creds))
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return lis.Addr().String()
}

// probeCheckAccess makes a single CheckAccess RPC through creds and returns
// the resulting gRPC status code (used to distinguish a completed handshake
// from a rejected one).
func probeCheckAccess(t *testing.T, target string, creds credentials.TransportCredentials) codes.Code {
	t.Helper()
	conn, err := NewGRPCClient(target, creds, authUnaryInterceptor(func() (string, bool) { return "", false }, "tenant"))
	if err != nil {
		t.Fatalf("NewGRPCClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = axiamv1.NewAuthorizationServiceClient(conn).CheckAccess(ctx, &axiamv1.CheckAccessRequest{})
	return status.Code(err)
}

// TestNewTLSCredentials_MTLSHandshake proves §6.1 for the gRPC transport: a
// channel built with a client certificate completes the mutual-TLS handshake
// against a server that requires one (reaching the server, which returns
// Unimplemented), while a channel without the client cert is rejected at the
// handshake (Unavailable). Server verification stays strict throughout.
func TestNewTLSCredentials_MTLSHandshake(t *testing.T) {
	pki := newGRPCMTLSPKI(t)
	target := startMTLSServer(t, pki)

	withCert, err := NewTLSCredentials(pki.caCertPEM, pki.clientCertPEM, pki.clientKeyPEM)
	if err != nil {
		t.Fatalf("NewTLSCredentials with client cert: %v", err)
	}
	if code := probeCheckAccess(t, target, withCert); code != codes.Unimplemented {
		t.Fatalf("with a client certificate the handshake should complete (want Unimplemented), got %s", code)
	}

	noCert, err := NewTLSCredentials(pki.caCertPEM, nil, nil)
	if err != nil {
		t.Fatalf("NewTLSCredentials without client cert: %v", err)
	}
	if code := probeCheckAccess(t, target, noCert); code != codes.Unavailable {
		t.Fatalf("without a client certificate the handshake should fail (want Unavailable), got %s", code)
	}
}

// TestNewTLSCredentials_InvalidClientCert proves §6.1 rule 1 on the gRPC
// side: a malformed client cert/key pair is a construction-time error.
func TestNewTLSCredentials_InvalidClientCert(t *testing.T) {
	if _, err := NewTLSCredentials(nil, []byte("not a cert"), []byte("not a key")); err == nil {
		t.Fatal("expected an error for an invalid client cert/key PEM")
	}
}
