// Package grpc implements the gRPC transport for AuthorizationService
// (CheckAccess/BatchCheckAccess) with strict TLS and a sync-safe auth/tenant
// interceptor (CONTRACT.md §5/§6, SC#3).
package grpc

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"google.golang.org/grpc/credentials"
)

// newTLSCredentials builds strict TLS transport credentials (TLS 1.3
// minimum, per CLAUDE.md's project-wide TLS floor). When customCAPEM is
// non-empty, it is added to the certificate verification pool; an invalid
// PEM returns an error. When clientCertPEM/clientKeyPEM are non-empty they
// configure a §6.1 client-certificate (mTLS) identity presented over the
// gRPC channel. Certificate verification is never disabled in this function
// — customCAPEM is the ONLY TLS-related escape hatch the SDK exposes, and
// presenting a client certificate never relaxes it (CONTRACT.md §6/§6.1,
// SC#3 absolute prohibition).
func newTLSCredentials(customCAPEM, clientCertPEM, clientKeyPEM []byte) (credentials.TransportCredentials, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13}

	if len(customCAPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(customCAPEM) {
			return nil, fmt.Errorf("grpc: invalid custom CA PEM")
		}
		tlsConfig.RootCAs = pool
	}

	// §6.1 client-certificate identity — separate code path from the
	// server-verification config above, so it never touches RootCAs or any
	// bypass surface. A malformed cert/key pair is a construction-time error.
	if len(clientCertPEM) > 0 || len(clientKeyPEM) > 0 {
		cert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("grpc: invalid client certificate/key PEM")
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	return credentials.NewTLS(tlsConfig), nil
}

// NewTLSCredentials is the exported entry point for constructing this
// package's strict TLS transport credentials (§6/§6.1) — the credentials.
// TransportCredentials value NewGRPCClient requires as its second argument.
// It is a thin, behavior-identical wrapper over newTLSCredentials: TLS 1.3
// minimum, no verification bypass, customCAPEM is the sole optional escape
// hatch for a development CA (mirrors WithCustomCA on the root REST Client).
//
// clientCertPEM/clientKeyPEM are optional; pass the SAME PEM cert chain and
// private key given to axiam.WithClientCertificate so the same logical
// client presents its mTLS identity over gRPC as well as REST (CONTRACT.md
// §6.1 "both transports"). Pass nil for both to keep the default
// bearer-token behavior. The private key bytes are secret (§7): callers must
// not log them.
func NewTLSCredentials(customCAPEM, clientCertPEM, clientKeyPEM []byte) (credentials.TransportCredentials, error) {
	return newTLSCredentials(customCAPEM, clientCertPEM, clientKeyPEM)
}
