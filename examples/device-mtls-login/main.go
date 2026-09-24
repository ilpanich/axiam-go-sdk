// Command device-mtls-login is the minimal shape of CONTRACT.md §6.1's mTLS
// device login: configure a client certificate, call AuthenticateDevice, use
// the client.
//
// This is deliberately smaller than examples/device-mtls-provisioning, which
// also covers minting and binding the certificate as an operator. Read this
// one first if all you want is "how does a device that already HAS a
// certificate sign in"; read the other one for the whole lifecycle.
//
// examples/device-login (RFC 8628, the Device Authorization Grant — a human
// with a browser elsewhere, no certificate involved) is a different
// operation with a similar name; the two are not interchangeable, and this
// example exists partly so the two stop being confused with each other.
//
// This example is illustrative/compilable — it reads connection details
// from environment variables and does not require a live AXIAM server to
// `go build ./examples/device-mtls-login/...`.
//
//	AXIAM_URL=https://axiam.example.com \
//	AXIAM_TENANT=acme \
//	AXIAM_DEVICE_CERT=./device-cert.pem \
//	AXIAM_DEVICE_KEY=./device-key.pem \
//	go run ./examples/device-mtls-login
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	axiam "github.com/ilpanich/axiam-go-sdk"
)

func env(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func mustReadFile(name, path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("read %s (%s): %v", name, path, err)
	}
	return b
}

func main() {
	certPEM := mustReadFile("AXIAM_DEVICE_CERT", env("AXIAM_DEVICE_CERT", "./device-cert.pem"))
	keyPEM := mustReadFile("AXIAM_DEVICE_KEY", env("AXIAM_DEVICE_KEY", "./device-key.pem"))

	opts := []axiam.Option{axiam.WithClientCertificate(certPEM, keyPEM)}
	if ca := os.Getenv("AXIAM_ORG_CA"); ca != "" {
		opts = append(opts, axiam.WithCustomCA(mustReadFile("AXIAM_ORG_CA", ca)))
	}

	client, err := axiam.NewClient(
		env("AXIAM_URL", "https://axiam.example.com"),
		env("AXIAM_TENANT", "acme"),
		opts...,
	)
	if err != nil {
		log.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	ctx := context.Background()

	// CONTRACT.md §6.1 rule 7: calling this on a Client built WITHOUT
	// WithClientCertificate fails client-side, with zero wire calls — try
	// removing the two Option lines above and re-running to see it.
	token, err := client.AuthenticateDevice(ctx)
	if err != nil {
		// §6.1 rule 8: every refusal here — unknown/untrusted/expired/
		// revoked/unbound certificate, or a Server-type certificate — is a
		// 401 mapped to *axiam.AuthError. There is no refresh token to fall
		// back to (rule 6): the recovery path is calling AuthenticateDevice
		// again, typically after fixing whatever made the certificate
		// unusable.
		log.Fatalf("AuthenticateDevice: %v", err)
	}
	fmt.Printf("authenticated: %s token, expires in %ds\n", token.TokenType, token.ExpiresIn)

	// The token is now adopted as this Client's credential for the REST
	// management surface and CheckAccess/BatchCheck — no further wiring
	// needed. It is a service-account token (aud=axiam:m2m), so what it can
	// do is exactly what CONTRACT.md §27.13's S-9 note lists plus
	// check_access/batch_check.
	allowed, reason, err := client.CheckAccess(ctx, "telemetry:publish", "device/self")
	if err != nil {
		log.Fatalf("CheckAccess: %v", err)
	}
	fmt.Printf("may publish telemetry: %v (%s)\n", allowed, reason)
}
