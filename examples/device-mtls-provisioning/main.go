// Command device-mtls-provisioning provisions an IoT device with an mTLS
// identity, then authenticates as that device.
//
// Two halves, and the split between them is the point.
//
// The OPERATOR half runs once, on a machine an administrator controls, against
// an authenticated §27 management client. It creates the device's service
// account, mints a Device certificate from the tenant's signing CA, binds the
// two, and writes the private key to disk. That key is returned by exactly one
// call and never again (§27.5 rule 3) — no later Get has a field where it was —
// so losing the response means revoking the certificate and minting another.
//
// The DEVICE half runs on the device, forever after, with no password and no
// management access at all. It presents the certificate and key as a §6.1
// mutual TLS identity and does nothing else privileged.
//
// This example is illustrative/compilable — it reads connection details from
// environment variables and does not require a live AXIAM server to
// `go build ./examples/device-mtls-provisioning/...`.
//
//	AXIAM_URL=https://axiam.example.com \
//	AXIAM_TENANT=acme \
//	AXIAM_ADMIN=admin@example.com \
//	AXIAM_ADMIN_PASSWORD=... \
//	go run ./examples/device-mtls-provisioning provision sensor-42
//
//	go run ./examples/device-mtls-provisioning run sensor-42
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	axiam "github.com/ilpanich/axiam-go-sdk"
)

func env(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func identityDir() string { return env("AXIAM_DEVICE_DIR", "./device-identity") }

// writeSecret writes content readable only by this user.
//
// The mode is set at creation rather than afterwards: a chmod after the fact
// leaves a window in which the private key is world-readable, which on a shared
// provisioning host is the whole exposure.
func writeSecret(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(content)
	return err
}

func newOperatorClient() (*axiam.Client, error) {
	opts := []axiam.Option{}
	if ca := os.Getenv("AXIAM_ORG_CA"); ca != "" {
		pem, err := os.ReadFile(ca)
		if err != nil {
			return nil, fmt.Errorf("read AXIAM_ORG_CA: %w", err)
		}
		opts = append(opts, axiam.WithCustomCA(pem))
	}
	return axiam.NewClient(env("AXIAM_URL", "https://axiam.example.com"), env("AXIAM_TENANT", "acme"), opts...)
}

// provision creates the device's identity and writes it to disk, once.
//
// Every step here is a §27 management call, and every one of them is a write
// that is issued exactly once — §27.4 rule 8 does not retry writes, because
// generating a certificate twice mints two and only one of them is the one
// written to disk.
func provision(ctx context.Context, deviceName string) error {
	client, err := newOperatorClient()
	if err != nil {
		return err
	}
	defer client.Close()

	if _, err := client.Login(ctx, env("AXIAM_ADMIN", "admin@example.com"),
		os.Getenv("AXIAM_ADMIN_PASSWORD")); err != nil {
		return fmt.Errorf("login: %w", err)
	}

	// 1. The signing CA this tenant's device certificates chain to.
	//
	// {org_id} defaults from the client (§27.4 rule 3). {tenant_id} does NOT on
	// this route: under CACertificates it names the tenant being administered
	// rather than the calling context, so it is an ordinary argument.
	// ResolvedTenantID is the UUID login decoded from the access token.
	tenantID, ok := client.ResolvedTenantID()
	if !ok {
		return errors.New("login did not resolve a tenant UUID; cannot address signing CAs")
	}
	signingCAs, err := client.CACertificates().ListSigningCasAll(ctx, tenantID, axiam.Limited(100))
	if err != nil {
		return fmt.Errorf("list signing CAs: %w", err)
	}
	var issuer *axiam.CACertificate
	for i := range signingCAs {
		if signingCAs[i].Status == axiam.CertificateStatusActive {
			issuer = &signingCAs[i]
			break
		}
	}
	if issuer == nil {
		return fmt.Errorf("tenant %q has no active signing CA; generate one with "+
			"CACertificates().GenerateSigningCA before provisioning devices", env("AXIAM_TENANT", "acme"))
	}

	// 2. The service account the device authenticates as.
	account, err := client.ServiceAccounts().Create(ctx, axiam.CreateServiceAccountRequest{
		Name:        deviceName,
		Description: ptr(fmt.Sprintf("IoT device %s, mTLS identity", deviceName)),
	})
	if err != nil {
		// Already provisioned. Re-minting a certificate for an existing account
		// is a decision an operator should make deliberately, so this stops
		// rather than quietly issuing a second identity.
		if errors.Is(err, axiam.ErrConflict) {
			return fmt.Errorf("a service account named %q already exists; revoke its "+
				"certificate and delete it first, or pick another name", deviceName)
		}
		return fmt.Errorf("create service account: %w", err)
	}

	// 3. The certificate. PrivateKeyPEM comes back from THIS call and no other
	//    — Certificates().Get has no field where it was.
	certificate, err := client.Certificates().Generate(ctx, axiam.CreateCertificateRequest{
		IssuerCAID:   issuer.ID,
		Subject:      fmt.Sprintf("CN=%s,OU=devices,O=%s", deviceName, env("AXIAM_TENANT", "acme")),
		CertType:     axiam.CertificateTypeDevice,
		KeyAlgorithm: axiam.KeyAlgorithmEd25519,
		ValidityDays: 825,
	})
	if err != nil {
		var invalid *axiam.ValidationError
		if errors.As(err, &invalid) {
			// A 400/422 here is usually the operator's input, not a bug: a
			// subject the CA policy rejects, a validity beyond the cap.
			for _, f := range invalid.Fields {
				log.Printf("  %s: %s", f.Field, f.Message)
			}
		}
		return fmt.Errorf("generate certificate: %w", err)
	}

	// 4. Write it down before doing anything else that could fail. The key is a
	//    Sensitive, so it is redacted from every fmt verb and JSON rendering —
	//    printing `certificate` anywhere shows [SENSITIVE].
	keyPath := filepath.Join(identityDir(), deviceName+"-key.pem")
	if err := writeSecret(keyPath, certificate.PrivateKeyPEM.Expose()); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}
	chain := certificate.PublicCertPEM
	if certificate.ChainPEM != nil {
		chain += *certificate.ChainPEM
	}
	certPath := filepath.Join(identityDir(), deviceName+"-cert.pem")
	if err := os.WriteFile(certPath, []byte(chain), 0o644); err != nil {
		return fmt.Errorf("write certificate: %w", err)
	}

	// 5. Bind the certificate to the account, so presenting it authenticates as
	//    that principal.
	if err := client.ServiceAccounts().BindCertificate(ctx, account.ID,
		axiam.BindCertificate{CertificateID: certificate.ID}); err != nil {
		return fmt.Errorf("bind certificate: %w", err)
	}

	fmt.Printf("provisioned %s\n", deviceName)
	fmt.Printf("  service account : %s\n", account.ID)
	fmt.Printf("  certificate     : %s (%s)\n", certificate.ID, certificate.Fingerprint)
	fmt.Printf("  valid until     : %s\n", certificate.NotAfter)
	fmt.Printf("  identity written: %s/\n", identityDir())
	return nil
}

// run authenticates as the device, with the identity provisioning wrote.
//
// No password, no management surface, no secret in the environment — the
// private key on disk IS the credential. Presenting it never relaxes server
// verification (§6.1 rule 2): strict TLS stays fully on.
func run(ctx context.Context, deviceName string) error {
	certPEM, err := os.ReadFile(filepath.Join(identityDir(), deviceName+"-cert.pem"))
	if err != nil {
		return fmt.Errorf("no identity for %q; provision it first: %w", deviceName, err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(identityDir(), deviceName+"-key.pem"))
	if err != nil {
		return fmt.Errorf("no identity for %q; provision it first: %w", deviceName, err)
	}

	opts := []axiam.Option{axiam.WithClientCertificate(certPEM, keyPEM)}
	if ca := os.Getenv("AXIAM_ORG_CA"); ca != "" {
		pem, err := os.ReadFile(ca)
		if err != nil {
			return fmt.Errorf("read AXIAM_ORG_CA: %w", err)
		}
		opts = append(opts, axiam.WithCustomCA(pem))
	}
	device, err := axiam.NewClient(env("AXIAM_URL", "https://axiam.example.com"),
		env("AXIAM_TENANT", "acme"), opts...)
	if err != nil {
		return err
	}
	defer device.Close()

	allowed, err := device.Can(ctx, "telemetry:publish", "device/"+deviceName)
	if err != nil {
		return fmt.Errorf("check access: %w", err)
	}
	fmt.Printf("%s may publish telemetry: %v\n", deviceName, allowed)
	return nil
}

// revoke is the decommissioning path.
//
// Deleting the service account alone leaves a valid certificate in the field;
// revoking the certificate is what actually stops the device authenticating.
func revoke(ctx context.Context, deviceName string) error {
	client, err := newOperatorClient()
	if err != nil {
		return err
	}
	defer client.Close()
	if _, err := client.Login(ctx, env("AXIAM_ADMIN", "admin@example.com"),
		os.Getenv("AXIAM_ADMIN_PASSWORD")); err != nil {
		return fmt.Errorf("login: %w", err)
	}

	accounts, err := client.ServiceAccounts().ListAll(ctx, axiam.Limited(200))
	if err != nil {
		return err
	}
	var accountID string
	for _, a := range accounts {
		if a.Name == deviceName {
			accountID = a.ID.String()
			if err := client.ServiceAccounts().Delete(ctx, a.ID); err != nil {
				return err
			}
		}
	}
	if accountID == "" {
		return fmt.Errorf("no service account named %q", deviceName)
	}

	certificates, err := client.Certificates().ListAll(ctx, axiam.Limited(200))
	if err != nil {
		return err
	}
	for _, cert := range certificates {
		if !strings.HasPrefix(cert.Subject, "CN="+deviceName+",") {
			continue
		}
		if err := client.Certificates().Revoke(ctx, cert.ID); err != nil {
			if errors.Is(err, axiam.ErrNotFound) {
				continue
			}
			return fmt.Errorf("revoke %s: %w", cert.ID, err)
		}
		fmt.Printf("revoked %s\n", cert.ID)
	}
	fmt.Printf("deleted service account %s\n", accountID)
	return nil
}

func main() {
	if len(os.Args) != 3 {
		log.Fatal("usage: device-mtls-provisioning <provision|run|revoke> <device-name>")
	}
	ctx := context.Background()
	var err error
	switch os.Args[1] {
	case "provision":
		err = provision(ctx, os.Args[2])
	case "run":
		err = run(ctx, os.Args[2])
	case "revoke":
		err = revoke(ctx, os.Args[2])
	default:
		log.Fatal("usage: device-mtls-provisioning <provision|run|revoke> <device-name>")
	}
	if err != nil {
		log.Fatal(err)
	}
}

func ptr[T any](v T) *T { return &v }
