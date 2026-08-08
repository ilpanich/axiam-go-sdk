// Device Authorization Grant (CONTRACT.md §14) — signing in a device that
// cannot show a browser.
//
// The shape this example is really demonstrating: the SDK hands you the user
// code and verification URI BEFORE it starts polling, and what you do with
// them is yours. Here that is fmt.Printf; on a real device it is a screen, a
// QR code, or an e-ink panel. The SDK never prints them for you (§14.3
// rule 2).
//
// Run: go run ./examples/device-login
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	axiam "github.com/ilpanich/axiam-go-sdk"
)

func main() {
	baseURL := envOr("AXIAM_BASE_URL", "https://localhost:8443")
	tenantID := envOr("AXIAM_TENANT_ID", "11111111-2222-3333-4444-555555555555")
	clientID := envOr("AXIAM_OIDC_CLIENT_ID", "my-device")

	// No client secret: a device that cannot show a browser cannot keep one
	// either, and §14.1 makes DeviceAuthorize unauthenticated for that reason.
	client, err := axiam.NewClient(baseURL, "acme", axiam.WithOidcClientID(clientID))
	if err != nil {
		log.Fatalf("NewClient: %v", err)
	}

	// A real device would bound this by its own power/idle policy; the grant's
	// own expires_in still applies independently.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	tokens, err := client.DeviceLogin(ctx, axiam.DeviceLoginParams{
		Scope:    "openid profile",
		TenantID: tenantID,
		OnUserCode: func(a axiam.DeviceAuthorization) error {
			// Called BEFORE the first poll. Display, then the SDK waits.
			fmt.Printf("\n  To sign in, visit: %s\n", a.VerificationURI)
			fmt.Printf("  and enter code:    %s\n", a.UserCode)
			if a.VerificationURIComplete != "" {
				// Prefer this when the device can render a QR code — the user
				// then types nothing at all. Never build it yourself when it
				// is absent: the format is the server's to choose (§14.3).
				fmt.Printf("  or go straight to: %s\n", a.VerificationURIComplete)
			}
			fmt.Println("\nWaiting for approval…")
			return nil
		},
		// §14.3 rule 4 (contract 1.7): adoption is the same opt-in MAY as
		// LoginClientCredentials. Left false here — this example hands the
		// tokens back rather than re-privileging the client.
		AdoptAsCredential: false,
	})
	if err != nil {
		// The two failure modes worth telling apart — a human said no, versus
		// nobody answered. Collapsing them loses the only information the
		// device can act on (§14.2 rule 3): whether re-prompting could help.
		var protocolErr *axiam.OAuthProtocolError
		if errors.As(err, &protocolErr) {
			switch protocolErr.ErrorCode {
			case "access_denied":
				log.Fatal("The user refused the request.")
			case "expired_token":
				log.Fatal("Nobody answered before the code expired.")
			}
		}
		log.Fatalf("DeviceLogin: %v", err)
	}

	fmt.Printf("Signed in. Access token expires in %ds.\n", tokens.ExpiresIn)
	if tokens.IDClaims.Sub != "" {
		fmt.Printf("Subject: %s\n", tokens.IDClaims.Sub)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
