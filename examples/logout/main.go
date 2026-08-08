// RP-initiated and back-channel logout (CONTRACT.md §12.7).
//
// Two halves that close each other's hole. Without the first, a user who logs
// out of your app stays logged in at AXIAM and is silently signed back in on
// the next "Login with AXIAM". Without the second, a user who logs out OF
// AXIAM stays logged in at your app indefinitely, because nothing tells you —
// which is what leaves live sessions behind when an admin revokes a
// compromised account.
//
// Run: go run ./examples/logout
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	axiam "github.com/ilpanich/axiam-go-sdk"
)

func main() {
	baseURL := envOr("AXIAM_BASE_URL", "https://localhost:8443")
	clientID := envOr("AXIAM_OIDC_CLIENT_ID", "my-app")

	client, err := axiam.NewClient(baseURL, "acme", axiam.WithOidcClientID(clientID))
	if err != nil {
		log.Fatalf("NewClient: %v", err)
	}
	ctx := context.Background()

	// ------------------------------------------------------------------
	// Half 1: the user clicked "log out" in YOUR app.
	// ------------------------------------------------------------------

	// The ID token you stored at login. It is what identifies WHICH session to
	// end — a signed statement rather than a parameter anyone could send.
	// AXIAM does not check its expiry (a logging-out user's ID token has
	// usually expired already), but it does check the signature.
	storedIDToken := envOr("AXIAM_ID_TOKEN", "the-id-token-from-login")

	url, err := client.LogoutURL(ctx, axiam.LogoutURLParams{
		IDToken:               axiam.Sensitive(storedIDToken),
		PostLogoutRedirectURI: "https://app.example.com/goodbye",
		// State is yours to generate and yours to check when it comes back.
		// The SDK passes it through and never invents one, because the value
		// only means something to the app that will receive it.
		State: "csrf-value-you-stored-in-the-session",
	})
	if err != nil {
		log.Fatalf("LogoutURL: %v", err)
	}

	// Redirect the browser here. Note what the SDK did NOT do: it did not
	// clear this client's own session. Whether your local session ends is your
	// decision — a backend holding a service-account session must not lose it
	// because a USER logged out.
	fmt.Printf("Redirect the user agent to:\n  %s\n", url)

	// The redirect URI is honoured only if it exactly matches your client's
	// registered post_logout_redirect_uris — a separate list from
	// redirect_uris. The SDK does not pre-check it against a local copy
	// (§12.7.2 rule 3): that copy would drift and would reject a URI an
	// operator had just registered.

	// ------------------------------------------------------------------
	// Half 2: AXIAM tells YOU a session ended.
	// ------------------------------------------------------------------
	//
	// Mount this at the backchannel_logout_uri you registered. AXIAM POSTs
	// `logout_token=<jwt>`, form-encoded.

	inbound := os.Getenv("AXIAM_LOGOUT_TOKEN")
	if inbound == "" {
		return
	}

	verified, err := client.VerifyLogoutToken(ctx, inbound, nil)
	if err != nil {
		// Answer 400 and log. Do not end anything: an unverifiable token is
		// not a logout instruction, and treating it as one would make your
		// endpoint a denial-of-service primitive for anyone who can reach it.
		fmt.Printf("rejected logout token: %v\n", err)
		return
	}

	// Dedup on JTI in YOUR store. Delivery is at-least-once, so a valid token
	// legitimately arrives twice — that is a retry, not an attack. The SDK
	// deliberately does not dedup: it has no durable store, and an in-memory
	// guard would silently drop a real second logout after a restart.
	fmt.Printf("logout token %s verified\n", verified.JTI)

	if verified.SID != "" {
		// End THAT session only. Falling back to "every session for this user"
		// is over-reach AXIAM itself refuses to make — the user's other
		// devices are still signed in on purpose.
		fmt.Printf("end session %s only\n", verified.SID)
	} else {
		fmt.Printf("no sid: this token names only sub %s\n", verified.Sub)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
