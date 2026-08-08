// Token Exchange (CONTRACT.md §15) — narrowing a user's token before calling
// the next service.
//
// The situation: an API gateway holds a user's access token and needs to call
// an orders service. Forwarding the user's token verbatim over-privileges that
// call and leaves the second hop unable to tell the caller from the user;
// using the gateway's own service credentials has the right privileges but
// loses the user entirely. The exchange gives you both.
//
// Run: go run ./examples/token-exchange
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"

	axiam "github.com/ilpanich/axiam-go-sdk"
)

func main() {
	baseURL := envOr("AXIAM_BASE_URL", "https://localhost:8443")
	tenantID := envOr("AXIAM_TENANT_ID", "11111111-2222-3333-4444-555555555555")
	clientID := envOr("AXIAM_OIDC_CLIENT_ID", "api-gateway")
	clientSecret := envOr("AXIAM_OIDC_CLIENT_SECRET", "gateway-secret")

	// The user's token, as it would arrive on an inbound request.
	userToken := envOr("AXIAM_SUBJECT_TOKEN", "the-users-access-token")

	// Unlike §14's device, an exchanging client is a confidential service and
	// authenticates.
	client, err := axiam.NewClient(baseURL, "acme",
		axiam.WithOidcClientID(clientID),
		axiam.WithOidcClientSecret(clientSecret),
	)
	if err != nil {
		log.Fatalf("NewClient: %v", err)
	}

	// Delegation: "the gateway, acting on behalf of the user". Supplying an
	// ActorToken is what makes it delegation; leaving it zero asks for
	// impersonation instead — a different operation with different risk, which
	// the server refuses unless this client holds that grant. The SDK will not
	// pick for you (§15.2 rule 1).
	exchanged, err := client.TokenExchange(context.Background(), axiam.TokenExchangeParams{
		SubjectToken: axiam.Sensitive(userToken),
		Scopes:       []string{"orders:read"},
		Audience:     "orders-service",
		TenantID:     tenantID,
	})
	if err != nil {
		// Each names something an operator must fix rather than something to
		// retry.
		var protocolErr *axiam.OAuthProtocolError
		if errors.As(err, &protocolErr) {
			switch protocolErr.ErrorCode {
			case "unauthorized_client":
				log.Fatal("This client may not exchange, or may not impersonate — a registration fact.")
			case "invalid_scope":
				// Do NOT re-send with fewer scopes: the server refused rather
				// than silently narrowing precisely so you would find out here.
				log.Fatal("You asked for a scope the user does not hold.")
			case "invalid_grant":
				// Cross-tenant collapses into this on purpose; do not try to
				// tell the cases apart.
				log.Fatal("The subject token is invalid, expired, or from another tenant.")
			}
		}
		log.Fatalf("TokenExchange: %v", err)
	}

	// Read what you actually got. On success the granted scope may still be
	// narrower than requested (§15.2 rule 7) — the client's registration bounds
	// it, and assuming the request was honoured verbatim is how a caller ends
	// up surprised at the *next* service.
	scope := exchanged.Scope
	if scope == "" {
		scope = "(server default)"
	}
	fmt.Printf("exchanged for %ds, granted scope: %s\n", exchanged.ExpiresIn, scope)

	// Hand it onward in ONE outbound call. It is not this client's session:
	// adopting it would silently re-privilege every later call the gateway
	// makes, and the narrowed token would make most of them fail far from here
	// (rule 5). There is also no refresh token, ever — re-run the exchange
	// (rule 4).
	// The explicit string() conversion is the friction point on purpose:
	// Sensitive redacts itself under every fmt verb and in JSON, so the only
	// way the raw value reaches a header is a conversion you had to type.
	_ = "Bearer " + string(exchanged.AccessToken)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
