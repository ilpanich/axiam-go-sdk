// Command uma-resource-server is the resource-server half of the UMA 2.0
// (CONTRACT.md §20) example pair.
//
// The situation: this service holds invoices that belong to *users*, not to
// itself. When someone asks for one, the useful answer is not just "no" — it
// is "not with what you're carrying, and here is where to go and get better".
// That actionable refusal is what UMA adds over plain RBAC.
//
// What this shows, in order:
//
//  1. Mint a PAT — a client-credentials token carrying `uma_protection`.
//     §20.2 rule 1 requires a *client* token: a minted ticket is bound to the
//     client_id that minted it, so a user token cannot stand in.
//  2. Register the resource this service guards. The returned id *is* the
//     AXIAM resource id — there is no parallel resource store to keep in sync.
//  3. Guard a route with middleware.RequireAccess(..., WithUmaChallenge(...)),
//     so a denial carries `WWW-Authenticate: UMA` with a fresh ticket.
//
// Its counterpart is examples/uma-client, which consumes that header.
//
// This example is illustrative/compilable — it starts a real net/http server
// bound to AXIAM_LISTEN_ADDR (default 127.0.0.1:8081) and builds without a
// live AXIAM server (SC#1). Serving real traffic requires AXIAM_BASE_URL to
// be reachable, since the PAT, the registration, and every ticket are real
// calls against it.
//
// Run: go run ./examples/uma-resource-server
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	axiam "github.com/ilpanich/axiam-go-sdk"
	"github.com/ilpanich/axiam-go-sdk/middleware"
)

func main() {
	ctx := context.Background()
	baseURL := getenv("AXIAM_BASE_URL", "https://localhost:8443")
	tenantSlug := getenv("AXIAM_TENANT_SLUG", "acme")
	listenAddr := getenv("AXIAM_LISTEN_ADDR", "127.0.0.1:8081")

	client, err := axiam.NewClient(baseURL, tenantSlug,
		axiam.WithOidcClientID(getenv("AXIAM_OIDC_CLIENT_ID", "invoices-resource-server")),
		axiam.WithOidcClientSecret(getenv("AXIAM_OIDC_CLIENT_SECRET", "resource-server-secret")))
	if err != nil {
		log.Fatalf("failed to construct client: %v", err)
	}

	verifier, err := axiam.NewJWKSVerifier(ctx, baseURL, nil)
	if err != nil {
		log.Fatalf("failed to construct JWKS verifier: %v", err)
	}

	// ---- 1. The PAT ----
	//
	// §20.2 rule 1: a client-credentials token carrying `uma_protection`. Not
	// a user token, and not this client's ambient session — the SDK will not
	// substitute either, and the Protection API would refuse them anyway.
	session, err := client.LoginClientCredentials(ctx, axiam.LoginClientCredentialsParams{
		Scope: axiam.UmaProtectionScope,
	})
	if err != nil {
		log.Fatalf("failed to mint a PAT: %v", err)
	}
	pat := session.AccessToken

	// ---- 2. Registration ----
	//
	// Registering the same name twice creates two resources, so a real service
	// registers once at provisioning time and stores the id, or reconciles by
	// listing. Inline here because it is the step that shows the returned id is
	// the AXIAM resource id.
	registered, err := client.UmaRegisterResource(ctx, pat, axiam.ResourceSet{
		Name: "invoice-7",
		Type: "invoice",
		// The declared scopes are the allow-list the permission endpoint
		// validates a ticket request against. A resource registered with none
		// can never appear in a ticket.
		ResourceScopes: []string{"invoices:read", "invoices:approve"},
	})
	if err != nil {
		log.Fatalf("failed to register the resource: %v", err)
	}

	// ---- 3. The challenger ----
	//
	// ASURI names where the caller should redeem the ticket. Read it from the
	// discovery document rather than assembling it by hand — a deployment is
	// free to move its endpoints, which is why §12.3 rule 6 forbids hardcoding
	// them.
	configuration, err := client.OidcDiscover(ctx)
	if err != nil {
		log.Fatalf("discovery failed: %v", err)
	}
	challenger := &middleware.UmaChallenger{
		Realm:  "invoices",
		ASURI:  configuration.Issuer,
		PAT:    pat,
		Minter: client,
	}

	mux := http.NewServeMux()
	// The load-bearing option is WithUmaChallenge. Without it this is an
	// ordinary §11 guard and a denial is a bare 403; with it, the denial
	// carries a ticket and the caller can act on it.
	mux.Handle("/invoices/{invoiceID}", middleware.RequireAccess(
		client, "invoices:read", middleware.ResourceFromPath("invoiceID"),
		middleware.WithUmaChallenge(challenger),
	)(http.HandlerFunc(invoiceHandler)))

	guarded := middleware.Middleware(verifier, tenantSlug)(mux)

	fmt.Printf("registered invoice-7 as %s\n", registered.ID)
	fmt.Printf("try:  curl -i http://%s/invoices/%s\n", listenAddr, registered.ID)
	if err := http.ListenAndServe(listenAddr, guarded); err != nil {
		log.Fatalf("server exited: %v", err)
	}
}

// invoiceHandler runs only when the engine allowed the request — including
// honouring any deny rule, which UMA does not bypass: the ticket minted on a
// refusal asks for the same action this check just evaluated, so the same
// grants and denies apply to whatever RPT comes back.
func invoiceHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.UserFromContext(r.Context())
	if !ok {
		http.Error(w, "no authenticated user in context", http.StatusInternalServerError)
		return
	}
	fmt.Fprintf(w, "invoice %s: 42.00 EUR — read by user %s\n", r.PathValue("invoiceID"), user.UserID)
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
