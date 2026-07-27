// Command oidc-login demonstrates "Login with AXIAM" — the OIDC/SSO
// relying-party helpers (CONTRACT.md §12) — wired into a plain net/http
// server via middleware.OidcLoginHandler and middleware.OidcCallbackHandler.
//
// GET /login redirects the browser to AXIAM's authorization endpoint,
// having built the request with axiam.Client.OidcBegin (state, nonce and a
// PKCE code_verifier — S256 only) and parked that state in an
// axiam.MemoryOidcStateStore (CONTRACT.md §12.3 rule 1). GET /auth/callback
// consumes that state, exchanges the authorization code via
// axiam.Client.OidcExchange (validating the returned ID token in full —
// §12.4), and either redirects to the destination captured at login time or
// replies with a token-free JSON summary.
//
// The caller — this example — owns all login state: the SDK's core §12
// operations (OidcBegin/OidcExchange) never store state/nonce/code_verifier
// themselves; MemoryOidcStateStore is what lets the two separate HTTP
// requests of this redirect flow share that state.
//
// This example is illustrative/compilable — it starts a real net/http
// server bound to AXIAM_LISTEN_ADDR (default 127.0.0.1:8081) and does not
// require a live AXIAM server to `go build ./examples/oidc-login/...`
// (SC#1). Serving real traffic requires the configured AXIAM_BASE_URL to be
// a reachable AXIAM server with an OIDC client registered for
// AXIAM_OIDC_CLIENT_ID/AXIAM_OIDC_CLIENT_SECRET and AXIAM_OIDC_REDIRECT_URI.
//
// Run: go run ./examples/oidc-login
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	axiam "github.com/ilpanich/axiam-go-sdk"
	"github.com/ilpanich/axiam-go-sdk/middleware"
)

func main() {
	baseURL := getenv("AXIAM_BASE_URL", "https://localhost:8443")
	tenantSlug := getenv("AXIAM_TENANT_SLUG", "acme")
	clientID := getenv("AXIAM_OIDC_CLIENT_ID", "my-app")
	clientSecret := os.Getenv("AXIAM_OIDC_CLIENT_SECRET") // optional: omit for a public client
	redirectURI := getenv("AXIAM_OIDC_REDIRECT_URI", "http://127.0.0.1:8081/auth/callback")
	listenAddr := getenv("AXIAM_LISTEN_ADDR", "127.0.0.1:8081")

	opts := []axiam.Option{axiam.WithOidcClientID(clientID)}
	if clientSecret != "" {
		opts = append(opts, axiam.WithOidcClientSecret(clientSecret))
	}

	// §5: tenantSlug is a non-optional constructor parameter. §12.1: the
	// OIDC client_id (and, for a confidential client, client_secret) is
	// configured here at construction time — never a per-call argument —
	// because it is also needed for §12.4 rule 4 audience matching.
	client, err := axiam.NewClient(baseURL, tenantSlug, opts...)
	if err != nil {
		log.Fatalf("failed to construct client: %v", err)
	}

	// CONTRACT.md §12.3 rule 1: an OidcStateStore is entirely OPTIONAL — the
	// core OidcBegin/OidcExchange operations never touch it — but a
	// redirect-based login flow split across two HTTP requests needs
	// SOMETHING to link them by `state`. NewMemoryOidcStateStore is a ready
	// single-process implementation (10-minute TTL, single-use consume); a
	// multi-instance deployment needs a shared store instead (Redis, a
	// database) implementing axiam.OidcStateStore directly.
	store := axiam.NewMemoryOidcStateStore(0)

	loginOptions := middleware.OidcLoginOptions{
		Client:      client,
		Store:       store,
		RedirectURI: redirectURI,
		Scope:       "openid profile email",
		OnSuccess: func(w http.ResponseWriter, r *http.Request, tokens axiam.OidcTokenSet, entry axiam.OidcStateEntry) {
			// This is where a real application establishes its OWN session
			// (sign a cookie, write a session row, ...) — the SDK
			// deliberately does not do this for you. tokens.IDClaims is the
			// ALREADY-VALIDATED (§12.4) ID-token claim set; tokens.AccessToken
			// and tokens.RefreshToken are Sensitive and are never logged here.
			sub := ""
			if tokens.IDClaims != nil {
				sub = tokens.IDClaims.Sub
			}
			log.Printf("oidc login succeeded: sub=%s expires_in=%ds", sub, tokens.ExpiresIn)
		},
	}

	mux := http.NewServeMux()
	mux.Handle("/login", middleware.OidcLoginHandler(loginOptions))
	mux.Handle("/auth/callback", middleware.OidcCallbackHandler(loginOptions))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "GET /login to start \"Login with AXIAM\"")
	})

	fmt.Printf("Listening on http://%s — GET /login to start the OIDC authorization-code + PKCE flow\n", listenAddr)
	if err := http.ListenAndServe(listenAddr, mux); err != nil {
		log.Fatalf("server exited: %v", err)
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
