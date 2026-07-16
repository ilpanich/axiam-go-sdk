// Command middleware-guard demonstrates wrapping a sample net/http route
// with middleware.Middleware (CONTRACT.md §10, SC#1), plus a second route
// additionally protected with middleware.RequireAccess (CONTRACT.md §11
// declarative authorization helpers).
//
// The middleware extracts the session from the Authorization: Bearer header
// (falling back to the axiam_access cookie), verifies it locally via a
// JWKS-backed verifier (no per-request AXIAM-server round-trip on a cache
// hit), enforces the configured-tenant claim, injects the authenticated
// identity into the request context, and returns 401/403 automatically
// before the wrapped handler ever runs.
//
// GET /docs/{id} additionally requires the authenticated caller to pass a
// "documents:read" authorization check for the {id} resolved from the path
// (middleware.ResourceFromPath) before docHandler runs — 401 if
// unauthenticated (never re-verifying the token itself), 400 if {id} is
// missing, 403 if denied, and 503 (fail closed) if the authz endpoint
// itself is unreachable.
//
// This example is illustrative/compilable — it starts a real net/http
// server bound to AXIAM_LISTEN_ADDR (default 127.0.0.1:8080) and does not
// require a live AXIAM server to `go build ./examples/middleware-guard/...`
// (SC#1). Serving real traffic requires the configured AXIAM_BASE_URL to be
// a reachable AXIAM server (for the verifier's JWKS fetch and for the
// RequireAccess authz check against /docs/{id}).
//
// Run: go run ./examples/middleware-guard
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
	baseURL := getenv("AXIAM_BASE_URL", "https://localhost:8443")
	tenantSlug := getenv("AXIAM_TENANT_SLUG", "acme")
	listenAddr := getenv("AXIAM_LISTEN_ADDR", "127.0.0.1:8080")

	// NewJWKSVerifier is the middleware-guard-friendly entry point exposed
	// alongside axiam.NewClient — it constructs the same local JWKS
	// verification primitive the middleware requires, bound to
	// {baseURL}/oauth2/jwks (§10, D-06).
	verifier, err := axiam.NewJWKSVerifier(context.Background(), baseURL, nil)
	if err != nil {
		log.Fatalf("failed to construct JWKS verifier: %v", err)
	}

	// The same *axiam.Client used for REST calls elsewhere in this SDK
	// satisfies middleware.AccessChecker via its CheckAccessAs method
	// (CONTRACT.md §11.2.2) — no separate authz client type is needed.
	client, err := axiam.NewClient(baseURL, tenantSlug)
	if err != nil {
		log.Fatalf("failed to construct client: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/protected", protectedHandler)

	// GET /docs/{id} additionally requires a "documents:read" authorization
	// check for the path-resolved {id} (§11) on top of the §10 identity
	// check every route under this mux already gets from the outer
	// middleware.Middleware wrap below.
	mux.Handle("/docs/{id}", middleware.RequireAccess(client, "documents:read", middleware.ResourceFromPath("id"))(http.HandlerFunc(docHandler)))

	// middleware.Middleware wraps the mux with local session verification,
	// cross-tenant rejection, and identity injection (§10). Verification
	// failures return standardized 401/403 JSON before the handler runs.
	guarded := middleware.Middleware(verifier, tenantSlug)(mux)

	fmt.Printf("Listening on http://%s — GET /protected requires an AXIAM session; GET /docs/{id} additionally requires a documents:read authorization check\n", listenAddr)
	if err := http.ListenAndServe(listenAddr, guarded); err != nil {
		log.Fatalf("server exited: %v", err)
	}
}

// protectedHandler reads the identity middleware.Middleware injected into
// the request context via middleware.UserFromContext.
func protectedHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.UserFromContext(r.Context())
	if !ok {
		http.Error(w, "no authenticated user in context", http.StatusInternalServerError)
		return
	}
	fmt.Fprintf(w, "Hello, user %s (tenant %s) — roles: %v\n", user.UserID, user.TenantID, user.Roles)
}

// docHandler reads both the identity middleware.Middleware injected (§10)
// and the {id} path parameter middleware.RequireAccess already confirmed
// the caller may read (§11) — by the time this handler runs, the
// documents:read check for r.PathValue("id") has already passed.
func docHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.UserFromContext(r.Context())
	if !ok {
		http.Error(w, "no authenticated user in context", http.StatusInternalServerError)
		return
	}
	fmt.Fprintf(w, "document %s: authorized for user %s (tenant %s)\n", r.PathValue("id"), user.UserID, user.TenantID)
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
