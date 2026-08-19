// Command srp-login demonstrates the SRP-6a login path (CONTRACT.md §23).
//
// SRP proves the password to the server without the password — or anything
// from which it can be cheaply recovered — ever crossing the wire. What the
// server receives is A and a proof, neither of which is useful without the
// account's verifier, so a TLS-terminating proxy, an accidentally verbose
// request log or a heap dump cannot capture a plaintext password.
//
// It does NOT protect against a compromised AXIAM server. Nothing client-side
// can.
//
// Three things this example is built to show:
//
//  1. LoginSrp returns the SAME LoginResult as Login, MFA branch included, so
//     the result handling below is identical to examples/login-mfa.
//  2. A tenant with srp_mode: disabled answers the challenge endpoint with
//     404, which reaches the caller as a *NetworkError and NOT as a
//     credential failure — so falling back to Login is correct and safe.
//  3. A tenant with srp_mode: required answers /auth/login with 403
//     srp_required, which is an *AuthzError. A user whose password is
//     perfectly good must never be shown "invalid username or password".
//
// This example is illustrative/compilable — it reads connection details from
// environment variables and does not require a live AXIAM server to
// `go build ./examples/srp-login/...`.
//
// Run: go run ./examples/srp-login
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
	baseURL := getenv("AXIAM_BASE_URL", "https://localhost:8443")
	tenantSlug := getenv("AXIAM_TENANT_SLUG", "acme")
	orgSlug := getenv("AXIAM_ORG_SLUG", "acme")
	username := getenv("AXIAM_USERNAME", "alice")
	password := os.Getenv("AXIAM_PASSWORD")
	if password == "" {
		log.Fatal("set AXIAM_PASSWORD")
	}

	client, err := axiam.NewClient(baseURL, tenantSlug, axiam.WithOrgSlug(orgSlug))
	if err != nil {
		log.Fatalf("client: %v", err)
	}
	defer client.Close()

	// In Go this is always true. It exists because PHP — the one language
	// with no native bignum — genuinely answers false, and §23.1 puts the
	// probe in every SDK's vocabulary so portable code can ask.
	if !client.SrpAvailable() {
		log.Fatal("this SDK build cannot perform SRP")
	}

	ctx := context.Background()
	result, err := client.LoginSrp(ctx, username, password)

	// A tenant that has not enabled SRP is not a failed login. Fall back
	// rather than reporting a credential problem the user does not have.
	if errors.Is(err, axiam.ErrNetwork) {
		log.Printf("SRP unavailable on this tenant (%v) — falling back to password login", err)
		result, err = client.Login(ctx, username, password)
	}
	if err != nil {
		var authzErr *axiam.AuthzError
		if errors.As(err, &authzErr) {
			// srp_mode: required. The credentials were never examined.
			log.Fatalf("this tenant refuses password login: %v", authzErr)
		}
		log.Fatalf("login: %v", err)
	}

	if result.MFARequired {
		// Identical to the non-SRP path — that is the point of §23.1's
		// same-result-type requirement.
		code := os.Getenv("AXIAM_TOTP_CODE")
		if code == "" {
			log.Fatalf("MFA required (%v); set AXIAM_TOTP_CODE", result.AvailableMethods)
		}
		result, err = client.VerifyMfa(ctx, result.MFAToken, code)
		if err != nil {
			log.Fatalf("verify_mfa: %v", err)
		}
	}

	fmt.Printf("authenticated: session=%s expires_in=%ds\n", result.SessionID, result.ExpiresIn)

	// Enrolment, for any request that SETS a password. The server cannot
	// compute a verifier — it never sees the plaintext — so it has to arrive
	// with the request or not at all. Read the tenant's parameters from
	// GET /api/v1/auth/me (or the reset context) rather than hard-coding
	// them: a verifier enrolled under different costs stays valid, and the
	// server dictates the costs per exchange.
	enrolment, err := client.SrpEnrollment(axiam.SrpEnrollmentRequest{
		// The account's USERNAME, which is the canonical identity the
		// challenge endpoint hands back. An email here produces a verifier no
		// login can ever satisfy.
		Identity: username,
		Password: os.Getenv("AXIAM_NEW_PASSWORD"),
	})
	if err != nil {
		log.Printf("enrolment skipped: %v", err)
		return
	}
	// Send this as the `srp` member of the change-password body. Never log
	// it: salt and verifier are §23.3 rule 12 material.
	fmt.Printf("enrolment ready: group=%s kdf=%s\n", enrolment.Group, enrolment.Kdf)
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
