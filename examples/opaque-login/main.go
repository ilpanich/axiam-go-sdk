// Command opaque-login demonstrates the OPAQUE (RFC 9807) login path
// (CONTRACT.md §23).
//
// What is worth reading here is the error handling, not the happy path. Three
// things about it are load-bearing:
//
//  1. LoginOpaque returns the SAME LoginResult as Login, MFA branch included,
//     so an application switching a tenant to OPAQUE changes nothing else.
//  2. A tenant with opaque_mode: disabled answers login/start with 404, which
//     this SDK reports as a *NetworkError. That is the ONLY case where falling
//     back to Login is correct.
//  3. A failed exchange is NOT retried here. Under CONTRACT.md §23.4 rule 7
//     LoginOpaque already did it, if the tenant's mode was optional — it
//     returns that retry's own result or error. An *AuthError reaching this
//     code means the fallback either happened and failed or was ruled out by
//     the tenant's policy, so retrying it over Login is the one mistake this
//     example exists to not make.
//
// Run: go run ./examples/opaque-login
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
	baseURL := env("AXIAM_URL", "https://axiam.example")
	tenant := env("AXIAM_TENANT", "default")
	org := env("AXIAM_ORG", "acme")
	username := env("AXIAM_USER", "alice")
	password := os.Getenv("AXIAM_PASSWORD")
	if password == "" {
		log.Fatal("AXIAM_PASSWORD is required")
	}

	client, err := axiam.NewClient(baseURL, tenant, axiam.WithOrgSlug(org))
	if err != nil {
		log.Fatalf("client: %v", err)
	}
	defer client.Close()

	ctx := context.Background()

	// Always true for the Go SDK, which compiles the implementation in. The
	// check is here because §23.2 puts it in the locked vocabulary, and in the
	// SDKs that load a native library it genuinely answers false.
	if !client.OpaqueAvailable() {
		log.Fatal("this build cannot perform OPAQUE")
	}

	result, err := client.LoginOpaque(ctx, username, password)
	if err != nil {
		var netErr *axiam.NetworkError
		if errors.As(err, &netErr) {
			// The tenant does not offer OPAQUE, or this SDK cannot perform the
			// KSF it named. Either way a configuration fault rather than a
			// wrong password — the one case where the password path is right.
			fmt.Printf("OPAQUE unavailable (%v); falling back to password login\n", netErr)
			result, err = client.Login(ctx, username, password)
			if err != nil {
				log.Fatalf("password login failed: %v", err)
			}
		} else {
			// An *AuthError: wrong password, no such account, or a server that
			// does not hold the record — indistinguishable by design. Under an
			// optional tenant this is already the password path's own answer
			// (§23.4 rule 7); under a required one /auth/login would refuse it
			// anyway. Do NOT retry over Login.
			log.Fatalf("OPAQUE login failed: %v", err)
		}
	}

	if result.MFARequired {
		fmt.Printf("signed in; MFA required (methods: %v)\n", result.AvailableMethods)
		return
	}
	fmt.Printf("signed in over OPAQUE; session %s (expires in %ds)\n",
		result.SessionID, result.ExpiresIn)

	// Enrolling a record for a new password. One argument, where the SRP
	// verifier this replaces took four: no identity (the server chooses the
	// credential identifier), no group and no KDF (the server names them in
	// its register/start response, which this call honours).
	if newPassword := os.Getenv("AXIAM_NEW_PASSWORD"); newPassword != "" {
		enrollment, err := client.OpaqueEnrollment(ctx, newPassword)
		if err != nil {
			log.Fatalf("enrolment failed: %v", err)
		}
		fmt.Printf("built an enrolment (%d-byte record) — send it as the request "+
			"body's `opaque` field\n", len(enrollment.RegistrationRecord)/2)
	}
}

func env(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
