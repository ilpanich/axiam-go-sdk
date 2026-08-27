// Command management-basics walks the CONTRACT §27 management surface.
//
// Namespaces, paging, sparse updates, the error sub-types and one-time secrets
// — the five things a caller meets first.
//
// This example is illustrative/compilable — it reads connection details from
// environment variables and does not require a live AXIAM server to
// `go build ./examples/management-basics/...`.
//
// Run: go run ./examples/management-basics
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
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

func randomSuffix() string {
	buf := make([]byte, 4)
	if _, err := rand.Read(buf); err != nil {
		return "fallback"
	}
	return hex.EncodeToString(buf)
}

func main() {
	ctx := context.Background()
	client, err := axiam.NewClient(env("AXIAM_URL", "https://axiam.example.com"), env("AXIAM_TENANT", "acme"))
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	if _, err := client.Login(ctx, env("AXIAM_ADMIN", "admin@example.com"),
		os.Getenv("AXIAM_ADMIN_PASSWORD")); err != nil {
		log.Fatalf("login: %v", err)
	}

	// --- Handles cost nothing ---------------------------------------------
	// Acquiring one performs no I/O (§27.2 rule 1). There is nothing to cache
	// and nothing to close.
	users := client.Users()

	// --- Paging -----------------------------------------------------------
	// Total is the size of the whole set, not of this page. That is the
	// distinction §27.4 rule 4 exists to preserve.
	page, err := users.List(ctx, axiam.Limited(25))
	if err != nil {
		log.Fatalf("users.list: %v", err)
	}
	fmt.Printf("%d of %d users; more? %v\n", len(page.Items), page.Total, page.HasMore())

	// ListAll walks to exhaustion. It stops on an empty page even if the
	// server's Total disagrees, so a misreporting server costs one wasted
	// request rather than an unbounded loop.
	everyone, err := users.ListAll(ctx, axiam.Limited(100))
	if err != nil {
		log.Fatalf("users.list_all: %v", err)
	}
	fmt.Printf("walked %d users\n", len(everyone))

	// --- Search -----------------------------------------------------------
	// The term rides on the page request rather than being a third argument on
	// each of the twenty List methods, and that is what makes ListAll carry it
	// across the whole walk: a walk that filtered page one and not page two
	// would hand back the matches followed by the unfiltered tail.
	//
	// The SERVER filters, before offset/limit, so Total counts MATCHES —
	// filtering the slice here in Go would give you neither that nor a page
	// count that belongs to the set it labels.
	matches, err := users.List(ctx, axiam.Matching(25, "ada"))
	if err != nil {
		log.Fatalf("users.list(search): %v", err)
	}
	fmt.Printf("%d users match \"ada\"\n", matches.Total)

	// Blank is the same request as unset: no search key at all. A box that
	// fires on every keystroke sends one of these the moment it is cleared,
	// and "rows containing the empty string" is a different question from
	// "all rows" — so this issues the identical request to the first List
	// above.
	cleared, err := users.List(ctx, axiam.Matching(25, "   "))
	if err != nil {
		log.Fatalf("users.list(cleared): %v", err)
	}
	fmt.Printf("a cleared box asks for everything again: %d users\n", cleared.Total)

	// The server caps the term's length. This SDK does not copy that cap: a
	// truncation the server would not have made is a silently different query,
	// with nothing to say so.

	// --- Open enums -------------------------------------------------------
	// Every generated enum is a `type X string` with named constants, so a
	// value this SDK's copy of the spec does not list still decodes, still
	// round-trips and still compares. The constant block reads like an
	// exhaustive set and is not one: the next Kind the server adds arrives as
	// itself rather than failing the whole page (§27.11 rule 1), which is why
	// a switch over it needs a default arm.
	tenants, err := client.Tenants().List(ctx, axiam.Limited(5))
	if err != nil {
		log.Fatalf("tenants.list: %v", err)
	}
	for _, tenant := range tenants.Items {
		switch {
		case tenant.Kind == nil:
			// A row written before organization scope existed. Read it as
			// standard -- that is what it is.
			fmt.Printf("tenant %q: standard (no kind recorded)\n", tenant.Slug)
		case *tenant.Kind == axiam.TenantKindOrganization:
			fmt.Printf("tenant %q: the organization's own scope\n", tenant.Slug)
		default:
			fmt.Printf("tenant %q: kind %q\n", tenant.Slug, *tenant.Kind)
		}
	}

	// --- One more nil that is not zero ------------------------------------
	// Certificate.BoundServiceAccountID is resolved by List and is nil on Get.
	// Nil there means "this read does not carry it", not "there is nothing
	// bound" — the SDK spends no second request filling it in behind you.
	// (MtlsTrustAnchorResponse.TrustedAnchors reads the same way: nil means
	// NOTHING WAS RELOADED, not that the listener trusts zero CAs.)
	certs, err := client.Certificates().List(ctx, axiam.Limited(5))
	if err != nil {
		log.Fatalf("certificates.list: %v", err)
	}
	for _, cert := range certs.Items {
		if cert.BoundServiceAccountID != nil {
			fmt.Printf("cert %s authenticates service account %s\n", cert.ID, *cert.BoundServiceAccountID)
		}
	}

	// A bare-array read returns a slice, not a page — modelling it as a page
	// would give it a Total that only ever equalled len(Items).
	resources, err := client.Resources().ListAll(ctx, axiam.Limited(100))
	if err != nil {
		log.Fatalf("resources.list_all: %v", err)
	}
	if len(resources) > 0 {
		scopes, err := client.Scopes().List(ctx, resources[0].ID)
		if err != nil {
			log.Fatalf("scopes.list: %v", err)
		}
		fmt.Printf("resource %q has %d scopes\n", resources[0].Name, len(scopes))
	}

	// --- Creating, and the error sub-types --------------------------------
	username := "demo-" + randomSuffix()
	created, err := users.Create(ctx, axiam.CreateUserRequest{
		Username: username,
		Email:    username + "@example.test",
		// A secret, so it is a Sensitive: redacted from every fmt verb, log
		// line and JSON rendering, and unwrapped only where it is needed.
		Password: axiam.Sensitive("correct-horse-battery-staple"),
	})
	if err != nil {
		var invalid *axiam.ValidationError
		switch {
		case errors.Is(err, axiam.ErrConflict):
			// 409 — a uniqueness or state conflict. Never retried: the server
			// is telling the truth, and a retry produces the same answer one
			// round-trip later.
			fmt.Printf("already taken: %v\n", err)
			return
		case errors.As(err, &invalid):
			// 400/422 — usually the USER'S input, not a bug in the caller.
			// This is why §27 splits it out of §2's network category: an
			// application needs to tell it from a broken socket without
			// matching on message text.
			for _, f := range invalid.Fields {
				fmt.Printf("  rejected %s: %s\n", f.Field, f.Message)
			}
			return
		default:
			log.Fatalf("users.create: %v", err)
		}
	}
	fmt.Printf("created %s (%s)\n", created.Username, created.ID)

	// --- Sparse updates ---------------------------------------------------
	// This body carries one field, so the wire body has exactly one key. What
	// you leave nil is left unchanged — omitted entirely rather than sent as
	// null (§27.4 rule 5).
	if _, err := users.Update(ctx, created.ID, axiam.UpdateUserRequest{
		Email: ptr("moved@example.test"),
	}); err != nil {
		log.Fatalf("users.update: %v", err)
	}

	// --- 404 is an authorization outcome ----------------------------------
	// The server answers identically for "does not exist" and "belongs to
	// another tenant", on purpose: a distinguishable answer would let a caller
	// enumerate another tenant's ids. So a NotFoundError also matches ErrAuthz,
	// and code written before §27 still catches it.
	if err := users.Delete(ctx, created.ID); err != nil {
		log.Fatalf("users.delete: %v", err)
	}
	if _, err := users.Get(ctx, created.ID); errors.Is(err, axiam.ErrNotFound) {
		fmt.Printf("gone, as expected: %v\n", err)
	}
}

func ptr[T any](v T) *T { return &v }
