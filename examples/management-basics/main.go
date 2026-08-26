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
