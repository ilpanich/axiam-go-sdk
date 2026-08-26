// Command management-manifest describes a tenant's shape and reconciles it
// (CONTRACT.md §27.6).
//
// Plan reads and writes nothing. Apply runs the plan it just reported, stops at
// the first failure, and tells you which steps never ran. There is no rollback:
// these are independent HTTP endpoints, nothing spans them, and an SDK that
// offered one could not honour it (§27.6 rule 7). Fix the cause and re-apply —
// applying twice converges, which is what makes that safe.
//
// This example is illustrative/compilable — it reads connection details from
// environment variables and does not require a live AXIAM server to
// `go build ./examples/management-manifest/...`.
//
// Run: go run ./examples/management-manifest [-apply]
package main

import (
	"context"
	"flag"
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

// tenantShape is built and validated before anything talks to the network.
//
// Every spec carries a manifest-local key. Nothing here can name a UUID,
// because none of it exists yet — resolving those keys against the tenant's
// current state is exactly what Plan does.
func tenantShape() (axiam.ManagementManifest, error) {
	return axiam.NewManifest().
		Resource("docs", "documents", "collection").
		Scope("docs", "draft", "draft", "Unpublished drafts").
		Scope("docs", "published", "published", "Live documents").
		// Ordering is derived, so declaring the child here is fine: Plan sorts
		// resources so a parent always precedes its children.
		ChildResource("archive", "archive", "collection", "docs").
		Permission("read", "document:read", "Read a document").
		Permission("write", "document:write", "Edit a document").
		Permission("purge", "document:purge", "Permanently delete").
		Role("reader", "Reader", "Reads published documents").
		Grant("reader", "read", "", "published").
		Role("editor", "Editor", "Edits drafts and reads everything").
		Grant("editor", "read", "").
		Grant("editor", "write", "", "draft").
		// A deny grant overrides EVERY allow, at any depth of the resource
		// hierarchy and at equal specificity — AXIAM's RBAC engine is
		// deny-override, not most-specific-wins. An editor who is also somehow
		// granted purge still cannot purge.
		Grant("editor", "purge", "deny").
		Group("staff", "Staff", "Everyone in the org", "reader").
		// The password is used ONLY if this user has to be created. A manifest
		// describes shape, and silently resetting a live account's password
		// because a config file mentions one is not a shape change.
		User("alice", "alice", "alice@example.test", axiam.Sensitive(env("ALICE_PASSWORD", ""))).
		AssignRole("alice", "editor").
		AddToGroup("alice", "staff").
		Build()
}

func main() {
	apply := flag.Bool("apply", false, "reconcile the tenant rather than only reporting the plan")
	flag.Parse()

	// Validation happens here, at declaration: a dangling key, a duplicate, or
	// a cycle in the resource parents fails where the manifest is WRITTEN
	// rather than on the first plan against a live tenant, possibly weeks later.
	shape, err := tenantShape()
	if err != nil {
		log.Fatalf("manifest: %v", err)
	}

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

	plan, err := client.Manifest().Plan(ctx, shape)
	if err != nil {
		// Validation precedes every request (§27.6 rule 2), and reports every
		// problem rather than the first — fixing them one at a time is a slow
		// way to learn about four.
		log.Fatalf("plan: %v", err)
	}

	changes := plan.Changes()
	if len(changes) == 0 {
		// Two plans over unchanged state are equal, in the same order
		// (§27.6 rule 8), which is what makes a plan diffable.
		fmt.Println("converged: nothing to do")
		return
	}

	fmt.Printf("%d change(s) of %d step(s):\n", len(changes), len(plan.Actions))
	for _, a := range changes {
		fmt.Printf("  %-10s %-13s %s\n", a.Change, a.Target, a.Summary)
	}

	if !*apply {
		fmt.Println("\nre-run with -apply to reconcile")
		return
	}

	report, err := client.Manifest().Apply(ctx, shape)
	if err != nil {
		log.Fatalf("apply: %v", err)
	}
	for _, s := range report.Steps {
		fmt.Printf("  %-15s %s\n", s.Outcome.Status, s.Action.Summary)
	}
	if failure, stopped := report.Failure(); stopped {
		// Everything before this step has already happened and will not be
		// undone. Fix the cause and re-apply.
		log.Fatalf("\nstopped at %s: %s", failure.Action.Summary, failure.Message)
	}
	fmt.Printf("\napplied %d change(s)\n", report.ChangedCount())
}
