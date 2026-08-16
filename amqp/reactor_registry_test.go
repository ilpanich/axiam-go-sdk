package amqp

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestReactorRegistry_PatchAllowLists is §22.13's registry block, stated
// field by field. The namespace-prefix rule is one sentence and five
// counterexamples, and every one of the five has been shipped as a bug in
// something: `ext.` itself, the bare namespace, the string-prefix match, the
// near-miss identifier, and the suffix match.
func TestReactorRegistry_PatchAllowLists(t *testing.T) {
	cases := []struct {
		event   string
		field   string
		allowed bool
	}{
		// token.pre_issue — the `ext.` namespace and nothing else.
		{ReactorEventTokenPreIssue, "ext.department", true},
		{ReactorEventTokenPreIssue, "ext.a.b.c", true},
		{ReactorEventTokenPreIssue, "ext.", false},
		{ReactorEventTokenPreIssue, "ext", false},
		{ReactorEventTokenPreIssue, "extra", false},
		{ReactorEventTokenPreIssue, "external_id", false},
		{ReactorEventTokenPreIssue, "evil.ext.department", false},
		// Every standard claim is out of reach because none of them begins
		// with `ext.`. A hook that can rewrite `sub` is a hook that can mint
		// a token for anyone.
		{ReactorEventTokenPreIssue, "iss", false},
		{ReactorEventTokenPreIssue, "sub", false},
		{ReactorEventTokenPreIssue, "aud", false},
		{ReactorEventTokenPreIssue, "exp", false},
		{ReactorEventTokenPreIssue, "iat", false},
		{ReactorEventTokenPreIssue, "nbf", false},
		{ReactorEventTokenPreIssue, "jti", false},
		{ReactorEventTokenPreIssue, "scope", false},
		{ReactorEventTokenPreIssue, "scp", false},
		{ReactorEventTokenPreIssue, "azp", false},
		{ReactorEventTokenPreIssue, "act", false},
		{ReactorEventTokenPreIssue, "client_id", false},

		// user.pre_create / user.pre_update — profile attributes only.
		{ReactorEventUserPreCreate, "username", true},
		{ReactorEventUserPreCreate, "email", true},
		{ReactorEventUserPreCreate, "metadata.source", true},
		{ReactorEventUserPreCreate, "metadata", false},
		{ReactorEventUserPreCreate, "metadata.", false},
		{ReactorEventUserPreCreate, "password", false},
		{ReactorEventUserPreCreate, "password_hash", false},
		{ReactorEventUserPreCreate, "tenant_id", false},
		{ReactorEventUserPreCreate, "id", false},
		{ReactorEventUserPreCreate, "roles", false},
		{ReactorEventUserPreCreate, "is_admin", false},
		{ReactorEventUserPreUpdate, "email", true},
		{ReactorEventUserPreUpdate, "roles", false},

		// Veto-only events accept no patch field at all.
		{ReactorEventLoginPostAuth, "username", false},
		{ReactorEventLoginPostAuth, "ext.department", false},
		{ReactorEventGrantPreAssign, "role", false},
		{ReactorEventGrantPreAssign, "ext.department", false},
	}

	for _, tc := range cases {
		spec, ok := ReactorEventSpecFor(tc.event)
		if !ok {
			t.Fatalf("%s must be in the registry", tc.event)
		}
		if got := spec.PatchFieldAllowed(tc.field); got != tc.allowed {
			t.Errorf("%s: PatchFieldAllowed(%q) = %v, want %v", tc.event, tc.field, got, tc.allowed)
		}
	}
}

// TestReactorRegistry_DefaultFailurePolicies pins the per-event defaults and
// §22.8's strictest-wins composition, in BOTH array orders.
//
// An SDK that took the first event's default would let the order of a JSON
// array decide whether an unreachable fraud check passes — which is why the
// contract writes this as a MUST NOT reimplement rather than a note.
func TestReactorRegistry_DefaultFailurePolicies(t *testing.T) {
	perEvent := map[string]string{
		ReactorEventTokenPreIssue:  ReactorFailOpen,
		ReactorEventLoginPostAuth:  ReactorFailClosed,
		ReactorEventUserPreCreate:  ReactorFailClosed,
		ReactorEventUserPreUpdate:  ReactorFailClosed,
		ReactorEventGrantPreAssign: ReactorFailClosed,
	}
	for event, want := range perEvent {
		spec, ok := ReactorEventSpecFor(event)
		if !ok {
			t.Fatalf("%s must be in the registry", event)
		}
		if spec.DefaultFailurePolicy != want {
			t.Errorf("%s default policy = %q, want %q", event, spec.DefaultFailurePolicy, want)
		}
	}

	composed := []struct {
		name   string
		events []string
		want   string
	}{
		{"open alone", []string{ReactorEventTokenPreIssue}, ReactorFailOpen},
		{"closed alone", []string{ReactorEventLoginPostAuth}, ReactorFailClosed},
		{"open then closed", []string{ReactorEventTokenPreIssue, ReactorEventLoginPostAuth}, ReactorFailClosed},
		{"closed then open", []string{ReactorEventLoginPostAuth, ReactorEventTokenPreIssue}, ReactorFailClosed},
		{"empty", nil, ReactorFailClosed},
		{"unknown name", []string{"nope.not_an_event"}, ReactorFailClosed},
	}
	for _, tc := range composed {
		if got := ReactorDefaultFailurePolicy(tc.events); got != tc.want {
			t.Errorf("%s: ReactorDefaultFailurePolicy(%v) = %q, want %q", tc.name, tc.events, got, tc.want)
		}
	}
}

// TestReactorRegistry_HotPathExclusion is §22.7's MUST NOT, asserted on the
// enum/list rather than on a comment.
//
// `authz.check`, `authz.check_batch` and `token.introspect` are not
// hookable. The reason is arithmetic, not policy: a reactor round-trip is
// milliseconds and the check path's budget is microseconds. An application
// that needs external input on an authorization decision writes a deny
// grant, which the engine evaluates in the hot path at hot-path cost.
func TestReactorRegistry_HotPathExclusion(t *testing.T) {
	excluded := []string{"authz.check", "authz.check_batch", "token.introspect"}

	for _, name := range excluded {
		if _, ok := ReactorEventSpecFor(name); ok {
			t.Errorf("%s MUST NOT be in the reactor event registry", name)
		}
		for _, spec := range ReactorEvents() {
			if spec.Name == name {
				t.Errorf("%s MUST NOT appear in ReactorEvents()", name)
			}
		}
	}

	// And nowhere in the reactor surface at all — §22.7 bars them from any
	// constant list AND any documentation example, which a registry lookup
	// alone would not catch.
	for _, file := range reactorSourceFiles(t) {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("failed to read %s: %v", file, err)
		}
		// This test file names them on purpose; it is the assertion.
		if strings.HasSuffix(file, "reactor_registry_test.go") {
			continue
		}
		for _, name := range excluded {
			if strings.Contains(string(src), name) {
				t.Errorf("%s names the non-hookable operation %q (§22.7)", file, name)
			}
		}
	}
}

// TestReactorMux_RejectsHotPathOperations is the same MUST NOT one layer up:
// ReactorMux accepts only registry names, so the three hot-path operations
// cannot be bound to a handler either. It lives in this file because this is
// the one file §22.7's source scan above allows to name them.
func TestReactorMux_RejectsHotPathOperations(t *testing.T) {
	noop := func(context.Context, ReactorEvent) (ReactorAnswer, error) { return ReactorAllow(), nil }
	for _, event := range []string{"authz.check", "authz.check_batch", "token.introspect"} {
		if _, err := NewReactorMux().On(event, noop).Handler(); err == nil {
			t.Errorf("binding %q was accepted; §22.7 makes it un-hookable", event)
		}
	}
}

// TestReactorRegistry_IsACopy asserts a caller cannot edit the SDK's own
// allow-lists in place. An allow-list a caller can widen is not an
// allow-list.
func TestReactorRegistry_IsACopy(t *testing.T) {
	events := ReactorEvents()
	for i := range events {
		if events[i].Name == ReactorEventTokenPreIssue {
			events[i].MutableFields = append(events[i].MutableFields, "sub")
			events[i].Mutable = true
		}
	}
	spec, _ := ReactorEventSpecFor(ReactorEventTokenPreIssue)
	if spec.PatchFieldAllowed("sub") {
		t.Fatal("mutating the slice returned by ReactorEvents() must not widen the registry")
	}

	spec.MutableFields = append(spec.MutableFields, "sub")
	fresh, _ := ReactorEventSpecFor(ReactorEventTokenPreIssue)
	if fresh.PatchFieldAllowed("sub") {
		t.Fatal("mutating a returned ReactorEventSpec must not widen the registry")
	}
}

// TestReactorRuntime_DeclaresNoTopology is §22.13's "the runtime declares no
// exchange, queue or binding".
//
// Asserted two ways, because either alone is weak. Structurally:
// ReactorTransport carries no declare or bind method, so there is no seam
// through which the runtime could ask for one. Textually: no reactor source
// file names amqp091's declare/bind calls, which is what catches somebody
// reaching around the interface to the concrete channel.
func TestReactorRuntime_DeclaresNoTopology(t *testing.T) {
	banned := []string{"ExchangeDeclare", "QueueDeclare", "QueueBind", "ExchangeBind"}
	for _, file := range reactorSourceFiles(t) {
		if strings.HasSuffix(file, "reactor_registry_test.go") {
			continue // names them to ban them
		}
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("failed to read %s: %v", file, err)
		}
		for _, call := range banned {
			if strings.Contains(string(src), call) {
				t.Errorf("%s calls %s — a reactor consumes, it never declares topology (§22.1)", file, call)
			}
		}
	}
}

// reactorSourceFiles lists the package's reactor sources, so the two
// scanning tests above cannot silently stop covering a file somebody adds.
func reactorSourceFiles(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob("reactor*.go")
	if err != nil {
		t.Fatalf("failed to glob reactor sources: %v", err)
	}
	if len(files) < 4 {
		t.Fatalf("expected the reactor implementation and its tests, found %v", files)
	}
	return files
}
