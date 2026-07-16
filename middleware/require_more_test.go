package middleware

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// raceChecker is a concurrency-safe AccessChecker double used by the -race
// test below: every field fakeChecker records is per-call local, so unlike
// fakeChecker (which mutates shared struct fields — fine for sequential
// tests, unsafe for concurrent ones) this double never races on its own
// state under `go test -race` with many goroutines in flight.
type raceChecker struct {
	mu    sync.Mutex
	calls int
}

func (c *raceChecker) CheckAccessAs(_ context.Context, subjectID, action, resourceID string, scope ...string) (bool, string, error) {
	c.mu.Lock()
	c.calls++
	c.mu.Unlock()
	// Deny every other subject purely to exercise both the 200 and 403
	// response paths concurrently; the important property under -race is
	// that concurrent requests through the SAME middleware instance never
	// corrupt each other's decision or context.
	return subjectID != "user-deny", "", nil
}

// TestRequireAccess_ConcurrentRequests exercises RequireAccess from many
// goroutines in parallel against a single shared middleware-wrapped handler,
// each with its own per-request identity in context. Run with `go test
// -race` to catch any shared mutable state accidentally introduced between
// request resolution (identity, resource, scope) and the eventual
// allow/deny response.
func TestRequireAccess_ConcurrentRequests(t *testing.T) {
	checker := &raceChecker{}
	h := RequireAccess(checker, "documents:read", ResourceFromPath("id"))(nopHandler())

	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()

			userID := fmt.Sprintf("user-%d", i)
			if i%7 == 0 {
				userID = "user-deny"
			}

			req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/docs/doc-%d", i), nil)
			req.SetPathValue("id", fmt.Sprintf("doc-%d", i))
			req = req.WithContext(withUser(req.Context(), &User{UserID: userID, TenantID: "tenant-abc"}))

			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)

			wantCode := http.StatusOK
			if userID == "user-deny" {
				wantCode = http.StatusForbidden
			}
			if w.Code != wantCode {
				t.Errorf("goroutine %d: expected %d, got %d", i, wantCode, w.Code)
			}
		}(i)
	}
	wg.Wait()

	if got := checker.calls; got != n {
		t.Fatalf("expected %d checker calls, got %d", n, got)
	}
}

// ---------------------------------------------------------------------------
// Godoc examples — rendered on pkg.go.dev (no hard doc-coverage gate for Go
// per the plan, but examples are the idiomatic way to document usage).
// ---------------------------------------------------------------------------

// exampleChecker is a minimal AccessChecker used only by the doc example
// below, standing in for a real *axiam.Client.
type exampleChecker struct{}

func (exampleChecker) CheckAccessAs(_ context.Context, subjectID, action, resourceID string, scope ...string) (bool, string, error) {
	return true, "", nil
}

// ExampleRequireAccess demonstrates protecting a single route with
// RequireAccess, resolving the resource id from a path parameter and
// requiring the request's authenticated caller to pass a "documents:read"
// check before the handler runs.
func ExampleRequireAccess() {
	mux := http.NewServeMux()
	mux.HandleFunc("/docs/{id}", func(w http.ResponseWriter, r *http.Request) {
		user, _ := UserFromContext(r.Context())
		fmt.Fprintf(w, "document %s for user %s", r.PathValue("id"), user.UserID)
	})

	guarded := RequireAccess(exampleChecker{}, "documents:read", ResourceFromPath("id"))(mux)

	// In a real server this handler chain would additionally be wrapped by
	// Middleware (CONTRACT.md §10) so UserFromContext has an identity to
	// find; here we inject one directly to keep the example self-contained.
	req := httptest.NewRequest(http.MethodGet, "/docs/doc-1", nil)
	req.SetPathValue("id", "doc-1")
	req = req.WithContext(withUser(req.Context(), &User{UserID: "user-42", TenantID: "tenant-abc"}))

	w := httptest.NewRecorder()
	guarded.ServeHTTP(w, req)
	fmt.Println(w.Body.String())

	// Output: document doc-1 for user user-42
}

// ExampleRequireRole demonstrates a cheaper, local-only role check as an
// alternative to (never a substitute for) a resource-level RequireAccess
// check.
func ExampleRequireRole() {
	mux := http.NewServeMux()
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "welcome, admin")
	})

	guarded := RequireRole("admin")(mux)

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req = req.WithContext(withUser(req.Context(), &User{UserID: "user-42", TenantID: "tenant-abc", Roles: []string{"admin"}}))

	w := httptest.NewRecorder()
	guarded.ServeHTTP(w, req)
	fmt.Println(w.Body.String())

	// Output: welcome, admin
}
