// D5 conformance — CONTRACT.md §16, §17, §18, §19.
//
// These assert through the PUBLIC CheckAccess surface, counting requests that
// reach the test server, rather than against the helpers in isolation. That
// distinction is normative as of contract 1.8.1: the TypeScript SDK shipped a
// retry helper that was exported, unit-tested and green while no production
// path called it, so that SDK performed no read-only retries at all and every
// test passed. Counting on the wire is the only assertion that catches it.

package axiam

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// scriptServer replays a status script and counts requests.
func scriptServer(t *testing.T, statuses []int, body string) (*httptest.Server, *int32) {
	t.Helper()
	var calls int32
	if body == "" {
		body = `{"allowed":true,"reason_code":"allowed"}`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		idx := int(n) - 1
		if idx >= len(statuses) {
			idx = len(statuses) - 1
		}
		status := statuses[idx]
		if status == http.StatusOK {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(body))
			return
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func d5Client(t *testing.T, baseURL string, opts ...Option) *Client {
	t.Helper()
	// Pin the jitter to 0 so the tests do not really sleep: a test that waits
	// 200ms is a test nobody runs (§16.7). The delay arithmetic itself is
	// asserted directly in TestDelayFor_*.
	opts = append(opts, WithOrgSlug("acme"), withJitterSource(func() float64 { return 0 }))
	c, err := NewClient(baseURL, "acme", opts...)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

// ---------------------------------------------------------------------------
// §16 — the policy table
// ---------------------------------------------------------------------------

func TestBackoffFor_DoublesFromBaseAndStopsAtCap(t *testing.T) {
	if got := backoffFor(1); got != BaseDelay {
		t.Fatalf("attempt 1: got %v, want %v", got, BaseDelay)
	}
	if got := backoffFor(2); got != 400*time.Millisecond {
		t.Fatalf("attempt 2: got %v, want 400ms", got)
	}
	// The old policy had NO cap — backoff *= 2 forever. This is the assertion
	// that would have failed against it.
	if got := backoffFor(20); got != MaxDelay {
		t.Fatalf("attempt 20: got %v, want the %v cap", got, MaxDelay)
	}
}

func TestDelayFor_UsesFullJitterNotPartial(t *testing.T) {
	// The range is [0, backoff], not backoff ± something. Pinning the fraction
	// to its endpoints is what distinguishes full from partial jitter — a
	// random draw would pass under either. The old Go policy had no jitter at
	// all, so every client retried in lockstep.
	if got := delayFor(1, 0, 0); got != 0 {
		t.Fatalf("fraction 0: got %v, want 0", got)
	}
	if got := delayFor(1, 0, 1); got != BaseDelay {
		t.Fatalf("fraction 1: got %v, want %v", got, BaseDelay)
	}
	if got := delayFor(2, 0, 0.5); got != 200*time.Millisecond {
		t.Fatalf("fraction 0.5 at attempt 2: got %v, want 200ms", got)
	}
}

func TestDelayFor_RetryAfterIsAFloorNeverACeiling(t *testing.T) {
	// A Retry-After of zero cannot shorten the wait. TypeScript's
	// `retryAfterMs ?? backoff(n)` made the hint REPLACE the backoff, so a zero
	// retried immediately and defeated the policy.
	if got := delayFor(1, 2*time.Second, 1); got != 2*time.Second {
		t.Fatalf("longer hint should win: got %v", got)
	}
	if got := delayFor(1, 0, 1); got != BaseDelay {
		t.Fatalf("zero hint must not shorten: got %v, want %v", got, BaseDelay)
	}
	if got := delayFor(1, 50*time.Millisecond, 0); got != 50*time.Millisecond {
		t.Fatalf("hint should floor a zero-jitter wait: got %v", got)
	}
}

func TestParseRetryAfter(t *testing.T) {
	if got := parseRetryAfter("2"); got != 2*time.Second {
		t.Fatalf("delta-seconds: got %v", got)
	}
	if got := parseRetryAfter(""); got != 0 {
		t.Fatalf("absent: got %v", got)
	}
	if got := parseRetryAfter("-5"); got != 0 {
		t.Fatalf("negative must collapse to zero, not become a floor: got %v", got)
	}
	if got := parseRetryAfter("garbage"); got != 0 {
		t.Fatalf("unparseable: got %v", got)
	}
	// The HTTP-date form is not hypothetical: CDNs and proxies use it on 429/503.
	future := time.Now().Add(30 * time.Second).UTC().Format(http.TimeFormat)
	if got := parseRetryAfter(future); got <= 0 || got > 31*time.Second {
		t.Fatalf("http-date: got %v, want ~30s", got)
	}
}

func TestCheckAccess_MakesExactlyThreeAttemptsOnPersistent503(t *testing.T) {
	srv, calls := scriptServer(t, []int{http.StatusServiceUnavailable}, "")
	c := d5Client(t, srv.URL)

	_, _, err := c.CheckAccess(context.Background(), "read", "r-1")
	if !errors.Is(err, ErrNetwork) {
		t.Fatalf("want *NetworkError, got %T: %v", err, err)
	}
	if got := atomic.LoadInt32(calls); got != MaxAttempts {
		t.Fatalf("got %d attempts, want %d", got, MaxAttempts)
	}
}

func TestCheckAccess_RetriesTransientThenSucceeds(t *testing.T) {
	srv, calls := scriptServer(t, []int{http.StatusServiceUnavailable, http.StatusOK}, "")
	c := d5Client(t, srv.URL)

	allowed, _, err := c.CheckAccess(context.Background(), "read", "r-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !allowed {
		t.Fatal("want allowed")
	}
	if got := atomic.LoadInt32(calls); got != 2 {
		t.Fatalf("got %d attempts, want 2", got)
	}
}

func TestCheckAccess_DoesNotRetryDecisive403(t *testing.T) {
	// A 403 is an answer, not a transport failure. Retrying reproduces the
	// identical rejection and spends the caller's latency budget.
	srv, calls := scriptServer(t, []int{http.StatusForbidden}, "")
	c := d5Client(t, srv.URL)

	if _, _, err := c.CheckAccess(context.Background(), "read", "r-1"); err == nil {
		t.Fatal("want an error")
	}
	if got := atomic.LoadInt32(calls); got != 1 {
		t.Fatalf("got %d attempts, want 1", got)
	}
}

func TestCheckAccess_SingleAttemptWhenRetryDisabled(t *testing.T) {
	srv, calls := scriptServer(t, []int{http.StatusServiceUnavailable}, "")
	c := d5Client(t, srv.URL, WithRetryDisabled())

	if _, _, err := c.CheckAccess(context.Background(), "read", "r-1"); err == nil {
		t.Fatal("want an error")
	}
	if got := atomic.LoadInt32(calls); got != 1 {
		t.Fatalf("got %d attempts, want 1", got)
	}
}

// ---------------------------------------------------------------------------
// §17 — decision memo
// ---------------------------------------------------------------------------

func TestMemo_IsOffByDefault(t *testing.T) {
	// The most important assertion here. §11.2 rule 6's ban on decision caching
	// is still the default; a build that quietly enabled this would change
	// authorization staleness for every existing caller without them asking.
	srv, calls := scriptServer(t, []int{http.StatusOK}, "")
	c := d5Client(t, srv.URL)

	for i := 0; i < 2; i++ {
		if _, _, err := c.CheckAccess(context.Background(), "read", "r-1"); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if got := atomic.LoadInt32(calls); got != 2 {
		t.Fatalf("got %d calls, want 2 — the memo must be off by default", got)
	}
}

func TestMemo_ServesRepeatInsideTTL(t *testing.T) {
	srv, calls := scriptServer(t, []int{http.StatusOK}, "")
	c := d5Client(t, srv.URL, WithDecisionMemoTTL(5*time.Second))

	first, err := c.CheckAccessDecision(context.Background(), "", "read", "r-1")
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := c.CheckAccessDecision(context.Background(), "", "read", "r-1")
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if got := atomic.LoadInt32(calls); got != 1 {
		t.Fatalf("got %d calls, want 1", got)
	}
	// §17.1 rule 5: the reason code survives the memo. Returning Allowed while
	// dropping the code would make the field intermittently absent.
	if second.ReasonCode != first.ReasonCode || second.ReasonCode == "" {
		t.Fatalf("reason code lost: first=%q second=%q", first.ReasonCode, second.ReasonCode)
	}
}

func TestMemo_CachesDeniesExactlyLikeAllows(t *testing.T) {
	// §17.1 rule 4 — asymmetric caching makes the two outcomes take measurably
	// different times, leaking which occurred. Assert the call count, not the
	// outcome.
	srv, calls := scriptServer(t, []int{http.StatusOK}, `{"allowed":false,"reason_code":"denied_by_rule"}`)
	c := d5Client(t, srv.URL, WithDecisionMemoTTL(5*time.Second))

	for i := 0; i < 2; i++ {
		if _, _, err := c.CheckAccess(context.Background(), "read", "r-1"); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if got := atomic.LoadInt32(calls); got != 1 {
		t.Fatalf("got %d calls, want 1 — denies must be memoized like allows", got)
	}
}

func TestMemo_NeverCachesAFailure(t *testing.T) {
	// §17.1 rule 7 — caching a transport error as a deny turns a blip into a
	// TTL-long outage.
	srv, calls := scriptServer(t, []int{http.StatusServiceUnavailable}, "")
	c := d5Client(t, srv.URL, WithDecisionMemoTTL(5*time.Second), WithRetryDisabled())

	for i := 0; i < 2; i++ {
		if _, _, err := c.CheckAccess(context.Background(), "read", "r-1"); err == nil {
			t.Fatalf("call %d: want an error", i)
		}
	}
	if got := atomic.LoadInt32(calls); got != 2 {
		t.Fatalf("got %d calls, want 2 — failures must not be memoized", got)
	}
}

func TestMemoKey_DistinguishesEveryComponent(t *testing.T) {
	base := AccessCheck{Action: "read", ResourceID: "r1"}
	keys := map[string]bool{
		memoKey(base): true,
		memoKey(AccessCheck{Action: "write", ResourceID: "r1"}):                 true,
		memoKey(AccessCheck{Action: "read", ResourceID: "r2"}):                  true,
		memoKey(AccessCheck{Action: "read", ResourceID: "r1", Scope: "col-a"}):  true,
		memoKey(AccessCheck{Action: "read", ResourceID: "r1", SubjectID: "u1"}): true,
	}
	if len(keys) != 5 {
		t.Fatalf("got %d distinct keys, want 5", len(keys))
	}
	// A caller-supplied value cannot forge a collision by embedding the
	// separator, because the separator cannot appear in a real action or UUID.
	if strings.Contains(memoKey(base), "read\x1fr1") {
		t.Fatal("component order must not let values run together")
	}
}

func TestMemo_ClampsTTLRatherThanRejecting(t *testing.T) {
	if got := newDecisionMemo(time.Hour).ttl; got != MaxMemoTTL {
		t.Fatalf("got %v, want clamp to %v", got, MaxMemoTTL)
	}
	if got := newDecisionMemo(2 * time.Second).ttl; got != 2*time.Second {
		t.Fatalf("got %v, want 2s", got)
	}
	if newDecisionMemo(0).enabled() {
		t.Fatal("zero TTL must mean disabled")
	}
}

func TestMemo_ExpiresExactlyAtTTL(t *testing.T) {
	now := time.Unix(1000, 0)
	m := newDecisionMemo(5 * time.Second)
	m.now = func() time.Time { return now }
	m.set("k", AccessResult{Allowed: true})

	now = now.Add(4999 * time.Millisecond)
	if _, ok := m.get("k"); !ok {
		t.Fatal("should still be live just before the TTL")
	}
	now = now.Add(time.Millisecond)
	if _, ok := m.get("k"); ok {
		t.Fatal("should be expired at exactly the TTL")
	}
}

// ---------------------------------------------------------------------------
// §18 — deterministic shutdown
// ---------------------------------------------------------------------------

func TestClose_IsIdempotent(t *testing.T) {
	srv, _ := scriptServer(t, []int{http.StatusOK}, "")
	c := d5Client(t, srv.URL)
	if err := c.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestClose_IssuesNoNetworkRequest(t *testing.T) {
	// §18.1 rule 5. The server-side session deliberately outlives the Client
	// value — that is what lets a process restart and resume — so a Close that
	// logged out would silently end every user's session on each deploy.
	// Asserted against the wire, because a Logout wired into Close succeeds
	// silently and would pass any return-value assertion.
	srv, calls := scriptServer(t, []int{http.StatusOK}, "")
	c := d5Client(t, srv.URL)

	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := atomic.LoadInt32(calls); got != 0 {
		t.Fatalf("Close made %d requests, want 0 — Close must not log out", got)
	}
}

func TestUseAfterClose_FailsRatherThanReconnecting(t *testing.T) {
	srv, calls := scriptServer(t, []int{http.StatusOK}, "")
	c := d5Client(t, srv.URL)

	if _, _, err := c.CheckAccess(context.Background(), "read", "r-1"); err != nil {
		t.Fatalf("pre-close call: %v", err)
	}
	before := atomic.LoadInt32(calls)

	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, _, err := c.CheckAccess(context.Background(), "read", "r-1"); err == nil ||
		!strings.Contains(err.Error(), "closed") {
		t.Fatalf("CheckAccess after Close: got %v, want a closed error", err)
	}
	if _, err := c.Login(context.Background(), "u@example.com", "pw"); err == nil ||
		!strings.Contains(err.Error(), "closed") {
		t.Fatalf("Login after Close: got %v, want a closed error", err)
	}
	if err := c.Logout(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "closed") {
		t.Fatalf("Logout after Close: got %v, want a closed error", err)
	}

	if got := atomic.LoadInt32(calls); got != before {
		t.Fatalf("requests reached the server after Close: %d -> %d", before, got)
	}
}

// ---------------------------------------------------------------------------
// §19 — telemetry
// ---------------------------------------------------------------------------

func TestTelemetry_EmitsRequestPairPerAttemptWithRetryBetween(t *testing.T) {
	srv, _ := scriptServer(t, []int{http.StatusServiceUnavailable, http.StatusOK}, "")

	var events []TelemetryEvent
	c := d5Client(t, srv.URL, WithTelemetryHook(func(e TelemetryEvent) {
		events = append(events, e)
	}))

	if _, _, err := c.CheckAccess(context.Background(), "read", "r-1"); err != nil {
		t.Fatalf("CheckAccess: %v", err)
	}

	var kinds []string
	var attempts []int
	for _, e := range events {
		switch ev := e.(type) {
		case RequestStartEvent:
			kinds = append(kinds, "start")
			attempts = append(attempts, ev.Attempt)
			// The path TEMPLATE, never a substituted URL — a metric label
			// carrying a UUID is a cardinality bomb.
			if ev.PathTemplate != checkPath {
				t.Fatalf("path template: got %q, want %q", ev.PathTemplate, checkPath)
			}
		case RequestEndEvent:
			kinds = append(kinds, "end")
		case RetryEvent:
			kinds = append(kinds, "retry")
		}
	}

	want := []string{"start", "end", "retry", "start", "end"}
	if strings.Join(kinds, ",") != strings.Join(want, ",") {
		t.Fatalf("event sequence: got %v, want %v", kinds, want)
	}
	// One pair per ATTEMPT: §19.2 rule 5 exists so a caller can count real wire
	// calls. Emitting both pairs as attempt 1 would make a retried call look
	// like a single slow one.
	if len(attempts) != 2 || attempts[0] != 1 || attempts[1] != 2 {
		t.Fatalf("attempt numbers: got %v, want [1 2]", attempts)
	}
}

func TestTelemetry_PanickingHookCannotFailTheOperation(t *testing.T) {
	// §19.2 rule 2 — telemetry is not permitted to fail an authorization check.
	// In Go the stakes are higher than elsewhere: an unrecovered panic in a
	// hook would take the process down, not just the request.
	srv, _ := scriptServer(t, []int{http.StatusOK}, "")
	c := d5Client(t, srv.URL, WithTelemetryHook(func(TelemetryEvent) {
		panic("hook exploded")
	}))

	allowed, _, err := c.CheckAccess(context.Background(), "read", "r-1")
	if err != nil {
		t.Fatalf("a panicking hook must not fail the call: %v", err)
	}
	if !allowed {
		t.Fatal("want allowed")
	}
}

func TestTelemetry_NoEventCarriesAToken(t *testing.T) {
	// §19.2 rule 3 — this surface exists to be shipped to a metrics backend,
	// which is the last place a bearer token should land.
	srv, _ := scriptServer(t, []int{http.StatusServiceUnavailable}, "")

	var rendered strings.Builder
	c := d5Client(t, srv.URL, WithTelemetryHook(func(e TelemetryEvent) {
		rendered.WriteString(strings.ToLower(errors.New("").Error()))
		switch ev := e.(type) {
		case RetryEvent:
			rendered.WriteString(strings.ToLower(ev.Reason))
		case RequestEndEvent:
			rendered.WriteString(strings.ToLower(ev.PathTemplate))
		}
	}))

	if _, _, err := c.CheckAccess(context.Background(), "read", "r-1"); err == nil {
		t.Fatal("want an error")
	}
	out := rendered.String()
	if strings.Contains(out, "eyj") { // a JWT-shaped string
		t.Fatalf("token-shaped content in telemetry: %q", out)
	}
	if strings.Contains(out, "authorization") {
		t.Fatalf("authorization header content in telemetry: %q", out)
	}
}

func TestTelemetry_NoHookCostsNothing(t *testing.T) {
	var d dispatcher
	if d.installed() {
		t.Fatal("zero dispatcher must report no hook")
	}
	// Must not panic with no hook installed.
	d.emit(RefreshEvent{Role: RefreshLeader, Duration: time.Millisecond})
}
