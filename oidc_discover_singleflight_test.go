package axiam

// Regression tests for OidcDiscover's single-flight COMPLETION ORDERING
// (CONTRACT.md §12.3 rule 6), the sibling of the OidcRefresh ordering covered
// in oidc_refresh_singleflight_test.go.
//
// TestOidcDiscover_ConcurrentCallsSingleFlight (oidc_discover_test.go) holds
// the discovery endpoint open until all N callers have joined, so every
// caller arrives BEFORE the outcome is handed over. It therefore cannot see a
// wrong completion order.
//
// The tests below target the instant after fetchOidcDiscovery has returned but
// before the guard's bookkeeping is finished. oidcState.discoveryFetch is a
// result-sharing channel, not a busy flag, so it must stay populated until
// close(f.done) has handed the outcome over. Whether the old ordering was
// observable depended on which path ran:
//
//   - SUCCESS: benign. discoveryDoc/discoveryExp are populated under the same
//     lock that vacates the slot, so a caller landing in the window hits the
//     warm cache — Java's state (b), "slot empty and the fresh value already
//     cached". TestOidcDiscover_LateArrivalMakesNoSecondFetch is a guard-rail
//     for that path, not a regression proof: it passes either way, and exists
//     so a future change that stops caching under that lock cannot silently
//     reintroduce a second fetch.
//   - ERROR: NOT benign, and the reason for this fix. No cache is written, so
//     a caller landing in the window observed "slot empty AND nothing
//     published" and started a SECOND discovery fetch.
//     TestOidcDiscover_LateArrivalSharesFetchFailure is the regression proof
//     and fails against the old ordering.
//
// A redundant GET is idempotent, so this was a spurious extra request rather
// than the wrong-result bug the OidcRefresh ordering caused against single-use
// rotating refresh tokens. It is fixed to make the bad interleaving
// unreachable rather than merely harmless, and to keep one invariant across
// both single-flight guards in this file.
//
// The window is a couple of instructions wide, so it is pinned open through
// the oidcState.afterDiscoveryPublish seam rather than raced for.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
)

// discoveryCountingServer serves GET /.well-known/openid-configuration,
// counting every request. While failing is true it answers 500 (mapped to
// *NetworkError by the §2 status mapper) instead of the document, so the
// no-cache-written error path can be exercised.
type discoveryCountingServer struct {
	*httptest.Server
	hits    int32
	failing atomic.Bool
}

func newDiscoveryCountingServer(t *testing.T) *discoveryCountingServer {
	t.Helper()
	s := &discoveryCountingServer{}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&s.hits, 1)
		if s.failing.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"discovery unavailable"}`))
			return
		}
		writeJSON(t, w, discoveryDoc(s.Server.URL))
	})
	s.Server = httptest.NewServer(mux)
	t.Cleanup(s.Server.Close)
	return s
}

func (s *discoveryCountingServer) Hits() int32 { return atomic.LoadInt32(&s.hits) }

// TestOidcDiscover_LateArrivalMakesNoSecondFetch is the success-path
// guard-rail: a caller running inside the published-but-not-yet-vacated window
// must get the same document without a second HTTP request. This holds under
// either completion order (the warm cache covers the old one), so it proves
// no regression by itself — see this file's header comment.
func TestOidcDiscover_LateArrivalMakesNoSecondFetch(t *testing.T) {
	srv := newDiscoveryCountingServer(t)
	client, err := NewClient(srv.URL, "acme")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	var (
		fired   atomic.Bool
		lateDoc OidcConfiguration
		lateErr error
		lateRan bool
		leaders int32
	)
	client.oidc.afterDiscoveryPublish = func() {
		atomic.AddInt32(&leaders, 1)
		// CompareAndSwap, not sync.Once: an inverted ordering makes the late
		// caller a second fetch LEADER, which re-enters this hook. Once.Do
		// would block that re-entrant call until the outer Do returned —
		// which is waiting on it — and deadlock instead of reporting the bug.
		if !fired.CompareAndSwap(false, true) {
			return
		}
		lateRan = true
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			lateDoc, lateErr = client.OidcDiscover(context.Background())
		}()
		wg.Wait()
	}

	leaderDoc, leaderErr := client.OidcDiscover(context.Background())
	if leaderErr != nil {
		t.Fatalf("leader OidcDiscover: %v", leaderErr)
	}
	if !lateRan {
		t.Fatal("afterDiscoveryPublish seam never fired — this test would prove nothing")
	}

	if got := srv.Hits(); got != 1 {
		t.Errorf("§12.3 rule 6: want exactly 1 discovery request, got %d", got)
	}
	if lateErr != nil {
		t.Errorf("late caller must share the leader's outcome, got error: %v", lateErr)
	}
	if lateDoc.Issuer != leaderDoc.Issuer || lateDoc.TokenEndpoint != leaderDoc.TokenEndpoint {
		t.Errorf("late caller got a different document: %+v vs leader %+v", lateDoc, leaderDoc)
	}
	if got := atomic.LoadInt32(&leaders); got != 1 {
		t.Errorf("the guard admitted %d discovery leaders, want exactly 1", got)
	}
}

// TestOidcDiscover_LateArrivalSharesFetchFailure is the regression proof. On
// the error path nothing is cached, so publication has to be what keeps a
// late arrival from re-fetching: a caller running inside the window must
// receive the ONE failed fetch's error and issue no second request. Against
// the old ordering it saw an empty slot with nothing published and fetched
// again.
func TestOidcDiscover_LateArrivalSharesFetchFailure(t *testing.T) {
	srv := newDiscoveryCountingServer(t)
	srv.failing.Store(true)

	client, err := NewClient(srv.URL, "acme")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	var (
		fired   atomic.Bool
		lateErr error
		lateRan bool
		leaders int32
	)
	client.oidc.afterDiscoveryPublish = func() {
		atomic.AddInt32(&leaders, 1)
		// CompareAndSwap, not sync.Once — see the note in
		// TestOidcDiscover_LateArrivalMakesNoSecondFetch.
		if !fired.CompareAndSwap(false, true) {
			return
		}
		lateRan = true
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, lateErr = client.OidcDiscover(context.Background())
		}()
		wg.Wait()
	}

	_, leaderErr := client.OidcDiscover(context.Background())
	if leaderErr == nil {
		t.Fatal("leader OidcDiscover: want the 5xx failure, got nil")
	}
	if !lateRan {
		t.Fatal("afterDiscoveryPublish seam never fired — this test would prove nothing")
	}

	if got := srv.Hits(); got != 1 {
		t.Errorf("§12.3 rule 6: a failed fetch must be shared, not re-issued; got %d discovery requests, want 1", got)
	}
	if lateErr == nil {
		t.Fatal("late caller must receive the shared failure, got nil error")
	}
	if lateErr.Error() != leaderErr.Error() {
		t.Errorf("late caller got a different error:\n  late:   %v\n  leader: %v", lateErr, leaderErr)
	}
	if got := atomic.LoadInt32(&leaders); got != 1 {
		t.Errorf("the guard admitted %d discovery leaders, want exactly 1", got)
	}

	// A failed fetch must leave the guard usable and must NOT have been
	// cached: the next call re-fetches and succeeds.
	client.oidc.afterDiscoveryPublish = nil
	srv.failing.Store(false)
	doc, err := client.OidcDiscover(context.Background())
	if err != nil {
		t.Fatalf("OidcDiscover after a failed fetch: %v", err)
	}
	if doc.Issuer != srv.URL {
		t.Errorf("Issuer = %q, want %q", doc.Issuer, srv.URL)
	}
	if got := srv.Hits(); got != 2 {
		t.Errorf("want 2 discovery requests in total, got %d", got)
	}
}

// TestOidcDiscover_BurstStraddlesCompletionWindow is the full §12.3 rule 6
// burst test with callers on BOTH sides of the leader's completion: some join
// while the fetch is still outstanding, the rest arrive inside the
// published-but-not-yet-vacated window. All must receive that one fetch's
// document, with exactly one HTTP request in total. Run on the error path,
// where no cache can mask a missing hand-over.
func TestOidcDiscover_BurstStraddlesCompletionWindow(t *testing.T) {
	const early = 6 // callers that join while the fetch is in flight
	const late = 4  // callers that arrive inside the completion window

	var hits int32
	release := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		<-release
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"discovery unavailable"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client, err := NewClient(srv.URL, "acme")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	var (
		fired    atomic.Bool
		lateErrs = make([]error, late)
	)
	client.oidc.afterDiscoveryPublish = func() {
		// CompareAndSwap, not sync.Once — see the note in
		// TestOidcDiscover_LateArrivalMakesNoSecondFetch.
		if !fired.CompareAndSwap(false, true) {
			return
		}
		var wg sync.WaitGroup
		wg.Add(late)
		for i := 0; i < late; i++ {
			go func(idx int) {
				defer wg.Done()
				_, lateErrs[idx] = client.OidcDiscover(context.Background())
			}(i)
		}
		wg.Wait()
	}

	earlyErrs := make([]error, early)
	var wg sync.WaitGroup
	wg.Add(early)
	for i := 0; i < early; i++ {
		go func(idx int) {
			defer wg.Done()
			_, earlyErrs[idx] = client.OidcDiscover(context.Background())
		}(i)
	}

	waitForGoroutines() // let all `early` callers reach the guard
	close(release)      // the leader's fetch now returns
	wg.Wait()

	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("§12.3 rule 6: want exactly 1 discovery request for %d early + %d late callers, got %d",
			early, late, got)
	}
	want := earlyErrs[0]
	if want == nil {
		t.Fatal("early caller 0: want the 5xx failure, got nil")
	}
	for i, err := range earlyErrs {
		if err == nil {
			t.Errorf("early caller %d: want the shared failure, got nil", i)
		} else if err.Error() != want.Error() {
			t.Errorf("early caller %d got %v, want the shared %v", i, err, want)
		}
	}
	for i, err := range lateErrs {
		if err == nil {
			t.Errorf("late caller %d: want the shared failure, got nil", i)
		} else if err.Error() != want.Error() {
			t.Errorf("late caller %d got %v, want the shared %v", i, err, want)
		}
	}
}
