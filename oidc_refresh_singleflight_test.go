package axiam

// Regression tests for OidcRefresh's single-flight COMPLETION ORDERING
// (CONTRACT.md §9 rules 2 and 3).
//
// TestOidcRefresh_ConcurrentCallsSingleFlight (oidc_test.go) covers the easy
// half of §9 rule 2: callers that arrive while the wire call is still
// outstanding all block on the same future. It cannot catch a wrong
// completion order, because it holds the token endpoint open until every
// caller has already joined.
//
// The tests below cover the hard half: the instant AFTER the wire call has
// returned but BEFORE the guard's bookkeeping is finished. oidcState's
// pendingRefresh slot is a result-sharing channel, not a busy flag, so the
// outcome must be published before the slot is vacated; otherwise a caller
// landing in that window finds an empty slot AND no published outcome, and
// starts a SECOND refresh_token grant. AXIAM refresh tokens are single-use
// with rotation, so that second grant replays an already-consumed token and
// fails with invalid_grant — a wrong result, not merely a spurious extra
// request.
//
// That window is a couple of instructions wide, so it is pinned open
// deterministically through the oidcState.afterRefreshPublish test seam
// rather than raced for.

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
)

// rotatingTokenEndpoint returns a token handler that models AXIAM's
// single-use, rotating refresh tokens: the first presentation of a given
// refresh_token succeeds and rotates it, and any replay of an
// already-consumed value fails with the OAuth2 invalid_grant error, exactly
// as the real authorization server would. It also records every
// refresh_token value it was presented with, in order, for diagnostics.
//
// If gate is non-nil the handler blocks on it before responding, so a test
// can hold the leader's wire call open while other callers pile up.
func rotatingTokenEndpoint(t *testing.T, gate <-chan struct{}) (http.HandlerFunc, func() []string) {
	t.Helper()
	var (
		mu       sync.Mutex
		consumed = map[string]bool{}
		seen     []string
		gen      int
	)
	handler := func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm: %v", err)
			return
		}
		presented := r.Form.Get("refresh_token")

		mu.Lock()
		seen = append(seen, presented)
		replay := consumed[presented]
		consumed[presented] = true
		gen++
		generation := gen
		mu.Unlock()

		if gate != nil {
			<-gate
		}

		if replay {
			// The server-side consequence of a redundant second grant.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"refresh token already used"}`))
			return
		}
		writeJSON(t, w, map[string]any{
			"access_token":  "access-gen-" + strconv.Itoa(generation),
			"refresh_token": "refresh-gen-" + strconv.Itoa(generation),
			"token_type":    "Bearer",
			"expires_in":    900,
		})
	}
	return handler, func() []string {
		mu.Lock()
		defer mu.Unlock()
		out := make([]string, len(seen))
		copy(out, seen)
		return out
	}
}

// TestOidcRefresh_LateArrivalJoinsPublishedOutcome is the §9 rule 2
// regression test for completion order.
//
// A second caller runs at the exact instant between the leader's two
// completion steps. It must find the outcome already published — a CLOSED
// done channel stays readable forever, so joining a settled flight costs
// nothing — and return that one wire call's token set. Were publication to
// happen after the slot is vacated, this caller would instead see an empty
// slot and issue a second refresh_token grant with the already-consumed
// token: two token calls, and invalid_grant for this caller.
func TestOidcRefresh_LateArrivalJoinsPublishedOutcome(t *testing.T) {
	srv := newOidcTestServer(t)
	handler, presented := rotatingTokenEndpoint(t, nil)
	srv.TokenHandler = handler

	client, err := NewClient(srv.URL, "acme", WithOidcClientID(testClientID))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	// Warm the discovery cache so the late caller's only possible wire call
	// is the token request itself.
	if _, err := client.OidcDiscover(context.Background()); err != nil {
		t.Fatalf("OidcDiscover: %v", err)
	}

	var (
		fired    atomic.Bool
		lateSet  OidcTokenSet
		lateErr  error
		lateRan  bool
		leaders  int
		leaderMu sync.Mutex
	)
	// Pin the published-but-not-yet-vacated window open: run an entire
	// second OidcRefresh inside it, on another goroutine, and wait for it.
	client.oidc.afterRefreshPublish = func() {
		leaderMu.Lock()
		leaders++
		leaderMu.Unlock()
		// CompareAndSwap, not sync.Once: an inverted ordering makes the
		// late caller a second LEADER, which re-enters this hook. Once.Do
		// would block that re-entrant call until the outer Do returned —
		// which is waiting on it — and deadlock instead of reporting the
		// bug.
		if !fired.CompareAndSwap(false, true) {
			return
		}
		lateRan = true
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			lateSet, lateErr = client.OidcRefresh(context.Background(), OidcRefreshParams{
				RefreshToken: Sensitive("rt-original"),
				TenantID:     testTenantID,
			})
		}()
		wg.Wait()
	}

	leaderSet, leaderErr := client.OidcRefresh(context.Background(), OidcRefreshParams{
		RefreshToken: Sensitive("rt-original"),
		TenantID:     testTenantID,
	})
	if leaderErr != nil {
		t.Fatalf("leader OidcRefresh: %v", leaderErr)
	}
	if !lateRan {
		t.Fatal("afterRefreshPublish seam never fired — this test would prove nothing")
	}

	if got := srv.TokenCalls(); got != 1 {
		t.Errorf("§9 rule 2: want exactly 1 token-endpoint call, got %d (refresh_token values presented: %q)",
			got, presented())
	}
	if lateErr != nil {
		t.Errorf("late caller must share the leader's outcome, got error: %v", lateErr)
	}
	if lateSet.AccessToken.expose() != leaderSet.AccessToken.expose() {
		t.Errorf("late caller got a different access token: %q, leader had %q",
			lateSet.AccessToken.expose(), leaderSet.AccessToken.expose())
	}
	if lateSet.RefreshToken.expose() != leaderSet.RefreshToken.expose() {
		t.Errorf("late caller got a different refresh token: %q, leader had %q",
			lateSet.RefreshToken.expose(), leaderSet.RefreshToken.expose())
	}
	leaderMu.Lock()
	gotLeaders := leaders
	leaderMu.Unlock()
	if gotLeaders != 1 {
		t.Errorf("the guard admitted %d refresh leaders, want exactly 1", gotLeaders)
	}

	// The guard must be usable again once the flight has fully retired: a
	// later, genuinely separate refresh is a NEW flight, not a joiner.
	client.oidc.afterRefreshPublish = nil
	if _, err := client.OidcRefresh(context.Background(), OidcRefreshParams{
		RefreshToken: leaderSet.RefreshToken,
		TenantID:     testTenantID,
	}); err != nil {
		t.Fatalf("sequential OidcRefresh after the flight retired: %v", err)
	}
	if got := srv.TokenCalls(); got != 2 {
		t.Errorf("want 2 token calls after a second, sequential refresh, got %d", got)
	}
}

// TestOidcRefresh_BurstStraddlesCompletionWindow is the full §9 rule 2 burst
// test with callers on BOTH sides of the leader's completion: some join while
// the wire call is still outstanding, the rest arrive inside the
// published-but-not-yet-vacated window. All of them, plus the leader, must
// receive that single wire call's outcome.
func TestOidcRefresh_BurstStraddlesCompletionWindow(t *testing.T) {
	const early = 6 // callers that join while the wire call is in flight
	const late = 4  // callers that arrive inside the completion window

	srv := newOidcTestServer(t)
	release := make(chan struct{})
	handler, presented := rotatingTokenEndpoint(t, release)
	srv.TokenHandler = handler

	client, err := NewClient(srv.URL, "acme", WithOidcClientID(testClientID))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.OidcDiscover(context.Background()); err != nil {
		t.Fatalf("OidcDiscover: %v", err)
	}

	refresh := func() (OidcTokenSet, error) {
		return client.OidcRefresh(context.Background(), OidcRefreshParams{
			RefreshToken: Sensitive("rt-burst"),
			TenantID:     testTenantID,
		})
	}

	var (
		fired    atomic.Bool
		lateSets = make([]OidcTokenSet, late)
		lateErrs = make([]error, late)
	)
	client.oidc.afterRefreshPublish = func() {
		// CompareAndSwap, not sync.Once — see the note in
		// TestOidcRefresh_LateArrivalJoinsPublishedOutcome.
		if !fired.CompareAndSwap(false, true) {
			return
		}
		var wg sync.WaitGroup
		wg.Add(late)
		for i := 0; i < late; i++ {
			go func(idx int) {
				defer wg.Done()
				lateSets[idx], lateErrs[idx] = refresh()
			}(i)
		}
		wg.Wait()
	}

	earlySets := make([]OidcTokenSet, early)
	earlyErrs := make([]error, early)
	var wg sync.WaitGroup
	wg.Add(early)
	for i := 0; i < early; i++ {
		go func(idx int) {
			defer wg.Done()
			earlySets[idx], earlyErrs[idx] = refresh()
		}(i)
	}

	waitForGoroutines() // let all `early` callers reach the guard
	close(release)      // the leader's wire call now returns
	wg.Wait()

	if got := srv.TokenCalls(); got != 1 {
		t.Errorf("§9 rule 2: want exactly 1 token-endpoint call for %d early + %d late callers, got %d "+
			"(refresh_token values presented: %q)", early, late, got, presented())
	}
	want := earlySets[0].AccessToken.expose()
	if want == "" {
		t.Fatalf("early caller 0 got no access token (err=%v)", earlyErrs[0])
	}
	for i, err := range earlyErrs {
		if err != nil {
			t.Errorf("early caller %d: %v", i, err)
		} else if got := earlySets[i].AccessToken.expose(); got != want {
			t.Errorf("early caller %d got access token %q, want the shared %q", i, got, want)
		}
	}
	for i, err := range lateErrs {
		if err != nil {
			t.Errorf("late caller %d must share the one flight's outcome, got: %v", i, err)
		} else if got := lateSets[i].AccessToken.expose(); got != want {
			t.Errorf("late caller %d got access token %q, want the shared %q", i, got, want)
		}
	}
}

// TestOidcRefresh_LateArrivalSharesFailureNoRetry is the §9 rule 3 half of
// the same ordering requirement: a FAILED refresh must also be published
// before the slot is vacated, so a caller landing in the window receives that
// failure rather than silently re-attempting the grant — which would be the
// automatic retry §9 rule 3 forbids. Afterwards the guard must still be
// usable.
func TestOidcRefresh_LateArrivalSharesFailureNoRetry(t *testing.T) {
	srv := newOidcTestServer(t)
	var mu sync.Mutex
	failNext := true
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		fail := failNext
		mu.Unlock()
		if fail {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"expired refresh token"}`))
			return
		}
		writeJSON(t, w, map[string]any{
			"access_token": "recovered-access", "token_type": "Bearer", "expires_in": 900,
		})
	}

	client, err := NewClient(srv.URL, "acme", WithOidcClientID(testClientID))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.OidcDiscover(context.Background()); err != nil {
		t.Fatalf("OidcDiscover: %v", err)
	}

	var (
		fired   atomic.Bool
		lateErr error
		lateRan bool
	)
	client.oidc.afterRefreshPublish = func() {
		// CompareAndSwap, not sync.Once — see the note in
		// TestOidcRefresh_LateArrivalJoinsPublishedOutcome.
		if !fired.CompareAndSwap(false, true) {
			return
		}
		lateRan = true
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, lateErr = client.OidcRefresh(context.Background(), OidcRefreshParams{
				RefreshToken: Sensitive("rt-expired"),
				TenantID:     testTenantID,
			})
		}()
		wg.Wait()
	}

	_, leaderErr := client.OidcRefresh(context.Background(), OidcRefreshParams{
		RefreshToken: Sensitive("rt-expired"),
		TenantID:     testTenantID,
	})
	if leaderErr == nil {
		t.Fatal("leader OidcRefresh: want the invalid_grant failure, got nil")
	}
	if !lateRan {
		t.Fatal("afterRefreshPublish seam never fired — this test would prove nothing")
	}

	// §9 rule 3: the one failed refresh is shared, never re-attempted.
	if got := srv.TokenCalls(); got != 1 {
		t.Errorf("§9 rule 3: a failed refresh must not be re-attempted; got %d token calls, want 1", got)
	}
	if lateErr == nil {
		t.Fatal("late caller must receive the shared failure, got nil error")
	}
	if lateErr.Error() != leaderErr.Error() {
		t.Errorf("late caller got a different error:\n  late:   %v\n  leader: %v", lateErr, leaderErr)
	}
	var leaderTyped, lateTyped *OAuthProtocolError
	if errors.As(leaderErr, &leaderTyped) != errors.As(lateErr, &lateTyped) {
		t.Errorf("late caller's error type differs from the leader's: %T vs %T", lateErr, leaderErr)
	}

	// A failed flight must leave the guard usable, not wedged.
	client.oidc.afterRefreshPublish = nil
	mu.Lock()
	failNext = false
	mu.Unlock()
	set, err := client.OidcRefresh(context.Background(), OidcRefreshParams{
		RefreshToken: Sensitive("rt-fresh"),
		TenantID:     testTenantID,
	})
	if err != nil {
		t.Fatalf("OidcRefresh after a failed flight: %v", err)
	}
	if set.AccessToken.expose() != "recovered-access" {
		t.Errorf("AccessToken = %q, want recovered-access", set.AccessToken.expose())
	}
	if got := srv.TokenCalls(); got != 2 {
		t.Errorf("want 2 token calls in total, got %d", got)
	}
}
