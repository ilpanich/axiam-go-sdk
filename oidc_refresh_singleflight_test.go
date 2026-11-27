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
	"strings"
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
	client.session.oidc.afterRefreshPublish = func() {
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
	client.session.oidc.afterRefreshPublish = nil
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
	client.session.oidc.afterRefreshPublish = func() {
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
	client.session.oidc.afterRefreshPublish = func() {
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
	client.session.oidc.afterRefreshPublish = nil
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

// ---------------------------------------------------------------------------
// Per-token keying (CONTRACT.md §9: the oidc_refresh single-flight is keyed
// by a digest of the refresh token). A caller presenting a DIFFERENT refresh
// token is not part of another token's burst: it never joins and never
// receives another grant's outcome.
// ---------------------------------------------------------------------------

// perTokenEndpoint answers every refresh_token grant with a token set derived
// from the refresh token it was presented, so a caller handed another
// token's outcome is detectable. It blocks on gate (when non-nil) so a test
// can hold a wire call open.
func perTokenEndpoint(t *testing.T, gate <-chan struct{}) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm: %v", err)
			return
		}
		presented := r.Form.Get("refresh_token")
		if gate != nil {
			<-gate
		}
		writeJSON(t, w, map[string]any{
			"access_token":  "access-for-" + presented,
			"refresh_token": "rotated-" + presented,
			"token_type":    "Bearer",
			"expires_in":    900,
		})
	}
}

func newPerTokenClient(t *testing.T, srv *oidcTestServer) *Client {
	t.Helper()
	client, err := NewClient(srv.URL, "acme", WithOidcClientID(testClientID))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.OidcDiscover(context.Background()); err != nil {
		t.Fatalf("OidcDiscover: %v", err)
	}
	return client
}

func refreshWith(client *Client, token string) (OidcTokenSet, error) {
	return client.OidcRefresh(context.Background(), OidcRefreshParams{
		RefreshToken: Sensitive(token),
		TenantID:     testTenantID,
	})
}

// TestOidcRefresh_DifferentTokenDuringLiveFlightGetsOwnWireCall: refresh
// token B, presented while token A's wire call is still outstanding, must
// make its own wire call and receive its own token set.
func TestOidcRefresh_DifferentTokenDuringLiveFlightGetsOwnWireCall(t *testing.T) {
	srv := newOidcTestServer(t)
	release := make(chan struct{})
	srv.TokenHandler = perTokenEndpoint(t, release)
	client := newPerTokenClient(t, srv)

	var (
		wg   sync.WaitGroup
		setA OidcTokenSet
		errA error
		setB OidcTokenSet
		errB error
	)
	wg.Add(2)
	go func() { defer wg.Done(); setA, errA = refreshWith(client, "rt-A") }()
	waitForGoroutines() // A is now the live flight
	go func() { defer wg.Done(); setB, errB = refreshWith(client, "rt-B") }()
	waitForGoroutines() // B has reached the guard
	close(release)
	wg.Wait()

	if errA != nil || errB != nil {
		t.Fatalf("errors: A=%v B=%v", errA, errB)
	}
	if got := srv.TokenCalls(); got != 2 {
		t.Errorf("want 2 wire calls (one per refresh token), got %d", got)
	}
	if got := setA.AccessToken.expose(); got != "access-for-rt-A" {
		t.Errorf("A received %q, want its own token set", got)
	}
	if got := setB.AccessToken.expose(); got != "access-for-rt-B" {
		t.Errorf("B received %q, want its own token set (it was handed another grant's outcome)", got)
	}
	if got := setB.RefreshToken.expose(); got != "rotated-rt-B" {
		t.Errorf("B refresh token = %q, want rotated-rt-B", got)
	}
}

// TestOidcRefresh_DifferentTokenInsidePublishWindowGetsOwnWireCall: token B
// arriving inside token A's published-but-not-yet-vacated window (§9 rule 6a)
// must not join A's settled flight.
func TestOidcRefresh_DifferentTokenInsidePublishWindowGetsOwnWireCall(t *testing.T) {
	srv := newOidcTestServer(t)
	srv.TokenHandler = perTokenEndpoint(t, nil)
	client := newPerTokenClient(t, srv)

	var (
		fired atomic.Bool
		ran   bool
		setB  OidcTokenSet
		errB  error
	)
	client.session.oidc.afterRefreshPublish = func() {
		if !fired.CompareAndSwap(false, true) {
			return
		}
		ran = true
		var wg sync.WaitGroup
		wg.Add(1)
		go func() { defer wg.Done(); setB, errB = refreshWith(client, "rt-B") }()
		wg.Wait()
	}

	setA, errA := refreshWith(client, "rt-A")
	if errA != nil {
		t.Fatalf("A: %v", errA)
	}
	if !ran {
		t.Fatal("afterRefreshPublish seam never fired — this test would prove nothing")
	}
	if errB != nil {
		t.Fatalf("B: %v", errB)
	}
	if got := srv.TokenCalls(); got != 2 {
		t.Errorf("want 2 wire calls, got %d", got)
	}
	if got := setA.AccessToken.expose(); got != "access-for-rt-A" {
		t.Errorf("A received %q", got)
	}
	if got := setB.AccessToken.expose(); got != "access-for-rt-B" {
		t.Errorf("B received %q, want its own token set", got)
	}
}

// TestOidcRefresh_FlightKeyHoldsNoRawToken: the registry is keyed by a
// digest, never the raw token; the slot is removed once vacated; and a failed
// grant's error carries no raw token.
func TestOidcRefresh_FlightKeyHoldsNoRawToken(t *testing.T) {
	const raw = "rt-very-secret-value"
	srv := newOidcTestServer(t)
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"refresh token rejected"}`))
	}
	client := newPerTokenClient(t, srv)

	var observed []string
	client.session.oidc.afterRefreshPublish = func() {
		// Inside the publish-before-vacate window the slot is occupied.
		client.session.oidc.refreshMu.Lock()
		for k := range client.session.oidc.pendingRefresh {
			observed = append(observed, k)
		}
		client.session.oidc.refreshMu.Unlock()
	}
	_, err := refreshWith(client, raw)
	if err == nil {
		t.Fatal("want the invalid_grant failure")
	}
	if len(observed) != 1 {
		t.Fatalf("want exactly one occupied slot inside the window, got %d", len(observed))
	}
	if strings.Contains(observed[0], raw) || len(observed[0]) != 64 {
		t.Errorf("flight key %q must be a 64-hex SHA-256 digest holding no raw token", observed[0])
	}
	if strings.Contains(err.Error(), raw) {
		t.Errorf("error leaks the raw refresh token: %v", err)
	}
	if n := len(client.session.oidc.pendingRefresh); n != 0 {
		t.Errorf("slot not removed once vacated: %d left", n)
	}
	// Same token under a different tenant is a different flight.
}

const otherTenantID = "22222222-2222-2222-2222-222222222222"

// TestOidcRefresh_SameTokenDifferentTenantSeparateFlights: the tenant is part
// of the key, so one token presented for two tenants is two flights.
func TestOidcRefresh_SameTokenDifferentTenantSeparateFlights(t *testing.T) {
	srv := newOidcTestServer(t)
	release := make(chan struct{})
	srv.TokenHandler = perTokenEndpoint(t, release)
	client := newPerTokenClient(t, srv)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = client.OidcRefresh(context.Background(), OidcRefreshParams{RefreshToken: "rt-same", TenantID: testTenantID})
	}()
	waitForGoroutines()
	go func() {
		defer wg.Done()
		_, _ = client.OidcRefresh(context.Background(), OidcRefreshParams{RefreshToken: "rt-same", TenantID: otherTenantID})
	}()
	waitForGoroutines()
	close(release)
	wg.Wait()
	if got := srv.TokenCalls(); got != 2 {
		t.Errorf("same token, different tenants: want 2 wire calls, got %d", got)
	}
}

// TestOidcRefresh_DefaultTenantExplicitVsOmittedOneFlight: an explicit tenant
// equal to the client's resolved default and an omitted tenant (in either
// letter case) are the same effective tenant, hence one flight and one wire
// call — a second call with the same rotating token would be a replay.
func TestOidcRefresh_DefaultTenantExplicitVsOmittedOneFlight(t *testing.T) {
	srv := newOidcTestServer(t)
	release := make(chan struct{})
	srv.TokenHandler = perTokenEndpoint(t, release)
	client := newPerTokenClient(t, srv)
	jwt := signIDTokenHS256(t, map[string]any{"tenant_id": testTenantID})
	client.httpc.Jar.SetCookies(client.baseURL, []*http.Cookie{{Name: accessCookie, Value: jwt, Path: "/"}})

	params := []OidcRefreshParams{
		{RefreshToken: "rt-same"},                                          // omitted
		{RefreshToken: "rt-same", TenantID: testTenantID},                  // explicit == default
		{RefreshToken: "rt-same", TenantID: strings.ToUpper(testTenantID)}, // same, other spelling
	}
	sets := make([]OidcTokenSet, len(params))
	errs := make([]error, len(params))
	var wg sync.WaitGroup
	for i, p := range params {
		wg.Add(1)
		go func(i int, p OidcRefreshParams) {
			defer wg.Done()
			sets[i], errs[i] = client.OidcRefresh(context.Background(), p)
		}(i, p)
		waitForGoroutines()
	}
	close(release)
	wg.Wait()
	if got := srv.TokenCalls(); got != 1 {
		t.Errorf("explicit-default vs omitted tenant: want 1 wire call, got %d", got)
	}
	for i := range sets {
		if errs[i] != nil || sets[i].AccessToken.expose() != "access-for-rt-same" {
			t.Errorf("caller %d: set=%q err=%v", i, sets[i].AccessToken.expose(), errs[i])
		}
	}
}
