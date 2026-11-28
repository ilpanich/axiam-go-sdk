package jwks

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// OI-38 review round 1: the cache never holds its state lock across a fetch,
// bounds every fetch with its own timeout on a context detached from the
// caller's, never records a caller's cancellation as a failed refresh, and
// never trusts held keys at a negative age.

// hangingJWKSServer serves the held set until hang is set, then blocks each
// request until the client gives up (or the test ends).
type hangingJWKSServer struct {
	*httptest.Server
	hits    atomic.Int32
	hang    atomic.Bool
	release chan struct{}
	once    sync.Once
}

func newHangingJWKSServer(t *testing.T, body []byte) *hangingJWKSServer {
	t.Helper()
	s := &hangingJWKSServer{release: make(chan struct{})}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		if s.hang.Load() {
			select {
			case <-r.Context().Done():
			case <-s.release:
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(func() {
		s.once.Do(func() { close(s.release) })
		s.Server.Close()
	})
	return s
}

// M1: while an unknown-kid fetch hangs, a token whose kid the fresh held set
// holds verifies promptly, on both paths.
func TestJWKS_Review_HangingFetchDoesNotBlockTheHeldSet(t *testing.T) {
	for _, path := range cooldownPaths {
		t.Run(path.name, func(t *testing.T) {
			priv, pub := generateKey(t, "held")
			srv := newHangingJWKSServer(t, marshalSet(t, pub))
			// The client has no timeout: only the verifier's own bound applies.
			v, err := NewVerifier(context.Background(), srv.URL, &http.Client{})
			if err != nil {
				t.Fatal(err)
			}
			setFetchTimeout(v, 2*time.Second)
			claims := Claims{Subject: "s", Exp: at(time.Now().Add(time.Hour))}
			held := signEdDSA(t, priv, "held", claims)
			if err := path.verify(v, held); err != nil {
				t.Fatal(err)
			}
			srv.hang.Store(true)
			p2, _ := generateKey(t, "rotated")
			go func() { _ = path.verify(v, signEdDSA(t, p2, "rotated", claims)) }()
			deadline := time.Now().Add(time.Second)
			for srv.hits.Load() < 2 && time.Now().Before(deadline) {
				time.Sleep(5 * time.Millisecond)
			}
			if srv.hits.Load() < 2 {
				t.Fatal("the unknown-kid fetch did not start")
			}
			done := make(chan error, 1)
			go func() { done <- path.verify(v, held) }()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("the held kid must verify while a fetch is in flight: %v", err)
				}
			case <-time.After(500 * time.Millisecond):
				t.Fatal("a held-kid verification waited for the in-flight fetch")
			}
		})
	}
}

// M1: a hanging endpoint is abandoned after the fetch timeout, even with a
// client that has none and a caller context without a deadline.
func TestJWKS_Review_HangingEndpointIsAbandoned(t *testing.T) {
	priv, pub := generateKey(t, "held")
	srv := newHangingJWKSServer(t, marshalSet(t, pub))
	srv.hang.Store(true)
	v, err := NewVerifier(context.Background(), srv.URL, &http.Client{})
	if err != nil {
		t.Fatal(err)
	}
	setFetchTimeout(v, 300*time.Millisecond)
	tok := signEdDSA(t, priv, "held", Claims{Subject: "s", Exp: at(time.Now().Add(time.Hour))})
	done := make(chan error, 1)
	go func() {
		_, err := v.VerifyPayload(context.Background(), tok)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("nothing verifies when the only fetch hangs")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a hanging JWKS endpoint was never abandoned")
	}
}

// M2: a caller's cancelled context is not a failed refresh: it opens no
// window, so the next verification still refreshes.
func TestJWKS_Review_CallerCancellationIsNotAFailedRefresh(t *testing.T) {
	path := cooldownPaths[0]
	f := newStaleFixture(t, path)
	f.at(ttl + time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = f.v.VerifySignatureOnlyUnchecked(ctx, f.held)
	waitIdle(f.v)
	f.at(ttl + 2*time.Second)
	if err := path.verify(f.v, f.held); err != nil {
		t.Fatal(err)
	}
	waitIdle(f.v)
	if got := f.srv.hits.Load(); got != 2 {
		t.Fatalf("a cancelled caller suppressed the refresh: %d fetches in all, want 2", got)
	}
	// And the refresh succeeded: the anchor moved, so the held kid still
	// verifies past the old bound with the endpoint failing.
	f.srv.set(func(s *staleJWKSServer) { s.mode = "fail" })
	f.at(ttl + 301*time.Second)
	if err := path.verify(f.v, f.held); err != nil {
		t.Fatalf("the refresh after a cancelled caller must have succeeded: %v", err)
	}
}

// M3: at a negative age (the clock moved back before the anchor) with a
// failing endpoint the held kid is refused; once a fetch succeeds it verifies.
// A window that "opened in the future" is over.
func TestJWKS_Review_NegativeAgeWithFailingEndpointIsRefused(t *testing.T) {
	for _, path := range cooldownPaths {
		t.Run(path.name, func(t *testing.T) {
			f := newStaleFixture(t, path)
			f.srv.set(func(s *staleJWKSServer) { s.mode = "fail" })
			f.at(-time.Hour)
			if err := path.verify(f.v, f.held); err == nil {
				t.Fatal("at a negative age with a failing endpoint the held kid must be refused")
			}
			waitIdle(f.v)
			f.srv.set(func(s *staleJWKSServer) { s.mode = "ok" })
			f.at(-time.Hour + minRefetchInterval + time.Second)
			before := f.srv.hits.Load()
			if err := path.verify(f.v, f.held); err != nil {
				t.Fatalf("after a successful fetch the held kid must verify: %v", err)
			}
			if got := f.srv.hits.Load() - before; got != 1 {
				t.Fatalf("want exactly one fetch, got %d", got)
			}
			// The window opened at -1h; the clock moves back further, before it:
			// a forced fetch is allowed again.
			f.at(-2 * time.Hour)
			before = f.srv.hits.Load()
			_ = path.verify(f.v, f.unknown())
			waitIdle(f.v)
			if f.srv.hits.Load() == before {
				t.Fatal("a window whose start is in the future must count as over")
			}
		})
	}
}

// Round 2, M1 (ADDENDUM point 10): a small advertised max-age is honoured as
// the TTL, but TTL-driven refreshes, successful or not, respect the 60 s
// window: max-age=0 never means one fetch per verification. A window opened
// only by a TTL refresh does not block the one forced (unknown-kid) fetch.
func TestJWKS_Review2_MaxAgeZeroIsBoundedByTheWindow(t *testing.T) {
	for _, path := range cooldownPaths {
		t.Run(path.name, func(t *testing.T) {
			priv, pub := generateKey(t, "held")
			srv := newStaleJWKSServer(t, marshalSet(t, pub))
			srv.set(func(s *staleJWKSServer) { s.cacheControl = "max-age=0" })
			v, err := NewVerifier(context.Background(), srv.URL, srv.Client())
			if err != nil {
				t.Fatal(err)
			}
			t0 := time.Unix(1_900_000_000, 0)
			clock := t0
			v.now = func() time.Time { return clock }
			claims := Claims{Subject: "s", Exp: at(time.Now().Add(time.Hour))}
			tok := signEdDSA(t, priv, "held", claims)
			if err := settled(path, v, tok); err != nil {
				t.Fatal(err)
			}
			for i := 1; i <= 20; i++ {
				clock = t0.Add(time.Duration(i) * time.Second)
				if err := settled(path, v, tok); err != nil {
					t.Fatalf("verification %d: %v", i, err)
				}
			}
			if extra := srv.hits.Load() - 1; extra > 1 {
				t.Fatalf("max-age=0: 20 verifications within one window caused %d fetches, want at most 1", extra)
			}
			clock = t0.Add(minRefetchInterval + 2*time.Second)
			before := srv.hits.Load()
			if err := settled(path, v, tok); err != nil {
				t.Fatal(err)
			}
			if got := srv.hits.Load() - before; got != 1 {
				t.Fatalf("the next window must allow one TTL refresh, got %d fetches", got)
			}
			// That window was opened by a TTL refresh only: an unknown kid still
			// gets its one forced fetch.
			clock = clock.Add(time.Second)
			before = srv.hits.Load()
			p2, _ := generateKey(t, "other")
			_ = settled(path, v, signEdDSA(t, p2, "other", claims))
			if got := srv.hits.Load() - before; got != 1 {
				t.Fatalf("an unknown kid after a TTL refresh must still get one forced fetch, got %d", got)
			}
		})
	}
}

// Round 2, L2 (ADDENDUM point 9): a window whose start lies in the future —
// the clock stepped back — is over. A refresh fails at T; the clock steps to
// T - 2 min, before the anchor: the refresh that the negative age makes due
// happens (and fails, so the held kid is refused); once the endpoint recovers,
// the next window's fetch succeeds and the held kid verifies.
func TestJWKS_Review2_WindowStartInTheFutureIsOver(t *testing.T) {
	path := cooldownPaths[0]
	priv, pub := generateKey(t, "held")
	srv := newStaleJWKSServer(t, marshalSet(t, pub))
	srv.set(func(s *staleJWKSServer) { s.cacheControl = "max-age=60" })
	v, err := NewVerifier(context.Background(), srv.URL, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Unix(1_900_000_000, 0)
	clock := t0
	v.now = func() time.Time { return clock }
	tok := signEdDSA(t, priv, "held", Claims{Subject: "s", Exp: at(time.Now().Add(time.Hour))})
	if err := settled(path, v, tok); err != nil {
		t.Fatal(err)
	}
	srv.set(func(s *staleJWKSServer) { s.mode = "fail" })
	T := t0.Add(61 * time.Second)
	clock = T
	if err := settled(path, v, tok); err != nil {
		t.Fatalf("at T the held kid still verifies after the failed refresh: %v", err)
	}
	clock = T.Add(-2 * time.Minute)
	before := srv.hits.Load()
	if err := settled(path, v, tok); err == nil {
		t.Fatal("at a negative age with a failing endpoint the held kid must be refused")
	}
	if srv.hits.Load() == before {
		t.Fatal("a window that starts in the future must count as over: the due refresh did not happen")
	}
	srv.set(func(s *staleJWKSServer) { s.mode = "ok" })
	clock = clock.Add(minRefetchInterval + time.Second)
	if err := settled(path, v, tok); err != nil {
		t.Fatalf("after the recovered fetch the held kid must verify: %v", err)
	}
}
