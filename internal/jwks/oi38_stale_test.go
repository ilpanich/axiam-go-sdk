package jwks

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// OI-38 — CONTRACT.md §12.4 rule 2 "Stale-if-error, bounded" (contract 1.69,
// D-10). The cache's age runs from the last successful fetch (a 200 holding
// at least one key, or a 304 to a conditional request); its TTL is the
// advertised max-age clamped to at most 300 s (300 s by default). A failed
// refresh — a transport error, another status, a body that is not a JWKS, an
// empty key set — keeps the held keys, never moves the anchor and counts
// toward the re-fetch window; held keys verify until exactly TTL + 300 s after
// the anchor and never after.

// staleJWKSServer serves /oauth2/jwks in one of several modes, counting hits
// and answering a conditional request whose If-None-Match matches its ETag
// with 304 when notModified is set.
type staleJWKSServer struct {
	*httptest.Server
	hits atomic.Int32

	mu           sync.Mutex
	mode         string // "ok", "fail", "empty", "garbage"
	body         []byte
	cacheControl string
	etag         string
	notModified  bool
	lastINM      string
}

func newStaleJWKSServer(t *testing.T, body []byte) *staleJWKSServer {
	t.Helper()
	s := &staleJWKSServer{mode: "ok", body: body, cacheControl: "public, max-age=300", etag: `"jwks-v1"`}
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/jwks", func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		s.mu.Lock()
		defer s.mu.Unlock()
		s.lastINM = r.Header.Get("If-None-Match")
		switch s.mode {
		case "fail":
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		case "empty":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"keys":[]}`))
			return
		case "emptyobj":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"keys":[{}]}`))
			return
		case "nonobj":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"keys":[0,null]}`))
			return
		case "unusable":
			// One well-formed JWK this library cannot use, beside the held key.
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"keys":[{"kty":"XYZ","kid":"odd"},` + strings.TrimPrefix(string(s.body), `{"keys":[`)))
			return
		case "accepted":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write(s.body)
			return
		case "garbage":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`not a jwks`))
			return
		}
		if s.cacheControl != "" {
			w.Header().Set("Cache-Control", s.cacheControl)
		}
		if s.etag != "" {
			w.Header().Set("ETag", s.etag)
		}
		if s.notModified && s.lastINM != "" && s.lastINM == s.etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(s.body)
	})
	s.Server = httptest.NewServer(mux)
	t.Cleanup(s.Server.Close)
	return s
}

func (s *staleJWKSServer) set(f func(s *staleJWKSServer)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f(s)
}

// staleFixture is a verifier on a fake clock, filled at t0 with kid "held".
type staleFixture struct {
	srv     *staleJWKSServer
	v       *Verifier
	clock   time.Time
	t0      time.Time
	held    []byte // a token signed with the held key
	unknown func() []byte
}

func newStaleFixture(t *testing.T, path cooldownPath) *staleFixture {
	t.Helper()
	priv, pub := generateKey(t, "held")
	f := &staleFixture{srv: newStaleJWKSServer(t, marshalSet(t, pub))}
	v, err := NewVerifier(context.Background(), f.srv.URL, f.srv.Client())
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	f.v = v
	f.t0 = time.Unix(1_900_000_000, 0)
	f.clock = f.t0
	v.now = func() time.Time { return f.clock }
	claims := Claims{Subject: "s", TenantID: "t", OrgID: "o", Exp: at(time.Now().Add(time.Hour))}
	f.held = signEdDSA(t, priv, "held", claims)
	n := 0
	f.unknown = func() []byte {
		n++
		kid := "unknown-" + string(rune('a'+n))
		p, _ := generateKey(t, kid)
		return signEdDSA(t, p, kid, claims)
	}
	if err := settled(path, v, f.held); err != nil {
		t.Fatalf("fill at t0: %v", err)
	}
	if got := f.srv.hits.Load(); got != 1 {
		t.Fatalf("filling the cache took %d fetches, want 1", got)
	}
	return f
}

func (f *staleFixture) at(d time.Duration) { f.clock = f.t0.Add(d) }

const ttl = 300 * time.Second

// The §12.4 rule 2 conformance test, on both verification paths.
func TestJWKS_StaleIfError_BoundedConformance(t *testing.T) {
	for _, path := range cooldownPaths {
		t.Run(path.name, func(t *testing.T) {
			f := newStaleFixture(t, path)
			f.srv.set(func(s *staleJWKSServer) { s.mode = "fail" })

			// TTL + 1 s: one failed refresh is attempted; the held kid verifies.
			f.at(ttl + time.Second)
			before := f.srv.hits.Load()
			if err := settled(path, f.v, f.held); err != nil {
				t.Fatalf("at TTL+1s the held kid must still verify after a failed refresh: %v", err)
			}
			if got := f.srv.hits.Load() - before; got != 1 {
				t.Fatalf("at TTL+1s want exactly one (failed) refresh, got %d fetches", got)
			}

			// TTL + 250 s: an unknown kid is refused (its refresh fails), the
			// held kid still verifies.
			f.at(ttl + 250*time.Second)
			if err := settled(path, f.v, f.unknown()); err == nil {
				t.Fatal("at TTL+250s an unknown kid must be refused")
			}
			if err := settled(path, f.v, f.held); err != nil {
				t.Fatalf("at TTL+250s the held kid must still verify: %v", err)
			}

			// TTL + 301 s: past the bound, the held kid is refused.
			f.at(ttl + 301*time.Second)
			if err := settled(path, f.v, f.held); err == nil {
				t.Fatal("at TTL+301s the held kid must be refused: held keys are never used past TTL + 300 s")
			}

			// The endpoint recovers; past the window, the held kid verifies after
			// exactly one fetch.
			f.srv.set(func(s *staleJWKSServer) { s.mode = "ok" })
			f.at(ttl + 400*time.Second)
			before = f.srv.hits.Load()
			if err := settled(path, f.v, f.held); err != nil {
				t.Fatalf("after one successful fetch the held kid must verify again: %v", err)
			}
			if got := f.srv.hits.Load() - before; got != 1 {
				t.Fatalf("recovery took %d fetches, want exactly 1", got)
			}
		})
	}
}

// The first half again with the endpoint answering 200 {"keys":[]} (and, as a
// second failure kind, a body that is not a JWKS): an empty set is a failed
// refresh, not a replacement, so the held kid still verifies at TTL + 1 s.
func TestJWKS_StaleIfError_EmptySetIsAFailedRefresh(t *testing.T) {
	for _, mode := range []string{"empty", "emptyobj", "nonobj", "garbage", "fail", "accepted"} {
		for _, path := range cooldownPaths {
			t.Run(mode+"/"+path.name, func(t *testing.T) {
				f := newStaleFixture(t, path)
				f.srv.set(func(s *staleJWKSServer) { s.mode = mode })
				f.at(ttl + time.Second)
				before := f.srv.hits.Load()
				if err := settled(path, f.v, f.held); err != nil {
					t.Fatalf("a %s response must not replace the held set: %v", mode, err)
				}
				if got := f.srv.hits.Load() - before; got != 1 {
					t.Fatalf("want exactly one refresh attempt, got %d", got)
				}
				// It did not move the anchor either: past TTL + 300 s the held
				// kid is refused.
				f.at(ttl + 301*time.Second)
				if err := settled(path, f.v, f.held); err == nil {
					t.Fatalf("a %s response must not move the anchor", mode)
				}
			})
		}
	}
}

// Within the TTL the held set answers with no fetch; an advertised max-age
// above 300 s is clamped to 300 s, a smaller one is honoured, and an absent
// one means 300 s.
func TestJWKS_StaleIfError_TTLFromMaxAgeClampedTo300s(t *testing.T) {
	path := cooldownPaths[0]
	for _, tc := range []struct {
		name         string
		cacheControl string
		ttl          time.Duration
	}{
		{"max-age=3600 clamped", "public, max-age=3600", 300 * time.Second},
		{"max-age=120 honoured", "max-age=120", 120 * time.Second},
		{"absent means 300 s", "", 300 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			priv, pub := generateKey(t, "held")
			srv := newStaleJWKSServer(t, marshalSet(t, pub))
			srv.set(func(s *staleJWKSServer) { s.cacheControl = tc.cacheControl })
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
			clock = t0.Add(tc.ttl - time.Second)
			if err := settled(path, v, tok); err != nil || srv.hits.Load() != 1 {
				t.Fatalf("inside the TTL the held set must answer with no fetch (err=%v hits=%d)", err, srv.hits.Load())
			}
			clock = t0.Add(tc.ttl + time.Second)
			if err := settled(path, v, tok); err != nil || srv.hits.Load() != 2 {
				t.Fatalf("past the TTL one refresh is due (err=%v hits=%d)", err, srv.hits.Load())
			}
		})
	}
}

// A 304 to a conditional refresh (If-None-Match with the held ETag) is a
// successful fetch: it re-confirms the held set and moves the anchor.
func TestJWKS_StaleIfError_304MovesTheAnchor(t *testing.T) {
	path := cooldownPaths[1]
	f := newStaleFixture(t, path)
	f.srv.set(func(s *staleJWKSServer) { s.notModified = true })
	f.at(ttl + time.Second)
	if err := settled(path, f.v, f.held); err != nil {
		t.Fatalf("a 304 must keep the held set: %v", err)
	}
	f.srv.mu.Lock()
	inm := f.srv.lastINM
	f.srv.mu.Unlock()
	if inm != `"jwks-v1"` {
		t.Fatalf("the refresh must be conditional on the held ETag, sent If-None-Match %q", inm)
	}
	f.srv.set(func(s *staleJWKSServer) { s.mode = "fail" })
	// The anchor is now t0 + TTL + 1 s: at t0 + 2*TTL + 250 s the held kid
	// still verifies, at t0 + 2*TTL + 302 s it is refused.
	f.at(2*ttl + 250*time.Second)
	if err := settled(path, f.v, f.held); err != nil {
		t.Fatalf("the 304 must have moved the anchor: %v", err)
	}
	f.at(2*ttl + 302*time.Second)
	if err := settled(path, f.v, f.held); err == nil {
		t.Fatal("past the moved anchor's bound the held kid must be refused")
	}
}

// A failing endpoint costs one fetch per window, not one per token, also
// before any set was ever held; nothing verifies meanwhile.
func TestJWKS_StaleIfError_FailingEndpointIsFetchedOncePerWindow(t *testing.T) {
	priv, pub := generateKey(t, "held")
	srv := newStaleJWKSServer(t, marshalSet(t, pub))
	srv.set(func(s *staleJWKSServer) { s.mode = "fail" })
	v, err := NewVerifier(context.Background(), srv.URL, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Unix(1_900_000_000, 0)
	clock := t0
	v.now = func() time.Time { return clock }
	tok := signEdDSA(t, priv, "held", Claims{Subject: "s", Exp: at(time.Now().Add(time.Hour))})
	for i := 0; i < 20; i++ {
		if err := settled(cooldownPaths[i%2], v, tok); err == nil {
			t.Fatal("nothing verifies before a JWKS was ever fetched")
		}
	}
	if got := srv.hits.Load(); got != 1 {
		t.Fatalf("a failing endpoint was fetched %d times inside one window, want 1", got)
	}
	srv.set(func(s *staleJWKSServer) { s.mode = "ok" })
	clock = t0.Add(minRefetchInterval + time.Second)
	if err := settled(cooldownPaths[0], v, tok); err != nil {
		t.Fatalf("past the window the recovered endpoint must be fetched: %v", err)
	}
	if got := srv.hits.Load(); got != 2 {
		t.Fatalf("want 2 fetches in all, got %d", got)
	}
}

// A 304 re-reads the max-age it carries: after a 304 advertising max-age=60
// the next refresh is due 60 s later.
func TestJWKS_StaleIfError_304RereadsMaxAge(t *testing.T) {
	path := cooldownPaths[0]
	f := newStaleFixture(t, path)
	f.srv.set(func(s *staleJWKSServer) { s.notModified = true; s.cacheControl = "max-age=60" })
	f.at(ttl + time.Second)
	if err := settled(path, f.v, f.held); err != nil {
		t.Fatal(err)
	}
	before := f.srv.hits.Load()
	f.at(ttl + 62*time.Second)
	if err := settled(path, f.v, f.held); err != nil {
		t.Fatal(err)
	}
	if got := f.srv.hits.Load() - before; got != 1 {
		t.Fatalf("the 304's max-age=60 must make a refresh due 60 s later, got %d fetches", got)
	}
}

// A clock moved back before the anchor makes a refresh due, never fresh.
func TestJWKS_StaleIfError_NegativeAgeIsDue(t *testing.T) {
	path := cooldownPaths[0]
	f := newStaleFixture(t, path)
	f.at(-time.Hour)
	before := f.srv.hits.Load()
	if err := settled(path, f.v, f.held); err != nil {
		t.Fatal(err)
	}
	if got := f.srv.hits.Load() - before; got != 1 {
		t.Fatalf("a negative age must make a refresh due, got %d fetches", got)
	}
}

// An ETag with a control character or longer than 256 bytes is never stored
// or echoed: the next refresh is unconditional.
func TestJWKS_StaleIfError_HostileETagIsNotEchoed(t *testing.T) {
	for _, etag := range []string{"\"a\tb\"", `"` + strings.Repeat("x", 300) + `"`} {
		priv, pub := generateKey(t, "held")
		srv := newStaleJWKSServer(t, marshalSet(t, pub))
		srv.set(func(s *staleJWKSServer) { s.etag = etag })
		v, err := NewVerifier(context.Background(), srv.URL, srv.Client())
		if err != nil {
			t.Fatal(err)
		}
		t0 := time.Unix(1_900_000_000, 0)
		clock := t0
		v.now = func() time.Time { return clock }
		tok := signEdDSA(t, priv, "held", Claims{Subject: "s", Exp: at(time.Now().Add(time.Hour))})
		if err := settled(cooldownPaths[0], v, tok); err != nil {
			t.Fatal(err)
		}
		clock = t0.Add(ttl + time.Second)
		if err := settled(cooldownPaths[0], v, tok); err != nil {
			t.Fatal(err)
		}
		srv.mu.Lock()
		inm := srv.lastINM
		srv.mu.Unlock()
		if inm != "" {
			t.Fatalf("a hostile ETag was echoed in If-None-Match: %q", inm)
		}
	}
}

// A JWKS entry this library cannot use is skipped, not a reason to refuse the
// set: the held key beside it still verifies after the refresh.
func TestJWKS_StaleIfError_UnusableEntryIsSkipped(t *testing.T) {
	path := cooldownPaths[1]
	f := newStaleFixture(t, path)
	f.srv.set(func(s *staleJWKSServer) { s.mode = "unusable" })
	f.at(ttl + time.Second)
	if err := settled(path, f.v, f.held); err != nil {
		t.Fatal(err)
	}
	// The refresh succeeded (anchor moved): fail now, and at the old bound
	// (t0 + TTL + 301 s) the held kid still verifies.
	f.srv.set(func(s *staleJWKSServer) { s.mode = "fail" })
	f.at(ttl + 301*time.Second)
	if err := settled(path, f.v, f.held); err != nil {
		t.Fatalf("a set with one unusable entry must be a successful refresh: %v", err)
	}
}
