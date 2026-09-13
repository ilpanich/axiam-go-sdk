package revocation

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

const aSessionID = "6f3e0a5c-1b2d-4e8f-9a7b-0c1d2e3f4a5b"

// feedServer serves a document (or a status) at /oauth2/revocations and counts
// the fetches that reached it.
type feedServer struct {
	*httptest.Server
	fetches int32
}

func newFeedServer(t *testing.T, handler func(w http.ResponseWriter, fetch int32)) *feedServer {
	t.Helper()
	s := &feedServer{}
	mux := http.NewServeMux()
	mux.HandleFunc(FeedPath, func(w http.ResponseWriter, _ *http.Request) {
		handler(w, atomic.AddInt32(&s.fetches, 1))
	})
	s.Server = httptest.NewServer(mux)
	t.Cleanup(s.Server.Close)
	return s
}

func (s *feedServer) Fetches() int32 { return atomic.LoadInt32(&s.fetches) }

func serveDocument(alg string, revoked []string) func(http.ResponseWriter, int32) {
	return func(w http.ResponseWriter, _ int32) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"alg": alg, "revoked": revoked})
	}
}

func newTestFeed(t *testing.T, s *feedServer) *Feed {
	t.Helper()
	f, err := NewFeed(s.Client(), s.URL)
	if err != nil {
		t.Fatalf("NewFeed: %v", err)
	}
	return f
}

// ---------------------------------------------------------------------------
// The entry format — eleven independent implementations need one vector
// ---------------------------------------------------------------------------

// The server computes this entry in axiam_core::revocation_feed and every SDK
// recomputes it from a sid claim. A pinned vector is the only thing that keeps
// twelve implementations of one wire format in agreement; a round-trip test
// against this same function would agree with itself while agreeing with
// nobody.
func TestEntryFor_MatchesThePinnedVector(t *testing.T) {
	const want = "i9N2lYMTV4FhA0husWjGYCqJXXTb7_fMBuomhWjSsgQ"
	if got := EntryFor(aSessionID); got != want {
		t.Fatalf("EntryFor(%q) = %q, want %q", aSessionID, got, want)
	}
}

// Hashed over the claim's EXACT string. An implementation that parsed the sid
// as a UUID and re-rendered it would agree on canonical input and disagree the
// moment a server issued anything else.
func TestEntryFor_HashesTheStringNotAParsedUUID(t *testing.T) {
	if EntryFor(aSessionID) == EntryFor("6F3E0A5C-1B2D-4E8F-9A7B-0C1D2E3F4A5B") {
		t.Fatal("an upper-case sid hashed to the same entry: the input was normalised")
	}
}

// ---------------------------------------------------------------------------
// The happy path
// ---------------------------------------------------------------------------

func TestIsRevoked_ReportsASessionTheDocumentLists(t *testing.T) {
	s := newFeedServer(t, serveDocument("SHA-256", []string{EntryFor(aSessionID)}))
	f := newTestFeed(t, s)

	if !f.IsRevoked(context.Background(), aSessionID) {
		t.Fatal("a listed session must be reported revoked")
	}
	if f.IsRevoked(context.Background(), "some-other-session") {
		t.Fatal("an unlisted session must not be reported revoked")
	}
}

// ---------------------------------------------------------------------------
// §10.4 rule 3 — it never fails closed
// ---------------------------------------------------------------------------
//
// Each of these is a way the feed can be unusable, and every one of them must
// behave exactly as no feed at all. The failure this forecloses is the
// opposite: a guard that starts denying every request because a document it
// treats as advisory became unreachable.

func TestIsRevoked_NeverFailsClosed(t *testing.T) {
	cases := []struct {
		name    string
		handler func(http.ResponseWriter, int32)
	}{
		{"a 404 — the deployment does not publish the feed", func(w http.ResponseWriter, _ int32) {
			w.WriteHeader(http.StatusNotFound)
		}},
		{"a 500 — the feed is broken", func(w http.ResponseWriter, _ int32) {
			w.WriteHeader(http.StatusInternalServerError)
		}},
		{"a body that is not JSON", func(w http.ResponseWriter, _ int32) {
			_, _ = w.Write([]byte("not json"))
		}},
		{"an alg this build does not know", serveDocument("SHA-512", []string{EntryFor(aSessionID)})},
		{"more entries than the cache bound", func(w http.ResponseWriter, _ int32) {
			oversized := make([]string, MaxEntries+1)
			for i := range oversized {
				oversized[i] = EntryFor(fmt.Sprintf("session-%d", i))
			}
			serveDocument("SHA-256", oversized)(w, 0)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newFeedServer(t, tc.handler)
			f := newTestFeed(t, s)
			if f.IsRevoked(context.Background(), aSessionID) {
				t.Fatal("an unusable feed must deny nothing")
			}
		})
	}
}

// An unreachable host is the same answer, and reaches a different code path
// (the request never completes at all).
func TestIsRevoked_AnUnreachableFeedDeniesNothing(t *testing.T) {
	s := newFeedServer(t, serveDocument("SHA-256", []string{EntryFor(aSessionID)}))
	f := newTestFeed(t, s)
	s.Close()

	if f.IsRevoked(context.Background(), aSessionID) {
		t.Fatal("an unreachable feed must deny nothing")
	}
}

// An oversized document drops the WHOLE set rather than truncating it. A
// truncated set is a guard that admits some revoked sessions and reports none,
// which is worse than one that admits all of them and says so.
func TestIsRevoked_AnOversizedDocumentDropsEverythingRatherThanTruncating(t *testing.T) {
	oversized := make([]string, MaxEntries+1)
	oversized[0] = EntryFor(aSessionID)
	for i := 1; i < len(oversized); i++ {
		oversized[i] = EntryFor(fmt.Sprintf("session-%d", i))
	}
	s := newFeedServer(t, serveDocument("SHA-256", oversized))
	f := newTestFeed(t, s)

	if f.IsRevoked(context.Background(), aSessionID) {
		t.Fatal("the first entry of an oversized document must not be honoured")
	}
}

// A blip must not un-revoke a session the guard already knows about: the
// previous set stays in place across a failed refresh.
func TestRefresh_AFailedPollKeepsThePreviousSet(t *testing.T) {
	s := newFeedServer(t, func(w http.ResponseWriter, fetch int32) {
		if fetch == 1 {
			serveDocument("SHA-256", []string{EntryFor(aSessionID)})(w, fetch)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	})
	f := newTestFeed(t, s)

	ctx := context.Background()
	f.Refresh(ctx)
	f.Refresh(ctx)

	if !f.IsRevoked(ctx, aSessionID) {
		t.Fatal("a failed refresh dropped a revocation the poller already knew about")
	}
}

// ---------------------------------------------------------------------------
// §10.4 rule 2 — the poll interval
// ---------------------------------------------------------------------------

// The request path never waits on a fetch it does not need: inside one
// interval, repeated checks answer from the cache.
func TestIsRevoked_DoesNotRefetchWithinThePollInterval(t *testing.T) {
	s := newFeedServer(t, serveDocument("SHA-256", nil))
	f := newTestFeed(t, s)

	ctx := context.Background()
	for range 5 {
		f.IsRevoked(ctx, aSessionID)
	}
	if got := s.Fetches(); got != 1 {
		t.Fatalf("five checks inside one interval made %d fetches, want 1", got)
	}
}

// Once the interval has elapsed, the next check refetches. Asserted through
// the injected clock rather than by sleeping — a test that really waited
// fifteen seconds is a test nobody runs.
func TestIsRevoked_RefetchesOnceThePollIntervalHasElapsed(t *testing.T) {
	s := newFeedServer(t, serveDocument("SHA-256", nil))
	f := newTestFeed(t, s)

	clock := time.Now()
	f.now = func() time.Time { return clock }

	ctx := context.Background()
	f.IsRevoked(ctx, aSessionID)
	clock = clock.Add(DefaultPollInterval + time.Second)
	f.IsRevoked(ctx, aSessionID)

	if got := s.Fetches(); got != 2 {
		t.Fatalf("got %d fetches across two intervals, want 2", got)
	}
}

// The floor is applied by clamping, not by refusing: a caller who asks for
// something faster gets the fastest thing on offer.
func TestWithPollInterval_ClampsToTheFloorRatherThanRefusing(t *testing.T) {
	s := newFeedServer(t, serveDocument("SHA-256", nil))
	f := newTestFeed(t, s).WithPollInterval(time.Millisecond)

	if f.pollInterval != MinPollInterval {
		t.Fatalf("poll interval = %v, want the %v floor", f.pollInterval, MinPollInterval)
	}
}

func TestWithPollInterval_KeepsAnIntervalAboveTheFloor(t *testing.T) {
	s := newFeedServer(t, serveDocument("SHA-256", nil))
	f := newTestFeed(t, s).WithPollInterval(2 * time.Minute)

	if f.pollInterval != 2*time.Minute {
		t.Fatalf("poll interval = %v, want 2m", f.pollInterval)
	}
}

// A feed that is down must not be retried on every request, which would put
// the request path back on the network — the cost §10.4 exists to avoid. The
// interval is measured from the last ATTEMPT, not the last success.
func TestIsRevoked_ADownFeedIsNotRetriedOnEveryRequest(t *testing.T) {
	s := newFeedServer(t, func(w http.ResponseWriter, _ int32) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	f := newTestFeed(t, s)

	ctx := context.Background()
	for range 5 {
		f.IsRevoked(ctx, aSessionID)
	}
	if got := s.Fetches(); got != 1 {
		t.Fatalf("five checks against a down feed made %d fetches, want 1", got)
	}
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

// A token with no session behind it never reaches the wire, let alone the set.
func TestIsRevoked_AnEmptySidIsNeverMatched(t *testing.T) {
	s := newFeedServer(t, serveDocument("SHA-256", []string{EntryFor("")}))
	f := newTestFeed(t, s)

	if f.IsRevoked(context.Background(), "") {
		t.Fatal("an empty sid must never match, even against a document listing its hash")
	}
	if got := s.Fetches(); got != 0 {
		t.Fatalf("an empty sid triggered %d fetches, want 0", got)
	}
}

func TestNewFeed_AppendsTheFeedPathToTheBaseURL(t *testing.T) {
	f, err := NewFeed(nil, "https://iam.example.com/")
	if err != nil {
		t.Fatalf("NewFeed: %v", err)
	}
	if want := "https://iam.example.com" + FeedPath; f.URL() != want {
		t.Fatalf("feed URL = %q, want %q", f.URL(), want)
	}
}

func TestNewFeed_RefusesARelativeBaseURL(t *testing.T) {
	if _, err := NewFeed(nil, "/oauth2"); err == nil {
		t.Fatal("a relative base URL must not produce a feed that silently polls nothing")
	}
}
