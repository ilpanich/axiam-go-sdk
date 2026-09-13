package axiam

// The public §10.4 surface (contract 1.44). The feed's behaviour is asserted in
// internal/revocation and its effect on a verification in internal/jwks; what
// is under test here is the surface an integrator actually types, which is the
// part a re-export can silently get wrong.

import (
	"net/http"
	"testing"
	"time"
)

func TestRevocationEntryFor_MatchesThePinnedVector(t *testing.T) {
	// The same vector the server pins in axiam_core::revocation_feed and every
	// sibling SDK reproduces. Twelve implementations of one wire format need
	// one literal to agree on; a round trip through this package's own hash
	// would agree with itself while agreeing with nobody.
	const sid = "6f3e0a5c-1b2d-4e8f-9a7b-0c1d2e3f4a5b"
	const want = "i9N2lYMTV4FhA0husWjGYCqJXXTb7_fMBuomhWjSsgQ"
	if got := RevocationEntryFor(sid); got != want {
		t.Fatalf("RevocationEntryFor(%q) = %q, want %q", sid, got, want)
	}
}

func TestNewRevocationFeed_BuildsAPollerForTheDeploymentsFeed(t *testing.T) {
	feed, err := NewRevocationFeed(http.DefaultClient, "https://iam.example.com")
	if err != nil {
		t.Fatalf("NewRevocationFeed: %v", err)
	}
	if want := "https://iam.example.com/oauth2/revocations"; feed.URL() != want {
		t.Fatalf("feed URL = %q, want %q", feed.URL(), want)
	}
}

// A deployment that does not publish the feed is not an error at construction
// — that is discovered on the first poll and behaves as no feed at all. Only a
// base URL that names no host is refused, because such a feed would poll
// nothing forever while looking configured.
func TestNewRevocationFeed_RefusesOnlyAnUnusableBaseURL(t *testing.T) {
	if _, err := NewRevocationFeed(nil, "not-a-url"); err == nil {
		t.Fatal("a base URL naming no host must not produce a silent no-op poller")
	}
}

func TestRevocationFeed_ExposesTheContractsBounds(t *testing.T) {
	if RevocationFeedMinPollInterval != 15*time.Second {
		t.Fatalf("min poll interval = %v, want 15s", RevocationFeedMinPollInterval)
	}
	if RevocationFeedDefaultPollInterval != 30*time.Second {
		t.Fatalf("default poll interval = %v, want 30s", RevocationFeedDefaultPollInterval)
	}
	if RevocationFeedMaxEntries != 100_000 {
		t.Fatalf("max entries = %d, want 100000", RevocationFeedMaxEntries)
	}
}

// The wiring an integrator writes: build a feed, attach it, keep the verifier.
// Default off is the assertion that matters — a verifier built without this
// call behaves exactly as it did before 1.44.
func TestWithRevocationFeed_AttachesAndReturnsTheVerifier(t *testing.T) {
	feed, err := NewRevocationFeed(nil, "https://iam.example.com")
	if err != nil {
		t.Fatalf("NewRevocationFeed: %v", err)
	}
	verifier := new(JWKSVerifier)
	if got := verifier.WithRevocationFeed(feed); got != verifier {
		t.Fatal("WithRevocationFeed must return the same verifier so construction reads as one expression")
	}
}
