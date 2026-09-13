// Package revocation implements the optional session-revocation feed poller
// (CONTRACT.md §10.4, contract 1.44 — AXIAM threats T-39 and T-143).
//
// # What this narrows, and what it is not
//
// An AXIAM access token is self-contained and valid for up to fifteen minutes,
// and this SDK verifies it locally. A logout, a role removal or an account
// disable therefore does not reach a token already in a caller's hands until
// it expires — §10.2 records that, and the documented answer has been "route
// the decision through gRPC introspection instead", which is correct and costs
// a round trip PER REQUEST.
//
// A deployment may publish GET /oauth2/revocations: the base64url-unpadded
// SHA-256 of every session id revoked within the last access-token lifetime. A
// guard that polls it rejects a revoked session within ONE POLL INTERVAL
// instead of one token lifetime, for one cacheable fetch per interval.
//
// It is NOT a control, and every rule below follows from that:
//
//   - Default off. Nothing polls unless a caller attaches a Feed.
//   - Never on the request path. IsRevoked answers from the cached set and, at
//     most, refreshes a set the NEXT caller sees.
//   - Never fail closed. An unreachable feed, a non-200, a body that does not
//     parse, an alg this build does not know — every one of them behaves
//     exactly as no feed at all. Not as an empty list: an empty list asserts
//     that nothing has been revoked, which is a guard that silently honours no
//     revocations while appearing to honour them.
//   - It only ever rejects. Every §10.1 rule runs first and still decides. The
//     feed can turn an accept into a reject and never the reverse.
//   - A token with no sid is never matched. There is no session behind a
//     client-credentials token, an RPT or a token exchange, and hashing jti
//     instead would match nothing while looking like it worked.
package revocation

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// FeedPath is the published feed's path, appended to a deployment's base URL.
const FeedPath = "/oauth2/revocations"

// supportedAlg is the only digest the feed publishes, and the only one this
// poller accepts.
//
// A document naming anything else is treated as unusable — exactly as an
// unreachable feed is — rather than as a list of entries that happen not to
// match. Silently matching nothing is how a guard ends up reporting that it
// honours revocations while honouring none.
const supportedAlg = "SHA-256"

// MinPollInterval is the shortest interval a caller may configure (§10.4
// rule 2).
//
// Bounded because the feed is one deployment-wide document and a fleet of
// guards polling it at a hundred milliseconds is a load source rather than a
// security improvement. The floor is applied by clamping, not by refusing: a
// caller who asked for something faster gets the fastest thing on offer.
const MinPollInterval = 15 * time.Second

// DefaultPollInterval is the interval §10.4 recommends, and the one a Feed
// uses unless told otherwise.
const DefaultPollInterval = 30 * time.Second

// MaxEntries is the largest number of entries kept in the cache (§10.4
// rule 2).
//
// The server bounds the document by its own revocation rate over one token
// lifetime, so this is defence against a server that stops doing so — a cache
// with no ceiling is an allocation an unauthenticated endpoint controls.
// Overflow drops the WHOLE set rather than truncating it: a truncated set is a
// guard that admits some revoked sessions and reports none, which is worse
// than a guard that admits all of them and says the feed is unusable.
const MaxEntries = 100_000

// maxBodyBytes caps what is read off the wire before the entry count can be
// known, since the count is only knowable after decoding. 64 bytes of entry
// plus JSON framing over MaxEntries, rounded up.
const maxBodyBytes = 8 << 20

// feedDocument is the feed document as published.
type feedDocument struct {
	Alg     string   `json:"alg"`
	Revoked []string `json:"revoked"`
}

// EntryFor is the feed entry for a sid, as the server computes it.
//
// Base64url without padding over the claim's EXACT string — never a
// parsed-and-re-rendered UUID, or the answer would depend on this module's
// UUID parser rather than on the feed.
func EntryFor(sid string) string {
	sum := sha256.Sum256([]byte(sid))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// Feed is a poller for one deployment's revocation feed.
//
// Safe for concurrent use, and meant to be shared: several guards built from
// one Feed poll once between them rather than once each.
type Feed struct {
	httpClient   *http.Client
	feedURL      string
	pollInterval time.Duration

	// fetchMu serializes refreshers, so a burst of guards that all notice the
	// cache is stale produces one fetch rather than one each — the same shape
	// as the JWKS verifier's refresh lock, and for the same reason.
	fetchMu sync.Mutex

	mu sync.RWMutex
	// entries nil means "never successfully fetched", which is NOT the same as
	// an empty set, and is why this is compared against nil rather than len.
	entries     map[string]struct{}
	lastAttempt time.Time

	// now is a testing seam only; nil means time.Now. Unexported so it can
	// never be reached from configuration.
	now func() time.Time
}

// NewFeed polls {baseURL}/oauth2/revocations on the default interval, through
// hc (nil means http.DefaultClient).
//
// A deployment that does not publish the feed is not an error here — that is
// discovered on the first poll, and behaves as no feed at all from then on.
// The only error is a baseURL that cannot be parsed.
func NewFeed(hc *http.Client, baseURL string) (*Feed, error) {
	base, err := url.Parse(baseURL)
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil, fmt.Errorf("revocation: %q is not an absolute base URL", baseURL)
	}
	feed := *base
	feed.Path = FeedPath
	feed.RawQuery = ""
	feed.Fragment = ""
	if hc == nil {
		hc = http.DefaultClient
	}
	return &Feed{httpClient: hc, feedURL: feed.String(), pollInterval: DefaultPollInterval}, nil
}

// WithPollInterval overrides the poll interval, clamped to MinPollInterval,
// and returns f so construction reads as one expression.
func (f *Feed) WithPollInterval(interval time.Duration) *Feed {
	if interval < MinPollInterval {
		interval = MinPollInterval
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pollInterval = interval
	return f
}

// URL is the feed document's URL, for diagnostics.
func (f *Feed) URL() string { return f.feedURL }

func (f *Feed) currentTime() time.Time {
	if f.now != nil {
		return f.now()
	}
	return time.Now()
}

// IsRevoked reports whether this session has been revoked, as far as this
// poller knows.
//
// False whenever the answer is not a confident yes — a feed never fetched,
// unreachable, malformed, or simply not listing this session. The caller
// admits the request in all of those cases, which is §10.4 rule 3 and is the
// whole reason the feature is safe to turn on.
func (f *Feed) IsRevoked(ctx context.Context, sid string) bool {
	if sid == "" {
		return false
	}
	f.refreshIfStale(ctx)
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.entries == nil {
		return false
	}
	_, revoked := f.entries[EntryFor(sid)]
	return revoked
}

// Refresh fetches now, whatever the interval says. For tests, and for a caller
// that wants the first poll to have happened before it starts serving.
func (f *Feed) Refresh(ctx context.Context) {
	f.fetchMu.Lock()
	defer f.fetchMu.Unlock()
	fetched := f.fetch(ctx)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastAttempt = f.currentTime()
	if fetched != nil {
		f.entries = fetched
	}
	// On failure the previous set is deliberately left in place: a blip must
	// not un-revoke a session the guard already knows about.
}

// refreshIfStale refetches if the poll interval has elapsed since the last
// ATTEMPT.
//
// Attempt, not success: a feed that is down must not be retried on every
// request, which would put the request path back on the network — the cost
// §10.4 exists to avoid.
func (f *Feed) refreshIfStale(ctx context.Context) {
	f.mu.RLock()
	last := f.lastAttempt
	interval := f.pollInterval
	f.mu.RUnlock()
	if !last.IsZero() && f.currentTime().Sub(last) < interval {
		return
	}
	f.Refresh(ctx)
}

// fetch performs one fetch. nil for every kind of failure, which the caller
// treats identically — see the package docs on why "unusable" must not
// collapse into "empty".
func (f *Feed) fetch(ctx context.Context) map[string]struct{} {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, f.feedURL, nil)
	if err != nil {
		return nil
	}
	response, err := f.httpClient.Do(request)
	if err != nil {
		return nil
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxBodyBytes))
	if err != nil {
		return nil
	}
	var document feedDocument
	if err := json.Unmarshal(body, &document); err != nil {
		return nil
	}
	if document.Alg != supportedAlg {
		return nil
	}
	if len(document.Revoked) > MaxEntries {
		return nil
	}
	entries := make(map[string]struct{}, len(document.Revoked))
	for _, entry := range document.Revoked {
		entries[entry] = struct{}{}
	}
	return entries
}
