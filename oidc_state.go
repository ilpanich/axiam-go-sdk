package axiam

// OidcStateStore + MemoryOidcStateStore (CONTRACT.md §12.3 rule 1).
//
// STRICTLY OPTIONAL. The nine §12 operations never touch a store themselves:
// OidcBegin and OidcExchange are stateless by contract, and the caller
// normally keeps state/nonce/code_verifier in its own HTTP session. This
// store exists for the framework glue (middleware.OidcLoginHandler /
// middleware.OidcCallbackHandler), where a login and its callback are two
// separate HTTP requests with nothing but a `state` value linking them.
//
// Semantics mirror the server's `federation_login_state` table: 10-minute
// TTL, single-use consume.

import (
	"sync"
	"time"
)

// OidcStateEntry is the tuple an OidcStateStore holds for one in-flight
// login.
//
// CodeVerifier stays Sensitive while stored (§12.5: the verifier is secret
// for its whole lifetime, "including ... in any OidcStateStore entry").
type OidcStateEntry struct {
	// State is the `state` value this entry is keyed by. Not a secret
	// (§12.3 rule 2).
	State string
	// Nonce is checked against the ID token's `nonce` claim. Not a secret
	// (§12.3 rule 2).
	Nonce string
	// CodeVerifier is the PKCE verifier for the matching authorization
	// request (§12.5 secret).
	CodeVerifier Sensitive
	// RedirectURI is the redirect_uri that was sent on the authorization
	// request and must be replayed on exchange.
	RedirectURI string
	// ReturnTo is optional application-owned data, e.g. the page the user
	// was heading to before login.
	ReturnTo string
}

// OidcStateStore is an OPTIONAL server-side store for in-flight OidcBegin
// state (CONTRACT.md §12.3 rule 1).
//
// Implement this to back the login/callback handlers with your own storage
// (Redis, a database, an encrypted cookie). Two invariants are normative:
//
//  1. Single-use: Consume MUST return the entry AND delete it atomically, so
//     a replayed callback cannot reuse a state.
//  2. Expiry: an entry older than the store's TTL (10 minutes, at most —
//     OidcStateTTL) MUST NOT be returned.
type OidcStateStore interface {
	// Save persists entry, keyed by its State, starting its TTL now.
	Save(entry OidcStateEntry) error
	// Consume atomically fetches AND REMOVES the entry for state. ok is
	// false when the state is unknown, already consumed, or expired — three
	// cases a caller MUST treat identically (as a failed login), because
	// distinguishing them leaks whether a state ever existed.
	Consume(state string) (entry OidcStateEntry, ok bool)
}

// OidcStateTTL is the contract-mandated MAXIMUM TTL for stored login state:
// 10 minutes, matching the server's federation_login_state row lifetime
// (D-22, CONTRACT.md §12.3 rule 1).
const OidcStateTTL = 10 * time.Minute

// memoryOidcStateEntry pairs a stored OidcStateEntry with its absolute
// expiry time.
type memoryOidcStateEntry struct {
	entry     OidcStateEntry
	expiresAt time.Time
}

// MemoryOidcStateStore is an in-memory reference implementation of
// OidcStateStore (CONTRACT.md §12.3 rule 1): per-instance (never
// process-global), single-use, TTL-bounded. Expired entries are dropped
// lazily on Save/Consume — there is NO background timer/goroutine, since a
// library must not keep the host process alive on its own.
//
// Suitable for a single-process app and for tests. A multi-instance
// deployment needs a shared store (Redis, a database) — implement
// OidcStateStore directly for that; nothing in this SDK assumes this type.
type MemoryOidcStateStore struct {
	mu      sync.Mutex
	ttl     time.Duration
	entries map[string]memoryOidcStateEntry
}

// NewMemoryOidcStateStore constructs a MemoryOidcStateStore. ttl is the
// entry lifetime; zero, negative, or greater than OidcStateTTL is CLAMPED to
// OidcStateTTL (10 minutes) — CONTRACT.md §12.3 rule 1 fixes that as the
// maximum, while a shorter TTL is honoured verbatim (useful in tests).
func NewMemoryOidcStateStore(ttl time.Duration) *MemoryOidcStateStore {
	if ttl <= 0 || ttl > OidcStateTTL {
		ttl = OidcStateTTL
	}
	return &MemoryOidcStateStore{ttl: ttl, entries: make(map[string]memoryOidcStateEntry)}
}

// Save persists entry under its own State, expiring ttl from now.
func (s *MemoryOidcStateStore) Save(entry OidcStateEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	s.entries[entry.State] = memoryOidcStateEntry{entry: entry, expiresAt: time.Now().Add(s.ttl)}
	return nil
}

// Consume atomically returns and deletes the entry for state. Deletion
// happens BEFORE the expiry check, so even an expired hit is removed rather
// than left to accumulate, and a second call can never return the same
// entry twice regardless of timing.
func (s *MemoryOidcStateStore) Consume(state string) (OidcStateEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	held, ok := s.entries[state]
	if !ok {
		return OidcStateEntry{}, false
	}
	delete(s.entries, state)
	if time.Now().After(held.expiresAt) {
		return OidcStateEntry{}, false
	}
	return held.entry, true
}

// Size reports the number of unexpired entries currently held. Intended for
// tests and metrics.
func (s *MemoryOidcStateStore) Size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	return len(s.entries)
}

// sweepLocked drops every expired entry. Caller must hold s.mu. Lazy
// housekeeping only — no background timer.
func (s *MemoryOidcStateStore) sweepLocked() {
	now := time.Now()
	for k, v := range s.entries {
		if now.After(v.expiresAt) {
			delete(s.entries, k)
		}
	}
}

var _ OidcStateStore = (*MemoryOidcStateStore)(nil)
