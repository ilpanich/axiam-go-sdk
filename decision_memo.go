// Client-side decision memo — CONTRACT.md §17.
//
// DISABLED BY DEFAULT. §11.2 rule 6's ban on caching allow/deny decisions is
// still the default behaviour; this is the single opt-in exception that section
// carves out, and a caller has to switch it on having read the cost.
//
// # What it costs
//
// The staleness bound is the TTL, IN BOTH DIRECTIONS. A grant revoked on the
// server can still read as allowed for up to the TTL, and a grant just added
// can still read as denied for up to the TTL. That second direction is the one
// that surprises people: reads-your-own-writes is NOT guaranteed. An admin UI
// that grants a role and immediately re-checks is the case that breaks, and it
// breaks silently.
//
// This mirrors the server's own bound rather than inventing a second staleness
// story — AXIAM__AUTHZ__DECISION_CACHE_TTL_SECS (default 5s) makes the same
// trade server-side. One deliberate difference: the server's setting is an
// unclamped integer, so an operator can configure a multi-hour staleness
// window. MaxMemoTTL clamps this one at 5s, because the client has no reason to
// repeat that.

package axiam

import (
	"container/list"
	"strings"
	"sync"
	"time"
)

// MaxMemoTTL is the §17.1 rule 2 ceiling. A configured TTL above this is
// clamped, not rejected: a caller who asked for a minute wants caching, and
// silently giving them the maximum safe value beats failing construction.
const MaxMemoTTL = 5 * time.Second

// maxMemoEntries bounds the memo before FIFO eviction (§17.1 rule 8). The memo
// is a latency optimisation, so dropping an entry is always correct.
const maxMemoEntries = 1024

const (
	// memoSep joins the key components. The unit separator cannot appear in an
	// action, a UUID or a scope, so no combination of caller-supplied values
	// can forge a collision.
	memoSep = "\x1f"
	// memoAbsent marks an absent optional, which is why an absent scope can
	// never collide with a present one — a memo that let them collide would
	// answer a narrower question with a broader answer.
	memoAbsent = "\x00"
)

// memoKey builds the §17.1 rule 3 key: all four components, with absent
// distinguished from present.
func memoKey(check AccessCheck) string {
	part := func(s string) string {
		if s == "" {
			return memoAbsent
		}
		return s
	}
	return strings.Join([]string{
		part(check.SubjectID),
		check.ResourceID,
		check.Action,
		part(check.Scope),
	}, memoSep)
}

type memoEntry struct {
	key      string
	result   AccessResult
	storedAt time.Time
}

// decisionMemo is a bounded, TTL-clamped decision cache.
//
// A zero ttl means DISABLED — not "cache for zero nanoseconds". That is the
// default, and both get and set become no-ops.
//
// Safe for concurrent use: a Go client is routinely shared across goroutines,
// and a cache that corrupted under concurrency would be a worse bug than the
// one it is optimising away.
type decisionMemo struct {
	mu      sync.Mutex
	ttl     time.Duration
	entries map[string]*list.Element
	order   *list.List // front = oldest, for FIFO eviction
	now     func() time.Time
}

func newDecisionMemo(ttl time.Duration) *decisionMemo {
	if ttl < 0 {
		ttl = 0
	} else if ttl > MaxMemoTTL {
		ttl = MaxMemoTTL
	}
	return &decisionMemo{
		ttl:     ttl,
		entries: make(map[string]*list.Element),
		order:   list.New(),
		now:     time.Now,
	}
}

func (m *decisionMemo) enabled() bool { return m != nil && m.ttl > 0 }

// get returns a live decision for key, if one is memoized and unexpired.
func (m *decisionMemo) get(key string) (AccessResult, bool) {
	if !m.enabled() {
		return AccessResult{}, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	el, ok := m.entries[key]
	if !ok {
		return AccessResult{}, false
	}
	entry := el.Value.(*memoEntry)
	if m.now().Sub(entry.storedAt) >= m.ttl {
		m.order.Remove(el)
		delete(m.entries, key)
		return AccessResult{}, false
	}
	// Returned whole, including ReasonCode: §17.1 rule 5 forbids returning
	// Allowed while dropping the code, which would make the field
	// intermittently absent — worse than never having had it.
	return entry.result, true
}

// set memoizes a decision the server actually returned.
//
// Callers must only reach here on success. §17.1 rule 7 forbids negative-
// caching a failure: memoizing a transport error as a deny would turn a blip
// into a TTL-long outage, and memoizing it as an allow is unthinkable.
func (m *decisionMemo) set(key string, result AccessResult) {
	if !m.enabled() {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if el, ok := m.entries[key]; ok {
		m.order.Remove(el)
		delete(m.entries, key)
	}
	el := m.order.PushBack(&memoEntry{key: key, result: result, storedAt: m.now()})
	m.entries[key] = el

	for m.order.Len() > maxMemoEntries {
		oldest := m.order.Front()
		if oldest == nil {
			break
		}
		m.order.Remove(oldest)
		delete(m.entries, oldest.Value.(*memoEntry).key)
	}
}

// clear drops every entry (§17.1 rule 9).
//
// Called on Login, VerifyMfa, Refresh and Logout. Entries are keyed by subject,
// not by session, so a re-authentication as a DIFFERENT principal would
// otherwise read the previous principal's decisions.
func (m *decisionMemo) clear() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries = make(map[string]*list.Element)
	m.order.Init()
}

// reportClamp emits a ConfigClampedEvent if the requested TTL was clamped
// (CONTRACT.md §19.2 rule 6).
//
// This is the clamp that matters most to get right: an operator who set a
// 60-second TTL believes their staleness bound is 60 seconds. It is five, and
// without this event nothing anywhere says so.
//
// Nothing is emitted when the requested value was already inside the limit, or
// when the memo is disabled — an event that fires when nothing happened trains
// its reader to ignore it.
func reportMemoClamp(requested time.Duration, effective time.Duration, d dispatcher) {
	if !d.installed() || requested <= 0 || requested == effective {
		return
	}
	d.emit(ConfigClampedEvent{
		Setting:           "WithDecisionMemoTTL",
		Requested:         requested.String(),
		Effective:         effective.String(),
		ContractReference: "§17.1 rule 2",
	})
}

// len reports the entry count, for tests.
func (m *decisionMemo) len() int {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.order.Len()
}
