package axiam

import (
	"sync"
	"testing"
	"time"
)

// TestMemoryOidcStateStore_SingleUseConsume proves CONTRACT.md §12.3 rule 1:
// Consume atomically returns AND deletes, so a replayed callback finds
// nothing.
func TestMemoryOidcStateStore_SingleUseConsume(t *testing.T) {
	store := NewMemoryOidcStateStore(0)
	entry := OidcStateEntry{
		State:        "state-1",
		Nonce:        "nonce-1",
		CodeVerifier: Sensitive("verifier-1"),
		RedirectURI:  "https://app.test/callback",
		ReturnTo:     "/dashboard",
	}
	if err := store.Save(entry); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, ok := store.Consume("state-1")
	if !ok {
		t.Fatal("expected Consume to find the saved entry")
	}
	if got != entry {
		t.Fatalf("Consume returned %+v, want %+v", got, entry)
	}

	if _, ok := store.Consume("state-1"); ok {
		t.Fatal("expected a second Consume of the same state to fail (single-use)")
	}
}

// TestMemoryOidcStateStore_UnknownStateFails proves an unknown state is
// indistinguishable from an expired/consumed one — both report ok=false.
func TestMemoryOidcStateStore_UnknownStateFails(t *testing.T) {
	store := NewMemoryOidcStateStore(0)
	if _, ok := store.Consume("never-saved"); ok {
		t.Fatal("expected Consume of an unknown state to fail")
	}
}

// TestMemoryOidcStateStore_TTLExpiry proves an entry older than its TTL is
// never returned, even on the first Consume.
func TestMemoryOidcStateStore_TTLExpiry(t *testing.T) {
	store := NewMemoryOidcStateStore(10 * time.Millisecond)
	if err := store.Save(OidcStateEntry{State: "state-1"}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	time.Sleep(30 * time.Millisecond)

	if _, ok := store.Consume("state-1"); ok {
		t.Fatal("expected an expired entry to be rejected by Consume")
	}
}

// TestMemoryOidcStateStore_TTLClampedToMaximum proves CONTRACT.md §12.3
// rule 1: 10 minutes is a MAXIMUM, so an over-long configured TTL is
// silently clamped down, while a SHORTER one is honoured verbatim.
func TestMemoryOidcStateStore_TTLClampedToMaximum(t *testing.T) {
	over := NewMemoryOidcStateStore(24 * time.Hour)
	if over.ttl != OidcStateTTL {
		t.Fatalf("ttl = %v, want the clamped maximum %v", over.ttl, OidcStateTTL)
	}

	short := NewMemoryOidcStateStore(5 * time.Second)
	if short.ttl != 5*time.Second {
		t.Fatalf("ttl = %v, want the shorter configured value honoured verbatim", short.ttl)
	}

	zero := NewMemoryOidcStateStore(0)
	if zero.ttl != OidcStateTTL {
		t.Fatalf("ttl = %v, want the default maximum %v for a zero/negative input", zero.ttl, OidcStateTTL)
	}
}

// TestMemoryOidcStateStore_SizeSweepsExpired proves Size() reports only
// unexpired entries and that expired ones are swept away lazily.
func TestMemoryOidcStateStore_SizeSweepsExpired(t *testing.T) {
	store := NewMemoryOidcStateStore(10 * time.Millisecond)
	_ = store.Save(OidcStateEntry{State: "a"})
	_ = store.Save(OidcStateEntry{State: "b"})
	if got := store.Size(); got != 2 {
		t.Fatalf("Size() = %d, want 2", got)
	}

	time.Sleep(30 * time.Millisecond)
	if got := store.Size(); got != 0 {
		t.Fatalf("Size() after expiry = %d, want 0", got)
	}
}

// TestMemoryOidcStateStore_ConcurrentSaveConsume is a -race regression guard
// proving the store is safe under concurrent Save/Consume from many
// goroutines, and that no state is ever consumed twice.
func TestMemoryOidcStateStore_ConcurrentSaveConsume(t *testing.T) {
	store := NewMemoryOidcStateStore(time.Minute)
	const n = 100

	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			state := stateKey(i)
			_ = store.Save(OidcStateEntry{State: state, Nonce: "nonce"})
		}(i)
	}
	wg.Wait()

	var mu sync.Mutex
	consumedCount := make(map[string]int, n)
	wg.Add(n * 2) // two concurrent Consume racers per state
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			state := stateKey(i)
			if _, ok := store.Consume(state); ok {
				mu.Lock()
				consumedCount[state]++
				mu.Unlock()
			}
		}(i)
		go func(i int) {
			defer wg.Done()
			state := stateKey(i)
			if _, ok := store.Consume(state); ok {
				mu.Lock()
				consumedCount[state]++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()

	for state, count := range consumedCount {
		if count != 1 {
			t.Fatalf("state %q was consumed %d times, want exactly 1 (single-use under concurrency)", state, count)
		}
	}
	if len(consumedCount) != n {
		t.Fatalf("expected all %d states to be consumed exactly once, got %d", n, len(consumedCount))
	}
}

func stateKey(i int) string {
	const letters = "0123456789abcdef"
	b := make([]byte, 8)
	for j := range b {
		b[j] = letters[(i>>(j*4))&0xF]
	}
	return string(b)
}

var _ OidcStateStore = (*MemoryOidcStateStore)(nil)
