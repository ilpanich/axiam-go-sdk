// §19.2 rule 6 — a clamped setting is reported, not swallowed (contract 1.9).
//
// Clamping is right: rejecting would break a caller whose configuration was
// merely optimistic, and honoring would let one client become the herd §16
// exists to prevent. Doing it SILENTLY is the part that is wrong — an operator
// who set a 60-second memo TTL believes they have one, and their staleness
// reasoning is off by a factor of twelve with nothing to say so.

package axiam

import (
	"testing"
	"time"
)

// clampsFor builds a client and returns only its ConfigClampedEvents.
//
// Construction alone is the subject: the event fires at build time, before any
// request, because that is the only moment an operator can act on it.
func clampsFor(t *testing.T, opts ...Option) []ConfigClampedEvent {
	t.Helper()
	var clamps []ConfigClampedEvent
	opts = append(opts,
		WithOrgSlug("acme"),
		WithTelemetryHook(func(e TelemetryEvent) {
			if c, ok := e.(ConfigClampedEvent); ok {
				clamps = append(clamps, c)
			}
		}),
	)
	if _, err := NewClient("https://axiam-d5.test", "acme", opts...); err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return clamps
}

func TestConfigClamped_ReportsAClampedMemoTTL(t *testing.T) {
	clamps := clampsFor(t, WithDecisionMemoTTL(60*time.Second))

	if len(clamps) != 1 {
		t.Fatalf("got %d clamp events, want 1", len(clamps))
	}
	if clamps[0].Setting != "WithDecisionMemoTTL" {
		t.Errorf("setting: got %q", clamps[0].Setting)
	}
	if clamps[0].Requested != "1m0s" {
		t.Errorf("requested: got %q, want 1m0s", clamps[0].Requested)
	}
	if clamps[0].Effective != MaxMemoTTL.String() {
		t.Errorf("effective: got %q, want %q", clamps[0].Effective, MaxMemoTTL)
	}
	if clamps[0].ContractReference != "§17.1 rule 2" {
		t.Errorf("contract reference: got %q", clamps[0].ContractReference)
	}
}

func TestConfigClamped_ReportsNothingForAValueWithinItsLimit(t *testing.T) {
	// An event that fires when nothing happened trains its reader to ignore it.
	if clamps := clampsFor(t, WithDecisionMemoTTL(2*time.Second)); len(clamps) != 0 {
		t.Fatalf("got %d clamp events for an in-range TTL, want 0", len(clamps))
	}
}

func TestConfigClamped_ReportsNothingForTheDisabledDefault(t *testing.T) {
	// Matters more than it looks: the memo is off by default, so without this
	// guard every client ever built would fire a zero-to-zero "clamp".
	if clamps := clampsFor(t); len(clamps) != 0 {
		t.Fatalf("got %d clamp events for the default client, want 0", len(clamps))
	}
	if clamps := clampsFor(t, WithDecisionMemoTTL(0)); len(clamps) != 0 {
		t.Fatalf("got %d clamp events for an explicit zero TTL, want 0", len(clamps))
	}
}
