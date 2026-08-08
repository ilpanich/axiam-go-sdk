package axiam

// Decision reason codes — CONTRACT.md §11 rule 9 (B1 deny-override).
//
// The rule exists because the two refusals mean OPPOSITE THINGS to the person
// on the other end: no_grant says "ask an admin for access", denied_by_rule
// says "an admin has already decided". An application that cannot tell them
// apart sends users to raise tickets that will be refused.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

const testResourceID = "11111111-2222-3333-4444-555555555555"

func newReasonCodeServer(t *testing.T, checkBody, batchBody any) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/authz/check", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(checkBody)
	})
	mux.HandleFunc("/api/v1/authz/check/batch", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(batchBody)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func checkWith(t *testing.T, body any) AccessResult {
	t.Helper()
	srv := newReasonCodeServer(t, body, nil)
	client, err := NewClient(srv.URL, "acme")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	result, err := client.CheckAccessDecision(context.Background(), "", "read", testResourceID)
	if err != nil {
		t.Fatalf("CheckAccessDecision: %v", err)
	}
	return result
}

func TestReasonCodeSurfacedOnAnAllow(t *testing.T) {
	result := checkWith(t, map[string]any{"allowed": true, "reason_code": "allowed"})
	if !result.Allowed {
		t.Fatal("Allowed: got false")
	}
	if result.ReasonCode != ReasonCodeAllowed {
		t.Errorf("ReasonCode: got %q, want %q", result.ReasonCode, ReasonCodeAllowed)
	}
}

func TestNoGrantAndDeniedByRuleAreNotCollapsed(t *testing.T) {
	noGrant := checkWith(t, map[string]any{"allowed": false, "reason_code": "no_grant"})
	byRule := checkWith(t, map[string]any{"allowed": false, "reason_code": "denied_by_rule"})

	// Both are refusals…
	if noGrant.Allowed || byRule.Allowed {
		t.Fatal("both must be refusals")
	}
	// …and the SDK must not reduce them to that shared false.
	if noGrant.ReasonCode != ReasonCodeNoGrant {
		t.Errorf("no_grant: got %q", noGrant.ReasonCode)
	}
	if byRule.ReasonCode != ReasonCodeDeniedByRule {
		t.Errorf("denied_by_rule: got %q", byRule.ReasonCode)
	}
	if noGrant.ReasonCode == byRule.ReasonCode {
		t.Error("the two refusals must remain distinguishable")
	}
}

func TestUnknownReasonCodeIsSurfacedVerbatimAndChangesNothing(t *testing.T) {
	// §11 rule 9: an SDK that does not recognise a code MUST surface it
	// unchanged and MUST NOT let it affect the outcome, which Allowed carries
	// alone. This is what lets the server add a fourth code without breaking
	// every deployed SDK.
	denied := checkWith(t, map[string]any{"allowed": false, "reason_code": "denied_by_some_future_thing"})
	if denied.Allowed {
		t.Error("an unknown code must not flip a deny")
	}
	if denied.ReasonCode != "denied_by_some_future_thing" {
		t.Errorf("ReasonCode: got %q, want it verbatim", denied.ReasonCode)
	}

	allowed := checkWith(t, map[string]any{"allowed": true, "reason_code": "something-unrecognised"})
	if !allowed.Allowed {
		t.Error("an unknown code must not flip an allow")
	}
}

func TestAnOlderServerOmittingReasonCodeIsNotAnError(t *testing.T) {
	// A newer SDK against an older server: the field is simply absent, and
	// that MUST degrade to today's behaviour rather than failing to parse.
	denied := checkWith(t, map[string]any{"allowed": false})
	if denied.Allowed || denied.ReasonCode != "" {
		t.Errorf("got Allowed=%v ReasonCode=%q", denied.Allowed, denied.ReasonCode)
	}

	allowed := checkWith(t, map[string]any{"allowed": true, "reason": "role grants it"})
	if !allowed.Allowed || allowed.ReasonCode != "" || allowed.Reason != "role grants it" {
		t.Errorf("got %+v", allowed)
	}
}

func TestCanStillReturnsFalseForBothRefusals(t *testing.T) {
	// §11 rule 9 is about REPORTING, not enforcement: Can is the "just tell me
	// yes or no" helper and both refusals answer false identically. An SDK
	// must not start varying enforcement on the code.
	for _, code := range []string{ReasonCodeNoGrant, ReasonCodeDeniedByRule} {
		t.Run(code, func(t *testing.T) {
			srv := newReasonCodeServer(t, map[string]any{"allowed": false, "reason_code": code}, nil)
			client, err := NewClient(srv.URL, "acme")
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			allowed, err := client.Can(context.Background(), "read", testResourceID)
			if err != nil {
				t.Fatalf("Can: %v", err)
			}
			if allowed {
				t.Error("Can must answer false for either refusal")
			}
		})
	}
}

func TestBatchCheckSurfacesAReasonCodePerDecision(t *testing.T) {
	srv := newReasonCodeServer(t, nil, map[string]any{
		"results": []map[string]any{
			{"allowed": true, "reason_code": "allowed"},
			{"allowed": false, "reason_code": "no_grant"},
			{"allowed": false, "reason_code": "denied_by_rule"},
		},
	})
	client, err := NewClient(srv.URL, "acme")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	results, err := client.BatchCheck(context.Background(), []AccessCheck{
		{Action: "read", ResourceID: testResourceID},
		{Action: "write", ResourceID: testResourceID},
		{Action: "delete", ResourceID: testResourceID},
	})
	if err != nil {
		t.Fatalf("BatchCheck: %v", err)
	}
	want := []string{ReasonCodeAllowed, ReasonCodeNoGrant, ReasonCodeDeniedByRule}
	if len(results) != len(want) {
		t.Fatalf("got %d results, want %d", len(results), len(want))
	}
	for i, w := range want {
		if results[i].ReasonCode != w {
			t.Errorf("result %d: got %q, want %q", i, results[i].ReasonCode, w)
		}
	}
}
