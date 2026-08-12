package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	axiam "github.com/ilpanich/axiam-go-sdk"
)

// ---------------------------------------------------------------------------
// The §20.3 emit half, wired into the §11 RequireAccess guard.
//
// Everything asserted here is about the DENY path, because that is the only
// path that mints anything:
//
//  1. A denial with a challenger mints exactly one ticket and emits it.
//  2. An allow mints nothing — a guard that minted on the happy path would put
//     a Protection API call in front of every authorized request.
//  3. A minting failure still denies, without a challenge. An outage must not
//     turn a deny into a 503, and must never turn it into an allow.
// ---------------------------------------------------------------------------

const testChallengeTicket = "ticket-value"

// fakeMinter is a hermetic UmaTicketMinter double recording what it was asked
// for, so the tests can assert the ticket names the action that was refused.
type fakeMinter struct {
	err error

	calls    int
	gotPAT   axiam.Sensitive
	gotPerms []axiam.RequestedPermission
}

func (f *fakeMinter) UmaRequestTicket(_ context.Context, pat axiam.Sensitive, permissions []axiam.RequestedPermission) (axiam.Sensitive, error) {
	f.calls++
	f.gotPAT = pat
	f.gotPerms = permissions
	if f.err != nil {
		return "", f.err
	}
	return axiam.Sensitive(testChallengeTicket), nil
}

func testChallenger(minter *fakeMinter) *UmaChallenger {
	return &UmaChallenger{
		Realm:  "invoices",
		ASURI:  "https://id.example",
		PAT:    axiam.Sensitive("pat-token-value"),
		Minter: minter,
	}
}

func TestUmaChallenge_DenialMintsOneTicketAndEmitsIt(t *testing.T) {
	minter := &fakeMinter{}
	checker := &fakeChecker{allowed: false, reason: "no matching grant"}
	rec := &recordingHandler{}
	h := RequireAccess(checker, "invoices:read", ResourceFromPath("id"),
		WithUmaChallenge(testChallenger(minter)))(rec.handler())

	w := httptest.NewRecorder()
	h.ServeHTTP(w, reqWithUser(testUser()))

	if w.Code != http.StatusForbidden {
		t.Fatalf("the challenge is additive, not a redirect: expected 403, got %d", w.Code)
	}
	if minter.calls != 1 {
		t.Fatalf("expected exactly one ticket, got %d", minter.calls)
	}

	// The emitted header is the one this SDK's own parser consumes — the round
	// trip is the point of shipping both halves.
	challenge, ok := axiam.UmaParseChallenge(w.Header().Get("WWW-Authenticate"))
	if !ok {
		t.Fatalf("emitted header did not parse as a UMA challenge: %q", w.Header().Get("WWW-Authenticate"))
	}
	if challenge.Realm != "invoices" || challenge.AsURI != "https://id.example" {
		t.Fatalf("unexpected realm/as_uri: %q / %q", challenge.Realm, challenge.AsURI)
	}
	if string(challenge.Ticket) != testChallengeTicket {
		t.Fatal("the parsed ticket is not the one that was minted")
	}
	if rec.called {
		t.Fatal("a denied request must not reach the wrapped handler")
	}
}

func TestUmaChallenge_TicketAsksForTheActionThatWasRefused(t *testing.T) {
	minter := &fakeMinter{}
	checker := &fakeChecker{allowed: false}
	h := RequireAccess(checker, "invoices:approve", ResourceFromPath("id"),
		WithUmaChallenge(testChallenger(minter)))((&recordingHandler{}).handler())

	h.ServeHTTP(httptest.NewRecorder(), reqWithUser(testUser()))

	// §20.2: the UMA scope is the AXIAM *action*. Asking for anything else
	// would mint a ticket for authority other than the one just refused — and
	// would step outside the grants the engine evaluated, deny rules included.
	if len(minter.gotPerms) != 1 {
		t.Fatalf("expected one requested permission, got %d", len(minter.gotPerms))
	}
	if got := minter.gotPerms[0].ResourceID; got != "doc-1" {
		t.Fatalf("expected the refused resource, got %q", got)
	}
	if got := minter.gotPerms[0].ResourceScopes; len(got) != 1 || got[0] != "invoices:approve" {
		t.Fatalf("expected the refused action as the only scope, got %v", got)
	}
	// §20.2 rule 1: the PAT is the challenger's, never the caller's token.
	if string(minter.gotPAT) != "pat-token-value" {
		t.Fatal("the ticket was minted with something other than the configured PAT")
	}
}

func TestUmaChallenge_AnAllowMintsNothing(t *testing.T) {
	minter := &fakeMinter{}
	checker := &fakeChecker{allowed: true}
	rec := &recordingHandler{}
	h := RequireAccess(checker, "invoices:read", ResourceFromPath("id"),
		WithUmaChallenge(testChallenger(minter)))(rec.handler())

	w := httptest.NewRecorder()
	h.ServeHTTP(w, reqWithUser(testUser()))

	if !rec.called || w.Code != http.StatusOK {
		t.Fatalf("expected the allowed request through, got %d", w.Code)
	}
	// Minting on the happy path would put a Protection API call — and a live
	// credential — in front of every authorized request.
	if minter.calls != 0 {
		t.Fatalf("expected no minting on an allow, got %d calls", minter.calls)
	}
	if got := w.Header().Get("WWW-Authenticate"); got != "" {
		t.Fatalf("expected no challenge on an allow, got %q", got)
	}
}

func TestUmaChallenge_MintingFailureStillDeniesWithoutAChallenge(t *testing.T) {
	minter := &fakeMinter{err: errors.New("protection api unavailable")}
	checker := &fakeChecker{allowed: false}
	h := RequireAccess(checker, "invoices:read", ResourceFromPath("id"),
		WithUmaChallenge(testChallenger(minter)))((&recordingHandler{}).handler())

	w := httptest.NewRecorder()
	h.ServeHTTP(w, reqWithUser(testUser()))

	// Failure is not escalation: the caller was going to be refused, and a
	// Protection API outage must not turn that into a 503 — nor, far worse,
	// into an allow.
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected the plain 403, got %d", w.Code)
	}
	if got := w.Header().Get("WWW-Authenticate"); got != "" {
		t.Fatalf("expected no challenge when minting failed, got %q", got)
	}
	if minter.calls != 1 {
		t.Fatalf("expected one attempt, got %d", minter.calls)
	}
}

func TestUmaChallenge_WithoutAChallengerADenialIsThePlain403(t *testing.T) {
	minter := &fakeMinter{}
	checker := &fakeChecker{allowed: false}
	h := RequireAccess(checker, "invoices:read", ResourceFromPath("id"))((&recordingHandler{}).handler())

	w := httptest.NewRecorder()
	h.ServeHTTP(w, reqWithUser(testUser()))

	// Opt-in means opt-in: an application that never asked for UMA semantics
	// gets no Protection API traffic from its guards.
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
	if got := w.Header().Get("WWW-Authenticate"); got != "" {
		t.Fatalf("expected no challenge without a challenger, got %q", got)
	}
	if minter.calls != 0 {
		t.Fatalf("expected no minting, got %d calls", minter.calls)
	}
}

func TestUmaChallenge_ANilChallengerIsIgnored(t *testing.T) {
	// A caller that builds its challenger conditionally should not have to
	// branch at the call site.
	checker := &fakeChecker{allowed: false}
	h := RequireAccess(checker, "invoices:read", ResourceFromPath("id"),
		WithUmaChallenge(nil))((&recordingHandler{}).handler())

	w := httptest.NewRecorder()
	h.ServeHTTP(w, reqWithUser(testUser()))

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
	if got := w.Header().Get("WWW-Authenticate"); got != "" {
		t.Fatalf("expected no challenge, got %q", got)
	}
}

func TestUmaChallenge_OtherOutcomesCarryNoChallenge(t *testing.T) {
	// Only a *resource denial* is answerable with a ticket. An unauthenticated
	// request has no subject to mint for, and a fail-closed 503 is not a
	// decision at all — offering a ticket for either would be inventing an
	// answer the engine never gave.
	minter := &fakeMinter{}
	challenger := WithUmaChallenge(testChallenger(minter))

	unauthenticated := httptest.NewRecorder()
	RequireAccess(&fakeChecker{allowed: false}, "invoices:read", ResourceFromPath("id"),
		challenger)((&recordingHandler{}).handler()).
		ServeHTTP(unauthenticated, reqWithUser(nil))
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", unauthenticated.Code)
	}

	unavailable := httptest.NewRecorder()
	RequireAccess(&fakeChecker{err: errors.New("boom")}, "invoices:read", ResourceFromPath("id"),
		challenger)((&recordingHandler{}).handler()).
		ServeHTTP(unavailable, reqWithUser(testUser()))
	if unavailable.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", unavailable.Code)
	}

	if minter.calls != 0 {
		t.Fatalf("expected no minting outside a resource denial, got %d calls", minter.calls)
	}
	for _, w := range []*httptest.ResponseRecorder{unauthenticated, unavailable} {
		if got := w.Header().Get("WWW-Authenticate"); got != "" {
			t.Fatalf("expected no challenge, got %q", got)
		}
	}
}
