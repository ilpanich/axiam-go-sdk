package jwks

// CONTRACT.md §10.4 — the optional session-revocation feed, wired into the
// verifier (contract 1.44, AXIAM threats T-39 and T-143).
//
// The feed's own behaviour is asserted in internal/revocation. What is under
// test here is the ONE thing that package cannot see: that attaching a feed
// changes a verification outcome in exactly one direction, and only ever for a
// token that names a session.
//
// Every negative here is paired with its I4 twin — a verifier built as it was
// before 1.44, a token with no session behind it, a feed that cannot be read.
// A guard that started denying requests because an advisory document went
// missing would be a worse failure than the fifteen-minute window §10.2
// records, and these are what rule that out.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ilpanich/axiam-go-sdk/internal/revocation"
)

const (
	revokedSid = "6f3e0a5c-1b2d-4e8f-9a7b-0c1d2e3f4a5b"
	liveSid    = "11111111-2222-3333-4444-555555555555"
)

// revocationServer serves a feed document listing revoked, at the path the
// poller appends to its base URL.
func revocationServer(t *testing.T, revoked ...string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc(revocation.FeedPath, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"alg": "SHA-256", "revoked": revoked})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// verifierFor builds a verifier over a fresh key, and returns it with a signer
// that mints a valid token for sid ("" for a token with no session).
func verifierFor(t *testing.T) (*Verifier, func(sid string) []byte, ValidationOptions) {
	t.Helper()
	priv, pubJWK := generateKey(t, "kid-1")
	srv := newMutableJWKSServer(t, marshalSet(t, pubJWK))
	v, err := NewVerifier(context.Background(), srv.URL, srv.Client())
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	sign := func(sid string) []byte {
		return signEdDSA(t, priv, "kid-1", Claims{
			Subject:   "user-123",
			TenantID:  "tenant-abc",
			OrgID:     "org-xyz",
			Exp:       at(time.Now().Add(time.Hour)),
			SessionID: sid,
		})
	}
	return v, sign, ValidationOptions{Tenant: "tenant-abc"}
}

func feedAt(t *testing.T, srv *httptest.Server) *revocation.Feed {
	t.Helper()
	feed, err := revocation.NewFeed(srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("NewFeed: %v", err)
	}
	return feed
}

// ---------------------------------------------------------------------------
// The claim
// ---------------------------------------------------------------------------

func TestClaims_SidIsParsedWhenPresentAndEmptyWhenAbsent(t *testing.T) {
	v, sign, opts := verifierFor(t)
	ctx := context.Background()

	withSid, err := v.VerifyAccessToken(ctx, sign(liveSid), opts)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	if withSid.SessionID != liveSid {
		t.Fatalf("SessionID = %q, want %q", withSid.SessionID, liveSid)
	}

	// A client-credentials token, an RPT or a token exchange carries none, and
	// that must stay distinguishable from "a session named the empty string".
	withoutSid, err := v.VerifyAccessToken(ctx, sign(""), opts)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	if withoutSid.SessionID != "" {
		t.Fatalf("SessionID = %q, want empty", withoutSid.SessionID)
	}
}

// ---------------------------------------------------------------------------
// What the feed changes
// ---------------------------------------------------------------------------

func TestVerifyAccessToken_RejectsARevokedSession(t *testing.T) {
	v, sign, opts := verifierFor(t)
	v.WithRevocationFeed(feedAt(t, revocationServer(t, revocation.EntryFor(revokedSid))))

	_, err := v.VerifyAccessToken(context.Background(), sign(revokedSid), opts)
	if !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("err = %v, want ErrSessionRevoked", err)
	}
}

// The sentinel is its own: "the session behind this token is gone" is not the
// same report as "this credential was never valid", and a guard that conflated
// them would tell a logged-out user their token had expired.
func TestVerifyAccessToken_ARevokedSessionIsNotReportedAsAnExpiredToken(t *testing.T) {
	v, sign, opts := verifierFor(t)
	v.WithRevocationFeed(feedAt(t, revocationServer(t, revocation.EntryFor(revokedSid))))

	_, err := v.VerifyAccessToken(context.Background(), sign(revokedSid), opts)
	for _, other := range []error{ErrExpired, ErrTenantMismatch, ErrMissingExp} {
		if errors.Is(err, other) {
			t.Fatalf("a revoked session was reported as %v", other)
		}
	}
}

func TestVerifyAccessToken_AdmitsASessionTheFeedDoesNotList(t *testing.T) {
	v, sign, opts := verifierFor(t)
	v.WithRevocationFeed(feedAt(t, revocationServer(t, revocation.EntryFor(revokedSid))))

	if _, err := v.VerifyAccessToken(context.Background(), sign(liveSid), opts); err != nil {
		t.Fatalf("a live session must verify: %v", err)
	}
}

// The feed can only ever turn an accept into a reject. A token that fails
// §10.1 still fails for its own reason, whatever the feed says — so a feed
// listing nothing can never rescue an expired token.
func TestVerifyAccessToken_TheFeedNeverTurnsARejectIntoAnAccept(t *testing.T) {
	priv, pubJWK := generateKey(t, "kid-1")
	srv := newMutableJWKSServer(t, marshalSet(t, pubJWK))
	ctx := context.Background()
	v, err := NewVerifier(ctx, srv.URL, srv.Client())
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	v.WithRevocationFeed(feedAt(t, revocationServer(t)))

	expired := signEdDSA(t, priv, "kid-1", Claims{
		Subject:   "user-123",
		TenantID:  "tenant-abc",
		OrgID:     "org-xyz",
		Exp:       at(time.Now().Add(-time.Hour)),
		SessionID: liveSid,
	})
	if _, err := v.VerifyAccessToken(ctx, expired, ValidationOptions{Tenant: "tenant-abc"}); !errors.Is(err, ErrExpired) {
		t.Fatalf("err = %v, want ErrExpired", err)
	}
}

// ---------------------------------------------------------------------------
// I4 — configured as today, behaves as today
// ---------------------------------------------------------------------------

// The default. A verifier built as it was before contract 1.44 accepts exactly
// what it accepted then, including a token whose session a feed WOULD have
// listed — which is the §10.2 posture this narrows rather than replaces.
func TestVerifyAccessToken_NoFeedAttachedIsUnchangedBehaviour(t *testing.T) {
	v, sign, opts := verifierFor(t)

	if _, err := v.VerifyAccessToken(context.Background(), sign(revokedSid), opts); err != nil {
		t.Fatalf("a verifier with no feed must behave as before 1.44: %v", err)
	}
}

// A token with no session behind it is never matched against the feed, even
// when the document happens to list the hash of the empty string. Hashing
// "jti" instead would match nothing while looking like it worked.
func TestVerifyAccessToken_ATokenWithNoSessionIsNeverMatched(t *testing.T) {
	v, sign, opts := verifierFor(t)
	v.WithRevocationFeed(feedAt(t, revocationServer(t, revocation.EntryFor(""))))

	if _, err := v.VerifyAccessToken(context.Background(), sign(""), opts); err != nil {
		t.Fatalf("a token with no sid must verify: %v", err)
	}
}

// §10.4 rule 3 at the verifier, not just at the poller: an unreachable feed
// denies nothing. This is the assertion that keeps the feature safe to turn on
// — the alternative is a guard that stops serving when an advisory document
// goes missing.
func TestVerifyAccessToken_AnUnreachableFeedDeniesNothing(t *testing.T) {
	v, sign, opts := verifierFor(t)
	dead := revocationServer(t, revocation.EntryFor(revokedSid))
	v.WithRevocationFeed(feedAt(t, dead))
	dead.Close()

	if _, err := v.VerifyAccessToken(context.Background(), sign(revokedSid), opts); err != nil {
		t.Fatalf("an unreachable feed must deny nothing: %v", err)
	}
}
