package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/ilpanich/axiam-go-sdk/internal/jwks"
)

// ---------------------------------------------------------------------------
// CONTRACT.md §10.1 rule 8 — "subject of the decision".
//
// Rules 1-7 ask whether the token is good. Rule 8 asks a different question:
// whether it is the token the decision is even ABOUT. SEC-085 satisfied all
// seven and was still an authentication bypass, because the PHP guard routed a
// failed verification into a second, successful one against the application's
// own session — admitting the caller as the app's service account, typically
// more privileged than the user whose request it replaced.
//
// This SDK is structurally safe from that shape: Middleware takes a verifier
// and a configured tenant, never a logged-in client, so no second credential is
// in scope to substitute. These tests pin that property instead of assuming it
// — they are the guardrail §15.3.1 asks for, and they fail if anyone ever
// threads a session or a client into the guard's inputs.
// ---------------------------------------------------------------------------

// recordingVerifier wraps a real verifier and records every token handed to it.
// It is deliberately NOT a stub that always fails: it delegates to the genuine
// verifier, so a fallback to some other credential would actually SUCCEED here.
// That is what makes the assertion below meaningful rather than vacuous.
type recordingVerifier struct {
	inner jwksVerifier
	seen  [][]byte
}

func (r *recordingVerifier) VerifyAccessToken(
	ctx context.Context,
	token []byte,
	opts jwks.ValidationOptions,
) (jwks.Claims, error) {
	r.seen = append(r.seen, append([]byte(nil), token...))
	return r.inner.VerifyAccessToken(ctx, token, opts)
}

func TestContract101_Rule8_GuardDecidesOnTheCallerTokenAndNoOther(t *testing.T) {
	priv, pubJWK := generateTestKey(t, "kid-1")
	jwksSrv := newTestJWKSServer(t, pubJWK)
	real := newTestVerifier(t, jwksSrv)

	// A token that WOULD verify. In the SEC-085 shape this is what the guard
	// reached for after the caller's token failed. If any fallback existed,
	// this is the credential it would have substituted.
	healthyClaims := validClaims()
	healthy := signTestToken(t, priv, "kid-1", healthyClaims)

	// The caller's credential: valid signature, genuinely expired. It fails
	// rule 2 and nothing else, so the ONLY reason to admit it would be a
	// substitution.
	expiredClaims := validClaims()
	expiredClaims.Exp = at(time.Now().Add(-2 * time.Hour))
	expired := signTestToken(t, priv, "kid-1", expiredClaims)

	rv := &recordingVerifier{inner: real}
	mw := Middleware(rv, testConfiguredTenant)

	rec := &recordingHandler{}
	h := mw(rec.handler())
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+expired)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if rec.called {
		t.Fatal("SECURITY: the guard admitted a caller whose token failed verification")
	}
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}

	// The heart of rule 8: exactly one credential was consulted, and it was the
	// caller's. A guard that fell back would show a second entry here.
	if len(rv.seen) != 1 {
		t.Fatalf("the guard consulted %d credentials; rule 8 allows exactly one", len(rv.seen))
	}
	if string(rv.seen[0]) != expired {
		t.Fatal("the guard decided on a credential other than the one the caller presented")
	}
	for _, seen := range rv.seen {
		if string(seen) == healthy {
			t.Fatal("SECURITY: the guard consulted a healthy credential the caller never presented")
		}
	}
}

func TestContract101_Rule8_NoIdentityIsInjectedOnRejection(t *testing.T) {
	// The consequence that made SEC-085 a bypass rather than a mere error: the
	// request continued, carrying an identity the caller had not authenticated
	// as. Rejection must leave the context empty, not merely unauthenticated.
	priv, pubJWK := generateTestKey(t, "kid-1")
	jwksSrv := newTestJWKSServer(t, pubJWK)
	verifier := newTestVerifier(t, jwksSrv)
	mw := Middleware(verifier, testConfiguredTenant)

	claims := validClaims()
	claims.Exp = at(time.Now().Add(-2 * time.Hour))
	expired := signTestToken(t, priv, "kid-1", claims)

	var leaked *User
	var leakedOK bool
	h := mw(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		leaked, leakedOK = UserFromContext(r.Context())
	}))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+expired)
	h.ServeHTTP(httptest.NewRecorder(), req)

	if leakedOK || leaked != nil {
		t.Fatalf("SECURITY: an identity was injected for a rejected caller: %+v", leaked)
	}
}

func TestContract101_Rule8_GuardInputExposesNoSecondCredential(t *testing.T) {
	// The shape of the bug: PHP's guard could reach a stateful session through
	// the client it held. Keep the guard's own dependency surface free of
	// anything like that, so the property above cannot be quietly undone by
	// widening the interface later.
	//
	// jwksVerifier is the entire contract Middleware depends on. One method,
	// taking the token to verify — there is nowhere for a second credential to
	// enter.
	iface := reflect.TypeOf((*jwksVerifier)(nil)).Elem()
	if iface.NumMethod() != 1 {
		t.Fatalf(
			"jwksVerifier gained %d methods; a guard dependency with more than "+
				"VerifyAccessToken can reach a credential the caller never presented",
			iface.NumMethod(),
		)
	}
	if name := iface.Method(0).Name; name != "VerifyAccessToken" {
		t.Fatalf("expected the sole guard dependency to be VerifyAccessToken, got %q", name)
	}

	// And nothing session-shaped may appear on the Middleware signature itself.
	mwType := reflect.TypeOf(Middleware)
	for i := 0; i < mwType.NumIn(); i++ {
		got := mwType.In(i).String()
		for _, forbidden := range []string{"Client", "Session", "TokenManager", "Credentials"} {
			if containsIdent(got, forbidden) {
				t.Fatalf(
					"Middleware parameter %d is %q — a %s in the guard's inputs makes rule 8 violable",
					i, got, forbidden,
				)
			}
		}
	}
}

// containsIdent reports whether needle appears in haystack, used to catch a
// session-shaped type arriving under any package path.
func containsIdent(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// Compile-time proof that recordingVerifier really does satisfy the interface
// Middleware requires — if the signature drifts, this file fails to build
// rather than silently testing a different seam.
var _ jwksVerifier = (*recordingVerifier)(nil)
