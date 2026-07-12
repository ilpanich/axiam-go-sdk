package middleware

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ilpanich/axiam-go-sdk/internal/jwks"
)

// stubVerifier is a hermetic jwksVerifier that returns canned claims/error, so
// the middleware's option plumbing and CSRF gate can be exercised without a
// live JWKS server or a signed token.
type stubVerifier struct {
	claims jwks.Claims
	err    error
}

func (s stubVerifier) Verify(context.Context, []byte) (jwks.Claims, error) { return s.claims, s.err }

func nopHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
}

// TestWithLogger_LogsRejections proves WithLogger wires the optional logger and
// writeError emits a redaction-safe line (no token) on a rejection.
func TestWithLogger_LogsRejections(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	mw := Middleware(stubVerifier{}, "tenant-abc", WithLogger(logger))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil) // no credentials -> 401
	mw(nopHandler()).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	if !strings.Contains(buf.String(), "axiam middleware rejected request") {
		t.Fatalf("expected the logger to record the rejection, got %q", buf.String())
	}
	if !strings.Contains(buf.String(), "status=401") {
		t.Fatalf("expected the status to be logged, got %q", buf.String())
	}
}

// TestCsrf_CookieSourcedStateChanging covers the cookie double-submit gate's
// failure branches: a state-changing cookie-sourced request with no CSRF
// cookie, and one with a length-mismatched header/cookie pair, are both 403 —
// and the verifier is never consulted (the gate runs first).
func TestCsrf_CookieSourcedStateChanging(t *testing.T) {
	// A verifier that would panic proves the CSRF gate short-circuits before
	// any verification is attempted.
	panicVerifier := stubVerifierFunc(func() (jwks.Claims, error) {
		t.Fatal("verifier must not be called when the CSRF gate rejects")
		return jwks.Claims{}, nil
	})
	mw := Middleware(panicVerifier, "tenant-abc")

	t.Run("header present but no csrf cookie -> 403", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.AddCookie(&http.Cookie{Name: "axiam_access", Value: "cookie-token"})
		req.Header.Set("X-CSRF-Token", "anything")
		rec := httptest.NewRecorder()
		mw(nopHandler()).ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", rec.Code)
		}
	})

	t.Run("header/cookie length mismatch -> 403", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.AddCookie(&http.Cookie{Name: "axiam_access", Value: "cookie-token"})
		req.AddCookie(&http.Cookie{Name: "axiam_csrf", Value: "short"})
		req.Header.Set("X-CSRF-Token", "a-much-longer-value")
		rec := httptest.NewRecorder()
		mw(nopHandler()).ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403 on length mismatch, got %d", rec.Code)
		}
	})
}

// TestExtractToken_MalformedAuthorizationHeader covers the non-Bearer header
// branch: a Basic (or empty-Bearer) Authorization header is rejected as
// missing credentials, never treated as a token.
func TestExtractToken_MalformedAuthorizationHeader(t *testing.T) {
	mw := Middleware(stubVerifier{}, "tenant-abc")
	for _, h := range []string{"Basic dXNlcjpwYXNz", "Bearer   ", "Bearer"} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", h)
		rec := httptest.NewRecorder()
		mw(nopHandler()).ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("Authorization %q: expected 401, got %d", h, rec.Code)
		}
	}
}

// stubVerifierFunc adapts a func into a jwksVerifier.
type stubVerifierFunc func() (jwks.Claims, error)

func (f stubVerifierFunc) Verify(context.Context, []byte) (jwks.Claims, error) { return f() }
