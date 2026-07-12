package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestProtectedHandler_NoUser proves the handler fails closed: without an
// authenticated user in context (i.e. reached without the middleware), it
// returns 500 rather than serving content.
func TestProtectedHandler_NoUser(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rec := httptest.NewRecorder()
	protectedHandler(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 without an authenticated user, got %d", rec.Code)
	}
}

func TestGetenv(t *testing.T) {
	t.Setenv("AXIAM_TEST_MW_KEY", "from-env")
	if got := getenv("AXIAM_TEST_MW_KEY", "fallback"); got != "from-env" {
		t.Fatalf("expected the env value, got %q", got)
	}
	if got := getenv("AXIAM_TEST_MW_UNSET_KEY", "fallback"); got != "fallback" {
		t.Fatalf("expected the fallback, got %q", got)
	}
}
