package axiam

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestSensitive_GoStringRedacts proves the %#v (fmt.GoStringer) path is
// redacted — the leak class Sensitive.GoString exists to close (CR-04).
func TestSensitive_GoStringRedacts(t *testing.T) {
	s := Sensitive("super-secret")
	got := fmt.Sprintf("%#v", s)
	if strings.Contains(got, "super-secret") {
		t.Fatalf("%%#v leaked the sensitive value: %q", got)
	}
	// GoString called directly must also redact.
	if strings.Contains(s.GoString(), "super-secret") {
		t.Fatalf("GoString leaked the sensitive value: %q", s.GoString())
	}
}

func TestErrorStrings(t *testing.T) {
	if got := (&AuthError{Message: "bad creds"}).Error(); got != "authentication failed: bad creds" {
		t.Fatalf("AuthError.Error() = %q", got)
	}
	if got := (&AuthzError{Message: "denied"}).Error(); got != "authorization denied: denied" {
		t.Fatalf("AuthzError.Error() = %q", got)
	}
	if got := (&NetworkError{Message: "timeout"}).Error(); got != "network error: timeout" {
		t.Fatalf("NetworkError.Error() = %q", got)
	}
}

// TestParseAuthzFields_MalformedBodyIsSwallowed proves the best-effort parse
// never surfaces an error: a non-JSON body yields empty action/resource.
func TestParseAuthzFields_MalformedBodyIsSwallowed(t *testing.T) {
	action, resource := parseAuthzFields([]byte("not json at all"))
	if action != "" || resource != "" {
		t.Fatalf("expected empty fields from a malformed body, got %q/%q", action, resource)
	}
}

// TestNewJWKSVerifier_Reexport proves the public re-export constructs a
// verifier bound to {baseURL}/oauth2/jwks. It points at a reachable httptest
// JWKS endpoint (and the context is cancelled on return) so the cache's
// background refresh workers can complete and terminate rather than blocking
// on an unreachable host.
func TestNewJWKSVerifier_Reexport(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	v, err := NewJWKSVerifier(ctx, srv.URL, srv.Client())
	if err != nil {
		t.Fatalf("NewJWKSVerifier: %v", err)
	}
	if v == nil {
		t.Fatal("expected a non-nil verifier")
	}
}
