package axiam

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestBatchCheck_MalformedBodyIsError covers the BatchCheck -> sendAuthzPost ->
// sendAuthzPostInto decode-error path (a 200 whose body is not valid JSON is a
// NetworkError, which retryReadOnly exhausts before returning).
func TestBatchCheck_MalformedBodyIsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != batchCheckPath {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not json"))
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "acme")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.BatchCheck(context.Background(), []AccessCheck{{Action: "resource:read", ResourceID: "r"}})
	var netErr *NetworkError
	if !isNetworkError(err, &netErr) {
		t.Fatalf("expected *NetworkError on a malformed batch body, got %T: %v", err, err)
	}
}

// TestBatchCheck_ForbiddenPropagates covers the BatchCheck non-retryable error
// path: a 403 maps to AuthzError and is returned without retrying.
func TestBatchCheck_ForbiddenPropagates(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"denied"}`))
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "acme")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.BatchCheck(context.Background(), []AccessCheck{{Action: "resource:read", ResourceID: "r"}})
	var authzErr *AuthzError
	if !isAuthzError(err, &authzErr) {
		t.Fatalf("expected *AuthzError on a 403 batch, got %T: %v", err, err)
	}
	if calls != 1 {
		t.Fatalf("a non-retryable 403 must not be retried; got %d calls", calls)
	}
}
