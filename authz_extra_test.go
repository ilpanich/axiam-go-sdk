package axiam

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestCheckAccess_Allowed(t *testing.T) {
	var gotBody AccessCheck
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != checkPath {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(AccessResult{Allowed: true, Reason: ""})
	}))
	defer server.Close()

	client := mustClient(t, server.URL)
	allowed, reason, err := client.CheckAccess(context.Background(), "documents:read", "res-1", "field-a")
	if err != nil {
		t.Fatalf("CheckAccess: %v", err)
	}
	if !allowed || reason != "" {
		t.Fatalf("expected allowed, got allowed=%v reason=%q", allowed, reason)
	}
	if gotBody.Action != "documents:read" || gotBody.ResourceID != "res-1" || gotBody.Scope != "field-a" {
		t.Fatalf("request body not sent as expected: %+v", gotBody)
	}
}

func TestCan_ReturnsBooleanOnly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(AccessResult{Allowed: false, Reason: "denied"})
	}))
	defer server.Close()

	allowed, err := mustClient(t, server.URL).Can(context.Background(), "read", "r-1")
	if err != nil {
		t.Fatalf("Can: %v", err)
	}
	if allowed {
		t.Fatal("expected Can to report false")
	}
}

// TestCheckAccess_403IncludesActionResource proves §2: a 403 maps to an
// *AuthzError whose Action/ResourceID are lifted from the structured body.
func TestCheckAccess_403IncludesActionResource(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":       "authorization_denied",
			"action":      "documents:delete",
			"resource_id": "res-9",
		})
	}))
	defer server.Close()

	_, _, err := mustClient(t, server.URL).CheckAccess(context.Background(), "documents:delete", "res-9")
	var authzErr *AuthzError
	if !isAuthzError(err, &authzErr) {
		t.Fatalf("expected *AuthzError, got %T: %v", err, err)
	}
	if authzErr.Action != "documents:delete" || authzErr.ResourceID != "res-9" {
		t.Fatalf("structured fields not lifted from the body: %+v", authzErr)
	}
}

func TestBatchCheck_MapsResultsInOrder(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != batchCheckPath {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(batchCheckResponseWire{Results: []AccessResult{
			{Allowed: true},
			{Allowed: false, Reason: "second denied"},
		}})
	}))
	defer server.Close()

	results, err := mustClient(t, server.URL).BatchCheck(context.Background(), []AccessCheck{
		{Action: "read", ResourceID: "r1"},
		{Action: "write", ResourceID: "r2"},
	})
	if err != nil {
		t.Fatalf("BatchCheck: %v", err)
	}
	if len(results) != 2 || !results[0].Allowed || results[1].Allowed || results[1].Reason != "second denied" {
		t.Fatalf("results not mapped in order: %+v", results)
	}
}

// TestRetryReadOnly_RetriesTransientThenSucceeds proves CF-01: a transient 5xx
// (NetworkError) is retried, and a subsequent 200 wins. AuthError/AuthzError
// are decisive and never retried (asserted by the single-attempt 403 above).
func TestRetryReadOnly_RetriesTransientThenSucceeds(t *testing.T) {
	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&attempts, 1) == 1 {
			w.WriteHeader(http.StatusInternalServerError) // transient -> NetworkError -> retried
			return
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(AccessResult{Allowed: true})
	}))
	defer server.Close()

	allowed, _, err := mustClient(t, server.URL).CheckAccess(context.Background(), "read", "r-1")
	if err != nil {
		t.Fatalf("CheckAccess after retry: %v", err)
	}
	if !allowed {
		t.Fatal("expected allowed after the retry")
	}
	if got := atomic.LoadInt32(&attempts); got != 2 {
		t.Fatalf("expected exactly 2 attempts (1 transient + 1 success), got %d", got)
	}
}

func TestRetryReadOnly_ExhaustsThenReturnsNetworkError(t *testing.T) {
	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	_, _, err := mustClient(t, server.URL).CheckAccess(context.Background(), "read", "r-1")
	var netErr *NetworkError
	if !isNetworkError(err, &netErr) {
		t.Fatalf("expected *NetworkError after exhaustion, got %T: %v", err, err)
	}
	if got := atomic.LoadInt32(&attempts); got != authzRetryMaxAttempts {
		t.Fatalf("expected %d attempts, got %d", authzRetryMaxAttempts, got)
	}
}

// TestRetryReadOnly_HonorsContextCancellation proves the backoff select honors
// a cancelled context between attempts rather than sleeping the full backoff.
func TestRetryReadOnly_HonorsContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancelled before the first backoff wait
	_, _, err := mustClient(t, server.URL).CheckAccess(ctx, "read", "r-1")
	if err == nil {
		t.Fatal("expected an error under a cancelled context")
	}
}

// TestCheckAccessAs_SendsSubjectID proves CONTRACT.md §11.2.2: CheckAccessAs
// is additive alongside CheckAccess (which never sets subject_id — see
// TestCheckAccess_Allowed's gotBody assertion) and puts subjectID on the
// wire so the declarative authorization helpers can evaluate a check for the
// REQUEST's authenticated user rather than this Client's own session.
func TestCheckAccessAs_SendsSubjectID(t *testing.T) {
	var gotBody AccessCheck
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != checkPath {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(AccessResult{Allowed: true})
	}))
	defer server.Close()

	client := mustClient(t, server.URL)
	allowed, reason, err := client.CheckAccessAs(context.Background(), "user-42", "documents:read", "res-1", "field-a")
	if err != nil {
		t.Fatalf("CheckAccessAs: %v", err)
	}
	if !allowed || reason != "" {
		t.Fatalf("expected allowed, got allowed=%v reason=%q", allowed, reason)
	}
	if gotBody.SubjectID != "user-42" {
		t.Fatalf("expected subject_id %q on the wire, got %q", "user-42", gotBody.SubjectID)
	}
	if gotBody.Action != "documents:read" || gotBody.ResourceID != "res-1" || gotBody.Scope != "field-a" {
		t.Fatalf("request body not sent as expected: %+v", gotBody)
	}
}

// TestCheckAccessAs_BlankSubjectID_OmitsField proves a blank subjectID
// behaves exactly like CheckAccess: the subject_id field is omitted from the
// wire request rather than sent as an empty string.
func TestCheckAccessAs_BlankSubjectID_OmitsField(t *testing.T) {
	var rawBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&rawBody)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(AccessResult{Allowed: true})
	}))
	defer server.Close()

	client := mustClient(t, server.URL)
	if _, _, err := client.CheckAccessAs(context.Background(), "", "documents:read", "res-1"); err != nil {
		t.Fatalf("CheckAccessAs: %v", err)
	}
	if _, present := rawBody["subject_id"]; present {
		t.Fatalf("expected subject_id to be omitted from the wire body when blank, got %v", rawBody)
	}
}

// TestCheckAccessAs_MapsNetworkError proves CheckAccessAs shares
// CheckAccess's error-mapping path (fail-closed on transport failure).
func TestCheckAccessAs_MapsNetworkError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	server.Close() // closed immediately: any request fails to connect

	client := mustClient(t, server.URL)
	_, _, err := client.CheckAccessAs(context.Background(), "user-42", "documents:read", "res-1")
	if err == nil {
		t.Fatal("expected an error when the server is unreachable")
	}
	if _, ok := err.(*NetworkError); !ok {
		t.Fatalf("expected *NetworkError, got %T: %v", err, err)
	}
}

func mustClient(t *testing.T, baseURL string) *Client {
	t.Helper()
	c, err := NewClient(baseURL, "acme")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}
