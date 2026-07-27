package axiam

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestOidcDiscover_FetchesAndDecodes proves the happy path: OidcDiscover
// fetches GET /.well-known/openid-configuration and decodes the document.
func TestOidcDiscover_FetchesAndDecodes(t *testing.T) {
	srv := newOidcTestServer(t)
	client, err := NewClient(srv.URL, "acme")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	got, err := client.OidcDiscover(context.Background())
	if err != nil {
		t.Fatalf("OidcDiscover: %v", err)
	}
	want := discoveryDoc(srv.URL)
	if got.Issuer != want.Issuer || got.TokenEndpoint != want.TokenEndpoint || got.JwksURI != want.JwksURI {
		t.Fatalf("OidcDiscover mismatch: got %+v, want %+v", got, want)
	}
}

// TestOidcDiscover_CachesWithinTTL proves the per-client discovery cache: a
// second call within the TTL performs NO additional HTTP request.
func TestOidcDiscover_CachesWithinTTL(t *testing.T) {
	var hits int32
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		writeJSON(t, w, discoveryDoc(srv.URL))
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()

	client, err := NewClient(srv.URL, "acme")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	if _, err := client.OidcDiscover(context.Background()); err != nil {
		t.Fatalf("first OidcDiscover: %v", err)
	}
	if _, err := client.OidcDiscover(context.Background()); err != nil {
		t.Fatalf("second OidcDiscover: %v", err)
	}

	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("expected exactly 1 discovery HTTP request across two cached calls, got %d", got)
	}
}

// TestOidcDiscover_TTLFloorIsFiveMinutes proves CONTRACT.md §12.3 rule 6: a
// smaller configured TTL is raised to the 5-minute floor.
func TestOidcDiscover_TTLFloorIsFiveMinutes(t *testing.T) {
	client, err := NewClient("https://example.test", "acme", WithOidcDiscoveryTTL(time.Second))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if client.oidc.discoveryTTL != MinOidcDiscoveryTTL {
		t.Fatalf("discoveryTTL = %v, want the floor %v", client.oidc.discoveryTTL, MinOidcDiscoveryTTL)
	}

	// A larger-than-floor configured value is honoured verbatim.
	client2, err := NewClient("https://example.test", "acme", WithOidcDiscoveryTTL(time.Hour))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if client2.oidc.discoveryTTL != time.Hour {
		t.Fatalf("discoveryTTL = %v, want the configured 1h honoured verbatim", client2.oidc.discoveryTTL)
	}
}

// TestOidcDiscover_ConcurrentCallsSingleFlight proves CONTRACT.md §12.3
// rule 6: N concurrent OidcDiscover callers against a cold cache collapse
// into exactly ONE HTTP request, and all receive the same document.
func TestOidcDiscover_ConcurrentCallsSingleFlight(t *testing.T) {
	var hits int32
	var srv *httptest.Server
	release := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		<-release // hold every concurrent caller until they've all arrived
		writeJSON(t, w, discoveryDoc(srv.URL))
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()

	client, err := NewClient(srv.URL, "acme")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	const goroutines = 10
	var wg sync.WaitGroup
	errs := make([]error, goroutines)
	docs := make([]OidcConfiguration, goroutines)
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			doc, err := client.OidcDiscover(context.Background())
			docs[idx], errs[idx] = doc, err
		}(i)
	}

	// Give every goroutine a chance to reach the single-flight gate before
	// releasing the handler.
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: OidcDiscover failed: %v", i, err)
		}
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("expected exactly 1 discovery HTTP request for %d concurrent callers, got %d", goroutines, got)
	}
	for i := 1; i < goroutines; i++ {
		if docs[i].Issuer != docs[0].Issuer || docs[i].TokenEndpoint != docs[0].TokenEndpoint {
			t.Fatalf("goroutine %d received a different document than goroutine 0", i)
		}
	}
}

// TestOidcDiscover_DoesNotRejectIssuerMismatch proves §12 port addendum
// item 8: a discovery document whose issuer differs from the client's base
// URL is NOT rejected.
func TestOidcDiscover_DoesNotRejectIssuerMismatch(t *testing.T) {
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		doc := discoveryDoc(srv.URL)
		doc.Issuer = "https://issuer.behind-a-proxy.example"
		writeJSON(t, w, doc)
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()

	client, err := NewClient(srv.URL, "acme")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	got, err := client.OidcDiscover(context.Background())
	if err != nil {
		t.Fatalf("expected an issuer/base-URL mismatch to be accepted, got error: %v", err)
	}
	if got.Issuer != "https://issuer.behind-a-proxy.example" {
		t.Fatalf("unexpected issuer: %q", got.Issuer)
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		t.Fatalf("encode response: %v", err)
	}
}
