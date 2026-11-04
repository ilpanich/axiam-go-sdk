package axiam

// Contract 1.66 — CONTRACT.md §12.1 rule 12b (#837): a federated sign-in is
// completed through the cookie jar that started it. This is the confirming
// test the rule asks of every SDK; it found no §4 defect, so no SDK code
// changed.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// fedBindValue is a 43-character binding value (32 bytes, base64url, no
// padding), the shape the server issues.
const fedBindValue = "Zm9vYmFyYmF6cXV4cXV1eGNvcmdlZ3JhdWx0Z2FycGx"

// TestSsoComplete_PresentsTheFederatedBindingCookieOfItsOwnStart proves the
// `axiam_fed_bind` cookie an SsoStart response sets is presented on the
// following SsoComplete from the same Client, and absent from a second,
// separate Client's SsoComplete (§12.1 rule 12b, §4).
func TestSsoComplete_PresentsTheFederatedBindingCookieOfItsOwnStart(t *testing.T) {
	if len(fedBindValue) != 43 {
		t.Fatalf("fixture must be 43 characters, got %d", len(fedBindValue))
	}
	srv := newOidcTestServer(t)
	token := makeAccessTokenWithOrgID(t, "33333333-3333-3333-3333-333333333333")

	srv.SsoStartHandler = func(w http.ResponseWriter, r *http.Request) {
		// Plain-http mock: the server's cookie_secure is off, so the name is
		// axiam_fed_bind and there is no Secure attribute.
		w.Header().Add("Set-Cookie", "axiam_fed_bind="+fedBindValue+"; Path=/; HttpOnly; SameSite=Strict")
		writeJSON(t, w, map[string]any{"authorize_url": "https://idp.example/authorize", "state": "federation-state", "expires_in_secs": 600})
	}

	var mu sync.Mutex
	var completeCookies []string
	srv.SsoCompleteHandler = func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		completeCookies = append(completeCookies, r.Header.Get("Cookie"))
		mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "axiam_access", Value: token, Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: "axiam_refresh", Value: "refresh-tok", Path: "/"})
		writeJSON(t, w, map[string]any{
			"user_id":      "44444444-4444-4444-4444-444444444444",
			"session_id":   "55555555-5555-5555-5555-555555555555",
			"expires_in":   900,
			"redirect_uri": "https://app.test/dashboard",
		})
	}

	client, err := NewClient(srv.URL, "acme", WithOrgSlug("acme-org"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	start, err := client.SsoStart(context.Background(), SsoStartParams{FederationConfigID: "f", RedirectURI: "https://app.test/cb"})
	if err != nil {
		t.Fatalf("SsoStart: %v", err)
	}
	if _, err := client.SsoComplete(context.Background(), SsoCompleteParams{State: start.State, Code: "upstream-code"}); err != nil {
		t.Fatalf("SsoComplete: %v", err)
	}

	other, err := NewClient(srv.URL, "acme", WithOrgSlug("acme-org"))
	if err != nil {
		t.Fatalf("NewClient (second): %v", err)
	}
	if _, err := other.SsoComplete(context.Background(), SsoCompleteParams{State: start.State, Code: "upstream-code"}); err != nil {
		t.Fatalf("SsoComplete (second client): %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(completeCookies) != 2 {
		t.Fatalf("expected two SsoComplete requests, got %d", len(completeCookies))
	}
	if !strings.Contains(completeCookies[0], "axiam_fed_bind="+fedBindValue) {
		t.Fatalf("SsoComplete from the starting client must present axiam_fed_bind; Cookie header had %d bytes and no binding", len(completeCookies[0]))
	}
	if strings.Contains(completeCookies[1], "axiam_fed_bind") {
		t.Fatal("SsoComplete from a second client must not present the first client's axiam_fed_bind")
	}
}
