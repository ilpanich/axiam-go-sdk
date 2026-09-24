package axiam

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ssoScopeServer answers a password login that reports a non-organization-level
// principal, and the three federation completions. ssoStatus is the status
// every completion answers with.
func ssoScopeServer(t *testing.T, ssoStatus int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		access := &http.Cookie{Name: "axiam_access", Value: makeAccessTokenWithOrgID(t, "44444444-4444-4444-4444-444444444444"), Path: "/"}
		switch r.URL.Path {
		case loginPath:
			http.SetCookie(w, access)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"user":{"id":"11111111-1111-1111-1111-111111111111","username":"alice","email":"a@example.test","organization_level":false},"session_id":"33333333-3333-3333-3333-333333333333","expires_in":900}`))
		case ssoCompletePath, ssoOAuth2CompletePath, ssoHandoffPath:
			if ssoStatus != http.StatusOK {
				w.WriteHeader(ssoStatus)
				return
			}
			http.SetCookie(w, access)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"user_id":"99999999-8888-7777-6666-555555555555","session_id":"12121212-3434-5656-7878-909090909090","expires_in":900,"redirect_uri":"https://app.example.test/"}`))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
}

var ssoCompletions = []struct {
	name     string
	complete func(*Client) error
}{
	{"SsoComplete", func(c *Client) error {
		_, err := c.SsoComplete(context.Background(), SsoCompleteParams{State: "s", Code: "c"})
		return err
	}},
	{"SsoCompleteOauth2", func(c *Client) error {
		_, err := c.SsoCompleteOauth2(context.Background(), SsoCompleteOauth2Params{State: "s", Code: "c"})
		return err
	}},
	{"SsoCompleteHandoff", func(c *Client) error {
		_, err := c.SsoCompleteHandoff(context.Background(), SsoCompleteHandoffParams{Code: "c"})
		return err
	}},
}

// TestActingTenant_ASsoCompletionResetsAStaleGate is C-12 question 5's
// stale-principal case. A federation sign-in completes a new session, maybe
// as a different principal, and reports no LoginUserInfo. The gate an
// earlier password login set must not survive it: ActingTenant refused the
// old principal client-side, and after the SSO completion it sends the
// header and lets the server decide.
func TestActingTenant_ASsoCompletionResetsAStaleGate(t *testing.T) {
	tenantID := mustUUID(t, "cccccccc-cccc-cccc-cccc-cccccccccccc")
	for _, tc := range ssoCompletions {
		t.Run(tc.name, func(t *testing.T) {
			server := ssoScopeServer(t, http.StatusOK)
			defer server.Close()
			client, err := NewClient(server.URL, "acme", WithOrgID(mustUUID(t, "44444444-4444-4444-4444-444444444444")))
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			if _, err := client.Login(context.Background(), randomPassword(t), randomPassword(t)); err != nil {
				t.Fatalf("Login: %v", err)
			}
			if _, err := client.ActingTenant(tenantID); err == nil {
				t.Fatal("precondition: a non-organization-level login must gate ActingTenant")
			}

			if err := tc.complete(client); err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			if _, err := client.ActingTenant(tenantID); err != nil {
				t.Fatalf("after %s the gate must be unknown, so ActingTenant sends the header; got %v", tc.name, err)
			}
		})
	}
}

// TestActingTenant_AFailedSsoCompletionKeepsTheGate is the twin: a
// completion the server refuses establishes no new session, so the
// principal the gate describes is still the one the cookies belong to.
func TestActingTenant_AFailedSsoCompletionKeepsTheGate(t *testing.T) {
	tenantID := mustUUID(t, "cccccccc-cccc-cccc-cccc-cccccccccccc")
	for _, tc := range ssoCompletions {
		t.Run(tc.name, func(t *testing.T) {
			server := ssoScopeServer(t, http.StatusBadRequest)
			defer server.Close()
			client, err := NewClient(server.URL, "acme", WithOrgID(mustUUID(t, "44444444-4444-4444-4444-444444444444")))
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}
			if _, err := client.Login(context.Background(), randomPassword(t), randomPassword(t)); err != nil {
				t.Fatalf("Login: %v", err)
			}

			if err := tc.complete(client); err == nil {
				t.Fatalf("precondition: %s must fail against a 400", tc.name)
			}
			_, err = client.ActingTenant(tenantID)
			if _, ok := err.(*AuthzError); !ok {
				t.Fatalf("a failed %s must leave the gate as the login set it; got %T: %v", tc.name, err, err)
			}
		})
	}
}
