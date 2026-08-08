package axiam

// Token Exchange (RFC 8693) — CONTRACT.md §15.
//
// Most of §15 is a list of things an SDK must NOT helpfully do, so most of
// these tests assert an absence: no defaulted ActorToken, no auto-narrow after
// invalid_scope, no synthesised refresh token, no adoption.

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

const (
	testSubjectToken = "subject-token-value"
	testActorToken   = "actor-token-value"
	testIssuedToken  = "issued-narrow-token"
)

func exchangeBody(overrides map[string]any) map[string]any {
	body := map[string]any{
		"access_token":      testIssuedToken,
		"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
		"token_type":        "Bearer",
		"expires_in":        300,
		"scope":             "orders:read",
	}
	for k, v := range overrides {
		body[k] = v
	}
	return body
}

func newExchangeClient(t *testing.T, srv *oidcTestServer, withSecret bool) *Client {
	t.Helper()
	opts := []Option{WithOidcClientID("api-gateway")}
	if withSecret {
		opts = append(opts, WithOidcClientSecret("gateway-secret"))
	}
	client, err := NewClient(srv.URL, "acme", opts...)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return client
}

// ---------------------------------------------------------------------------
// §15.1 wire shape
// ---------------------------------------------------------------------------

func TestTokenExchangeSendsTheRFC8693GrantAndAuthenticates(t *testing.T) {
	srv := newOidcTestServer(t)
	var form url.Values
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		form = r.PostForm
		writeStatusJSON(w, http.StatusOK, exchangeBody(nil))
	}

	result, err := newExchangeClient(t, srv, true).TokenExchange(context.Background(), TokenExchangeParams{
		SubjectToken: Sensitive(testSubjectToken),
		Scopes:       []string{"orders:read", "orders:write"},
		Audience:     "orders-service",
		TenantID:     testTenantUUID,
	})
	if err != nil {
		t.Fatalf("TokenExchange: %v", err)
	}

	if got := form.Get("grant_type"); got != "urn:ietf:params:oauth:grant-type:token-exchange" {
		t.Errorf("grant_type: got %q", got)
	}
	if got := form.Get("subject_token"); got != testSubjectToken {
		t.Errorf("subject_token: got %q", got)
	}
	if got := form.Get("subject_token_type"); got != "urn:ietf:params:oauth:token-type:access_token" {
		t.Errorf("subject_token_type: got %q", got)
	}
	if got := form.Get("scope"); got != "orders:read orders:write" {
		t.Errorf("scope: got %q", got)
	}
	if got := form.Get("audience"); got != "orders-service" {
		t.Errorf("audience: got %q", got)
	}
	if got := form.Get("client_secret"); got != "gateway-secret" {
		t.Error("§15.1: the exchanging client is confidential and authenticates")
	}

	if result.AccessToken.expose() != testIssuedToken {
		t.Error("issued token not returned")
	}
	if result.IssuedTokenType != "urn:ietf:params:oauth:token-type:access_token" {
		t.Error("§15.2 rule 6: issued_token_type is surfaced, not dropped")
	}
}

func TestTokenExchangeFailsClientSideForAPublicClient(t *testing.T) {
	srv := newOidcTestServer(t)
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		t.Error("a public client must fail before any wire call")
	}

	_, err := newExchangeClient(t, srv, false).TokenExchange(context.Background(), TokenExchangeParams{
		SubjectToken: Sensitive(testSubjectToken),
		TenantID:     testTenantUUID,
	})
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("want *AuthError, got %T: %v", err, err)
	}
	if srv.TokenCalls() != 0 {
		t.Error("no request should have been sent")
	}
}

// ---------------------------------------------------------------------------
// §15.2 rule 1 — delegation vs impersonation
// ---------------------------------------------------------------------------

func TestAbsentActorTokenIsNeverDefaulted(t *testing.T) {
	srv := newOidcTestServer(t)
	var form url.Values
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		form = r.PostForm
		writeStatusJSON(w, http.StatusOK, exchangeBody(nil))
	}

	_, err := newExchangeClient(t, srv, true).TokenExchange(context.Background(), TokenExchangeParams{
		SubjectToken: Sensitive(testSubjectToken),
		TenantID:     testTenantUUID,
	})
	if err != nil {
		t.Fatalf("TokenExchange: %v", err)
	}

	// §15.2 rule 1: leaving ActorToken zero asks for IMPERSONATION. An SDK
	// that helpfully substituted its own session token would silently turn
	// that into a delegation — a different operation with different risk.
	if form.Has("actor_token") {
		t.Error("actor_token must be absent when the caller did not supply one")
	}
	if form.Has("actor_token_type") {
		t.Error("actor_token_type must not be sent without actor_token")
	}
}

func TestActorTokenAndTypeAreSentAsAPair(t *testing.T) {
	srv := newOidcTestServer(t)
	var form url.Values
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		form = r.PostForm
		writeStatusJSON(w, http.StatusOK, exchangeBody(nil))
	}

	_, err := newExchangeClient(t, srv, true).TokenExchange(context.Background(), TokenExchangeParams{
		SubjectToken: Sensitive(testSubjectToken),
		ActorToken:   Sensitive(testActorToken),
		TenantID:     testTenantUUID,
	})
	if err != nil {
		t.Fatalf("TokenExchange: %v", err)
	}
	if got := form.Get("actor_token"); got != testActorToken {
		t.Errorf("actor_token: got %q", got)
	}
	// RFC 8693 §2.1 requires the pair; the type alone is a malformed request.
	if got := form.Get("actor_token_type"); got != "urn:ietf:params:oauth:token-type:access_token" {
		t.Errorf("actor_token_type: got %q", got)
	}
}

// ---------------------------------------------------------------------------
// §15.2 rules 2-3 and §15.3 — refusals surface unchanged
// ---------------------------------------------------------------------------

func TestExchangeErrorCodesReachTheCallerUnchanged(t *testing.T) {
	// Including cross-tenant, which the server deliberately collapses into
	// invalid_grant — the SDK must not re-derive the distinction it withheld
	// (that is a tenant-enumeration signal).
	for _, code := range []string{
		"invalid_request", "invalid_grant", "invalid_scope",
		"invalid_target", "unauthorized_client", "invalid_client",
	} {
		t.Run(code, func(t *testing.T) {
			srv := newOidcTestServer(t)
			status := http.StatusBadRequest
			if code == "invalid_client" {
				status = http.StatusUnauthorized
			}
			srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
				writeStatusJSON(w, status, oauthErrorBody(code))
			}

			_, err := newExchangeClient(t, srv, true).TokenExchange(context.Background(), TokenExchangeParams{
				SubjectToken: Sensitive(testSubjectToken),
				Scopes:       []string{"orders:read", "orders:admin"},
				TenantID:     testTenantUUID,
			})
			var protocolErr *OAuthProtocolError
			if !errors.As(err, &protocolErr) {
				t.Fatalf("want *OAuthProtocolError, got %T: %v", err, err)
			}
			if protocolErr.ErrorCode != code {
				t.Errorf("ErrorCode: got %q, want %q", protocolErr.ErrorCode, code)
			}
			// §15.2 rules 2-3: no retry, no downgrade, no auto-narrowing. The
			// server refuses rather than silently narrowing precisely so the
			// caller finds out HERE.
			if srv.TokenCalls() != 1 {
				t.Errorf("exactly one request expected, got %d", srv.TokenCalls())
			}
		})
	}
}

// ---------------------------------------------------------------------------
// §15.2 rules 4-7 — what the result is, and is not
// ---------------------------------------------------------------------------

func TestExchangeDoesNotSurfaceAServerSentRefreshToken(t *testing.T) {
	// Deliberately hostile fixture: RFC 8693 issues no refresh token, so the
	// type has no field for one and there is nothing to synthesise.
	srv := newOidcTestServer(t)
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		writeStatusJSON(w, http.StatusOK, exchangeBody(map[string]any{"refresh_token": "should-not-exist"}))
	}

	result, err := newExchangeClient(t, srv, true).TokenExchange(context.Background(), TokenExchangeParams{
		SubjectToken: Sensitive(testSubjectToken),
		TenantID:     testTenantUUID,
	})
	if err != nil {
		t.Fatalf("TokenExchange: %v", err)
	}
	if strings.Contains(result.AccessToken.expose(), "should-not-exist") {
		t.Error("a refresh token must not leak into the access token")
	}
}

func TestExchangeReportsTheGrantedScope(t *testing.T) {
	srv := newOidcTestServer(t)
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		writeStatusJSON(w, http.StatusOK, exchangeBody(map[string]any{"scope": "orders:read"}))
	}

	result, err := newExchangeClient(t, srv, true).TokenExchange(context.Background(), TokenExchangeParams{
		SubjectToken: Sensitive(testSubjectToken),
		Scopes:       []string{"orders:read", "orders:write"},
		TenantID:     testTenantUUID,
	})
	if err != nil {
		t.Fatalf("TokenExchange: %v", err)
	}
	// §15.2 rule 7: the response scope is the GRANTED set and may be narrower
	// than requested even on success.
	if result.Scope != "orders:read" {
		t.Errorf("Scope: got %q, want the granted (narrower) set", result.Scope)
	}
}

func TestExchangeNeverAdoptsTheIssuedToken(t *testing.T) {
	srv := newOidcTestServer(t)
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		writeStatusJSON(w, http.StatusOK, exchangeBody(nil))
	}

	client := newExchangeClient(t, srv, true)
	if _, err := client.TokenExchange(context.Background(), TokenExchangeParams{
		SubjectToken: Sensitive(testSubjectToken),
		TenantID:     testTenantUUID,
	}); err != nil {
		t.Fatalf("TokenExchange: %v", err)
	}

	// §15.2 rule 5: a MUST NOT, with no opt-in flag — unlike
	// LoginClientCredentials and DeviceLogin, where adoption is a MAY.
	// Adopting a narrowed, short-lived token would re-privilege every later
	// call this client makes, and most would then fail far from here.
	if client.adoptedOidcCredential() != "" {
		t.Error("the exchanged token must never become this client's credential")
	}
}

func TestExchangedTokenIsRedacted(t *testing.T) {
	srv := newOidcTestServer(t)
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		writeStatusJSON(w, http.StatusOK, exchangeBody(nil))
	}

	result, err := newExchangeClient(t, srv, true).TokenExchange(context.Background(), TokenExchangeParams{
		SubjectToken: Sensitive(testSubjectToken),
		TenantID:     testTenantUUID,
	})
	if err != nil {
		t.Fatalf("TokenExchange: %v", err)
	}
	if strings.Contains(result.AccessToken.String(), testIssuedToken) {
		t.Error("§15.5: the issued token is a bearer credential and must not render")
	}
}

func TestAFailedExchangeNeverEchoesTheSubjectToken(t *testing.T) {
	// §15.5 calls this out specifically: an exchange failure is exactly when a
	// naive implementation logs the request body.
	srv := newOidcTestServer(t)
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		writeStatusJSON(w, http.StatusBadRequest, oauthErrorBody("invalid_grant"))
	}

	_, err := newExchangeClient(t, srv, true).TokenExchange(context.Background(), TokenExchangeParams{
		SubjectToken: Sensitive(testSubjectToken),
		ActorToken:   Sensitive(testActorToken),
		TenantID:     testTenantUUID,
	})
	if err == nil {
		t.Fatal("want an error")
	}
	if strings.Contains(err.Error(), testSubjectToken) || strings.Contains(err.Error(), testActorToken) {
		t.Errorf("error text leaked token material: %q", err.Error())
	}
}
