package axiam

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// brokenDiscoveryServer serves a failing discovery endpoint, so any §12
// operation that must resolve a configuration (and was not given a
// pre-fetched one) fails during resolveOidcConfiguration.
func brokenDiscoveryServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestOidcRefresh_ConfigurationFetchFailure(t *testing.T) {
	srv := brokenDiscoveryServer(t)
	client, err := NewClient(srv.URL, "acme", WithOidcClientID(testClientID))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.OidcRefresh(context.Background(), OidcRefreshParams{RefreshToken: Sensitive("r"), TenantID: testTenantID})
	var netErr *NetworkError
	if !errors.As(err, &netErr) {
		t.Fatalf("expected *NetworkError, got %T: %v", err, err)
	}
}

func TestLoginClientCredentials_ConfigurationFetchFailure(t *testing.T) {
	srv := brokenDiscoveryServer(t)
	client, err := NewClient(srv.URL, "acme", WithOidcClientID(testClientID), WithOidcClientSecret("shh"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.LoginClientCredentials(context.Background(), LoginClientCredentialsParams{TenantID: testTenantID})
	var netErr *NetworkError
	if !errors.As(err, &netErr) {
		t.Fatalf("expected *NetworkError, got %T: %v", err, err)
	}
}

func TestIntrospect_ConfigurationFetchFailure(t *testing.T) {
	srv := brokenDiscoveryServer(t)
	client, err := NewClient(srv.URL, "acme", WithOidcClientID(testClientID), WithOidcClientSecret("shh"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.Introspect(context.Background(), IntrospectParams{Token: Sensitive("t"), TenantID: testTenantID})
	var netErr *NetworkError
	if !errors.As(err, &netErr) {
		t.Fatalf("expected *NetworkError, got %T: %v", err, err)
	}
}

func TestRevoke_ConfigurationFetchFailure(t *testing.T) {
	srv := brokenDiscoveryServer(t)
	client, err := NewClient(srv.URL, "acme", WithOidcClientID(testClientID), WithOidcClientSecret("shh"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	err = client.Revoke(context.Background(), RevokeParams{Token: Sensitive("t"), TenantID: testTenantID})
	var netErr *NetworkError
	if !errors.As(err, &netErr) {
		t.Fatalf("expected *NetworkError, got %T: %v", err, err)
	}
}

// TestOidcExchange_InvalidTenantIDIsRejected proves resolveOidcTenantID's
// UUID-validation branch: a non-UUID explicit TenantID is a client-side
// *AuthError.
func TestOidcExchange_InvalidTenantIDIsRejected(t *testing.T) {
	srv := newOidcTestServer(t)
	client, err := NewClient(srv.URL, "acme", WithOidcClientID(testClientID))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.OidcExchange(context.Background(), OidcExchangeParams{
		Code: "c", CodeVerifier: Sensitive("v"), RedirectURI: "https://app.test/cb", Nonce: "n",
		TenantID: "not-a-uuid",
	})
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("expected *AuthError, got %T: %v", err, err)
	}
	if srv.TokenCalls() != 0 {
		t.Fatalf("expected no wire call for an invalid tenant_id, got %d", srv.TokenCalls())
	}
}

// TestOidcEndpointURL_InvalidEndpoint proves a malformed endpoint URL from a
// (malicious or misconfigured) discovery document is a *NetworkError.
func TestOidcEndpointURL_InvalidEndpoint(t *testing.T) {
	client, err := NewClient("https://example.test", "acme")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.oidcEndpointURL("://not-a-valid-url", testTenantID)
	var netErr *NetworkError
	if !errors.As(err, &netErr) {
		t.Fatalf("expected *NetworkError, got %T: %v", err, err)
	}
}

// TestNewAbsoluteRequest_InvalidURL proves the construction-error branch.
func TestNewAbsoluteRequest_InvalidURL(t *testing.T) {
	client, err := NewClient("https://example.test", "acme")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.newAbsoluteRequest(context.Background(), "GET", "http://example.test/\n", nil)
	if err == nil {
		t.Fatal("expected an error for a URL containing an invalid control character")
	}
	var netErr *NetworkError
	if !errors.As(err, &netErr) {
		t.Fatalf("expected *NetworkError, got %T: %v", err, err)
	}
}

// TestPostOAuth2Form_DecodeError proves a malformed 2xx body surfaces as a
// deserialization *NetworkError.
func TestPostOAuth2Form_DecodeError(t *testing.T) {
	srv := newOidcTestServer(t)
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not json"))
	}
	client, err := NewClient(srv.URL, "acme", WithOidcClientID(testClientID))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.OidcRefresh(context.Background(), OidcRefreshParams{RefreshToken: Sensitive("r"), TenantID: testTenantID})
	var netErr *NetworkError
	if !errors.As(err, &netErr) {
		t.Fatalf("expected *NetworkError, got %T: %v", err, err)
	}
}

// closedServerURL starts and immediately closes an httptest.Server,
// returning its (now-unreachable) loopback URL — a fast, deterministic way
// to force "connection refused" without depending on how a given sandbox's
// network policy handles an arbitrary unassigned port.
func closedServerURL(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()
	return url
}

// Note: an analogous "unreachable jwks_uri" test for verifyIDToken is
// deliberately NOT included here. jwks.NewVerifierForURL (like the
// pre-existing NewVerifier) registers the URL with the lestrrat-go/httprc
// client, whose Register call performs its own internal retry/backoff
// against a genuinely-refusing endpoint rather than failing fast — this is
// pre-existing behavior inherited unchanged from the §10 middleware's
// NewVerifier path (untouched by §12), not something introduced here, and
// is out of this task's scope to change. Exercising it in a unit test would
// make the suite hang rather than prove anything about the §12 code added
// in this PR.

// TestSsoStart_TransportFailureIsNetworkError proves the doRequest failure
// branch (server unreachable).
func TestSsoStart_TransportFailureIsNetworkError(t *testing.T) {
	client, err := NewClient(closedServerURL(t), "acme", WithOrgSlug("acme-org"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.SsoStart(context.Background(), SsoStartParams{FederationConfigID: "f", RedirectURI: "https://app.test/cb"})
	var netErr *NetworkError
	if !errors.As(err, &netErr) {
		t.Fatalf("expected *NetworkError, got %T: %v", err, err)
	}
}

// TestSsoComplete_TransportFailureIsNetworkError proves the doRequest
// failure branch (server unreachable).
func TestSsoComplete_TransportFailureIsNetworkError(t *testing.T) {
	client, err := NewClient(closedServerURL(t), "acme")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.SsoComplete(context.Background(), SsoCompleteParams{State: "s", Code: "c"})
	var netErr *NetworkError
	if !errors.As(err, &netErr) {
		t.Fatalf("expected *NetworkError, got %T: %v", err, err)
	}
}

// TestIntrospectionResultFromWire_AllFieldsPresent exercises every optional
// field of the wire-to-SDK mapping.
func TestIntrospectionResultFromWire_AllFieldsPresent(t *testing.T) {
	sub, clientID, scope, tokenType := "sub-1", "client-1", "openid", "Bearer"
	exp, iat := int64(1000), int64(500)
	wire := introspectionResponseWire{
		Active: true, Sub: &sub, ClientID: &clientID, Scope: &scope, TokenType: &tokenType, Exp: &exp, Iat: &iat,
	}
	got := introspectionResultFromWire(wire)
	want := IntrospectionResult{Active: true, Sub: sub, ClientID: clientID, Scope: scope, TokenType: tokenType, Exp: exp, Iat: iat}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

// TestExtractExtraClaims_NoUnknownClaims proves the nil-when-empty branch:
// a payload with only the seven modeled claims yields a nil Extra map.
func TestExtractExtraClaims_NoUnknownClaims(t *testing.T) {
	payload := mustMarshal(t, map[string]any{
		"iss": "i", "sub": "s", "aud": "a", "exp": 1, "iat": 1, "nbf": 1, "nonce": "n", "azp": "a",
	})
	if got := extractExtraClaims(payload); got != nil {
		t.Fatalf("expected nil Extra when only modeled claims are present, got %+v", got)
	}
}

// TestExtractExtraClaims_MalformedPayload proves the decode-error branch
// returns nil rather than panicking.
func TestExtractExtraClaims_MalformedPayload(t *testing.T) {
	if got := extractExtraClaims([]byte("not json")); got != nil {
		t.Fatalf("expected nil for a malformed payload, got %+v", got)
	}
}

// TestNormalizeAud_Empty proves the empty-input branch.
func TestNormalizeAud_Empty(t *testing.T) {
	if got := normalizeAud(nil); got != nil {
		t.Fatalf("expected nil for empty input, got %v", got)
	}
}

// TestResolveOidcTenantID_ResolvedFromPriorLogin proves the fallback
// branch: no explicit TenantID, but a prior Login resolved one.
func TestResolveOidcTenantID_ResolvedFromPriorLogin(t *testing.T) {
	token := makeAccessTokenWithOrgID(t, "44444444-4444-4444-4444-444444444444")
	// makeAccessTokenWithOrgID hardcodes tenant_id to a fixed UUID; read it
	// back out rather than assuming it matches the local `tenantID` const.
	claims, err := decodeUnverifiedClaims(token)
	if err != nil {
		t.Fatalf("decodeUnverifiedClaims: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/auth/login", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "axiam_access", Value: token, Path: "/"})
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"session_id": "33333333-3333-3333-3333-333333333333", "expires_in": 900})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client, err := NewClient(srv.URL, "acme")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.Login(context.Background(), "alice@example.test", "hunter2"); err != nil {
		t.Fatalf("Login: %v", err)
	}

	got, err := client.resolveOidcTenantID("")
	if err != nil {
		t.Fatalf("resolveOidcTenantID: %v", err)
	}
	if got != claims.TenantID {
		t.Fatalf("resolveOidcTenantID() = %q, want %q (resolved from the login's access token)", got, claims.TenantID)
	}
}
