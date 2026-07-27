package axiam

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestWithOidcClockSkew_Clamped proves construction-time clamping of the
// configured clock skew (CONTRACT.md §12.4 rule 5).
func TestWithOidcClockSkew_Clamped(t *testing.T) {
	client, err := NewClient("https://example.test", "acme", WithOidcClockSkew(3600))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if client.oidc.clockSkewSec != MaxIDTokenClockSkewSec {
		t.Fatalf("clockSkewSec = %d, want the clamped %d", client.oidc.clockSkewSec, MaxIDTokenClockSkewSec)
	}

	client2, err := NewClient("https://example.test", "acme", WithOidcClockSkew(30))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if client2.oidc.clockSkewSec != 30 {
		t.Fatalf("clockSkewSec = %d, want the configured 30", client2.oidc.clockSkewSec)
	}
}

// TestOidcExchange_UsesPreFetchedConfiguration proves resolveOidcConfiguration
// skips the discovery wire call when a Configuration is supplied.
func TestOidcExchange_UsesPreFetchedConfiguration(t *testing.T) {
	srv := newOidcTestServer(t)
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, map[string]any{"access_token": "tok", "token_type": "Bearer", "expires_in": 900})
	}
	client, err := NewClient(srv.URL, "acme", WithOidcClientID(testClientID))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	configuration := discoveryDoc(srv.URL)

	if _, err := client.OidcExchange(context.Background(), OidcExchangeParams{
		Code: "c", CodeVerifier: Sensitive("v"), RedirectURI: "https://app.test/cb", Nonce: "n",
		TenantID: testTenantID, Configuration: &configuration,
	}); err != nil {
		t.Fatalf("OidcExchange: %v", err)
	}
}

// TestOidcJWKSVerifier_ReusesCachedVerifierPerJwksURI exercises the
// cache-hit path of oidcJWKSVerifier: two exchanges against the same
// jwks_uri must not construct a second verifier.
func TestOidcJWKSVerifier_ReusesCachedVerifierPerJwksURI(t *testing.T) {
	client, err := NewClient("https://example.test", "acme")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	srv := newOidcTestServer(t)

	v1, err := client.oidcJWKSVerifier(context.Background(), srv.URL+"/oauth2/jwks")
	if err != nil {
		t.Fatalf("oidcJWKSVerifier: %v", err)
	}
	v2, err := client.oidcJWKSVerifier(context.Background(), srv.URL+"/oauth2/jwks")
	if err != nil {
		t.Fatalf("oidcJWKSVerifier: %v", err)
	}
	if v1 != v2 {
		t.Fatal("expected the second call for the same jwks_uri to reuse the cached verifier")
	}
}

// TestSsoStart_DefaultsOrgFromResolvedLogin proves the fallback path: when
// neither WithOrgID/WithOrgSlug nor an explicit argument is given, a
// previously resolved org (from a successful Login) is used.
func TestSsoStart_DefaultsOrgFromResolvedLogin(t *testing.T) {
	const orgID = "66666666-6666-6666-6666-666666666666"
	token := makeAccessTokenWithOrgID(t, orgID)

	var capturedBody map[string]string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/auth/login", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "axiam_access", Value: token, Path: "/"})
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"session_id": "33333333-3333-3333-3333-333333333333", "expires_in": 900})
	})
	mux.HandleFunc("/api/v1/auth/federation/oidc/start", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&capturedBody)
		writeJSON(t, w, map[string]any{"authorize_url": "https://idp.example/x", "state": "s", "expires_in_secs": 600})
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

	if _, err := client.SsoStart(context.Background(), SsoStartParams{FederationConfigID: "f", RedirectURI: "https://app.test/cb"}); err != nil {
		t.Fatalf("SsoStart: %v", err)
	}
	if capturedBody["org_id"] != orgID {
		t.Fatalf("expected org_id=%s resolved from the prior login, got %v", orgID, capturedBody)
	}
}

// TestSsoStart_NonOKStatusMapsToGenericError proves a non-200 SsoStart
// response is mapped via the generic §2 status mapper.
func TestSsoStart_NonOKStatusMapsToGenericError(t *testing.T) {
	srv := newOidcTestServer(t)
	srv.SsoStartHandler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}
	client, err := NewClient(srv.URL, "acme", WithOrgSlug("acme-org"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.SsoStart(context.Background(), SsoStartParams{FederationConfigID: "f", RedirectURI: "https://app.test/cb"})
	var netErr *NetworkError
	if !errors.As(err, &netErr) {
		t.Fatalf("expected *NetworkError for a 500, got %T: %v", err, err)
	}
}

// TestSsoStart_DecodeErrorIsNetworkError proves a malformed 200 body is a
// deserialization *NetworkError.
func TestSsoStart_DecodeErrorIsNetworkError(t *testing.T) {
	srv := newOidcTestServer(t)
	srv.SsoStartHandler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not json"))
	}
	client, err := NewClient(srv.URL, "acme", WithOrgSlug("acme-org"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.SsoStart(context.Background(), SsoStartParams{FederationConfigID: "f", RedirectURI: "https://app.test/cb"})
	var netErr *NetworkError
	if !errors.As(err, &netErr) {
		t.Fatalf("expected *NetworkError for a malformed body, got %T: %v", err, err)
	}
}

// TestSsoComplete_NonOKStatusMapsToGenericError proves a non-200 SsoComplete
// response is mapped via the generic §2 status mapper.
func TestSsoComplete_NonOKStatusMapsToGenericError(t *testing.T) {
	srv := newOidcTestServer(t)
	srv.SsoCompleteHandler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}
	client, err := NewClient(srv.URL, "acme")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.SsoComplete(context.Background(), SsoCompleteParams{State: "s", Code: "c"})
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("expected *AuthError for a 401, got %T: %v", err, err)
	}
}

// TestSsoComplete_DecodeErrorIsNetworkError proves a malformed 200 body is a
// deserialization *NetworkError.
func TestSsoComplete_DecodeErrorIsNetworkError(t *testing.T) {
	srv := newOidcTestServer(t)
	srv.SsoCompleteHandler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not json"))
	}
	client, err := NewClient(srv.URL, "acme")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.SsoComplete(context.Background(), SsoCompleteParams{State: "s", Code: "c"})
	var netErr *NetworkError
	if !errors.As(err, &netErr) {
		t.Fatalf("expected *NetworkError for a malformed body, got %T: %v", err, err)
	}
}

// TestSsoComplete_NoAccessCookieIsAuthError proves absorbSessionCookies'
// failure (no axiam_access cookie set) surfaces from SsoComplete.
func TestSsoComplete_NoAccessCookieIsAuthError(t *testing.T) {
	srv := newOidcTestServer(t)
	srv.SsoCompleteHandler = func(w http.ResponseWriter, r *http.Request) {
		// 200 but never sets axiam_access.
		writeJSON(t, w, map[string]any{"user_id": "u", "session_id": "s", "expires_in": 900, "redirect_uri": "/x"})
	}
	client, err := NewClient(srv.URL, "acme")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.SsoComplete(context.Background(), SsoCompleteParams{State: "s", Code: "c"})
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("expected *AuthError when no session cookie is set, got %T: %v", err, err)
	}
}

// TestOidcExchange_MalformedIDTokenMapsToInvalidSignature proves
// mapJWKSVerifyError's default branch: a completely unparseable id_token
// (not a JWS at all) still surfaces as a taxonomy AuthError.
func TestOidcExchange_MalformedIDTokenMapsToInvalidSignature(t *testing.T) {
	srv := newOidcTestServer(t)
	err := exchangeWithIDToken(t, srv, "not-a-jws-at-all")
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("expected *AuthError, got %T: %v", err, err)
	}
	if authErr.Reason == "" {
		t.Fatalf("expected a non-empty Reason code, got %+v", authErr)
	}
}

// TestValidateIDToken_AudNeitherStringNorArray proves normalizeAud's nil
// fallback for an aud claim of an unexpected JSON shape.
func TestValidateIDToken_AudNeitherStringNorArray(t *testing.T) {
	claims := map[string]any{
		"iss": "https://issuer.test", "sub": "u", "aud": 12345,
		"exp": 9999999999, "iat": 1, "nonce": "n",
	}
	_, err := validateIDToken(mustMarshal(t, claims), idTokenExpectations{issuer: "https://issuer.test", clientID: "rp-client", nonce: "n", hasNonce: true}, time.Now())
	expectReason(t, err, ReasonInvalidAudience)
}

// TestOidcTokenSet_ScopeAndRefreshOmittedWhenAbsent proves the wire-to-SDK
// mapping leaves Scope/RefreshToken/IDToken at their zero values when the
// server omits them.
func TestOidcTokenSet_ScopeAndRefreshOmittedWhenAbsent(t *testing.T) {
	srv := newOidcTestServer(t)
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, map[string]any{"access_token": "tok", "token_type": "Bearer", "expires_in": 900})
	}
	client, err := NewClient(srv.URL, "acme", WithOidcClientID(testClientID))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	set, err := client.OidcRefresh(context.Background(), OidcRefreshParams{RefreshToken: Sensitive("r"), TenantID: testTenantID})
	if err != nil {
		t.Fatalf("OidcRefresh: %v", err)
	}
	if set.Scope != "" || set.RefreshToken != "" || set.IDToken != "" || set.IDClaims != nil {
		t.Fatalf("expected all optional fields to be zero, got %+v", set)
	}
}
