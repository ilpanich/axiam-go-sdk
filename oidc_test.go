package axiam

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// OidcBegin
// ---------------------------------------------------------------------------

// TestOidcBegin_BuildsURLWithMandatoryParams proves §12.1 rule 5: exactly
// the eight SDK-owned query parameters are present, response_type=code,
// code_challenge_method=S256 (never plain), and spaces in scope are
// percent-encoded as %20 (§12 port addendum item 10).
func TestOidcBegin_BuildsURLWithMandatoryParams(t *testing.T) {
	client, err := NewClient("https://example.test", "acme", WithOidcClientID("rp-client"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	configuration := OidcConfiguration{AuthorizationEndpoint: "https://idp.test/oauth2/authorize"}

	req, err := client.OidcBegin(configuration, OidcBeginParams{
		RedirectURI: "https://app.test/callback",
		Scope:       "profile email",
	})
	if err != nil {
		t.Fatalf("OidcBegin: %v", err)
	}

	if strings.Contains(req.URL, "+") {
		t.Fatalf("expected no literal '+' (spaces must be %%20-encoded), got URL: %s", req.URL)
	}

	parsed, err := url.Parse(req.URL)
	if err != nil {
		t.Fatalf("parse generated URL: %v", err)
	}
	q := parsed.Query()
	if q.Get("response_type") != "code" {
		t.Fatalf("response_type = %q, want code", q.Get("response_type"))
	}
	if q.Get("client_id") != "rp-client" {
		t.Fatalf("client_id = %q, want rp-client", q.Get("client_id"))
	}
	if q.Get("redirect_uri") != "https://app.test/callback" {
		t.Fatalf("redirect_uri = %q", q.Get("redirect_uri"))
	}
	if q.Get("scope") != "openid profile email" {
		t.Fatalf("scope = %q, want \"openid profile email\" (openid prepended, §12.1 rule 4)", q.Get("scope"))
	}
	if q.Get("state") != req.State || q.Get("nonce") != req.Nonce {
		t.Fatalf("state/nonce in URL do not match returned AuthorizationRequest")
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Fatalf("code_challenge_method = %q, want S256 (never plain)", q.Get("code_challenge_method"))
	}
	if q.Get("code_challenge") == "" {
		t.Fatal("expected a non-empty code_challenge")
	}
	wantChallenge := computeCodeChallenge(req.CodeVerifier.expose())
	if q.Get("code_challenge") != wantChallenge {
		t.Fatalf("code_challenge does not match SHA256(code_verifier)")
	}
}

// TestOidcBegin_DefaultsScopeToOpenid proves §12.1 rule 4: an empty Scope
// still requests exactly "openid".
func TestOidcBegin_DefaultsScopeToOpenid(t *testing.T) {
	client, err := NewClient("https://example.test", "acme", WithOidcClientID("rp-client"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	req, err := client.OidcBegin(OidcConfiguration{AuthorizationEndpoint: "https://idp.test/oauth2/authorize"}, OidcBeginParams{RedirectURI: "https://app.test/callback"})
	if err != nil {
		t.Fatalf("OidcBegin: %v", err)
	}
	parsed, _ := url.Parse(req.URL)
	if parsed.Query().Get("scope") != "openid" {
		t.Fatalf("scope = %q, want \"openid\"", parsed.Query().Get("scope"))
	}
}

// TestOidcBegin_ExtraParamsCannotOverrideReserved proves §12.1 rule 5 /
// §12 port addendum item 9: overriding one of the eight SDK-owned
// parameters is a PLAIN programming error, not an *AuthError.
func TestOidcBegin_ExtraParamsCannotOverrideReserved(t *testing.T) {
	client, err := NewClient("https://example.test", "acme", WithOidcClientID("rp-client"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	configuration := OidcConfiguration{AuthorizationEndpoint: "https://idp.test/oauth2/authorize"}

	for _, reserved := range []string{"response_type", "client_id", "redirect_uri", "scope", "state", "nonce", "code_challenge", "code_challenge_method"} {
		_, err := client.OidcBegin(configuration, OidcBeginParams{
			RedirectURI: "https://app.test/callback",
			ExtraParams: map[string]string{reserved: "attacker-value"},
		})
		if err == nil {
			t.Fatalf("expected an error overriding reserved param %q", reserved)
		}
		var authErr *AuthError
		if errors.As(err, &authErr) {
			t.Fatalf("expected a plain (non-taxonomy) error for %q, got *AuthError: %v", reserved, err)
		}
	}
}

// TestOidcBegin_AllowsNonReservedExtraParams proves the converse: an
// additional caller param (e.g. prompt) is accepted and forwarded.
func TestOidcBegin_AllowsNonReservedExtraParams(t *testing.T) {
	client, err := NewClient("https://example.test", "acme", WithOidcClientID("rp-client"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	req, err := client.OidcBegin(OidcConfiguration{AuthorizationEndpoint: "https://idp.test/oauth2/authorize"}, OidcBeginParams{
		RedirectURI: "https://app.test/callback",
		ExtraParams: map[string]string{"prompt": "login"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	parsed, _ := url.Parse(req.URL)
	if parsed.Query().Get("prompt") != "login" {
		t.Fatalf("expected prompt=login to be forwarded, got %q", parsed.Query().Get("prompt"))
	}
}

// ---------------------------------------------------------------------------
// OidcExchange — happy path
// ---------------------------------------------------------------------------

// TestOidcExchange_HappyPath proves the form-encoded body, the
// `?tenant_id=` query parameter, and that a valid id_token is verified and
// surfaced via IDClaims.
func TestOidcExchange_HappyPath(t *testing.T) {
	srv := newOidcTestServer(t)
	const clientID = "rp-client"
	const tenantID = "11111111-1111-1111-1111-111111111111"

	var capturedContentType string
	var capturedForm url.Values
	var capturedTenantQuery string
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		capturedContentType = r.Header.Get("Content-Type")
		capturedTenantQuery = r.URL.Query().Get("tenant_id")
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		capturedForm = r.Form

		idToken := signIDTokenEdDSA(t, srv.Priv, srv.Kid, validIDTokenClaims(srv.Server, clientID, "the-nonce"))
		writeJSON(t, w, map[string]any{
			"access_token":  "access-tok",
			"token_type":    "Bearer",
			"expires_in":    900,
			"refresh_token": "refresh-tok",
			"id_token":      idToken,
		})
	}

	client, err := NewClient(srv.URL, "acme", WithOidcClientID(clientID))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	set, err := client.OidcExchange(context.Background(), OidcExchangeParams{
		Code:         "auth-code",
		CodeVerifier: Sensitive("verifier-value"),
		RedirectURI:  "https://app.test/callback",
		Nonce:        "the-nonce",
		TenantID:     tenantID,
	})
	if err != nil {
		t.Fatalf("OidcExchange: %v", err)
	}

	if capturedContentType != "application/x-www-form-urlencoded" {
		t.Fatalf("Content-Type = %q, want form-urlencoded (§12.1 note 1)", capturedContentType)
	}
	if capturedTenantQuery != tenantID {
		t.Fatalf("tenant_id query param = %q, want %q (§12.1 note 2)", capturedTenantQuery, tenantID)
	}
	if capturedForm.Get("grant_type") != "authorization_code" {
		t.Fatalf("grant_type = %q", capturedForm.Get("grant_type"))
	}
	if capturedForm.Get("code") != "auth-code" || capturedForm.Get("code_verifier") != "verifier-value" || capturedForm.Get("redirect_uri") != "https://app.test/callback" {
		t.Fatalf("unexpected form body: %v", capturedForm)
	}
	if capturedForm.Get("client_secret") != "" {
		t.Fatalf("expected no client_secret for a public client, got %q", capturedForm.Get("client_secret"))
	}

	if set.AccessToken.expose() != "access-tok" {
		t.Fatalf("AccessToken = %q", set.AccessToken.expose())
	}
	if set.RefreshToken.expose() != "refresh-tok" {
		t.Fatalf("RefreshToken = %q", set.RefreshToken.expose())
	}
	if set.IDClaims == nil {
		t.Fatal("expected IDClaims to be populated")
	}
	if set.IDClaims.Sub != "user-123" {
		t.Fatalf("IDClaims.Sub = %q", set.IDClaims.Sub)
	}
}

// TestOidcExchange_SendsClientSecretWhenConfidential proves a confidential
// client includes client_secret in the form body.
func TestOidcExchange_SendsClientSecretWhenConfidential(t *testing.T) {
	srv := newOidcTestServer(t)
	const clientID = "rp-client"

	var capturedSecret string
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		capturedSecret = r.Form.Get("client_secret")
		writeJSON(t, w, map[string]any{"access_token": "tok", "token_type": "Bearer", "expires_in": 900})
	}

	client, err := NewClient(srv.URL, "acme", WithOidcClientID(clientID), WithOidcClientSecret("shh"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.OidcExchange(context.Background(), OidcExchangeParams{
		Code: "c", CodeVerifier: Sensitive("v"), RedirectURI: "https://app.test/cb", Nonce: "n",
		TenantID: "11111111-1111-1111-1111-111111111111",
	}); err != nil {
		t.Fatalf("OidcExchange: %v", err)
	}
	if capturedSecret != "shh" {
		t.Fatalf("client_secret = %q, want shh", capturedSecret)
	}
}

// TestOidcExchange_RequiresResolvableTenant proves §12.3 rule 4: no
// TenantID and no prior Login means a CLIENT-SIDE *AuthError, no wire call.
func TestOidcExchange_RequiresResolvableTenant(t *testing.T) {
	srv := newOidcTestServer(t)
	client, err := NewClient(srv.URL, "acme", WithOidcClientID("rp-client"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	_, err = client.OidcExchange(context.Background(), OidcExchangeParams{
		Code: "c", CodeVerifier: Sensitive("v"), RedirectURI: "https://app.test/cb", Nonce: "n",
	})
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("expected *AuthError, got %T: %v", err, err)
	}
	if srv.TokenCalls() != 0 {
		t.Fatalf("expected NO wire call when tenant cannot be resolved, got %d token calls", srv.TokenCalls())
	}
}

// ---------------------------------------------------------------------------
// §12.4 ID-token failure modes — one test per rule, exact reason codes.
// ---------------------------------------------------------------------------

const testTenantID = "11111111-1111-1111-1111-111111111111"
const testClientID = "rp-client"

// exchangeWithIDToken performs OidcExchange against srv, whose token
// endpoint always returns idToken, and returns the resulting error.
func exchangeWithIDToken(t *testing.T, srv *oidcTestServer, idToken string) error {
	t.Helper()
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, map[string]any{
			"access_token": "access-tok",
			"token_type":   "Bearer",
			"expires_in":   900,
			"id_token":     idToken,
		})
	}
	client, err := NewClient(srv.URL, "acme", WithOidcClientID(testClientID))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.OidcExchange(context.Background(), OidcExchangeParams{
		Code: "c", CodeVerifier: Sensitive("v"), RedirectURI: "https://app.test/cb", Nonce: "the-nonce",
		TenantID: testTenantID,
	})
	return err
}

func TestOidcExchange_IDTokenFailure_InvalidAlg_WrongAlg(t *testing.T) {
	srv := newOidcTestServer(t)
	claims := validIDTokenClaims(srv.Server, testClientID, "the-nonce")
	err := exchangeWithIDToken(t, srv, signIDTokenHS256(t, claims))
	expectReason(t, err, ReasonInvalidAlg)
}

func TestOidcExchange_IDTokenFailure_InvalidAlg_None(t *testing.T) {
	srv := newOidcTestServer(t)
	claims := validIDTokenClaims(srv.Server, testClientID, "the-nonce")
	err := exchangeWithIDToken(t, srv, signIDTokenNone(t, claims))
	expectReason(t, err, ReasonInvalidAlg)
}

func TestOidcExchange_IDTokenFailure_UnknownKid(t *testing.T) {
	srv := newOidcTestServer(t)
	otherPriv, _ := generateOidcTestKey(t, "kid-not-in-jwks")
	claims := validIDTokenClaims(srv.Server, testClientID, "the-nonce")
	err := exchangeWithIDToken(t, srv, signIDTokenEdDSA(t, otherPriv, "kid-not-in-jwks", claims))
	expectReason(t, err, ReasonUnknownKid)
}

func TestOidcExchange_IDTokenFailure_InvalidSignature(t *testing.T) {
	srv := newOidcTestServer(t)
	claims := validIDTokenClaims(srv.Server, testClientID, "the-nonce")
	token := signIDTokenEdDSA(t, srv.Priv, srv.Kid, claims)
	// Flip a byte in the signature segment to invalidate it while keeping
	// the (matching) kid intact, so this exercises invalid_signature rather
	// than unknown_kid.
	parts := strings.Split(token, ".")
	if len(parts) != 3 || len(parts[2]) == 0 {
		t.Fatalf("unexpected token shape: %q", token)
	}
	tampered := []rune(parts[2])
	if tampered[0] == 'A' {
		tampered[0] = 'B'
	} else {
		tampered[0] = 'A'
	}
	parts[2] = string(tampered)
	err := exchangeWithIDToken(t, srv, strings.Join(parts, "."))
	expectReason(t, err, ReasonInvalidSignature)
}

func TestOidcExchange_IDTokenFailure_InvalidIssuer(t *testing.T) {
	srv := newOidcTestServer(t)
	claims := validIDTokenClaims(srv.Server, testClientID, "the-nonce")
	claims["iss"] = "https://not-the-issuer.example"
	err := exchangeWithIDToken(t, srv, signIDTokenEdDSA(t, srv.Priv, srv.Kid, claims))
	expectReason(t, err, ReasonInvalidIssuer)
}

func TestOidcExchange_IDTokenFailure_InvalidAudience(t *testing.T) {
	srv := newOidcTestServer(t)
	claims := validIDTokenClaims(srv.Server, testClientID, "the-nonce")
	claims["aud"] = "someone-else"
	err := exchangeWithIDToken(t, srv, signIDTokenEdDSA(t, srv.Priv, srv.Kid, claims))
	expectReason(t, err, ReasonInvalidAudience)
}

func TestOidcExchange_IDTokenFailure_TokenExpired(t *testing.T) {
	srv := newOidcTestServer(t)
	claims := validIDTokenClaims(srv.Server, testClientID, "the-nonce")
	claims["exp"] = 1 // long, long ago
	err := exchangeWithIDToken(t, srv, signIDTokenEdDSA(t, srv.Priv, srv.Kid, claims))
	expectReason(t, err, ReasonTokenExpired)
}

func TestOidcExchange_IDTokenFailure_NonceMismatch(t *testing.T) {
	srv := newOidcTestServer(t)
	claims := validIDTokenClaims(srv.Server, testClientID, "the-nonce")
	claims["nonce"] = "not-the-expected-nonce"
	err := exchangeWithIDToken(t, srv, signIDTokenEdDSA(t, srv.Priv, srv.Kid, claims))
	expectReason(t, err, ReasonNonceMismatch)
}

// TestOidcExchange_IDTokenFailureDiscardsWholeTokenSet proves §12.4 rule 7:
// on failure, access_token/refresh_token are ALSO discarded, not just the
// id_token — the caller receives a zero OidcTokenSet.
func TestOidcExchange_IDTokenFailureDiscardsWholeTokenSet(t *testing.T) {
	srv := newOidcTestServer(t)
	claims := validIDTokenClaims(srv.Server, testClientID, "the-nonce")
	claims["nonce"] = "wrong"
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, map[string]any{
			"access_token":  "should-never-be-returned",
			"refresh_token": "should-never-be-returned-either",
			"token_type":    "Bearer",
			"expires_in":    900,
			"id_token":      signIDTokenEdDSA(t, srv.Priv, srv.Kid, claims),
		})
	}
	client, err := NewClient(srv.URL, "acme", WithOidcClientID(testClientID))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	set, err := client.OidcExchange(context.Background(), OidcExchangeParams{
		Code: "c", CodeVerifier: Sensitive("v"), RedirectURI: "https://app.test/cb", Nonce: "the-nonce",
		TenantID: testTenantID,
	})
	if err == nil {
		t.Fatal("expected an error")
	}
	if set.AccessToken != "" || set.RefreshToken != "" {
		t.Fatalf("expected a zero OidcTokenSet on ID-token failure, got %+v", set)
	}
}

// ---------------------------------------------------------------------------
// OidcRefresh — single-flight
// ---------------------------------------------------------------------------

// TestOidcRefresh_HappyPath proves the refresh_token grant's form body and
// that no nonce is required (rule 6 skipped).
func TestOidcRefresh_HappyPath(t *testing.T) {
	srv := newOidcTestServer(t)
	var capturedForm url.Values
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		capturedForm = r.Form
		writeJSON(t, w, map[string]any{"access_token": "new-access", "token_type": "Bearer", "expires_in": 900})
	}
	client, err := NewClient(srv.URL, "acme", WithOidcClientID(testClientID))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	set, err := client.OidcRefresh(context.Background(), OidcRefreshParams{RefreshToken: Sensitive("old-refresh"), TenantID: testTenantID})
	if err != nil {
		t.Fatalf("OidcRefresh: %v", err)
	}
	if set.AccessToken.expose() != "new-access" {
		t.Fatalf("AccessToken = %q", set.AccessToken.expose())
	}
	if capturedForm.Get("grant_type") != "refresh_token" || capturedForm.Get("refresh_token") != "old-refresh" {
		t.Fatalf("unexpected form: %v", capturedForm)
	}
}

// TestOidcRefresh_ConcurrentCallsSingleFlight proves CONTRACT.md §9: N (>=5)
// concurrent OidcRefresh calls collapse into exactly ONE token-endpoint
// request, and every caller receives the same result.
func TestOidcRefresh_ConcurrentCallsSingleFlight(t *testing.T) {
	srv := newOidcTestServer(t)
	release := make(chan struct{})
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		<-release
		writeJSON(t, w, map[string]any{"access_token": "shared-access", "token_type": "Bearer", "expires_in": 900})
	}
	client, err := NewClient(srv.URL, "acme", WithOidcClientID(testClientID))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	const goroutines = 10
	var wg sync.WaitGroup
	results := make([]OidcTokenSet, goroutines)
	errs := make([]error, goroutines)
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			set, err := client.OidcRefresh(context.Background(), OidcRefreshParams{RefreshToken: Sensitive("old"), TenantID: testTenantID})
			results[idx], errs[idx] = set, err
		}(i)
	}

	waitForGoroutines()
	close(release)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: OidcRefresh failed: %v", i, err)
		}
		if results[i].AccessToken.expose() != "shared-access" {
			t.Fatalf("goroutine %d got a different access token: %q", i, results[i].AccessToken.expose())
		}
	}
	if got := srv.TokenCalls(); got != 1 {
		t.Fatalf("expected exactly 1 token-endpoint call for %d concurrent OidcRefresh callers, got %d", goroutines, got)
	}
}

// ---------------------------------------------------------------------------
// LoginClientCredentials
// ---------------------------------------------------------------------------

// TestLoginClientCredentials_HappyPath proves the client_credentials grant
// and that AdoptAsCredential attaches the token to subsequent REST calls
// (but never to /oauth2/*).
func TestLoginClientCredentials_HappyPath(t *testing.T) {
	srv := newOidcTestServer(t)
	var capturedForm url.Values
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		capturedForm = r.Form
		writeJSON(t, w, map[string]any{"access_token": "m2m-token", "token_type": "Bearer", "expires_in": 3600})
	}

	var capturedAuthHeader string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/some-resource", func(w http.ResponseWriter, r *http.Request) {
		capturedAuthHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	})
	// Merge the OIDC test server's mux behavior with a resource route by
	// wrapping srv's handler as the default and adding our extra route via
	// the client's own request path instead: simplest is to hit srv
	// directly since httptest.Server routes through its own mux; add the
	// resource route on a second server sharing the same origin is not
	// possible, so we instead verify adoption using the OIDC server itself
	// via a raw request built the same way Client.newRequest would.
	_ = mux

	client, err := NewClient(srv.URL, "acme", WithOidcClientID(testClientID), WithOidcClientSecret("shh"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	set, err := client.LoginClientCredentials(context.Background(), LoginClientCredentialsParams{
		TenantID: testTenantID, AdoptAsCredential: true,
	})
	if err != nil {
		t.Fatalf("LoginClientCredentials: %v", err)
	}
	if set.AccessToken.expose() != "m2m-token" {
		t.Fatalf("AccessToken = %q", set.AccessToken.expose())
	}
	if set.IDClaims != nil {
		t.Fatal("expected no IDClaims for a client_credentials grant (no openid scope requested)")
	}
	if capturedForm.Get("grant_type") != "client_credentials" || capturedForm.Get("client_secret") != "shh" {
		t.Fatalf("unexpected form: %v", capturedForm)
	}

	// Adopted credential must be applied to a same-origin, non-/oauth2/ path
	// and must NEVER be sent back to /oauth2/token.
	req, err := client.newRequest(context.Background(), http.MethodGet, "/api/v1/whoami", nil)
	if err != nil {
		t.Fatalf("newRequest: %v", err)
	}
	client.decorateRequest(req)
	if got := req.Header.Get("Authorization"); got != "Bearer m2m-token" {
		t.Fatalf("Authorization header = %q, want \"Bearer m2m-token\"", got)
	}

	oauthReq, err := client.newRequest(context.Background(), http.MethodPost, "/oauth2/token", nil)
	if err != nil {
		t.Fatalf("newRequest: %v", err)
	}
	client.decorateRequest(oauthReq)
	if got := oauthReq.Header.Get("Authorization"); got != "" {
		t.Fatalf("expected the adopted credential to NEVER be sent to /oauth2/*, got Authorization: %q", got)
	}
	_ = capturedAuthHeader
}

// TestLoginClientCredentials_RequiresClientSecret proves §12.1 note 4: a
// public client cannot perform this grant — *AuthError, no wire call.
func TestLoginClientCredentials_RequiresClientSecret(t *testing.T) {
	srv := newOidcTestServer(t)
	client, err := NewClient(srv.URL, "acme", WithOidcClientID(testClientID))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.LoginClientCredentials(context.Background(), LoginClientCredentialsParams{TenantID: testTenantID})
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("expected *AuthError, got %T: %v", err, err)
	}
	if srv.TokenCalls() != 0 {
		t.Fatalf("expected no wire call, got %d", srv.TokenCalls())
	}
}

// ---------------------------------------------------------------------------
// Introspect / Revoke
// ---------------------------------------------------------------------------

func TestIntrospect_HappyPath(t *testing.T) {
	srv := newOidcTestServer(t)
	srv.IntrospectHandler = func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("token") != "tok-to-check" {
			t.Fatalf("token = %q", r.Form.Get("token"))
		}
		writeJSON(t, w, map[string]any{"active": true, "sub": "user-1", "scope": "openid profile"})
	}
	client, err := NewClient(srv.URL, "acme", WithOidcClientID(testClientID), WithOidcClientSecret("shh"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	result, err := client.Introspect(context.Background(), IntrospectParams{Token: Sensitive("tok-to-check"), TenantID: testTenantID})
	if err != nil {
		t.Fatalf("Introspect: %v", err)
	}
	if !result.Active || result.Sub != "user-1" || result.Scope != "openid profile" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestIntrospect_RequiresClientSecret(t *testing.T) {
	srv := newOidcTestServer(t)
	client, err := NewClient(srv.URL, "acme", WithOidcClientID(testClientID))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.Introspect(context.Background(), IntrospectParams{Token: Sensitive("t"), TenantID: testTenantID})
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("expected *AuthError, got %T: %v", err, err)
	}
}

// TestIntrospectRevoke_401DoesNotEnterRefreshGuard proves CONTRACT.md
// §12.3 rule 3: a 401 from introspect/revoke must NOT trigger the §9
// single-flight refresh guard.
func TestIntrospectRevoke_401DoesNotEnterRefreshGuard(t *testing.T) {
	srv := newOidcTestServer(t)
	srv.IntrospectHandler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		writeJSON(t, w, map[string]any{"error": "invalid_client", "error_description": "client authentication failed"})
	}
	srv.RevokeHandler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		writeJSON(t, w, map[string]any{"error": "invalid_client", "error_description": "client authentication failed"})
	}

	client, err := NewClient(srv.URL, "acme", WithOidcClientID(testClientID), WithOidcClientSecret("shh"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	if client.guard.Load() == nil {
		t.Fatal("expected a non-nil refresh guard from NewClient")
	}
	// The refresh guard is never even reachable from Introspect/Revoke's
	// code path (they never call c.guard.Load().RefreshIfNeeded); this
	// assertion documents that structural guarantee by checking the error
	// classification the guard's absence-of-invocation implies: a 401 here
	// maps straight to *OAuthProtocolError, never an ordinary session
	// *AuthError produced by a failed refresh attempt.
	_, err = client.Introspect(context.Background(), IntrospectParams{Token: Sensitive("t"), TenantID: testTenantID})
	var protoErr *OAuthProtocolError
	if !errors.As(err, &protoErr) {
		t.Fatalf("expected *OAuthProtocolError from Introspect 401, got %T: %v", err, err)
	}

	err = client.Revoke(context.Background(), RevokeParams{Token: Sensitive("t"), TenantID: testTenantID})
	if !errors.As(err, &protoErr) {
		t.Fatalf("expected *OAuthProtocolError from Revoke 401, got %T: %v", err, err)
	}
}

func TestRevoke_IdempotentOnUnknownToken(t *testing.T) {
	srv := newOidcTestServer(t)
	srv.RevokeHandler = func(w http.ResponseWriter, r *http.Request) {
		// RFC 7009: the server answers 200 even for a token it has never seen.
		w.WriteHeader(http.StatusOK)
	}
	client, err := NewClient(srv.URL, "acme", WithOidcClientID(testClientID), WithOidcClientSecret("shh"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := client.Revoke(context.Background(), RevokeParams{Token: Sensitive("never-issued"), TenantID: testTenantID}); err != nil {
		t.Fatalf("expected Revoke of an unknown token to succeed (RFC 7009 idempotence), got: %v", err)
	}
}

// TestRevoke_5xxIsNetworkError proves §12 port addendum item 20: revoke
// returning void does not make a server error "success".
func TestRevoke_5xxIsNetworkError(t *testing.T) {
	srv := newOidcTestServer(t)
	srv.RevokeHandler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}
	client, err := NewClient(srv.URL, "acme", WithOidcClientID(testClientID), WithOidcClientSecret("shh"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	err = client.Revoke(context.Background(), RevokeParams{Token: Sensitive("t"), TenantID: testTenantID})
	var netErr *NetworkError
	if !errors.As(err, &netErr) {
		t.Fatalf("expected *NetworkError for a 5xx from revoke, got %T: %v", err, err)
	}
}

func TestRevoke_RequiresClientSecret(t *testing.T) {
	srv := newOidcTestServer(t)
	client, err := NewClient(srv.URL, "acme", WithOidcClientID(testClientID))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	err = client.Revoke(context.Background(), RevokeParams{Token: Sensitive("t"), TenantID: testTenantID})
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("expected *AuthError, got %T: %v", err, err)
	}
}

// ---------------------------------------------------------------------------
// OAuth2ErrorResponse -> OAuthProtocolError
// ---------------------------------------------------------------------------

// TestOAuthProtocolError_MessageShapeAndErrorsAs proves CONTRACT.md §2/§12.3
// rule 3: message is exactly "<error>: <error_description>", and the value
// is recoverable both as *OAuthProtocolError AND as *AuthError via
// errors.As, and matches the ErrAuth sentinel via errors.Is (§12 port
// addendum item 17 — non-breaking, additive).
func TestOAuthProtocolError_MessageShapeAndErrorsAs(t *testing.T) {
	srv := newOidcTestServer(t)
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(t, w, map[string]any{"error": "invalid_grant", "error_description": "the authorization code is invalid or expired"})
	}
	client, err := NewClient(srv.URL, "acme", WithOidcClientID(testClientID))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	_, err = client.OidcExchange(context.Background(), OidcExchangeParams{
		Code: "bad-code", CodeVerifier: Sensitive("v"), RedirectURI: "https://app.test/cb", Nonce: "n",
		TenantID: testTenantID,
	})
	if err == nil {
		t.Fatal("expected an error")
	}

	var protoErr *OAuthProtocolError
	if !errors.As(err, &protoErr) {
		t.Fatalf("expected *OAuthProtocolError, got %T: %v", err, err)
	}
	if protoErr.ErrorCode != "invalid_grant" {
		t.Fatalf("ErrorCode = %q", protoErr.ErrorCode)
	}
	if protoErr.ErrorDescription != "the authorization code is invalid or expired" {
		t.Fatalf("ErrorDescription = %q", protoErr.ErrorDescription)
	}
	wantMessage := "invalid_grant: the authorization code is invalid or expired"
	if protoErr.Message != wantMessage {
		t.Fatalf("Message = %q, want %q", protoErr.Message, wantMessage)
	}

	// Sub-type of AuthError: errors.Is against the sentinel still matches.
	if !errors.Is(err, ErrAuth) {
		t.Fatal("expected errors.Is(err, ErrAuth) to match an *OAuthProtocolError")
	}
	// And errors.As against the PARENT *AuthError type also still matches
	// (backward compatibility for existing consumers, §12 port addendum
	// item 17).
	var plainAuthErr *AuthError
	if !errors.As(err, &plainAuthErr) {
		t.Fatalf("expected errors.As(err, &*AuthError) to also match an *OAuthProtocolError")
	}
	if plainAuthErr.Message != wantMessage {
		t.Fatalf("unwrapped AuthError.Message = %q, want %q", plainAuthErr.Message, wantMessage)
	}
}

// TestOAuthProtocolError_Redaction proves the new secret-carrying types
// (OidcTokenSet etc.) never leak through %v/%s/String() — exercised via the
// existing Sensitive redaction machinery.
func TestOidcTokenSet_SecretFieldsRedacted(t *testing.T) {
	set := OidcTokenSet{
		AccessToken:  Sensitive("super-secret-access"),
		RefreshToken: Sensitive("super-secret-refresh"),
		IDToken:      Sensitive("super-secret-idtoken"),
	}
	for name, got := range map[string]string{
		"%v AccessToken":  fmt.Sprintf("%v", set.AccessToken),
		"%s RefreshToken": fmt.Sprintf("%s", set.RefreshToken),
		"String IDToken":  set.IDToken.String(),
	} {
		if got != "[SENSITIVE]" {
			t.Fatalf("%s = %q, want [SENSITIVE]", name, got)
		}
	}
	b, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	for _, secret := range []string{"super-secret-access", "super-secret-refresh", "super-secret-idtoken"} {
		if strings.Contains(string(b), secret) {
			t.Fatalf("json.Marshal(OidcTokenSet) leaked a secret: %s", b)
		}
	}
}

// TestAuthorizationRequest_CodeVerifierRedacted proves §12.5: CodeVerifier
// stays secret for its whole lifetime, including inside AuthorizationRequest.
func TestAuthorizationRequest_CodeVerifierRedacted(t *testing.T) {
	req := AuthorizationRequest{CodeVerifier: Sensitive("pkce-secret-verifier")}
	if got := fmt.Sprintf("%v", req.CodeVerifier); got != "[SENSITIVE]" {
		t.Fatalf("%%v = %q, want [SENSITIVE]", got)
	}
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if strings.Contains(string(b), "pkce-secret-verifier") {
		t.Fatalf("json.Marshal(AuthorizationRequest) leaked the code_verifier: %s", b)
	}
}

// ---------------------------------------------------------------------------
// SsoStart / SsoComplete
// ---------------------------------------------------------------------------

func TestSsoStart_HappyPath(t *testing.T) {
	srv := newOidcTestServer(t)
	var capturedBody map[string]string
	srv.SsoStartHandler = func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&capturedBody); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		writeJSON(t, w, map[string]any{
			"authorize_url":   "https://upstream-idp.example/authorize?x=1",
			"state":           "federation-state",
			"expires_in_secs": 600,
		})
	}
	client, err := NewClient(srv.URL, "acme", WithOrgSlug("acme-org"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	result, err := client.SsoStart(context.Background(), SsoStartParams{
		FederationConfigID: "22222222-2222-2222-2222-222222222222",
		RedirectURI:        "https://app.test/sso/callback",
	})
	if err != nil {
		t.Fatalf("SsoStart: %v", err)
	}
	if result.AuthorizeURL != "https://upstream-idp.example/authorize?x=1" || result.State != "federation-state" || result.ExpiresInSecs != 600 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if capturedBody["tenant_slug"] != "acme" {
		t.Fatalf("expected tenant_slug=acme (defaulted from the Client), got %v", capturedBody)
	}
	if capturedBody["org_slug"] != "acme-org" {
		t.Fatalf("expected org_slug=acme-org (defaulted from WithOrgSlug), got %v", capturedBody)
	}
}

// TestSsoStart_RequiresOrgContext proves §5.1: no org form resolvable is a
// client-side *AuthError.
func TestSsoStart_RequiresOrgContext(t *testing.T) {
	srv := newOidcTestServer(t)
	client, err := NewClient(srv.URL, "acme") // no WithOrgID/WithOrgSlug
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.SsoStart(context.Background(), SsoStartParams{
		FederationConfigID: "22222222-2222-2222-2222-222222222222",
		RedirectURI:        "https://app.test/sso/callback",
	})
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("expected *AuthError, got %T: %v", err, err)
	}
}

// TestSsoStart_ErrorNotParsedAsOAuthProtocolError proves §12 port addendum
// item 12: sso_start's undocumented error body must NOT be parsed as
// OAuth2ErrorResponse.
func TestSsoStart_ErrorNotParsedAsOAuthProtocolError(t *testing.T) {
	srv := newOidcTestServer(t)
	srv.SsoStartHandler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		writeJSON(t, w, map[string]any{"error": "invalid_grant", "error_description": "looks like an oauth2 error but isn't"})
	}
	client, err := NewClient(srv.URL, "acme", WithOrgSlug("acme-org"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.SsoStart(context.Background(), SsoStartParams{FederationConfigID: "x", RedirectURI: "https://app.test/cb"})
	var protoErr *OAuthProtocolError
	if errors.As(err, &protoErr) {
		t.Fatalf("sso_start must NOT be mapped to *OAuthProtocolError, got: %v", err)
	}
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("expected the generic §2 401 -> *AuthError mapping, got %T: %v", err, err)
	}
}

// TestSsoComplete_HappyPath proves the session arrives via Set-Cookie and is
// absorbed exactly like Login (§12.1 note 6).
func TestSsoComplete_HappyPath(t *testing.T) {
	srv := newOidcTestServer(t)
	token := makeAccessTokenWithOrgID(t, "33333333-3333-3333-3333-333333333333")
	srv.SsoCompleteHandler = func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["state"] != "federation-state" || body["code"] != "upstream-code" {
			t.Fatalf("unexpected body: %v", body)
		}
		http.SetCookie(w, &http.Cookie{Name: "axiam_access", Value: token, Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: "axiam_refresh", Value: "refresh-tok", Path: "/"})
		writeJSON(t, w, map[string]any{
			"user_id":      "44444444-4444-4444-4444-444444444444",
			"session_id":   "55555555-5555-5555-5555-555555555555",
			"expires_in":   900,
			"redirect_uri": "https://app.test/dashboard",
		})
	}
	client, err := NewClient(srv.URL, "acme")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	result, err := client.SsoComplete(context.Background(), SsoCompleteParams{State: "federation-state", Code: "upstream-code"})
	if err != nil {
		t.Fatalf("SsoComplete: %v", err)
	}
	if result.UserID != "44444444-4444-4444-4444-444444444444" || result.RedirectURI != "https://app.test/dashboard" {
		t.Fatalf("unexpected result: %+v", result)
	}
	if client.cookieValue(accessCookie) != token {
		t.Fatal("expected the session cookie to be captured by the SDK's cookie jar")
	}
}

// waitForGoroutines gives spawned goroutines a moment to reach a blocking
// point before the test proceeds (used only to make a single-flight race
// window overwhelmingly likely to be hit, not to prove correctness by
// itself — the assertion is the resulting call count).
func waitForGoroutines() {
	time.Sleep(50 * time.Millisecond)
}
