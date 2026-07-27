package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	axiam "github.com/ilpanich/axiam-go-sdk"
)

// fakeOidcLoginClient is a minimal, in-memory OidcLoginClient double so
// these tests never need a live AXIAM server.
type fakeOidcLoginClient struct {
	discoverErr error
	beginErr    error
	exchangeErr error
	tokens      axiam.OidcTokenSet

	beginParams axiam.OidcBeginParams
}

func (f *fakeOidcLoginClient) OidcDiscover(ctx context.Context) (axiam.OidcConfiguration, error) {
	if f.discoverErr != nil {
		return axiam.OidcConfiguration{}, f.discoverErr
	}
	return axiam.OidcConfiguration{AuthorizationEndpoint: "https://idp.test/oauth2/authorize"}, nil
}

func (f *fakeOidcLoginClient) OidcBegin(configuration axiam.OidcConfiguration, params axiam.OidcBeginParams) (axiam.AuthorizationRequest, error) {
	f.beginParams = params
	if f.beginErr != nil {
		return axiam.AuthorizationRequest{}, f.beginErr
	}
	return axiam.AuthorizationRequest{
		URL:          "https://idp.test/oauth2/authorize?state=abc",
		State:        "state-value",
		Nonce:        "nonce-value",
		CodeVerifier: axiam.Sensitive("verifier-value"),
	}, nil
}

func (f *fakeOidcLoginClient) OidcExchange(ctx context.Context, params axiam.OidcExchangeParams) (axiam.OidcTokenSet, error) {
	if f.exchangeErr != nil {
		return axiam.OidcTokenSet{}, f.exchangeErr
	}
	return f.tokens, nil
}

var _ OidcLoginClient = (*fakeOidcLoginClient)(nil)

// TestOidcLoginHandler_RedirectsAndSavesState proves step 1: the handler
// redirects to the authorization URL and parks state/nonce/code_verifier in
// the store, capturing ?return_to=.
func TestOidcLoginHandler_RedirectsAndSavesState(t *testing.T) {
	client := &fakeOidcLoginClient{}
	store := axiam.NewMemoryOidcStateStore(0)

	handler := OidcLoginHandler(OidcLoginOptions{
		Client:      client,
		Store:       store,
		RedirectURI: "https://app.test/callback",
		Scope:       "profile",
	})

	req := httptest.NewRequest(http.MethodGet, "/login?return_to=/dashboard", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusFound)
	}
	loc := rec.Header().Get("Location")
	if loc != "https://idp.test/oauth2/authorize?state=abc" {
		t.Fatalf("Location = %q", loc)
	}
	if client.beginParams.RedirectURI != "https://app.test/callback" || client.beginParams.Scope != "profile" {
		t.Fatalf("unexpected OidcBegin params: %+v", client.beginParams)
	}

	entry, ok := store.Consume("state-value")
	if !ok {
		t.Fatal("expected the state to have been saved")
	}
	if entry.Nonce != "nonce-value" || entry.CodeVerifier.String() != "[SENSITIVE]" {
		t.Fatalf("unexpected entry: %+v", entry)
	}
	if entry.ReturnTo != "/dashboard" {
		t.Fatalf("ReturnTo = %q, want /dashboard", entry.ReturnTo)
	}
}

// TestOidcLoginHandler_DiscoveryFailureIs503 proves a network-level failure
// to start the flow surfaces as 503 oidc_unavailable.
func TestOidcLoginHandler_DiscoveryFailureIs503(t *testing.T) {
	client := &fakeOidcLoginClient{discoverErr: &axiam.NetworkError{Message: "unreachable"}}
	handler := OidcLoginHandler(OidcLoginOptions{Client: client, Store: axiam.NewMemoryOidcStateStore(0), RedirectURI: "https://app.test/callback"})

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	var body errorBody
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Error != "oidc_unavailable" {
		t.Fatalf("error code = %q, want oidc_unavailable", body.Error)
	}
}

// TestOidcCallbackHandler_HappyPathRedirectsToReturnTo proves step 2: a
// valid callback exchanges the code and redirects to the ReturnTo captured
// at login time.
func TestOidcCallbackHandler_HappyPathRedirectsToReturnTo(t *testing.T) {
	store := axiam.NewMemoryOidcStateStore(0)
	_ = store.Save(axiam.OidcStateEntry{
		State: "state-value", Nonce: "nonce-value",
		CodeVerifier: axiam.Sensitive("verifier"), RedirectURI: "https://app.test/callback",
		ReturnTo: "/dashboard",
	})
	client := &fakeOidcLoginClient{tokens: axiam.OidcTokenSet{AccessToken: axiam.Sensitive("access-tok"), ExpiresIn: 900}}

	var onSuccessCalled bool
	handler := OidcCallbackHandler(OidcLoginOptions{
		Client: client, Store: store, RedirectURI: "https://app.test/callback",
		OnSuccess: func(w http.ResponseWriter, r *http.Request, tokens axiam.OidcTokenSet, entry axiam.OidcStateEntry) {
			onSuccessCalled = true
			if entry.ReturnTo != "/dashboard" {
				t.Fatalf("OnSuccess entry.ReturnTo = %q", entry.ReturnTo)
			}
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/callback?state=state-value&code=auth-code", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusFound, rec.Body.String())
	}
	if rec.Header().Get("Location") != "/dashboard" {
		t.Fatalf("Location = %q", rec.Header().Get("Location"))
	}
	if !onSuccessCalled {
		t.Fatal("expected OnSuccess to be called")
	}

	// Single-use: replaying the same callback must now fail.
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("replayed callback status = %d, want 401", rec2.Code)
	}
}

// TestOidcCallbackHandler_NoRedirectConfiguredReturnsJSON proves the
// no-destination fallback: a 200 JSON summary with no token material.
func TestOidcCallbackHandler_NoRedirectConfiguredReturnsJSON(t *testing.T) {
	store := axiam.NewMemoryOidcStateStore(0)
	_ = store.Save(axiam.OidcStateEntry{State: "s", Nonce: "n", RedirectURI: "https://app.test/callback"})
	claims := &axiam.IDTokenClaims{Sub: "user-42"}
	client := &fakeOidcLoginClient{tokens: axiam.OidcTokenSet{AccessToken: axiam.Sensitive("tok"), ExpiresIn: 900, IDClaims: claims}}

	handler := OidcCallbackHandler(OidcLoginOptions{Client: client, Store: store, RedirectURI: "https://app.test/callback"})
	req := httptest.NewRequest(http.MethodGet, "/callback?state=s&code=c", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["authenticated"] != true {
		t.Fatalf("expected authenticated=true, got %v", body)
	}
	if body["sub"] != "user-42" {
		t.Fatalf("expected sub=user-42, got %v", body)
	}
	if _, hasAccessToken := body["access_token"]; hasAccessToken {
		t.Fatalf("response body must not carry token material: %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "tok\"") {
		t.Fatalf("response body appears to leak the raw access token value: %s", rec.Body.String())
	}
}

// TestOidcCallbackHandler_IdpError proves an `error=` query parameter from
// the IdP maps to 401 authentication_failed without ever consuming state.
func TestOidcCallbackHandler_IdpError(t *testing.T) {
	client := &fakeOidcLoginClient{}
	store := axiam.NewMemoryOidcStateStore(0)
	handler := OidcCallbackHandler(OidcLoginOptions{Client: client, Store: store, RedirectURI: "https://app.test/callback"})

	req := httptest.NewRequest(http.MethodGet, "/callback?"+url.Values{
		"error":             {"access_denied"},
		"error_description": {"user cancelled"},
	}.Encode(), nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// TestOidcCallbackHandler_MissingStateOrCodeIs400 proves a malformed
// callback (missing state or code) is 400 invalid_request.
func TestOidcCallbackHandler_MissingStateOrCodeIs400(t *testing.T) {
	client := &fakeOidcLoginClient{}
	store := axiam.NewMemoryOidcStateStore(0)
	handler := OidcCallbackHandler(OidcLoginOptions{Client: client, Store: store, RedirectURI: "https://app.test/callback"})

	req := httptest.NewRequest(http.MethodGet, "/callback?code=only-code", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// TestOidcCallbackHandler_UnknownStateIs401 proves an unknown/expired/
// already-used state maps to 401, indistinguishable from other causes.
func TestOidcCallbackHandler_UnknownStateIs401(t *testing.T) {
	client := &fakeOidcLoginClient{}
	store := axiam.NewMemoryOidcStateStore(0)
	handler := OidcCallbackHandler(OidcLoginOptions{Client: client, Store: store, RedirectURI: "https://app.test/callback"})

	req := httptest.NewRequest(http.MethodGet, "/callback?state=never-saved&code=c", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// TestOidcCallbackHandler_ExchangeNetworkErrorIs503 proves a NetworkError
// from OidcExchange maps to 503 oidc_unavailable rather than 401.
func TestOidcCallbackHandler_ExchangeNetworkErrorIs503(t *testing.T) {
	store := axiam.NewMemoryOidcStateStore(0)
	_ = store.Save(axiam.OidcStateEntry{State: "s", Nonce: "n", RedirectURI: "https://app.test/callback"})
	client := &fakeOidcLoginClient{exchangeErr: &axiam.NetworkError{Message: "token endpoint unreachable"}}
	handler := OidcCallbackHandler(OidcLoginOptions{Client: client, Store: store, RedirectURI: "https://app.test/callback"})

	req := httptest.NewRequest(http.MethodGet, "/callback?state=s&code=c", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

// TestOidcCallbackHandler_ExchangeAuthErrorIs401 proves an *AuthError
// (including an ID-token failure reason) from OidcExchange maps to 401.
func TestOidcCallbackHandler_ExchangeAuthErrorIs401(t *testing.T) {
	store := axiam.NewMemoryOidcStateStore(0)
	_ = store.Save(axiam.OidcStateEntry{State: "s", Nonce: "n", RedirectURI: "https://app.test/callback"})
	client := &fakeOidcLoginClient{exchangeErr: &axiam.AuthError{Message: "id_token validation failed (nonce_mismatch): ...", Reason: "nonce_mismatch"}}
	handler := OidcCallbackHandler(OidcLoginOptions{Client: client, Store: store, RedirectURI: "https://app.test/callback"})

	req := httptest.NewRequest(http.MethodGet, "/callback?state=s&code=c", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	var body errorBody
	_ = json.NewDecoder(rec.Body).Decode(&body)
	if body.Error != "authentication_failed" {
		t.Fatalf("error code = %q", body.Error)
	}
}

// TestOidcCallbackHandler_SuccessRedirectOverridesReturnTo proves an
// explicitly configured SuccessRedirect wins over the captured ReturnTo.
func TestOidcCallbackHandler_SuccessRedirectOverridesReturnTo(t *testing.T) {
	store := axiam.NewMemoryOidcStateStore(0)
	_ = store.Save(axiam.OidcStateEntry{State: "s", Nonce: "n", RedirectURI: "https://app.test/callback", ReturnTo: "/from-login"})
	client := &fakeOidcLoginClient{tokens: axiam.OidcTokenSet{AccessToken: axiam.Sensitive("tok"), ExpiresIn: 900}}
	handler := OidcCallbackHandler(OidcLoginOptions{
		Client: client, Store: store, RedirectURI: "https://app.test/callback",
		SuccessRedirect: "/fixed-destination",
	})

	req := httptest.NewRequest(http.MethodGet, "/callback?state=s&code=c", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Header().Get("Location") != "/fixed-destination" {
		t.Fatalf("Location = %q, want the configured SuccessRedirect", rec.Header().Get("Location"))
	}
}

// failingOidcStateStore always fails Save, to exercise OidcLoginHandler's
// store-failure branch.
type failingOidcStateStore struct{}

func (failingOidcStateStore) Save(axiam.OidcStateEntry) error { return errors.New("store unavailable") }
func (failingOidcStateStore) Consume(string) (axiam.OidcStateEntry, bool) {
	return axiam.OidcStateEntry{}, false
}

var _ axiam.OidcStateStore = failingOidcStateStore{}

// TestOidcLoginHandler_BeginFailureIs503 proves an OidcBegin failure (e.g.
// a caller-supplied ExtraParams programming error surfacing here) is also
// mapped to 503 oidc_unavailable, with a logger attached to exercise the
// logged-warning path too.
func TestOidcLoginHandler_BeginFailureIs503(t *testing.T) {
	client := &fakeOidcLoginClient{beginErr: errors.New("boom")}
	logger := slog.New(slog.NewTextHandler(discardWriter{}, nil))
	handler := OidcLoginHandler(OidcLoginOptions{Client: client, Store: axiam.NewMemoryOidcStateStore(0), RedirectURI: "https://app.test/callback", Logger: logger})

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

// TestOidcLoginHandler_StoreSaveFailureIs503 proves a state-store Save
// failure is mapped to 503 oidc_unavailable.
func TestOidcLoginHandler_StoreSaveFailureIs503(t *testing.T) {
	client := &fakeOidcLoginClient{}
	handler := OidcLoginHandler(OidcLoginOptions{Client: client, Store: failingOidcStateStore{}, RedirectURI: "https://app.test/callback"})

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

// TestOidcCallbackHandler_LoggerReceivesDebugEvents exercises the
// logger-non-nil branch of logOidcDebug/writeOidcError through a realistic
// failure (IdP error callback).
func TestOidcCallbackHandler_LoggerReceivesDebugEvents(t *testing.T) {
	client := &fakeOidcLoginClient{}
	store := axiam.NewMemoryOidcStateStore(0)
	logger := slog.New(slog.NewTextHandler(discardWriter{}, &slog.HandlerOptions{Level: slog.LevelDebug}))
	handler := OidcCallbackHandler(OidcLoginOptions{Client: client, Store: store, RedirectURI: "https://app.test/callback", Logger: logger})

	req := httptest.NewRequest(http.MethodGet, "/callback?error=access_denied&error_description=nope", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// discardWriter is an io.Writer that discards everything written to it —
// used to give slog a real handler without printing test noise.
type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }
