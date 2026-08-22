package axiam

// Pushed Authorization Requests — CONTRACT.md §26 (RFC 9126).
//
// The first test is the one this section exists for: the endpoint answers
// 201, and a success predicate written == 200 treats every successful push as
// a failure while passing every other assertion here.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

const (
	parClientID    = "axiam-rp"
	parSecret      = "rp-secret-value"
	parRedirectURI = "https://app.example.test/auth/callback"
	parTenantUUID  = "11111111-1111-1111-1111-111111111111"
	parRequestURI  = "urn:ietf:params:oauth:request_uri:6esc_11ACC5bwc014ltc14eY22c"
)

type parCapture struct {
	forms   []url.Values
	queries []url.Values
	types   []string
	calls   int32
}

// parServer stands up POST /oauth2/par with a caller-supplied responder.
func parServer(t *testing.T, respond http.HandlerFunc) (*httptest.Server, *parCapture) {
	t.Helper()
	capture := &parCapture{}
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/par", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&capture.calls, 1)
		if err := r.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		capture.forms = append(capture.forms, r.PostForm)
		capture.queries = append(capture.queries, r.URL.Query())
		capture.types = append(capture.types, r.Header.Get("Content-Type"))
		respond(w, r)
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server, capture
}

// parCreated is the RFC 9126 §2.2 success: Created, not OK.
func parCreated(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"request_uri": parRequestURI,
		"expires_in":  90,
	})
}

func parClient(t *testing.T, server *httptest.Server, opts ...Option) *Client {
	t.Helper()
	opts = append([]Option{WithOidcClientID(parClientID)}, opts...)
	client, err := NewClient(server.URL, parTenantUUID, opts...)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return client
}

func parPush(t *testing.T, client *Client, server *httptest.Server) (AuthorizationRequest, PushedAuthorizationRequest, error) {
	t.Helper()
	configuration := discoveryDoc(server.URL)
	request, err := client.OidcBegin(configuration, OidcBeginParams{
		RedirectURI: parRedirectURI,
		Scope:       "openid profile",
	})
	if err != nil {
		t.Fatalf("OidcBegin: %v", err)
	}
	pushed, err := client.OidcPar(context.Background(), OidcParParams{
		Request:       request,
		RedirectURI:   parRedirectURI,
		Scope:         "openid profile",
		TenantID:      parTenantUUID,
		Configuration: &configuration,
	})
	return request, pushed, err
}

// ---------------------------------------------------------------------------
// §26.1 — the 201 and the wire shape
// ---------------------------------------------------------------------------

func TestOidcPar201IsTreatedAsSuccess(t *testing.T) {
	server, _ := parServer(t, parCreated)
	client := parClient(t, server, WithOidcClientSecret(parSecret))

	_, pushed, err := parPush(t, client, server)
	if err != nil {
		t.Fatalf("a 201 is the RFC 9126 success status: %v", err)
	}
	if pushed.RequestURI.expose() != parRequestURI {
		t.Fatalf("request_uri: got %q", pushed.RequestURI.expose())
	}
	if pushed.ExpiresIn != 90 {
		t.Fatalf("expires_in: got %d", pushed.ExpiresIn)
	}
}

func TestOidcParIsFormEncodedWithTenantIDInTheQuery(t *testing.T) {
	server, capture := parServer(t, parCreated)
	client := parClient(t, server, WithOidcClientSecret(parSecret))
	if _, _, err := parPush(t, client, server); err != nil {
		t.Fatalf("OidcPar: %v", err)
	}

	if !strings.Contains(capture.types[0], "application/x-www-form-urlencoded") {
		t.Fatalf("content type: got %q", capture.types[0])
	}
	if got := capture.queries[0].Get("tenant_id"); got != parTenantUUID {
		t.Fatalf("tenant_id query: got %q", got)
	}
	if capture.forms[0].Has("tenant_id") {
		t.Fatal("tenant_id is a query parameter, never a body field (§12.1 note 2)")
	}
}

func TestOidcParCarriesExactlyTheRule1Parameters(t *testing.T) {
	server, capture := parServer(t, parCreated)
	client := parClient(t, server, WithOidcClientSecret(parSecret))
	request, _, err := parPush(t, client, server)
	if err != nil {
		t.Fatalf("OidcPar: %v", err)
	}

	form := capture.forms[0]
	for field, want := range map[string]string{
		"client_id":             parClientID,
		"response_type":         "code",
		"redirect_uri":          parRedirectURI,
		"scope":                 "openid profile",
		"state":                 request.State,
		"nonce":                 request.Nonce,
		"code_challenge_method": "S256",
		"client_secret":         parSecret,
	} {
		if got := form.Get(field); got != want {
			t.Fatalf("%s: got %q, want %q", field, got, want)
		}
	}
	// §26.2 rule 1: derived from OidcBegin's verifier, not a fresh one.
	if got, want := form.Get("code_challenge"), computeCodeChallenge(request.CodeVerifier.expose()); got != want {
		t.Fatalf("code_challenge: got %q, want %q", got, want)
	}
}

func TestOidcParOmitsClientSecretForAPublicClient(t *testing.T) {
	server, capture := parServer(t, parCreated)
	client := parClient(t, server)
	if _, _, err := parPush(t, client, server); err != nil {
		t.Fatalf("OidcPar: %v", err)
	}
	if capture.forms[0].Has("client_secret") {
		t.Fatal("§12.1 forbids sending an empty value for an absent optional field")
	}
}

func TestOidcParAddsOpenidWhenTheCallerOmitsIt(t *testing.T) {
	server, capture := parServer(t, parCreated)
	client := parClient(t, server, WithOidcClientSecret(parSecret))
	configuration := discoveryDoc(server.URL)
	request, err := client.OidcBegin(configuration, OidcBeginParams{RedirectURI: parRedirectURI})
	if err != nil {
		t.Fatalf("OidcBegin: %v", err)
	}
	if _, err := client.OidcPar(context.Background(), OidcParParams{
		Request:       request,
		RedirectURI:   parRedirectURI,
		Scope:         "profile",
		TenantID:      parTenantUUID,
		Configuration: &configuration,
	}); err != nil {
		t.Fatalf("OidcPar: %v", err)
	}
	if got := capture.forms[0].Get("scope"); got != "openid profile" {
		t.Fatalf("scope: got %q", got)
	}
}

func TestOidcParErrorsRatherThanConcatenatingAURL(t *testing.T) {
	server, capture := parServer(t, parCreated)
	client := parClient(t, server, WithOidcClientSecret(parSecret))
	configuration := discoveryDocWithoutOptionalEndpoints(server.URL)
	request, err := client.OidcBegin(configuration, OidcBeginParams{RedirectURI: parRedirectURI})
	if err != nil {
		t.Fatalf("OidcBegin: %v", err)
	}

	_, err = client.OidcPar(context.Background(), OidcParParams{
		Request:       request,
		RedirectURI:   parRedirectURI,
		TenantID:      parTenantUUID,
		Configuration: &configuration,
	})
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("expected *AuthError, got %T (%v)", err, err)
	}
	if n := atomic.LoadInt32(&capture.calls); n != 0 {
		t.Fatalf("expected 0 requests, got %d", n)
	}
}

// ---------------------------------------------------------------------------
// §26.2 rule 2 — the redirect URL carries exactly two parameters
// ---------------------------------------------------------------------------

func TestOidcParAuthorizationURLCarriesExactlyTwoParameters(t *testing.T) {
	server, _ := parServer(t, parCreated)
	client := parClient(t, server, WithOidcClientSecret(parSecret))
	_, pushed, err := parPush(t, client, server)
	if err != nil {
		t.Fatalf("OidcPar: %v", err)
	}

	parsed, err := url.Parse(pushed.AuthorizationURL)
	if err != nil {
		t.Fatalf("parse authorization URL: %v", err)
	}
	query := parsed.Query()
	// Asserted on the FULL parameter set, not on the presence of the two: the
	// server refuses a request mixing a request_uri with inline authorization
	// parameters rather than merging them, and re-adding them "for
	// compatibility" restores the parameter-confusion attack that prevents.
	if len(query) != 2 {
		t.Fatalf("expected exactly client_id and request_uri, got %v", query)
	}
	if query.Get("client_id") != parClientID || query.Get("request_uri") != parRequestURI {
		t.Fatalf("unexpected parameters: %v", query)
	}
	if !strings.HasPrefix(pushed.AuthorizationURL, server.URL+"/oauth2/authorize") {
		t.Fatalf("wrong endpoint: %s", pushed.AuthorizationURL)
	}
}

// ---------------------------------------------------------------------------
// §26.2 rules 1 and 6 — one generator, one code verifier
// ---------------------------------------------------------------------------

func TestOidcParCarriesOidcBeginsStateNonceAndVerifier(t *testing.T) {
	server, _ := parServer(t, parCreated)
	client := parClient(t, server, WithOidcClientSecret(parSecret))
	request, pushed, err := parPush(t, client, server)
	if err != nil {
		t.Fatalf("OidcPar: %v", err)
	}

	if pushed.State != request.State || pushed.Nonce != request.Nonce {
		t.Fatal("state and nonce must come from OidcBegin unchanged")
	}
	// The same verifier, so there is exactly one value to keep and no second
	// place for the two to disagree (§26.2 rule 6).
	if pushed.CodeVerifier.expose() != request.CodeVerifier.expose() {
		t.Fatal("the code verifier must be OidcBegin's, not a fresh one")
	}
}

// ---------------------------------------------------------------------------
// §26.2 rule 4 / §26.3 — retries and errors
// ---------------------------------------------------------------------------

func TestOidcParDoesNotRetryA5xx(t *testing.T) {
	server, capture := parServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	client := parClient(t, server, WithOidcClientSecret(parSecret))
	if _, _, err := parPush(t, client, server); err == nil {
		t.Fatal("expected an error on 503")
	}
	// It is a POST that creates server state, so it falls outside §16.2's
	// read-only eligibility exactly as OidcExchange does.
	if n := atomic.LoadInt32(&capture.calls); n != 1 {
		t.Fatalf("expected exactly 1 request, got %d", n)
	}
}

func TestOidcParMapsOAuth2Errors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		code   string
	}{
		{"invalid_client", http.StatusUnauthorized, "invalid_client"},
		{"invalid_request", http.StatusBadRequest, "invalid_request"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, _ := parServer(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"error":             tc.code,
					"error_description": "nope",
				})
			})
			client := parClient(t, server, WithOidcClientSecret(parSecret))
			_, _, err := parPush(t, client, server)

			var protocolErr *OAuthProtocolError
			if !errors.As(err, &protocolErr) {
				t.Fatalf("expected *OAuthProtocolError, got %T (%v)", err, err)
			}
			if protocolErr.ErrorCode != tc.code {
				t.Fatalf("error code: got %q, want %q", protocolErr.ErrorCode, tc.code)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// §26.5 — sensitivity
// ---------------------------------------------------------------------------

func TestOidcParRequestURIIsSensitiveButStillReachesTheRedirect(t *testing.T) {
	server, _ := parServer(t, parCreated)
	client := parClient(t, server, WithOidcClientSecret(parSecret))
	_, pushed, err := parPush(t, client, server)
	if err != nil {
		t.Fatalf("OidcPar: %v", err)
	}

	for _, format := range []string{"%v", "%+v", "%s", "%q", "%#v"} {
		rendered := fmt.Sprintf(format, pushed)
		if strings.Contains(rendered, parRequestURI) {
			t.Fatalf("request_uri leaked via %s: %s", format, rendered)
		}
		if strings.Contains(rendered, pushed.CodeVerifier.expose()) {
			t.Fatalf("code_verifier leaked via %s", format)
		}
	}
	// …but it must reach the redirect URL, which is the point of it.
	if !strings.Contains(pushed.AuthorizationURL, url.QueryEscape(parRequestURI)) {
		t.Fatalf("the request_uri must reach the redirect: %s", pushed.AuthorizationURL)
	}
	// state, nonce and expires_in are not secrets and must stay readable.
	if pushed.State == "" || pushed.Nonce == "" || pushed.ExpiresIn == 0 {
		t.Fatal("state, nonce and expires_in are not secrets")
	}
}
