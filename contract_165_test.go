package axiam

// Contract 1.65 — CONTRACT.md §37 (native sign-in with a provider ID token),
// §12.1 / §26.2 rule 8 (idp_hint) and the §9 refresh-reuse confirmation.
// Test names follow §37.9's, in Go casing.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	nativeGrantURN   = "urn:axiam:params:oauth:grant-type:provider-id-token"
	nativeRawNonce   = "n-0S6_WzA2Mj"
	nativeNonceHash  = "0823a09b54cb9381561068b00aaf4e539b3f54604631d3e6a820879b6b04cc19"
	nativeFixtureTok = "eyJhbGciOiJSUzI1NiJ9.eyJub25jZSI6IjA4MjNhMDliNTRjYjkzODE1NjEwNjhiMDBhYWY0ZTUzOWIzZjU0NjA0NjMxZDNlNmE4MjA4NzliNmIwNGNjMTkifQ.c2ln"
)

// nativeSeen is what the token endpoint recorded about one request.
type nativeSeen struct {
	query  url.Values
	form   url.Values
	body   string
	header http.Header
	ctype  string
}

// nativeEnv is a fake AXIAM whose every request is counted (discovery and JWKS
// included), so "one request in total" is assertable.
type nativeEnv struct {
	srv      *oidcTestServer
	total    int32
	mu       sync.Mutex
	requests []nativeSeen
}

func (e *nativeEnv) Total() int32 { return atomic.LoadInt32(&e.total) }

func (e *nativeEnv) Seen() []nativeSeen {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]nativeSeen(nil), e.requests...)
}

func newNativeEnv(t *testing.T, token http.HandlerFunc) *nativeEnv {
	t.Helper()
	e := &nativeEnv{srv: newOidcTestServer(t)}
	inner := e.srv.Config.Handler
	e.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&e.total, 1)
		inner.ServeHTTP(w, r)
	})
	e.srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		raw := new(bytes.Buffer)
		_, _ = raw.ReadFrom(r.Body)
		form, _ := url.ParseQuery(raw.String())
		e.mu.Lock()
		e.requests = append(e.requests, nativeSeen{
			query: r.URL.Query(), form: form, body: raw.String(),
			header: r.Header.Clone(), ctype: r.Header.Get("Content-Type"),
		})
		e.mu.Unlock()
		token(w, r)
	}
	return e
}

func (e *nativeEnv) client(t *testing.T, opts ...Option) *Client {
	t.Helper()
	opts = append([]Option{WithOidcClientID(testClientID)}, opts...)
	c, err := NewClient(e.srv.URL, "acme", opts...)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func (e *nativeEnv) config() *OidcConfiguration {
	d := discoveryDoc(e.srv.URL)
	d.GrantTypesSupported = append(d.GrantTypesSupported, nativeGrantURN)
	return &d
}

func (e *nativeEnv) params() LoginWithProviderIdTokenParams {
	return LoginWithProviderIdTokenParams{
		Provider: "corp-okta", IDToken: Sensitive(nativeFixtureTok), Nonce: Sensitive(nativeRawNonce),
		TenantID: testTenantID, Configuration: e.config(),
	}
}

func okTokens(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, map[string]any{"access_token": "at", "token_type": "Bearer", "expires_in": 900})
	}
}

func oauthErr(status int, code, desc string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = fmt.Fprintf(w, `{"error":%q,"error_description":%q}`, code, desc)
	}
}

func asProtocolErr(t *testing.T, err error) *OAuthProtocolError {
	t.Helper()
	var pe *OAuthProtocolError
	if !errors.As(err, &pe) {
		t.Fatalf("want *OAuthProtocolError, got %T: %v", err, err)
	}
	return pe
}

// §37.9 test 1.
func TestNativeSignIn_RequestBodyExact(t *testing.T) {
	e := newNativeEnv(t, okTokens(t))
	c := e.client(t)
	p := e.params()
	p.Scopes = []string{"profile", "email"}
	p.Resource = "https://api.example.test"
	if _, err := c.LoginWithProviderIdToken(context.Background(), p); err != nil {
		t.Fatalf("LoginWithProviderIdToken: %v", err)
	}
	seen := e.Seen()
	if len(seen) != 1 {
		t.Fatalf("want 1 token request, got %d", len(seen))
	}
	s := seen[0]
	if s.query.Get("tenant_id") != testTenantID || s.form.Has("tenant_id") {
		t.Errorf("tenant_id must be a query parameter only: query=%v form=%v", s.query, s.form)
	}
	if s.ctype != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q", s.ctype)
	}
	want := []string{"client_id", "grant_type", "id_token", "nonce", "provider", "resource", "scope"}
	if got := sortedKeys(s.form); !reflect.DeepEqual(got, want) {
		t.Errorf("body keys = %v, want %v", got, want)
	}
	if s.form.Get("grant_type") != nativeGrantURN || s.form.Get("scope") != "profile email" {
		t.Errorf("grant_type/scope wrong: %v", s.form)
	}
	for _, h := range []string{"Authorization", "Cookie", "X-CSRF-Token"} {
		if s.header.Get(h) != "" {
			t.Errorf("header %s must be absent, got %q", h, s.header.Get(h))
		}
	}

	// No scopes, no resource: neither key, and no openid.
	e2 := newNativeEnv(t, okTokens(t))
	if _, err := e2.client(t).LoginWithProviderIdToken(context.Background(), e2.params()); err != nil {
		t.Fatalf("LoginWithProviderIdToken: %v", err)
	}
	want = []string{"client_id", "grant_type", "id_token", "nonce", "provider"}
	if got := sortedKeys(e2.Seen()[0].form); !reflect.DeepEqual(got, want) {
		t.Errorf("body keys without scope/resource = %v, want %v", got, want)
	}
	if strings.Contains(e2.Seen()[0].body, "openid") || strings.Contains(e2.Seen()[0].body, "scope") {
		t.Errorf("openid/scope must not be added: %s", e2.Seen()[0].body)
	}
}

// §37.9 test 2.
func TestNativeSignIn_RawNonceSentNotHash(t *testing.T) {
	e := newNativeEnv(t, okTokens(t))
	if _, err := e.client(t).LoginWithProviderIdToken(context.Background(), e.params()); err != nil {
		t.Fatalf("LoginWithProviderIdToken: %v", err)
	}
	s := e.Seen()[0]
	if s.form.Get("nonce") != nativeRawNonce {
		t.Errorf("nonce = %q, want the raw value", s.form.Get("nonce"))
	}
	if strings.Contains(s.body, nativeNonceHash) {
		t.Error("the body must not contain the SHA-256 hex of the nonce")
	}
	// The fixture token's own nonce claim carries the hash; it is in id_token
	// only, never sent as the nonce.
	if sum := sha256.Sum256([]byte(nativeRawNonce)); hex.EncodeToString(sum[:]) != nativeNonceHash {
		t.Fatal("fixture hash is wrong")
	}
	payload, _ := base64.RawURLEncoding.DecodeString(strings.Split(nativeFixtureTok, ".")[1])
	if !strings.Contains(string(payload), nativeNonceHash) {
		t.Fatal("fixture token must carry the hash as its nonce claim")
	}
	if s.form.Get("nonce") == nativeNonceHash {
		t.Error("the token's nonce claim was sent")
	}
}

// §37.9 test 3.
func TestNativeSignIn_ProviderSentVerbatim(t *testing.T) {
	e := newNativeEnv(t, okTokens(t))
	c := e.client(t)
	values := []string{"3f2c7a52-1b7e-4a47-9d52-8a3b5f0d1e11", "Corp-Okta", "google"}
	for _, v := range values {
		p := e.params()
		p.Provider = v
		if _, err := c.LoginWithProviderIdToken(context.Background(), p); err != nil {
			t.Fatalf("provider %q: %v", v, err)
		}
	}
	seen := e.Seen()
	if len(seen) != len(values) {
		t.Fatalf("want %d token requests, got %d", len(values), len(seen))
	}
	for i, v := range values {
		if seen[i].form.Get("provider") != v {
			t.Errorf("provider %d = %q, want %q", i, seen[i].form.Get("provider"), v)
		}
	}
	if e.Total() != int32(len(values)) {
		t.Errorf("total requests = %d, want %d: no sso_providers lookup and no discovery fetch", e.Total(), len(values))
	}
}

// §37.9 test 4.
func TestNativeSignIn_PublicClientSendsClientIdOnly(t *testing.T) {
	e := newNativeEnv(t, okTokens(t))
	if _, err := e.client(t).LoginWithProviderIdToken(context.Background(), e.params()); err != nil {
		t.Fatalf("a public client must not be refused client-side: %v", err)
	}
	s := e.Seen()[0]
	if s.form.Has("client_secret") || s.form.Has("client_assertion") || s.header.Get("Authorization") != "" {
		t.Errorf("a public client sends no credential: %v %v", s.form, s.header)
	}
	if s.form.Get("client_id") != testClientID {
		t.Errorf("client_id = %q", s.form.Get("client_id"))
	}
}

func TestNativeSignIn_ConfidentialClientSendsItsCredential(t *testing.T) {
	for _, method := range []string{"client_secret_post", "client_secret_basic"} {
		t.Run(method, func(t *testing.T) {
			e := newNativeEnv(t, okTokens(t))
			cfg := e.config()
			cfg.TokenEndpointAuthMethodsSupported = []string{method}
			p := e.params()
			p.Configuration = cfg
			if _, err := e.client(t, WithOidcClientSecret("shh")).LoginWithProviderIdToken(context.Background(), p); err != nil {
				t.Fatalf("LoginWithProviderIdToken: %v", err)
			}
			s := e.Seen()[0]
			if s.form.Get("client_secret") != "shh" {
				t.Errorf("client_secret missing from the body: %v", sortedKeys(s.form))
			}
			if s.header.Get("Authorization") != "" {
				t.Errorf("never a Basic header, got %q", s.header.Get("Authorization"))
			}
		})
	}
}

// §37.9 test 5.
func TestNativeSignIn_EmptyInputsRefusedLocally(t *testing.T) {
	e := newNativeEnv(t, okTokens(t))
	c := e.client(t)
	cases := map[string]func(*LoginWithProviderIdTokenParams){
		"provider": func(p *LoginWithProviderIdTokenParams) { p.Provider = "" },
		"id_token": func(p *LoginWithProviderIdTokenParams) { p.IDToken = "" },
		"nonce":    func(p *LoginWithProviderIdTokenParams) { p.Nonce = "" },
	}
	for name, mutate := range cases {
		p := e.params()
		mutate(&p)
		_, err := c.LoginWithProviderIdToken(context.Background(), p)
		var ve *ValidationError
		if !errors.As(err, &ve) {
			t.Errorf("empty %s: want *ValidationError (C165-07), got %T %v", name, err, err)
		}
	}
	// A slug-only client with no tenant UUID: refused with no wire call, not
	// even a discovery fetch.
	p := e.params()
	p.TenantID, p.Configuration = "", nil
	_, err := c.LoginWithProviderIdToken(context.Background(), p)
	var ae *AuthError
	if !errors.As(err, &ae) {
		t.Errorf("slug-only client: want the taxonomy *AuthError, got %T %v", err, err)
	}
	if e.Total() != 0 {
		t.Errorf("zero requests expected, got %d", e.Total())
	}
}

// §37.9 test 6.
func TestNativeSignIn_GenericInvalidGrantMapped(t *testing.T) {
	const desc = "the provider ID token is not acceptable"
	e := newNativeEnv(t, oauthErr(400, "invalid_grant", desc))
	c := e.client(t)
	_, err := c.LoginWithProviderIdToken(context.Background(), e.params())
	pe := asProtocolErr(t, err)
	if pe.ErrorCode != "invalid_grant" || pe.ErrorDescription != desc {
		t.Errorf("error fields = %q / %q", pe.ErrorCode, pe.ErrorDescription)
	}
	if pe.Message != "invalid_grant: "+desc {
		t.Errorf("message = %q", pe.Message)
	}
	if n := len(e.Seen()); n != 1 {
		t.Errorf("exactly one request, got %d (no retry, no regenerated nonce)", n)
	}
	if c.session.oidc.pendingRefresh != nil {
		t.Error("the §9 refresh guard must not be entered")
	}
}

// §37.9 test 7.
func TestNativeSignIn_ConsentRequiredMapped(t *testing.T) {
	e := newNativeEnv(t, oauthErr(400, "consent_required", "consent is needed"))
	_, err := e.client(t).LoginWithProviderIdToken(context.Background(), e.params())
	if pe := asProtocolErr(t, err); pe.ErrorCode != "consent_required" {
		t.Errorf("error = %q", pe.ErrorCode)
	}
	if len(e.Seen()) != 1 || e.srv.TokenCalls() != 1 {
		t.Errorf("one request and no fallback to another grant, got %d/%d", len(e.Seen()), e.srv.TokenCalls())
	}
}

// §37.9 test 8.
func TestNativeSignIn_ClientAndScopeRefusalsSurfaced(t *testing.T) {
	cases := []struct {
		status int
		code   string
		www    bool
	}{
		{400, "unauthorized_client", false},
		{401, "invalid_client", true},
		{400, "invalid_scope", false},
		{400, "invalid_target", false},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			e := newNativeEnv(t, func(w http.ResponseWriter, r *http.Request) {
				if tc.www {
					w.Header().Set("WWW-Authenticate", `Bearer error="invalid_client"`)
				}
				oauthErr(tc.status, tc.code, "refused")(w, r)
			})
			c := e.client(t)
			p := e.params()
			p.Scopes = []string{"profile", "address"}
			_, err := c.LoginWithProviderIdToken(context.Background(), p)
			if pe := asProtocolErr(t, err); pe.ErrorCode != tc.code {
				t.Errorf("error = %q", pe.ErrorCode)
			}
			seen := e.Seen()
			if len(seen) != 1 {
				t.Fatalf("one request, got %d", len(seen))
			}
			if seen[0].form.Get("scope") != "profile address" {
				t.Errorf("scope narrowed or altered: %q", seen[0].form.Get("scope"))
			}
			if c.session.oidc.pendingRefresh != nil {
				t.Error("a 401 must not enter the §9 guard")
			}
		})
	}
}

// §37.9 test 9.
func TestNativeSignIn_RateLimitWithRetryAfterMapped(t *testing.T) {
	e := newNativeEnv(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "7")
		oauthErr(429, "rate_limit_exceeded", "slow down")(w, r)
	})
	_, err := e.client(t).LoginWithProviderIdToken(context.Background(), e.params())
	pe := asProtocolErr(t, err)
	if pe.ErrorCode != "rate_limit_exceeded" || pe.RetryAfter != 7*time.Second {
		t.Errorf("error=%q retryAfter=%v", pe.ErrorCode, pe.RetryAfter)
	}
	if len(e.Seen()) != 1 {
		t.Errorf("one request, got %d", len(e.Seen()))
	}
}

// §37.9 test 10.
func TestNativeSignIn_ServerErrorNotRetried(t *testing.T) {
	t.Run("500 with a body is OAuthProtocolError", func(t *testing.T) {
		e := newNativeEnv(t, oauthErr(500, "server_error", "datastore unavailable"))
		_, err := e.client(t).LoginWithProviderIdToken(context.Background(), e.params())
		if pe := asProtocolErr(t, err); pe.ErrorCode != "server_error" {
			t.Errorf("error = %q", pe.ErrorCode)
		}
		if len(e.Seen()) != 1 {
			t.Errorf("one request, got %d", len(e.Seen()))
		}
	})
	t.Run("500 without a body is NetworkError", func(t *testing.T) {
		e := newNativeEnv(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) })
		_, err := e.client(t).LoginWithProviderIdToken(context.Background(), e.params())
		var ne *NetworkError
		if !errors.As(err, &ne) {
			t.Fatalf("want *NetworkError, got %T: %v", err, err)
		}
		if len(e.Seen()) != 1 {
			t.Errorf("one request, got %d", len(e.Seen()))
		}
	})
	t.Run("transport failure after the request is sent is NetworkError", func(t *testing.T) {
		e := newNativeEnv(t, func(w http.ResponseWriter, r *http.Request) {
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Error("hijacker unavailable")
				return
			}
			conn, _, _ := hj.Hijack()
			_ = conn.Close()
		})
		_, err := e.client(t).LoginWithProviderIdToken(context.Background(), e.params())
		var ne *NetworkError
		if !errors.As(err, &ne) {
			t.Fatalf("want *NetworkError, got %T: %v", err, err)
		}
		if len(e.Seen()) != 1 {
			t.Errorf("one request, got %d", len(e.Seen()))
		}
	})
}

// §37.9 test 11.
func TestNativeSignIn_ResultIsTheOrdinaryTokenSet(t *testing.T) {
	respond := func(e *nativeEnv, nonceClaim string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			claims := validIDTokenClaims(e.srv.Server, testClientID, nonceClaim)
			writeJSON(t, w, map[string]any{
				"access_token": "at-1", "refresh_token": "rt-1", "token_type": "DPoP", "expires_in": 900,
				"scope": "openid profile", "id_token": signIDTokenEdDSA(t, e.srv.Priv, e.srv.Kid, claims),
			})
		}
	}
	t.Run("decodes and validates with the raw nonce", func(t *testing.T) {
		e := &nativeEnv{}
		e = newNativeEnv(t, func(w http.ResponseWriter, r *http.Request) { respond(e, nativeRawNonce)(w, r) })
		c := e.client(t)
		before := c.adoptedOidcCredential()
		set, err := c.LoginWithProviderIdToken(context.Background(), func() LoginWithProviderIdTokenParams {
			p := e.params()
			p.Scopes = []string{"openid", "profile"}
			return p
		}())
		if err != nil {
			t.Fatalf("LoginWithProviderIdToken: %v", err)
		}
		if set.TokenType != "DPoP" || set.AccessToken.Expose() != "at-1" || set.RefreshToken.Expose() != "rt-1" || set.Scope != "openid profile" {
			t.Errorf("token set = %+v", set)
		}
		if set.IDClaims == nil || set.IDClaims.Nonce != nativeRawNonce {
			t.Errorf("id claims = %+v", set.IDClaims)
		}
		if c.adoptedOidcCredential() != before {
			t.Error("without AdoptAsCredential the client's credential is unchanged")
		}
	})
	t.Run("a nonce claim that is not the raw nonce is nonce_mismatch", func(t *testing.T) {
		e := &nativeEnv{}
		e = newNativeEnv(t, func(w http.ResponseWriter, r *http.Request) { respond(e, nativeNonceHash)(w, r) })
		_, err := e.client(t).LoginWithProviderIdToken(context.Background(), e.params())
		var ae *AuthError
		if !errors.As(err, &ae) || string(ae.Reason) != "nonce_mismatch" {
			t.Fatalf("want AuthError nonce_mismatch, got %T %v", err, err)
		}
	})
	t.Run("without refresh_token and id_token both are absent", func(t *testing.T) {
		e := newNativeEnv(t, okTokens(t))
		set, err := e.client(t).LoginWithProviderIdToken(context.Background(), e.params())
		if err != nil {
			t.Fatal(err)
		}
		if set.RefreshToken != "" || set.IDToken != "" || set.IDClaims != nil {
			t.Errorf("want both absent: %+v", set)
		}
	})
	t.Run("AdoptAsCredential follows the LoginClientCredentials posture", func(t *testing.T) {
		e := newNativeEnv(t, okTokens(t))
		c := e.client(t)
		p := e.params()
		p.AdoptAsCredential = true
		if _, err := c.LoginWithProviderIdToken(context.Background(), p); err != nil {
			t.Fatal(err)
		}
		if c.adoptedOidcCredential().Expose() != "at" {
			t.Error("AdoptAsCredential must adopt the access token")
		}
	})
}

// §37.9 test 12.
func TestNativeSignIn_NoSecretInLogsOrErrors(t *testing.T) {
	const secretToken = "FIXTURE-PROVIDER-ID-TOKEN-8c1f"
	const secretNonce = "FIXTURE-RAW-NONCE-4d2a"
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	var telemetry []string
	var tmu sync.Mutex
	hook := func(ev TelemetryEvent) {
		tmu.Lock()
		defer tmu.Unlock()
		telemetry = append(telemetry, fmt.Sprintf("%+v|%#v", ev, ev))
	}

	scenarios := map[string]http.HandlerFunc{
		"success":          okTokens(t),
		"invalid_grant":    oauthErr(400, "invalid_grant", "the provider ID token is not acceptable"),
		"consent_required": oauthErr(400, "consent_required", "consent"),
		"invalid_client":   oauthErr(401, "invalid_client", "bad"),
		"invalid_scope":    oauthErr(400, "invalid_scope", "bad"),
		"rate_limited": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Retry-After", "7")
			oauthErr(429, "rate_limit_exceeded", "x")(w, r)
		},
		"server_error":        oauthErr(500, "server_error", "db"),
		"server_error_nobody": func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) },
		"transport": func(w http.ResponseWriter, r *http.Request) {
			conn, _, _ := w.(http.Hijacker).Hijack()
			_ = conn.Close()
		},
	}
	var rendered []string
	for name, h := range scenarios {
		e := newNativeEnv(t, h)
		c := e.client(t, WithLogger(logger), WithTelemetryHook(hook))
		p := e.params()
		p.IDToken, p.Nonce = Sensitive(secretToken), Sensitive(secretNonce)
		set, err := c.LoginWithProviderIdToken(context.Background(), p)
		rendered = append(rendered, name+":"+fmt.Sprintf("%v|%+v|%#v|%s|%q|%v|%+v", err, err, err, err, err, set, p))
		if err != nil {
			var pe *OAuthProtocolError
			if errors.As(err, &pe) {
				rendered = append(rendered, pe.Message, pe.ErrorCode, pe.ErrorDescription)
			}
			for u := err; u != nil; u = errors.Unwrap(u) {
				rendered = append(rendered, u.Error())
			}
		}
	}
	// The empty-input refusals (test 5) too.
	e := newNativeEnv(t, okTokens(t))
	c := e.client(t, WithLogger(logger), WithTelemetryHook(hook))
	for _, mutate := range []func(*LoginWithProviderIdTokenParams){
		func(p *LoginWithProviderIdTokenParams) { p.Provider = "" },
		func(p *LoginWithProviderIdTokenParams) { p.IDToken = "" },
		func(p *LoginWithProviderIdTokenParams) { p.Nonce = "" },
		func(p *LoginWithProviderIdTokenParams) { p.TenantID, p.Configuration = "", nil },
	} {
		p := e.params()
		p.IDToken, p.Nonce = Sensitive(secretToken), Sensitive(secretNonce)
		mutate(&p)
		_, err := c.LoginWithProviderIdToken(context.Background(), p)
		rendered = append(rendered, fmt.Sprintf("%v|%+v|%#v", err, err, err))
	}
	// ProviderNonce.Raw's rendering.
	pair := NativeNonce()
	rendered = append(rendered, fmt.Sprintf("%v|%+v|%#v|%s", pair, pair, pair, pair.Raw))

	tmu.Lock()
	haystack := strings.Join(append(rendered, logs.String(), strings.Join(telemetry, "\n")), "\n")
	tmu.Unlock()
	for _, secret := range []string{secretToken, secretNonce, pair.Raw.Expose()} {
		if strings.Contains(haystack, secret) {
			t.Errorf("secret %q leaked into logs, errors or telemetry", secret)
		}
	}
}

// §37.9 test 13.
func TestNativeSignIn_NativeNoncePair(t *testing.T) {
	// The hashing step against the fixed vector.
	if got := hashNativeNonce(nativeRawNonce); got != nativeNonceHash {
		t.Fatalf("hash vector: got %s", got)
	}
	a, b := NativeNonce(), NativeNonce()
	if a.Raw == b.Raw || a.Hashed == b.Hashed {
		t.Error("two calls must return different pairs")
	}
	raw := a.Raw.Expose()
	if strings.ContainsAny(raw, "=+/") {
		t.Errorf("raw must be base64url without padding: %q", raw)
	}
	dec, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || len(dec) < 32 {
		t.Errorf("raw must decode to >=32 bytes: %d, %v", len(dec), err)
	}
	if len(a.Hashed) != 64 || a.Hashed != strings.ToLower(a.Hashed) {
		t.Errorf("hashed must be 64 lower-case hex characters: %q", a.Hashed)
	}
	sum := sha256.Sum256([]byte(raw))
	if a.Hashed != hex.EncodeToString(sum[:]) {
		t.Error("hashed must be SHA-256(raw)")
	}
	if fmt.Sprint(a.Raw) != redacted || fmt.Sprintf("%#v", a.Raw) != redacted {
		t.Error("raw must be wrapped")
	}
	if a.Hashed == redacted {
		t.Error("hashed must be a plain string")
	}
	if (&Client{}).NativeNonce().Hashed == "" {
		t.Error("the method form returns a pair too")
	}
}

// ---------------------------------------------------------------------------
// idp_hint — §12.1 and §26.2 rule 8
// ---------------------------------------------------------------------------

func hintPtr(s string) *string { return &s }

func beginClient(t *testing.T) (*Client, OidcConfiguration) {
	t.Helper()
	c, err := NewClient("https://axiam.example.test", "acme", WithOidcClientID(testClientID))
	if err != nil {
		t.Fatal(err)
	}
	return c, discoveryDoc("https://axiam.example.test")
}

func parsedQuery(t *testing.T, raw string) url.Values {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query()
}

func TestIdpHint_EmittedOnce(t *testing.T) {
	c, cfg := beginClient(t)
	for _, hint := range []string{"corp-okta", "3f2c7a52-1b7e-4a47-9d52-8a3b5f0d1e11", "Google", "a b&c=d/é+"} {
		req, err := c.OidcBegin(cfg, OidcBeginParams{RedirectURI: "https://app.example.test/cb", IdpHint: hintPtr(hint)})
		if err != nil {
			t.Fatalf("hint %q: %v", hint, err)
		}
		q := parsedQuery(t, req.URL)
		if got := q["axiam_idp_hint"]; len(got) != 1 || got[0] != hint {
			t.Errorf("axiam_idp_hint = %q, want exactly [%q]", got, hint)
		}
		if len(q) != 9 {
			t.Errorf("want the eight parameters plus the hint, got %v", sortedKeys(q))
		}
		if q.Get("client_id") != testClientID || q.Get("code_challenge_method") != "S256" || q.Get("response_type") != "code" {
			t.Errorf("the other parameters changed: %v", q)
		}
	}
}

func TestIdpHint_OmittedWhenUnset(t *testing.T) {
	c, cfg := beginClient(t)
	req, err := c.OidcBegin(cfg, OidcBeginParams{RedirectURI: "https://app.example.test/cb"})
	if err != nil {
		t.Fatal(err)
	}
	q := parsedQuery(t, req.URL)
	want := []string{"client_id", "code_challenge", "code_challenge_method", "nonce", "redirect_uri", "response_type", "scope", "state"}
	if got := sortedKeys(q); !reflect.DeepEqual(got, want) {
		t.Errorf("parameters = %v, want %v", got, want)
	}
	if strings.Contains(req.URL, "idp_hint") {
		t.Error("no hint and no kc_idp_hint may appear")
	}
}

func TestIdpHint_NotDuplicated(t *testing.T) {
	c, cfg := beginClient(t)
	req, err := c.OidcBegin(cfg, OidcBeginParams{
		RedirectURI: "https://app.example.test/cb", IdpHint: hintPtr("mine"),
		ExtraParams: map[string]string{"axiam_idp_hint": "other"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := parsedQuery(t, req.URL)["axiam_idp_hint"]; len(got) != 1 || got[0] != "mine" {
		t.Errorf("want the option's hint once, got %q", got)
	}
	// Unset: the extra passes through, still once.
	req, err = c.OidcBegin(cfg, OidcBeginParams{
		RedirectURI: "https://app.example.test/cb", ExtraParams: map[string]string{"axiam_idp_hint": "other"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := parsedQuery(t, req.URL)["axiam_idp_hint"]; len(got) != 1 || got[0] != "other" {
		t.Errorf("want the extra passed through once, got %q", got)
	}
}

func TestIdpHint_Bounds(t *testing.T) {
	c, cfg := beginClient(t)
	for name, hint := range map[string]string{"empty": "", "257 bytes": strings.Repeat("a", 257)} {
		req, err := c.OidcBegin(cfg, OidcBeginParams{RedirectURI: "https://app.example.test/cb", IdpHint: hintPtr(hint)})
		var ve *ValidationError
		if !errors.As(err, &ve) || req.URL != "" {
			t.Errorf("%s: want a *ValidationError with no URL built, got %q %T %v", name, req.URL, err, err)
		}
	}
	max := strings.Repeat("a", 256)
	req, err := c.OidcBegin(cfg, OidcBeginParams{RedirectURI: "https://app.example.test/cb", IdpHint: hintPtr(max)})
	if err != nil {
		t.Fatalf("256 bytes must be accepted: %v", err)
	}
	if parsedQuery(t, req.URL).Get("axiam_idp_hint") != max {
		t.Error("a 256-byte hint must be emitted unchanged")
	}
}

func TestParIdpHintInPushedBody(t *testing.T) {
	for _, tc := range []struct {
		name string
		hint *string
	}{{"set", hintPtr("corp-okta")}, {"unset", nil}} {
		t.Run(tc.name, func(t *testing.T) {
			server, capture := parServer(t, parCreated)
			client := parClient(t, server)
			configuration := discoveryDoc(server.URL)
			request, err := client.OidcBegin(configuration, OidcBeginParams{RedirectURI: parRedirectURI, IdpHint: tc.hint})
			if err != nil {
				t.Fatal(err)
			}
			pushed, err := client.OidcPar(context.Background(), OidcParParams{
				Request: request, RedirectURI: parRedirectURI, TenantID: parTenantUUID,
				Configuration: &configuration, IdpHint: tc.hint,
			})
			if err != nil {
				t.Fatalf("OidcPar: %v", err)
			}
			form := capture.forms[0]
			if tc.hint != nil {
				if got := form["axiam_idp_hint"]; len(got) != 1 || got[0] != *tc.hint {
					t.Errorf("pushed axiam_idp_hint = %q", got)
				}
			} else if form.Has("axiam_idp_hint") {
				t.Error("no hint: the field must be absent from the pushed body")
			}
			q := parsedQuery(t, pushed.AuthorizationURL)
			if got := sortedKeys(q); !reflect.DeepEqual(got, []string{"client_id", "request_uri"}) {
				t.Errorf("the redirect URL must carry exactly client_id and request_uri, got %v", got)
			}
		})
	}
	t.Run("bounds refuse before any request", func(t *testing.T) {
		server, capture := parServer(t, parCreated)
		client := parClient(t, server)
		configuration := discoveryDoc(server.URL)
		for _, h := range []string{"", strings.Repeat("a", 257)} {
			_, err := client.OidcPar(context.Background(), OidcParParams{
				RedirectURI: parRedirectURI, TenantID: parTenantUUID, Configuration: &configuration, IdpHint: hintPtr(h),
			})
			var ve *ValidationError
			if !errors.As(err, &ve) {
				t.Errorf("hint of %d bytes: want *ValidationError, got %T %v", len(h), err, err)
			}
		}
		if atomic.LoadInt32(&capture.calls) != 0 {
			t.Error("a refused hint must send nothing")
		}
	})
}

// ---------------------------------------------------------------------------
// §9 refresh-reuse confirmation (contract 1.65, informative (c))
// ---------------------------------------------------------------------------

func TestOidcRefresh_InvalidGrantConfirmation(t *testing.T) {
	const waiters = 8
	srv := newOidcTestServer(t)
	gate := make(chan struct{})
	var mu sync.Mutex
	var presented []string
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		mu.Lock()
		presented = append(presented, r.Form.Get("refresh_token"))
		mu.Unlock()
		<-gate
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"refresh token already used"}`))
	}
	client, err := NewClient(srv.URL, "acme", WithOidcClientID(testClientID))
	if err != nil {
		t.Fatal(err)
	}
	cfg := discoveryDoc(srv.URL)
	spent := Sensitive("spent-refresh-token")

	// Hold the single wire call open until every waiter has been released.
	started := make(chan struct{}, waiters)
	errs := make([]error, waiters)
	var wg sync.WaitGroup
	for i := 0; i < waiters; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			started <- struct{}{}
			_, errs[i] = client.OidcRefresh(context.Background(), OidcRefreshParams{
				RefreshToken: spent, TenantID: testTenantID, Configuration: &cfg,
			})
		}(i)
	}
	for i := 0; i < waiters; i++ {
		<-started
	}
	for deadline := time.Now().Add(5 * time.Second); srv.TokenCalls() < 1 && time.Now().Before(deadline); {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond) // let the other goroutines join the flight
	close(gate)
	wg.Wait()

	if n := srv.TokenCalls(); n != 1 {
		t.Fatalf("exactly one wire call, got %d", n)
	}
	var first *OAuthProtocolError
	for i, err := range errs {
		pe := asProtocolErr(t, err)
		if pe.ErrorCode != "invalid_grant" {
			t.Errorf("waiter %d: error = %q", i, pe.ErrorCode)
		}
		if first == nil {
			first = pe
		} else if pe != first {
			t.Errorf("waiter %d did not receive the one shared error", i)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(presented) != 1 || presented[0] != spent.Expose() {
		t.Errorf("the spent token must be presented exactly once, got %v", presented)
	}
}

// ---------------------------------------------------------------------------
// W4.13 fix round: C165-06, C165-14, C165-11 (D-N36)
// ---------------------------------------------------------------------------

// C165-06: a Client built without WithOidcClientID is refused before any
// request, with the taxonomy *AuthError.
func TestNativeSignIn_MissingClientIDRefusedLocally(t *testing.T) {
	e := newNativeEnv(t, okTokens(t))
	c, err := NewClient(e.srv.URL, "acme")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = c.LoginWithProviderIdToken(context.Background(), e.params())
	var ae *AuthError
	if !errors.As(err, &ae) {
		t.Fatalf("want *AuthError, got %T %v", err, err)
	}
	if e.Total() != 0 {
		t.Errorf("zero requests expected, got %d", e.Total())
	}
}

// C165-14 / §12.1 rule 3: a 307 from an /oauth2/* POST is not followed and is a
// *NetworkError; the redirect target sees no request.
func TestNativeSignIn_RedirectNotFollowed(t *testing.T) {
	var otherHits int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&otherHits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer other.Close()

	for _, status := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect, http.StatusFound} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			e := newNativeEnv(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", other.URL+"/steal")
				w.WriteHeader(status)
			})
			c := e.client(t)
			_, err := c.LoginWithProviderIdToken(context.Background(), e.params())
			var ne *NetworkError
			if !errors.As(err, &ne) {
				t.Fatalf("want *NetworkError, got %T %v", err, err)
			}
			if strings.Contains(err.Error(), other.URL) || strings.Contains(err.Error(), nativeFixtureTok) {
				t.Errorf("the error must not echo the Location or the token: %v", err)
			}
			if got := atomic.LoadInt32(&otherHits); got != 0 {
				t.Errorf("the redirect target received %d request(s)", got)
			}
			if got := len(e.Seen()); got != 1 {
				t.Errorf("the token endpoint must see exactly one request, got %d", got)
			}
		})
	}
}

// D-N36: a request from OidcBegin(IdpHint) passed to OidcPar with no IdpHint
// pushes the begin URL's hint exactly once.
func TestParIdpHintFromBeginURLPushed(t *testing.T) {
	server, capture := parServer(t, parCreated)
	client := parClient(t, server)
	configuration := discoveryDoc(server.URL)
	request, err := client.OidcBegin(configuration, OidcBeginParams{RedirectURI: parRedirectURI, IdpHint: hintPtr("corp-okta")})
	if err != nil {
		t.Fatal(err)
	}
	pushed, err := client.OidcPar(context.Background(), OidcParParams{
		Request: request, RedirectURI: parRedirectURI, TenantID: parTenantUUID, Configuration: &configuration,
	})
	if err != nil {
		t.Fatalf("OidcPar: %v", err)
	}
	if got := capture.forms[0]["axiam_idp_hint"]; len(got) != 1 || got[0] != "corp-okta" {
		t.Errorf("pushed axiam_idp_hint = %q, want [corp-okta]", got)
	}
	if got := sortedKeys(parsedQuery(t, pushed.AuthorizationURL)); !reflect.DeepEqual(got, []string{"client_id", "request_uri"}) {
		t.Errorf("the redirect URL must carry exactly client_id and request_uri, got %v", got)
	}
}

// D-N36: the IdpHint argument wins over the begin URL's hint.
func TestParIdpHintArgumentWins(t *testing.T) {
	server, capture := parServer(t, parCreated)
	client := parClient(t, server)
	configuration := discoveryDoc(server.URL)
	request, err := client.OidcBegin(configuration, OidcBeginParams{RedirectURI: parRedirectURI, IdpHint: hintPtr("corp-okta")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.OidcPar(context.Background(), OidcParParams{
		Request: request, RedirectURI: parRedirectURI, TenantID: parTenantUUID, Configuration: &configuration,
		IdpHint: hintPtr("other"),
	}); err != nil {
		t.Fatalf("OidcPar: %v", err)
	}
	if got := capture.forms[0]["axiam_idp_hint"]; len(got) != 1 || got[0] != "other" {
		t.Errorf("pushed axiam_idp_hint = %q, want [other] and never corp-okta", got)
	}
}
