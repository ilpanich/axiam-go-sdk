package axiam

// CIBA — CONTRACT.md §33.8's sixteen required tests (nine initiation and
// polling, four ping, three signed request), numbered t01–t16 as in the Rust
// reference, plus the edges around them.
//
// No credential, key or token literal: the client secret, the auth_req_id, the
// notification token and every signing key are generated at run time.

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
)

const cibaClientID = "ciba-client"

var cibaTenant = uuid.NewString()

type cibaSeen struct {
	form  url.Values
	query url.Values
	at    time.Duration
}

// cibaTestServer serves bc-authorize and the token endpoint from scripts, and a
// JWKS for the ID tokens it mints.
type cibaTestServer struct {
	*httptest.Server
	t      *testing.T
	mu     sync.Mutex
	clock  *cibaTestClock
	all    atomic.Int32
	bc     []cibaSeen
	token  []cibaSeen
	bcResp func(w http.ResponseWriter)
	script []func(w http.ResponseWriter)
	kid    string
	priv   ed25519.PrivateKey
}

func newCibaTestServer(t *testing.T) *cibaTestServer {
	t.Helper()
	s := &cibaTestServer{t: t, kid: "ciba-id-token-key"}
	priv, pub := generateOidcTestKey(t, s.kid)
	s.priv = priv
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(marshalOidcJWKS(t, pub))
	})
	mux.HandleFunc("/oauth2/bc-authorize", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		s.mu.Lock()
		s.bc = append(s.bc, cibaSeen{form: r.PostForm, query: r.URL.Query()})
		respond := s.bcResp
		s.mu.Unlock()
		if respond == nil {
			w.WriteHeader(http.StatusNotImplemented)
			return
		}
		respond(w)
	})
	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		s.mu.Lock()
		seen := cibaSeen{form: r.PostForm, query: r.URL.Query()}
		if s.clock != nil {
			seen.at = s.clock.elapsed()
		}
		s.token = append(s.token, seen)
		i := len(s.token) - 1
		if i >= len(s.script) {
			i = len(s.script) - 1
		}
		var respond func(http.ResponseWriter)
		if i >= 0 {
			respond = s.script[i]
		}
		s.mu.Unlock()
		if respond == nil {
			w.WriteHeader(http.StatusNotImplemented)
			return
		}
		respond(w)
	})
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.all.Add(1)
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *cibaTestServer) bcSeen() []cibaSeen {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]cibaSeen(nil), s.bc...)
}

func (s *cibaTestServer) tokenSeen() []cibaSeen {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]cibaSeen(nil), s.token...)
}

func (s *cibaTestServer) configuration() *OidcConfiguration {
	doc := discoveryDoc(s.URL)
	return &doc
}

func jsonReply(status int, body any) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}
}

func oauthErrorReply(status int, code string) func(http.ResponseWriter) {
	return jsonReply(status, map[string]any{"error": code, "error_description": code + " here"})
}

func bareReply(status int) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) { w.WriteHeader(status) }
}

func (s *cibaTestServer) tokensReply(t *testing.T) func(http.ResponseWriter) {
	claims := validIDTokenClaims(s.Server, cibaClientID, "")
	delete(claims, "nonce")
	idToken := signIDTokenEdDSA(t, s.priv, s.kid, claims)
	return jsonReply(200, map[string]any{
		"access_token": randomSecret(t, "at-"), "token_type": "Bearer", "expires_in": 900,
		"scope": "openid profile", "id_token": idToken,
	})
}

func cibaTestClient(t *testing.T, base string, opts ...Option) (*Client, string) {
	t.Helper()
	secret := randomSecret(t, "cs-")
	all := append([]Option{WithOidcClientID(cibaClientID), WithOidcClientSecret(secret)}, opts...)
	c, err := NewClient(base, "acme", all...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, secret
}

func (s *cibaTestServer) params() CibaInitiateParams {
	return CibaInitiateParams{Scope: "openid profile", LoginHint: "ada", TenantID: cibaTenant, Configuration: s.configuration()}
}

// cibaTestClock never sleeps: Sleep advances it and records the wait.
type cibaTestClock struct {
	mu     sync.Mutex
	start  time.Time
	offset time.Duration
	sleeps []time.Duration
}

func newCibaTestClock() *cibaTestClock { return &cibaTestClock{start: time.Now()} }

func (c *cibaTestClock) elapsed() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.offset
}

func (c *cibaTestClock) Now() time.Time { return c.start.Add(c.elapsed()) }

func (c *cibaTestClock) Sleep(_ context.Context, d time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.offset += d
	c.sleeps = append(c.sleeps, d)
	return nil
}

func (c *cibaTestClock) sleepSeconds() []int {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]int, 0, len(c.sleeps))
	for _, d := range c.sleeps {
		out = append(out, int(d/time.Second))
	}
	return out
}

func initiatedAt(start time.Time, expiresIn, interval int) CibaInitiateResponse {
	return CibaInitiateResponse{AuthReqID: Sensitive(uuid.NewString()), ExpiresIn: expiresIn, Interval: interval, ReceivedAt: start}
}

func formKeys(v url.Values) []string {
	out := make([]string, 0, len(v))
	for k := range v {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ── t01. Redaction ──────────────────────────────────────────────────────────

func TestCiba_T01_TheValuesAreOnTheWireAndInNoRendering(t *testing.T) {
	s := newCibaTestServer(t)
	c, _ := cibaTestClient(t, s.URL)
	notification := randomSecret(t, "cnt-")
	authReqID := randomSecret(t, "arid-")
	s.bcResp = jsonReply(200, map[string]any{"auth_req_id": authReqID, "expires_in": 120, "interval": 5})
	p := s.params()
	p.Delivery = CibaDeliveryPing
	p.ClientNotificationToken = Sensitive(notification)
	assertNoFragmentIn(t, p, notification, "CibaInitiateParams")

	response, err := c.CibaInitiate(context.Background(), p)
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}
	assertNoFragmentIn(t, response, authReqID, "CibaInitiateResponse")
	if response.AuthReqID.Expose() != authReqID {
		t.Fatal("the auth_req_id is returned")
	}
	if s.bcSeen()[0].form.Get("client_notification_token") != notification {
		t.Fatal("the notification token is on the wire")
	}

	s.mu.Lock()
	s.bcResp = oauthErrorReply(400, "invalid_binding_message")
	s.mu.Unlock()
	_, err = c.CibaInitiate(context.Background(), p)
	var protocolErr *OAuthProtocolError
	if !errors.As(err, &protocolErr) || protocolErr.ErrorCode != "invalid_binding_message" ||
		protocolErr.ErrorDescription != "invalid_binding_message here" {
		t.Fatalf("invalid_binding_message surfaces with its description, got %T", err)
	}
	assertNoFragment(t, errorRenderings(err), notification, "initiate error")
}

// ── t02. Client authentication is mandatory ─────────────────────────────────

func TestCiba_T02_NoCredentialIsRefusedLocallyAndOneIsSentWithTheTenantInTheQuery(t *testing.T) {
	s := newCibaTestServer(t)
	s.bcResp = jsonReply(200, map[string]any{"auth_req_id": uuid.NewString(), "expires_in": 120})
	s.script = []func(http.ResponseWriter){oauthErrorReply(400, "authorization_pending")}
	ctx := context.Background()
	pollParams := CibaPollParams{AuthReqID: Sensitive(uuid.NewString()), TenantID: cibaTenant, Configuration: s.configuration()}

	public, err := NewClient(s.URL, "acme", WithOidcClientID(cibaClientID))
	if err != nil {
		t.Fatal(err)
	}
	anonymous, err := NewClient(s.URL, "acme")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []*Client{public, anonymous} {
		var authErr *AuthError
		if _, err := c.CibaInitiate(ctx, s.params()); !errors.As(err, &authErr) {
			t.Fatalf("initiate without a credential: want AuthError, got %T", err)
		}
		if _, err := c.CibaPoll(ctx, pollParams); !errors.As(err, &authErr) {
			t.Fatalf("poll without a credential: want AuthError, got %T", err)
		}
	}
	if s.all.Load() != 0 {
		t.Fatal("no request without a credential")
	}

	c, secret := cibaTestClient(t, s.URL)
	if _, err := c.CibaInitiate(ctx, s.params()); err != nil {
		t.Fatalf("initiate: %v", err)
	}
	_, _ = c.CibaPoll(ctx, pollParams)
	for _, seen := range []cibaSeen{s.bcSeen()[0], s.tokenSeen()[0]} {
		if seen.form.Get("client_id") != cibaClientID || seen.form.Get("client_secret") != secret {
			t.Fatal("the registered credential is sent")
		}
		if seen.form.Has("tenant_id") {
			t.Fatal("tenant_id is never a body field")
		}
		if seen.query.Get("tenant_id") != cibaTenant {
			t.Fatal("tenant_id travels in the query")
		}
	}

	// A tls_client_auth client: the certificate is the credential.
	certPEM, keyPEM := testClientIdentity(t)
	mtls, err := NewClient(s.URL, "acme", WithOidcClientID(cibaClientID), WithClientCertificate(certPEM, keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mtls.CibaInitiate(ctx, s.params()); err != nil {
		t.Fatalf("certificate client: %v", err)
	}
	form := s.bcSeen()[1].form
	if form.Get("client_id") != cibaClientID || form.Has("client_secret") {
		t.Fatal("an mTLS client sends client_id only")
	}
}

// ── t03. The initiate request ───────────────────────────────────────────────

func TestCiba_T03_ExactlyTheMembersSetAreSent(t *testing.T) {
	s := newCibaTestServer(t)
	c, _ := cibaTestClient(t, s.URL)
	s.bcResp = jsonReply(200, map[string]any{"auth_req_id": uuid.NewString(), "expires_in": 120})
	ctx := context.Background()
	if _, err := c.CibaInitiate(ctx, s.params()); err != nil {
		t.Fatal(err)
	}
	full := s.params()
	full.LoginHint = ""
	full.IDTokenHint = "an.id.token"
	full.BindingMessage = "W4SCT"
	full.RequestedExpiry = 120
	full.AcrValues = "urn:axiam:acr:mfa"
	full.Resource = "https://api.example.test"
	token := randomSecret(t, "cnt-")
	full.Delivery = CibaDeliveryPing
	full.ClientNotificationToken = Sensitive(token)
	if _, err := c.CibaInitiate(ctx, full); err != nil {
		t.Fatal(err)
	}
	sent := s.bcSeen()
	if got := formKeys(sent[0].form); !reflect.DeepEqual(got, []string{"client_id", "client_secret", "login_hint", "scope"}) {
		t.Fatalf("minimal form: %v", got)
	}
	want := []string{"acr_values", "binding_message", "client_id", "client_notification_token", "client_secret",
		"id_token_hint", "requested_expiry", "resource", "scope"}
	if got := formKeys(sent[1].form); !reflect.DeepEqual(got, want) {
		t.Fatalf("full form: %v", got)
	}
	if sent[1].form.Get("requested_expiry") != "120" || sent[1].form.Get("client_notification_token") != token {
		t.Fatal("requested_expiry travels as a string on the form; the token as given")
	}

	// No parameter exists for login_hint_token, user_code or request_uri.
	typ := reflect.TypeOf(CibaInitiateParams{})
	for _, forbidden := range []string{"LoginHintToken", "UserCode", "RequestURI", "ExtraParams"} {
		if _, has := typ.FieldByName(forbidden); has {
			t.Fatalf("CibaInitiateParams must have no %s", forbidden)
		}
	}
	both := s.params()
	both.IDTokenHint = "x.y.z"
	neither := s.params()
	neither.LoginHint = ""
	pingWithout := s.params()
	pingWithout.Delivery = CibaDeliveryPing
	pollWith := s.params()
	pollWith.ClientNotificationToken = Sensitive(token)
	push := s.params()
	push.Delivery = "push"
	for i, bad := range []CibaInitiateParams{both, neither, pingWithout, pollWith, push} {
		var verr *ValidationError
		if _, err := c.CibaInitiate(ctx, bad); !errors.As(err, &verr) {
			t.Fatalf("case %d: want a local ValidationError, got %T", i, err)
		}
	}
	if len(s.bcSeen()) != 2 {
		t.Fatal("the refused requests sent nothing")
	}
}

// ── t04. No retry on initiate ───────────────────────────────────────────────

func TestCiba_T04_InitiateIsSentOnceOn503And429AndADroppedConnection(t *testing.T) {
	for _, status := range []int{503, 429} {
		s := newCibaTestServer(t)
		c, _ := cibaTestClient(t, s.URL, withJitterSource(func() float64 { return 0 }))
		if status == 429 {
			s.bcResp = oauthErrorReply(429, "rate_limit_exceeded")
		} else {
			s.bcResp = bareReply(503)
		}
		_, err := c.CibaInitiate(context.Background(), s.params())
		if len(s.bcSeen()) != 1 {
			t.Fatalf("%d: exactly one request, got %d", status, len(s.bcSeen()))
		}
		var netErr *NetworkError
		var protocolErr *OAuthProtocolError
		if status == 503 && !errors.As(err, &netErr) {
			t.Fatalf("503: want NetworkError, got %T", err)
		}
		if status == 429 && (!errors.As(err, &protocolErr) || protocolErr.ErrorCode != "rate_limit_exceeded") {
			t.Fatalf("429: §2's /oauth2 row gives an OAuthProtocolError, got %T", err)
		}
	}

	// A listener that accepts and hangs up.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	var accepts atomic.Int32
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			_ = conn.Close()
		}
	}()
	s := newCibaTestServer(t)
	c, _ := cibaTestClient(t, s.URL)
	p := s.params()
	p.Configuration.BackchannelAuthenticationEndpoint = "http://" + listener.Addr().String() + "/oauth2/bc-authorize"
	_, err = c.CibaInitiate(context.Background(), p)
	var netErr *NetworkError
	if !errors.As(err, &netErr) {
		t.Fatalf("a dropped connection is a NetworkError, got %T", err)
	}
	time.Sleep(100 * time.Millisecond)
	if accepts.Load() != 1 {
		t.Fatalf("one connection, no retry: got %d", accepts.Load())
	}
}

// ── t05. Poll outcomes ──────────────────────────────────────────────────────

func TestCiba_T05_PendingLoopsSlowDownPersistsAndTheTerminalAnswersAreDistinct(t *testing.T) {
	s := newCibaTestServer(t)
	c, _ := cibaTestClient(t, s.URL)
	clock := newCibaTestClock()
	s.clock = clock
	s.script = []func(http.ResponseWriter){
		oauthErrorReply(400, "slow_down"), oauthErrorReply(400, "slow_down"),
		oauthErrorReply(400, "authorization_pending"), s.tokensReply(t),
	}
	initiated := initiatedAt(clock.start, 600, 5)
	set, err := c.CibaAwait(context.Background(), initiated, CibaAwaitParams{
		TenantID: cibaTenant, Configuration: s.configuration(), Clock: clock})
	if err != nil {
		t.Fatalf("tokens: %v", err)
	}
	if set.IDClaims == nil {
		t.Fatal("the ID token is validated")
	}
	if got := clock.sleepSeconds(); !reflect.DeepEqual(got, []int{5, 10, 15, 15}) {
		t.Fatalf("+5 s twice, and pending lowers nothing: %v", got)
	}
	for _, seen := range s.tokenSeen() {
		if seen.form.Get("grant_type") != CibaGrantType || seen.form.Get("auth_req_id") != initiated.AuthReqID.Expose() {
			t.Fatal("every poll is the CIBA grant for the request")
		}
	}

	for _, tc := range []struct {
		code  string
		check func(error) bool
	}{
		{"access_denied", func(e error) bool { return errors.Is(e, ErrAccessDenied) && !errors.Is(e, ErrExpiredToken) }},
		{"expired_token", func(e error) bool { return errors.Is(e, ErrExpiredToken) && !errors.Is(e, ErrAccessDenied) }},
		{"invalid_grant", func(e error) bool {
			var p *OAuthProtocolError
			return errors.As(e, &p) && p.ErrorCode == "invalid_grant"
		}},
		{"a_code_nobody_defined", func(e error) bool {
			var p *OAuthProtocolError
			return errors.As(e, &p) && p.ErrorCode == "a_code_nobody_defined" && errors.Is(e, ErrAuth)
		}},
	} {
		s := newCibaTestServer(t)
		c, _ := cibaTestClient(t, s.URL)
		clock := newCibaTestClock()
		s.script = []func(http.ResponseWriter){oauthErrorReply(400, tc.code)}
		_, err := c.CibaAwait(context.Background(), initiatedAt(clock.start, 600, 5), CibaAwaitParams{
			TenantID: cibaTenant, Configuration: s.configuration(), Clock: clock})
		if !tc.check(err) {
			t.Fatalf("%s: unexpected outcome %T", tc.code, err)
		}
		if len(s.tokenSeen()) != 1 {
			t.Fatalf("%s is terminal: %d requests", tc.code, len(s.tokenSeen()))
		}
	}
}

// ── t06. The first poll waits ───────────────────────────────────────────────

func TestCiba_T06_TheFirstPollWaitsTheIntervalOrFiveSeconds(t *testing.T) {
	for _, tc := range []struct {
		interval any
		want     int
	}{{7, 7}, {nil, 5}, {0, 5}} {
		s := newCibaTestServer(t)
		c, _ := cibaTestClient(t, s.URL)
		clock := newCibaTestClock()
		s.clock = clock
		body := map[string]any{"auth_req_id": uuid.NewString(), "expires_in": 300}
		if tc.interval != nil {
			body["interval"] = tc.interval
		}
		s.bcResp = jsonReply(200, body)
		s.script = []func(http.ResponseWriter){oauthErrorReply(400, "access_denied")}
		response, err := c.CibaInitiate(context.Background(), s.params())
		if err != nil {
			t.Fatal(err)
		}
		if response.Interval != tc.want || response.ExpiresIn != 300 {
			t.Fatalf("interval: got %d, want %d", response.Interval, tc.want)
		}
		response.ReceivedAt = clock.start
		_, _ = c.CibaAwait(context.Background(), response, CibaAwaitParams{
			TenantID: cibaTenant, Configuration: s.configuration(), Clock: clock})
		if at := s.tokenSeen()[0].at; at != time.Duration(tc.want)*time.Second {
			t.Fatalf("the first poll at %v, want %ds", at, tc.want)
		}
	}
}

// ── t07. Deadline ───────────────────────────────────────────────────────────

func TestCiba_T07_NoRequestAfterExpiresInAndExpiredTokenIsRaisedLocally(t *testing.T) {
	s := newCibaTestServer(t)
	c, _ := cibaTestClient(t, s.URL)
	clock := newCibaTestClock()
	s.clock = clock
	s.script = []func(http.ResponseWriter){oauthErrorReply(400, "authorization_pending")}
	_, err := c.CibaAwait(context.Background(), initiatedAt(clock.start, 12, 5), CibaAwaitParams{
		TenantID: cibaTenant, Configuration: s.configuration(), Clock: clock})
	if !errors.Is(err, ErrExpiredToken) {
		t.Fatalf("want the local expired_token, got %T", err)
	}
	var at []time.Duration
	for _, seen := range s.tokenSeen() {
		at = append(at, seen.at)
	}
	if !reflect.DeepEqual(at, []time.Duration{5 * time.Second, 10 * time.Second}) {
		t.Fatalf("nothing at 15 s, past the 12 s deadline: %v", at)
	}
}

// ── t08. Transient failure is not terminal ──────────────────────────────────

func TestCiba_T08_A500AndA429MidLoopAreSurvived(t *testing.T) {
	s := newCibaTestServer(t)
	c, _ := cibaTestClient(t, s.URL, withJitterSource(func() float64 { return 0 }))
	clock := newCibaTestClock()
	s.script = []func(http.ResponseWriter){
		oauthErrorReply(400, "authorization_pending"), bareReply(500),
		oauthErrorReply(429, "rate_limit_exceeded"), s.tokensReply(t),
	}
	set, err := c.CibaAwait(context.Background(), initiatedAt(clock.start, 600, 5), CibaAwaitParams{
		TenantID: cibaTenant, Configuration: s.configuration(), Clock: clock})
	if err != nil {
		t.Fatalf("the loop succeeds after the transient failures: %v", err)
	}
	if set.AccessToken == "" || set.IDToken == "" || set.IDClaims == nil {
		t.Fatal("the 200 is returned with its id_token and access_token")
	}
	if len(s.tokenSeen()) != 4 {
		t.Fatalf("four requests, got %d", len(s.tokenSeen()))
	}

	// A 5xx that outlives §16 inside one poll is transient for the loop too.
	s2 := newCibaTestServer(t)
	c2, _ := cibaTestClient(t, s2.URL, withJitterSource(func() float64 { return 0 }))
	clock2 := newCibaTestClock()
	s2.script = []func(http.ResponseWriter){bareReply(503), bareReply(503), bareReply(503), s2.tokensReply(t)}
	if _, err := c2.CibaAwait(context.Background(), initiatedAt(clock2.start, 600, 5), CibaAwaitParams{
		TenantID: cibaTenant, Configuration: s2.configuration(), Clock: clock2}); err != nil {
		t.Fatalf("an exhausted §16 run is waited out: %v", err)
	}
	if got := clock2.sleepSeconds(); !reflect.DeepEqual(got, []int{5, 5}) {
		t.Fatalf("one interval per failed poll: %v", got)
	}
}

// ── t09. Single use ─────────────────────────────────────────────────────────

func TestCiba_T09_ASecondRedemptionIsInvalidGrantAndNotRetried(t *testing.T) {
	s := newCibaTestServer(t)
	c, _ := cibaTestClient(t, s.URL)
	s.script = []func(http.ResponseWriter){s.tokensReply(t), oauthErrorReply(400, "invalid_grant")}
	params := CibaPollParams{AuthReqID: Sensitive(randomSecret(t, "arid-")), TenantID: cibaTenant, Configuration: s.configuration()}
	if _, err := c.CibaPoll(context.Background(), params); err != nil {
		t.Fatalf("redeemed: %v", err)
	}
	_, err := c.CibaPoll(context.Background(), params)
	var protocolErr *OAuthProtocolError
	if !errors.As(err, &protocolErr) || protocolErr.ErrorCode != "invalid_grant" {
		t.Fatalf("want invalid_grant, got %T", err)
	}
	if len(s.tokenSeen()) != 2 {
		t.Fatalf("no retry of the second: %d requests", len(s.tokenSeen()))
	}
}

// ── t10–t13. The ping ───────────────────────────────────────────────────────

func pingHeaders(values ...string) http.Header {
	h := http.Header{"Content-Type": {"application/json"}}
	if len(values) > 0 {
		h["Authorization"] = append([]string(nil), values...)
	}
	return h
}

func TestCiba_T10_AValidPingReturnsItsAuthReqIDInAnySchemeCase(t *testing.T) {
	c, _ := cibaTestClient(t, "https://iam.example.test")
	token := randomSecret(t, "cnt-")
	id := randomSecret(t, "arid-")
	body := []byte(`{"auth_req_id":"` + id + `"}`)
	for _, scheme := range []string{"Bearer", "bearer", "BEARER"} {
		got, err := c.CibaHandlePing(pingHeaders(scheme+" "+token), body, Sensitive(token))
		if err != nil {
			t.Fatalf("%s: accepted, got %T", scheme, err)
		}
		if got.Expose() != id {
			t.Fatal("the auth_req_id is returned")
		}
		assertNoFragmentIn(t, got, id, "ping result")
	}
	// A header map whose key a framework did not canonicalise still matches.
	got, err := c.CibaHandlePing(http.Header{"authorization": {"Bearer " + token}}, body, Sensitive(token))
	if err != nil || got.Expose() != id {
		t.Fatal("the header name is matched case-insensitively")
	}
}

func TestCiba_T11_AWrongAbsentEmptyDuplicateOrBasicAuthorizationIsRefused(t *testing.T) {
	c, _ := cibaTestClient(t, "https://iam.example.test")
	token := randomSecret(t, "cnt-")
	lastDiffers := token[:len(token)-1] + "a"
	if lastDiffers == token {
		lastDiffers = token[:len(token)-1] + "b"
	}
	body := []byte(`{"auth_req_id":"` + uuid.NewString() + `"}`)
	cases := []http.Header{
		pingHeaders("Bearer " + randomSecret(t, "cnt-")),
		pingHeaders(),
		pingHeaders(""),
		pingHeaders("Bearer "),
		pingHeaders("Bearer "+token, "Bearer "+token),
		{"Authorization": {"Bearer " + token}, "authorization": {"Bearer " + token}},
		pingHeaders("Basic " + token),
		pingHeaders("Bearer " + lastDiffers),
		pingHeaders("Bearer  " + token),
		pingHeaders("Bearer" + token),
	}
	for i, headers := range cases {
		_, err := c.CibaHandlePing(headers, body, Sensitive(token))
		var authErr *AuthError
		if !errors.As(err, &authErr) {
			t.Fatalf("case %d: want AuthError, got %T", i, err)
		}
		assertNoFragment(t, errorRenderings(err), token, fmt.Sprintf("case %d", i))
	}
	var authErr *AuthError
	if _, err := c.CibaHandlePing(pingHeaders("Bearer "+token), body, ""); !errors.As(err, &authErr) {
		t.Fatal("an empty expected token matches nothing")
	}
	// Go has no timing harness here, so §33.8 test 11 is asserted
	// structurally: the comparison is crypto/subtle's.
	source, err := os.ReadFile("oidc_ciba.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(source), "subtle.ConstantTimeCompare([]byte(token), []byte(expected))") {
		t.Fatal("the token comparison must be subtle.ConstantTimeCompare")
	}
}

func TestCiba_T12_AMalformedBodyIsAValidationErrorAndExtrasAreIgnored(t *testing.T) {
	c, _ := cibaTestClient(t, "https://iam.example.test")
	token := randomSecret(t, "cnt-")
	headers := pingHeaders("Bearer " + token)
	for i, body := range []string{"not json", `{}`, `{"auth_req_id":""}`, `{"auth_req_id":42}`, `["auth_req_id"]`, `null`} {
		var verr *ValidationError
		if _, err := c.CibaHandlePing(headers, []byte(body), Sensitive(token)); !errors.As(err, &verr) {
			t.Fatalf("body %d: want ValidationError, got %T", i, err)
		}
	}
	id := uuid.NewString()
	got, err := c.CibaHandlePing(headers, []byte(`{"auth_req_id":"`+id+`","status":"approved","access_token":"x"}`), Sensitive(token))
	if err != nil || got.Expose() != id {
		t.Fatal("extra members are ignored")
	}
}

func TestCiba_T13_ThePingHelperMakesNoNetworkCall(t *testing.T) {
	s := newCibaTestServer(t)
	c, _ := cibaTestClient(t, s.URL)
	token := randomSecret(t, "cnt-")
	if _, err := c.CibaHandlePing(pingHeaders("Bearer "+token), []byte(`{"auth_req_id":"`+uuid.NewString()+`"}`), Sensitive(token)); err != nil {
		t.Fatal(err)
	}
	if s.all.Load() != 0 {
		t.Fatal("the transport was touched")
	}
}

// ── t14–t16. The signed form ────────────────────────────────────────────────

func ed25519PEM(t *testing.T) (Sensitive, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return Sensitive(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), pub
}

func decodeSegment(t *testing.T, part string) map[string]any {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestCiba_T14_TheSignedRequestIsOneMemberWithTheRegisteredAlgAndAFreshJti(t *testing.T) {
	s := newCibaTestServer(t)
	c, secret := cibaTestClient(t, s.URL)
	s.bcResp = jsonReply(200, map[string]any{"auth_req_id": uuid.NewString(), "expires_in": 120})
	keyPEM, pub := ed25519PEM(t)
	signer, err := NewCibaRequestSignerFromPEM(CibaSigningEdDSA, keyPEM, "client-key-1")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	notification := randomSecret(t, "cnt-")
	p := s.params()
	p.BindingMessage = "W4SCT"
	p.RequestedExpiry = 90
	p.Delivery = CibaDeliveryPing
	p.ClientNotificationToken = Sensitive(notification)
	p.Signer = signer
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if _, err := c.CibaInitiate(ctx, p); err != nil {
			t.Fatalf("initiate: %v", err)
		}
	}

	var jtis []string
	for _, seen := range s.bcSeen() {
		if got := formKeys(seen.form); !reflect.DeepEqual(got, []string{"client_id", "client_secret", "request"}) {
			t.Fatalf("nothing beside request: %v", got)
		}
		if seen.form.Get("client_secret") != secret {
			t.Fatal("client authentication rides beside it")
		}
		request := seen.form.Get("request")
		header := decodeSegment(t, strings.Split(request, ".")[0])
		if header["alg"] != "EdDSA" || header["kid"] != "client-key-1" {
			t.Fatalf("header: %v", header)
		}
		// The caller's key signed it, under the caller's algorithm.
		payload, err := jws.Verify([]byte(request), jws.WithKey(jwa.EdDSA(), pub))
		if err != nil {
			t.Fatalf("the signature verifies with the caller's public key: %v", err)
		}
		var claims map[string]any
		_ = json.Unmarshal(payload, &claims)
		exp, nbf, iat := claims["exp"].(float64), claims["nbf"].(float64), claims["iat"].(float64)
		if claims["iss"] != cibaClientID || claims["aud"] != s.URL || exp <= nbf || exp-nbf > 3600 || iat != nbf {
			t.Fatalf("iss/aud/exp/nbf/iat: %v", claims)
		}
		if claims["login_hint"] != "ada" || claims["binding_message"] != "W4SCT" ||
			claims["requested_expiry"] != float64(90) || claims["client_notification_token"] != notification ||
			claims["scope"] != "openid profile" {
			t.Fatal("every member travels inside the JWT, requested_expiry as a number")
		}
		jti, _ := claims["jti"].(string)
		if len(jti) < 22 {
			t.Fatal("a jti of at least 128 bits")
		}
		jtis = append(jtis, jti)
	}
	if len(jtis) != 2 || jtis[0] == jtis[1] {
		t.Fatal("a fresh jti per request")
	}

	// ES256 and PS256 sign under their own algorithm only.
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	for _, tc := range []struct {
		alg    CibaSigningAlg
		signer func() (*CibaRequestSigner, error)
		jose   jwa.SignatureAlgorithm
		pub    any
	}{
		{CibaSigningES256, func() (*CibaRequestSigner, error) { return NewCibaRequestSigner(CibaSigningES256, ecKey, "") }, jwa.ES256(), &ecKey.PublicKey},
		{CibaSigningPS256, func() (*CibaRequestSigner, error) { return NewCibaRequestSigner(CibaSigningPS256, rsaKey, "") }, jwa.PS256(), &rsaKey.PublicKey},
	} {
		signer, err := tc.signer()
		if err != nil || signer.Alg() != tc.alg {
			t.Fatalf("%s signer: %v", tc.alg, err)
		}
		p := s.params()
		p.Signer = signer
		if _, err := c.CibaInitiate(ctx, p); err != nil {
			t.Fatal(err)
		}
		seen := s.bcSeen()
		request := seen[len(seen)-1].form.Get("request")
		if header := decodeSegment(t, strings.Split(request, ".")[0]); header["alg"] != string(tc.alg) || header["kid"] != nil {
			t.Fatalf("%s header: %v", tc.alg, header)
		}
		if _, err := jws.Verify([]byte(request), jws.WithKey(tc.jose, tc.pub)); err != nil {
			t.Fatalf("%s verifies: %v", tc.alg, err)
		}
	}
}

func TestCiba_T15_NoKeyOrAKeyForAnotherAlgIsRefusedBeforeAnyRequest(t *testing.T) {
	s := newCibaTestServer(t)
	edPEM, _ := ed25519PEM(t)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecDER, _ := x509.MarshalECPrivateKey(ecKey)
	ecPEM := Sensitive(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER}))
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	smallRSA, _ := rsa.GenerateKey(rand.Reader, 1024)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaPEM := Sensitive(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)}))
	var verr *ValidationError
	for i, pemCase := range []struct {
		alg CibaSigningAlg
		pem Sensitive
	}{
		{CibaSigningEdDSA, ""},
		{CibaSigningEdDSA, "not a pem"},
		{CibaSigningES256, edPEM},
		{CibaSigningPS256, ecPEM},
		{CibaSigningEdDSA, ecPEM},
		{"HS256", edPEM},
		{"", edPEM},
		{CibaSigningEdDSA, Sensitive(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("junk")}))},
	} {
		if _, err := NewCibaRequestSignerFromPEM(pemCase.alg, pemCase.pem, ""); !errors.As(err, &verr) {
			t.Fatalf("pem case %d: want ValidationError, got %T", i, err)
		}
	}
	for i, keyCase := range []struct {
		alg CibaSigningAlg
		key crypto.Signer
	}{
		{CibaSigningEdDSA, nil},
		{CibaSigningES256, p384},
		{CibaSigningPS256, smallRSA},
	} {
		if _, err := NewCibaRequestSigner(keyCase.alg, keyCase.key, ""); !errors.As(err, &verr) {
			t.Fatalf("key case %d: want ValidationError, got %T", i, err)
		}
	}
	// PKCS#1 RSA and SEC 1 EC PEMs are accepted for their own algorithm.
	if _, err := NewCibaRequestSignerFromPEM(CibaSigningPS256, rsaPEM, ""); err != nil {
		t.Fatalf("PKCS#1: %v", err)
	}
	if _, err := NewCibaRequestSignerFromPEM(CibaSigningES256, ecPEM, ""); err != nil {
		t.Fatalf("SEC 1: %v", err)
	}
	// The algorithm and the key are the constructor's two required arguments,
	// so "no algorithm" cannot be written; and with a signer set every member
	// travels inside request — there is no channel for a form parameter beside
	// it (t14 asserts the form).
	if s.all.Load() != 0 {
		t.Fatal("no request")
	}
}

func TestCiba_T16_TheKeyAndTheRequestAppearInNoRendering(t *testing.T) {
	s := newCibaTestServer(t)
	c, _ := cibaTestClient(t, s.URL)
	s.bcResp = oauthErrorReply(400, "invalid_request")
	keyPEM, _ := ed25519PEM(t)
	bodyLine := strings.Split(keyPEM.Expose(), "\n")[1]
	signer, err := NewCibaRequestSignerFromPEM(CibaSigningEdDSA, keyPEM, "")
	if err != nil {
		t.Fatal(err)
	}
	p := s.params()
	p.Signer = signer
	_, initErr := c.CibaInitiate(context.Background(), p)
	if initErr == nil {
		t.Fatal("expected the 400")
	}
	request := s.bcSeen()[0].form.Get("request")
	for what, rendering := range map[string]string{
		"signer": renderings(signer), "params": renderings(p), "error": errorRenderings(initErr),
	} {
		assertNoFragment(t, rendering, bodyLine, what)
		assertNoFragment(t, rendering, request, what)
	}
	assertNoFragment(t, signer.GoString(), bodyLine, "GoString")
	if errors.Is(initErr, ErrNetwork) || errors.Is(initErr, ErrAccessDenied) {
		t.Fatal("an invalid_request OAuthProtocolError matches neither sentinel")
	}
	var nilSigner *CibaRequestSigner
	if !strings.Contains(nilSigner.String(), "nil") {
		t.Fatal("a nil signer renders")
	}
}

// ── Edges ───────────────────────────────────────────────────────────────────

func TestCiba_ADocumentWithoutTheEndpointIsUnsupported(t *testing.T) {
	s := newCibaTestServer(t)
	c, _ := cibaTestClient(t, s.URL)
	p := s.params()
	p.Configuration.BackchannelAuthenticationEndpoint = ""
	var authErr *AuthError
	if _, err := c.CibaInitiate(context.Background(), p); !errors.As(err, &authErr) || !strings.Contains(err.Error(), "does not support CIBA") {
		t.Fatalf("want the unsupported AuthError, got %T", err)
	}
	if s.all.Load() != 0 {
		t.Fatal("never a concatenated URL")
	}
}

func TestCiba_AwaitAdoptsOnlyWhenAskedAndHonoursCancellation(t *testing.T) {
	s := newCibaTestServer(t)
	c, _ := cibaTestClient(t, s.URL)
	s.script = []func(http.ResponseWriter){s.tokensReply(t)}
	clock := newCibaTestClock()
	set, err := c.CibaAwait(context.Background(), initiatedAt(clock.start, 600, 5), CibaAwaitParams{
		TenantID: cibaTenant, Configuration: s.configuration(), Clock: clock, AdoptAsCredential: true})
	if err != nil {
		t.Fatal(err)
	}
	if c.adoptedOidcCredential() != set.AccessToken {
		t.Fatal("AdoptAsCredential adopts the access token")
	}

	// The system clock honours a cancelled context.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.CibaAwait(ctx, initiatedAt(time.Now(), 600, 5), CibaAwaitParams{
		TenantID: cibaTenant, Configuration: s.configuration()}); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %T", err)
	}
	if err := (systemCibaClock{}).Sleep(context.Background(), time.Millisecond); err != nil {
		t.Fatal(err)
	}
}

func TestCiba_UndecodableAnswersAndAClosedClient(t *testing.T) {
	s := newCibaTestServer(t)
	c, _ := cibaTestClient(t, s.URL)
	s.bcResp = jsonReply(200, map[string]any{"expires_in": 120})
	s.script = []func(http.ResponseWriter){func(w http.ResponseWriter) { _, _ = w.Write([]byte("not json")) }}
	var netErr *NetworkError
	if _, err := c.CibaInitiate(context.Background(), s.params()); !errors.As(err, &netErr) {
		t.Fatalf("a response without auth_req_id is a NetworkError, got %T", err)
	}
	if _, err := c.CibaPoll(context.Background(), CibaPollParams{AuthReqID: "x", TenantID: cibaTenant,
		Configuration: s.configuration()}); !errors.As(err, &netErr) {
		t.Fatalf("an undecodable 200 is a NetworkError, got %T", err)
	}
	if len(s.tokenSeen()) != 1 {
		t.Fatal("an undecodable 200 is not retried: the request may be redeemed")
	}
	s.script = []func(http.ResponseWriter){bareReply(401)}
	var authErr *AuthError
	if _, err := c.CibaPoll(context.Background(), CibaPollParams{AuthReqID: "x", TenantID: cibaTenant,
		Configuration: s.configuration()}); !errors.As(err, &authErr) {
		t.Fatalf("a bodiless 401 maps by status, got %T", err)
	}
	_ = c.Close()
	if _, err := c.CibaInitiate(context.Background(), s.params()); !errors.As(err, &netErr) {
		t.Fatal("a closed client refuses")
	}
	if _, err := c.CibaPoll(context.Background(), CibaPollParams{}); !errors.As(err, &netErr) {
		t.Fatal("a closed client refuses")
	}
}
