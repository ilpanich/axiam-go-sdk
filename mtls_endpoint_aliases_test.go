package axiam

// RFC 8705 §5 mtls_endpoint_aliases — CONTRACT.md §21.3 rule 2 (contract 1.40).
//
// The rule has one sentence and three named ways to get it wrong, and this
// file is organised around them rather than around the SDK's method list:
//
//   - a call going over mTLS prefers the alias;
//   - a call NOT going over mTLS keeps the top-level entry;
//   - an ABSENT member means "no separate mTLS host", never "unsupported";
//   - only the six listed endpoints are ever aliased — not
//     authorization_endpoint, end_session_endpoint or jwks_uri;
//   - issuer is not an endpoint, does not move, and still governs `iss`
//     validation by exact string for a token minted at an alias host.
//
// Two httptest servers stand in for the two listeners a deployment runs. The
// §6.1 identity is a throwaway keypair minted in-process; the test servers
// speak plain HTTP, so no handshake occurs — what is under test is WHICH URL
// the SDK chooses, which the configured identity and the document decide, not
// the socket.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

const aliasTenantID = "11111111-2222-3333-4444-555555555555"

// aliasRecorder is a pair of servers plus the set of OAuth2 paths each was
// asked for. Both origins serve every endpoint, so choosing the wrong one is a
// RECORDED call rather than a 404 — the assertion then names the host used.
type aliasRecorder struct {
	conventional *httptest.Server
	mtls         *httptest.Server

	mu   sync.Mutex
	hits map[string][]string // path -> origins that received it, in order
}

func (r *aliasRecorder) record(origin, path string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hits[path] = append(r.hits[path], origin)
}

// origins returns which hosts received a POST to path.
func (r *aliasRecorder) origins(path string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.hits[path]...)
}

// assertOnly fails unless path was posted exactly once, to wantOrigin.
func (r *aliasRecorder) assertOnly(t *testing.T, path, wantOrigin string) {
	t.Helper()
	got := r.origins(path)
	if len(got) != 1 || got[0] != wantOrigin {
		t.Fatalf("%s: got origins %v, want exactly [%s]", path, got, wantOrigin)
	}
}

// oauth2Body is the reply each endpoint's caller will accept.
func oauth2Body(path string) (int, any) {
	switch path {
	case "/oauth2/device_authorization":
		return http.StatusOK, map[string]any{
			"device_code":      "device-code-value",
			"user_code":        "WDJB-MJHT",
			"verification_uri": "https://example.test/device",
			"expires_in":       30,
			"interval":         1,
		}
	case "/oauth2/par":
		// RFC 9126 §2.2 specifies Created, and the SDK asserts exactly that.
		return http.StatusCreated, map[string]any{
			"request_uri": "urn:ietf:params:oauth:request_uri:x",
			"expires_in":  60,
		}
	case "/oauth2/introspect":
		return http.StatusOK, map[string]any{"active": true}
	case "/oauth2/revoke":
		return http.StatusOK, map[string]any{}
	default:
		return http.StatusOK, map[string]any{
			"access_token": "access-token-value",
			"token_type":   "Bearer",
			"expires_in":   900,
		}
	}
}

var oauth2Paths = []string{
	"/oauth2/token",
	"/oauth2/introspect",
	"/oauth2/revoke",
	"/oauth2/device_authorization",
	"/oauth2/par",
}

// newAliasServers stands up both listeners. document is called with the two
// base URLs and must return the discovery body the conventional host serves.
func newAliasServers(t *testing.T, document func(base, mtlsBase string) any) *aliasRecorder {
	t.Helper()
	r := &aliasRecorder{hits: map[string][]string{}}

	mtlsMux := http.NewServeMux()
	r.mtls = httptest.NewServer(mtlsMux)
	t.Cleanup(r.mtls.Close)

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(document(r.conventional.URL, r.mtls.URL))
	})
	r.conventional = httptest.NewServer(mux)
	t.Cleanup(r.conventional.Close)

	for _, p := range oauth2Paths {
		path := p
		handler := func(origin string) http.HandlerFunc {
			return func(w http.ResponseWriter, _ *http.Request) {
				r.record(origin, path)
				status, body := oauth2Body(path)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(status)
				_ = json.NewEncoder(w).Encode(body)
			}
		}
		mux.HandleFunc(path, handler(r.conventional.URL))
		mtlsMux.HandleFunc(path, handler(r.mtls.URL))
	}
	return r
}

// aliasDoc is discoveryDoc plus the six aliases on mtlsBase.
func aliasDoc(base, mtlsBase string) OidcConfiguration {
	doc := discoveryDoc(base)
	doc.MtlsEndpointAliases = &MtlsEndpointAliases{
		TokenEndpoint:                      mtlsBase + "/oauth2/token",
		UserinfoEndpoint:                   mtlsBase + "/oauth2/userinfo",
		RevocationEndpoint:                 mtlsBase + "/oauth2/revoke",
		IntrospectionEndpoint:              mtlsBase + "/oauth2/introspect",
		DeviceAuthorizationEndpoint:        mtlsBase + "/oauth2/device_authorization",
		PushedAuthorizationRequestEndpoint: mtlsBase + "/oauth2/par",
	}
	return doc
}

// testClientIdentity mints a throwaway self-signed certificate + PKCS#8 key
// PEM pair for use as a §6.1 client identity. Nothing is committed.
func testClientIdentity(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "axiam-sdk-test-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
}

// aliasClient builds a Client against the conventional origin, optionally
// carrying a §6.1 identity so §21.3 rule 2 applies to every call it makes.
func aliasClient(t *testing.T, r *aliasRecorder, mtls bool) *Client {
	t.Helper()
	opts := []Option{
		WithOidcClientID("axiam-rp"),
		WithOidcClientSecret("rp-secret-value"),
	}
	if mtls {
		certPEM, keyPEM := testClientIdentity(t)
		opts = append(opts, WithClientCertificate(certPEM, keyPEM))
	}
	client, err := NewClient(r.conventional.URL, "acme", opts...)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// ── The document round-trips the member ────────────────────────────────────

func TestMtlsAliases_DiscoveryExposesTheMemberWhenPublished(t *testing.T) {
	r := newAliasServers(t, func(base, mtlsBase string) any { return aliasDoc(base, mtlsBase) })
	client := aliasClient(t, r, false)

	got, err := client.OidcDiscover(context.Background())
	if err != nil {
		t.Fatalf("OidcDiscover: %v", err)
	}
	if got.MtlsEndpointAliases == nil {
		t.Fatal("the member the server published must survive decoding")
	}
	if want := r.mtls.URL + "/oauth2/token"; got.MtlsEndpointAliases.TokenEndpoint != want {
		t.Fatalf("alias token_endpoint: got %q, want %q", got.MtlsEndpointAliases.TokenEndpoint, want)
	}
	// Alongside, never instead of: the conventional entry is untouched.
	if want := r.conventional.URL + "/oauth2/token"; got.TokenEndpoint != want {
		t.Fatalf("top-level token_endpoint: got %q, want %q", got.TokenEndpoint, want)
	}
}

func TestMtlsAliases_AbsentMemberDecodesToNilRatherThanFailing(t *testing.T) {
	r := newAliasServers(t, func(base, _ string) any { return discoveryDoc(base) })
	client := aliasClient(t, r, true)

	got, err := client.OidcDiscover(context.Background())
	if err != nil {
		t.Fatalf("a document with no aliases is valid, not an error: %v", err)
	}
	if got.MtlsEndpointAliases != nil {
		t.Fatalf("expected nil aliases, got %+v", got.MtlsEndpointAliases)
	}
}

func TestMtlsAliases_AbsentMemberMarshalsAsAbsentNotNull(t *testing.T) {
	// The server omits the key rather than writing null; so does this type.
	body, err := json.Marshal(discoveryDoc("https://iam.example.test"))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(body), "mtls_endpoint_aliases") {
		t.Fatalf("an absent member must not be serialised at all, got %s", body)
	}
}

// ── A call over mTLS prefers the alias ─────────────────────────────────────

func TestMtlsAliases_TokenEndpointCallGoesToTheAliasHost(t *testing.T) {
	r := newAliasServers(t, func(base, mtlsBase string) any { return aliasDoc(base, mtlsBase) })
	client := aliasClient(t, r, true)

	if _, err := client.LoginClientCredentials(context.Background(), LoginClientCredentialsParams{
		TenantID: aliasTenantID,
	}); err != nil {
		t.Fatalf("LoginClientCredentials: %v", err)
	}

	r.assertOnly(t, "/oauth2/token", r.mtls.URL)
}

func TestMtlsAliases_IntrospectRevokeDeviceAndParUseTheirAliases(t *testing.T) {
	r := newAliasServers(t, func(base, mtlsBase string) any { return aliasDoc(base, mtlsBase) })
	client := aliasClient(t, r, true)
	ctx := context.Background()

	if _, err := client.Introspect(ctx, IntrospectParams{Token: Sensitive("t"), TenantID: aliasTenantID}); err != nil {
		t.Fatalf("Introspect: %v", err)
	}
	if err := client.Revoke(ctx, RevokeParams{Token: Sensitive("t"), TenantID: aliasTenantID}); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := client.DeviceAuthorize(ctx, DeviceAuthorizeParams{TenantID: aliasTenantID}); err != nil {
		t.Fatalf("DeviceAuthorize: %v", err)
	}
	configuration, err := client.OidcDiscover(ctx)
	if err != nil {
		t.Fatalf("OidcDiscover: %v", err)
	}
	request, err := client.OidcBegin(configuration, OidcBeginParams{
		RedirectURI: "https://app.example.com/auth/callback",
		Scope:       "openid",
	})
	if err != nil {
		t.Fatalf("OidcBegin: %v", err)
	}
	if _, err := client.OidcPar(ctx, OidcParParams{
		Request:     request,
		RedirectURI: "https://app.example.com/auth/callback",
		Scope:       "openid",
		TenantID:    aliasTenantID,
	}); err != nil {
		t.Fatalf("OidcPar: %v", err)
	}

	for _, p := range []string{"/oauth2/introspect", "/oauth2/revoke", "/oauth2/device_authorization", "/oauth2/par"} {
		r.assertOnly(t, p, r.mtls.URL)
	}
}

func TestMtlsAliases_AliasURLKeepsTheMandatoryTenantIDParameter(t *testing.T) {
	r := newAliasServers(t, func(base, mtlsBase string) any { return aliasDoc(base, mtlsBase) })
	client := aliasClient(t, r, true)

	var seen string
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, req *http.Request) {
		seen = req.URL.Query().Get("tenant_id")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "a", "token_type": "Bearer", "expires_in": 900,
		})
	})
	// Replace the mTLS listener's token handler by pointing the client at a
	// document whose alias names this third server instead.
	probe := httptest.NewServer(mux)
	defer probe.Close()

	configuration, err := client.OidcDiscover(context.Background())
	if err != nil {
		t.Fatalf("OidcDiscover: %v", err)
	}
	configuration.MtlsEndpointAliases.TokenEndpoint = probe.URL + "/oauth2/token"
	if _, err := client.LoginClientCredentials(context.Background(), LoginClientCredentialsParams{
		TenantID:      aliasTenantID,
		Configuration: &configuration,
	}); err != nil {
		t.Fatalf("LoginClientCredentials: %v", err)
	}

	if seen != aliasTenantID {
		t.Fatalf("tenant_id on the alias URL: got %q, want %q", seen, aliasTenantID)
	}
}

// ── Consequence 1: absence means "no separate host" ────────────────────────

func TestMtlsAliases_MtlsClientWithNoAliasesKeepsTopLevelEndpoints(t *testing.T) {
	r := newAliasServers(t, func(base, _ string) any { return discoveryDoc(base) })
	client := aliasClient(t, r, true)

	// Not an error, and not the alias origin: a deployment running
	// client_auth = optional on one listener serves both populations at the
	// conventional endpoints and correctly publishes nothing.
	if _, err := client.Introspect(context.Background(), IntrospectParams{
		Token: Sensitive("t"), TenantID: aliasTenantID,
	}); err != nil {
		t.Fatalf("an mTLS client against an alias-free document must still work: %v", err)
	}

	r.assertOnly(t, "/oauth2/introspect", r.conventional.URL)
}

func TestMtlsAliases_ClientNotDoingMtlsKeepsTopLevelEndpoints(t *testing.T) {
	r := newAliasServers(t, func(base, mtlsBase string) any { return aliasDoc(base, mtlsBase) })
	client := aliasClient(t, r, false)

	if err := client.Revoke(context.Background(), RevokeParams{
		Token: Sensitive("t"), TenantID: aliasTenantID,
	}); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	r.assertOnly(t, "/oauth2/revoke", r.conventional.URL)
}

func TestMtlsAliases_PartialAliasObjectFallsBackPerEndpoint(t *testing.T) {
	// RFC 8705 §5 does not require an OP to alias all six, and the shape of
	// this member must never be why a client stops working: an object naming
	// only token_endpoint is a valid document, and every endpoint it does not
	// name falls back to the top-level entry.
	r := newAliasServers(t, func(base, mtlsBase string) any {
		doc := discoveryDoc(base)
		doc.MtlsEndpointAliases = &MtlsEndpointAliases{TokenEndpoint: mtlsBase + "/oauth2/token"}
		return doc
	})
	client := aliasClient(t, r, true)
	ctx := context.Background()

	if _, err := client.LoginClientCredentials(ctx, LoginClientCredentialsParams{TenantID: aliasTenantID}); err != nil {
		t.Fatalf("LoginClientCredentials: %v", err)
	}
	if _, err := client.Introspect(ctx, IntrospectParams{Token: Sensitive("t"), TenantID: aliasTenantID}); err != nil {
		t.Fatalf("a partial alias object is a valid document, not an error: %v", err)
	}

	r.assertOnly(t, "/oauth2/token", r.mtls.URL)
	r.assertOnly(t, "/oauth2/introspect", r.conventional.URL)
}

func TestMtlsAliases_UnsupportedGrantStillReportedWhenNeitherLevelNamesIt(t *testing.T) {
	r := newAliasServers(t, func(base, mtlsBase string) any {
		doc := aliasDoc(base, mtlsBase)
		doc.DeviceAuthorizationEndpoint = ""
		doc.MtlsEndpointAliases.DeviceAuthorizationEndpoint = ""
		return doc
	})
	client := aliasClient(t, r, true)

	// Neither level names the endpoint, so the answer is still "this server
	// does not support the device grant" — never a URL built by concatenation.
	_, err := client.DeviceAuthorize(context.Background(), DeviceAuthorizeParams{TenantID: aliasTenantID})
	if err == nil {
		t.Fatal("expected an error when neither level advertises the device endpoint")
	}
	if _, ok := err.(*AuthError); !ok {
		t.Fatalf("expected *AuthError, got %T: %v", err, err)
	}
}

// ── Consequence 2: no alias is ever synthesised ────────────────────────────

func TestMtlsAliases_FrontChannelAndJwksAreNeverAliased(t *testing.T) {
	r := newAliasServers(t, func(base, mtlsBase string) any { return aliasDoc(base, mtlsBase) })
	client := aliasClient(t, r, true)
	ctx := context.Background()

	configuration, err := client.OidcDiscover(ctx)
	if err != nil {
		t.Fatalf("OidcDiscover: %v", err)
	}

	// A browser sent to an mTLS host raises a native certificate-chooser
	// dialog most users cannot answer, and jwks_uri is public key material
	// that gains nothing from a handshake.
	request, err := client.OidcBegin(configuration, OidcBeginParams{
		RedirectURI: "https://app.example.com/auth/callback",
		Scope:       "openid",
	})
	if err != nil {
		t.Fatalf("OidcBegin: %v", err)
	}
	assertOriginIs(t, "authorization_endpoint", request.URL, r.conventional.URL)

	logout, err := client.LogoutURL(ctx, LogoutURLParams{
		IDToken:       Sensitive("not-a-real-token"),
		Configuration: &configuration,
	})
	if err != nil {
		t.Fatalf("LogoutURL: %v", err)
	}
	assertOriginIs(t, "end_session_endpoint", logout, r.conventional.URL)
	assertOriginIs(t, "jwks_uri", configuration.JwksURI, r.conventional.URL)
}

func assertOriginIs(t *testing.T, what, rawURL, wantOrigin string) {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("%s: parse %q: %v", what, rawURL, err)
	}
	if got := u.Scheme + "://" + u.Host; got != wantOrigin {
		t.Fatalf("%s must stay on the conventional host: got %s, want %s", what, got, wantOrigin)
	}
}

// ── Consequence 3: issuer is never aliased ─────────────────────────────────

func TestMtlsAliases_IssuerDoesNotMoveWithTheEndpoints(t *testing.T) {
	r := newAliasServers(t, func(base, mtlsBase string) any { return aliasDoc(base, mtlsBase) })
	client := aliasClient(t, r, true)

	configuration, err := client.OidcDiscover(context.Background())
	if err != nil {
		t.Fatalf("OidcDiscover: %v", err)
	}

	// §12.4 rule 3 compares `iss` against THIS value by exact string, for
	// every token — including one minted at an alias endpoint. An SDK that
	// derived an expected issuer from the host it called would reject every
	// token it obtains over mTLS.
	if configuration.Issuer != r.conventional.URL {
		t.Fatalf("issuer: got %q, want %q", configuration.Issuer, r.conventional.URL)
	}
	if configuration.Issuer == r.mtls.URL {
		t.Fatal("issuer must not follow the aliased endpoints to the mTLS host")
	}
}

// ── Vector C: a malformed alias is refused, never fallen back from ─────────
//
// CONTRACT.md §21.3.1 vector C, contract 1.43. Rule 2 had been normative since
// 1.40 and, until the 2026-09-12 pass, said nothing about an alias that is
// PRESENT and unusable — every SDK that read the member at all fell back to the
// top-level endpoint. Falling back looks like the safe answer and is the
// dangerous one: the caller asked to authenticate with a certificate, the
// operator published something unusable, and sending the certificate to the
// front-channel host authenticates nothing while appearing to work.

// assertRefusedAsAuthError checks that err is the §21.3.1 refusal and not a
// transport failure. The distinction is not cosmetic: §16.3 retries
// *NetworkError and only *NetworkError, so a *NetworkError here would have
// attempted a permanent misconfiguration three times.
func assertRefusedAsAuthError(t *testing.T, err error, wantSubstring string) {
	t.Helper()
	if err == nil {
		t.Fatal("a malformed alias must be refused, not fallen back from")
	}
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("err = %T(%v), want *AuthError", err, err)
	}
	if !strings.Contains(authErr.Message, wantSubstring) {
		t.Fatalf("message %q does not name %q", authErr.Message, wantSubstring)
	}
}

func TestMtlsAliases_ARelativeAliasIsRefusedRatherThanResolved(t *testing.T) {
	// A relative alias resolves against nothing the client holds, and the base
	// that might seem obvious — the issuer's host — is precisely the host the
	// alias exists to name a different one from.
	r := newAliasServers(t, func(base, _ string) any {
		doc := discoveryDoc(base)
		doc.MtlsEndpointAliases = &MtlsEndpointAliases{TokenEndpoint: "/oauth2/token"}
		return doc
	})
	client := aliasClient(t, r, true)

	_, err := client.LoginClientCredentials(context.Background(), LoginClientCredentialsParams{
		TenantID: aliasTenantID,
	})
	assertRefusedAsAuthError(t, err, "not an absolute URL")

	// And the certificate never reached the conventional host, which is the
	// whole point of refusing rather than falling back.
	if origins := r.origins("/oauth2/token"); len(origins) != 0 {
		t.Fatalf("a refused alias still produced a call to %v", origins)
	}
}

func TestMtlsAliases_ASchemeDowngradeIsRefused(t *testing.T) {
	// The comparison is like with like: the alias substitutes for exactly one
	// top-level endpoint, and that endpoint's scheme is what a downgrade is
	// measured against.
	r := newAliasServers(t, func(base, _ string) any {
		doc := discoveryDoc(base)
		doc.TokenEndpoint = "https://iam.example.test/oauth2/token"
		doc.MtlsEndpointAliases = &MtlsEndpointAliases{TokenEndpoint: "http://mtls.example.test/oauth2/token"}
		return doc
	})
	client := aliasClient(t, r, true)

	_, err := client.LoginClientCredentials(context.Background(), LoginClientCredentialsParams{
		TenantID: aliasTenantID,
	})
	assertRefusedAsAuthError(t, err, "downgrade")
}

// The I4 twin of the downgrade refusal, and the reason the rule compares like
// with like rather than demanding https outright: an http alias for an http
// endpoint is a development deployment, which AXIAM's own build_mtls_aliases
// supports and this suite's own servers are. A rule written as "the scheme must
// be https" would have failed every test in this file.
func TestMtlsAliases_AnHttpAliasForAnHttpEndpointIsAccepted(t *testing.T) {
	r := newAliasServers(t, func(base, mtlsBase string) any { return aliasDoc(base, mtlsBase) })
	client := aliasClient(t, r, true)

	if _, err := client.LoginClientCredentials(context.Background(), LoginClientCredentialsParams{
		TenantID: aliasTenantID,
	}); err != nil {
		t.Fatalf("an http alias replacing an http endpoint is a development deployment: %v", err)
	}
	r.assertOnly(t, "/oauth2/token", r.mtls.URL)
}

// The second I4 twin, and the more important one: a client with no certificate
// never reads the member at all, not even to validate it. A deployment whose
// aliases are malformed cannot break the clients that never use them.
func TestMtlsAliases_AMalformedAliasCannotBreakAClientNotDoingMtls(t *testing.T) {
	r := newAliasServers(t, func(base, _ string) any {
		doc := discoveryDoc(base)
		doc.MtlsEndpointAliases = &MtlsEndpointAliases{TokenEndpoint: "not-a-url-at-all"}
		return doc
	})
	client := aliasClient(t, r, false)

	if err := client.Revoke(context.Background(), RevokeParams{
		Token: Sensitive("t"), TenantID: aliasTenantID,
	}); err != nil {
		t.Fatalf("a client presenting no certificate must be unaffected: %v", err)
	}
	r.assertOnly(t, "/oauth2/revoke", r.conventional.URL)
}

// Per endpoint, like the fallback itself: one malformed alias refuses the calls
// that would have used it and leaves every other endpoint working.
func TestMtlsAliases_OneMalformedAliasDoesNotPoisonTheOthers(t *testing.T) {
	r := newAliasServers(t, func(base, mtlsBase string) any {
		doc := aliasDoc(base, mtlsBase)
		doc.MtlsEndpointAliases.IntrospectionEndpoint = "::not a url::"
		return doc
	})
	client := aliasClient(t, r, true)
	ctx := context.Background()

	if _, err := client.LoginClientCredentials(ctx, LoginClientCredentialsParams{TenantID: aliasTenantID}); err != nil {
		t.Fatalf("a well-formed token alias must still be used: %v", err)
	}
	r.assertOnly(t, "/oauth2/token", r.mtls.URL)

	_, err := client.Introspect(ctx, IntrospectParams{Token: Sensitive("t"), TenantID: aliasTenantID})
	assertRefusedAsAuthError(t, err, "not an absolute URL")
}
