package axiam

// The four public "Sign in with X" operations added by contract 1.38 —
// SsoProviders, SsoStartOauth2, SsoCompleteOauth2, SsoCompleteHandoff
// (CONTRACT.md §12.1).
//
// Two kinds of assertion live here, and both are needed.
//
// The wire-shape tests read the vendored openapi.json and assert the method,
// path, content type and — for SsoProviders — the *parameter location* the
// server declares, then assert that what this SDK actually puts on the wire
// matches. Asserting only against the mock would pin the SDK to the test's own
// idea of the endpoint; asserting only against the spec would not notice an
// SDK that agrees with the spec and calls something else.
//
// The rule tests cover the four §12.1 notes easiest to get quietly wrong:
// note 9 (an empty provider list is a success, not a not-found), note 10
// (Protocol selects the start operation), note 12 (a handoff 401 is terminal
// and is never retried) and rule 12a (a 400 from a start call is a
// configuration refusal, not something to retry).

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"testing"
)

const (
	testProvidersPath      = "/api/v1/auth/federation/providers"
	testOidcStartPath      = "/api/v1/auth/federation/oidc/start"
	testOAuth2StartPath    = "/api/v1/auth/federation/oauth2/start"
	testOAuth2CallbackPath = "/api/v1/auth/federation/oauth2/callback"
	testHandoffPath        = "/api/v1/auth/federation/handoff"

	testConfigID = "44444444-4444-4444-4444-444444444444"
	testRedirect = "https://app.test/post-login"
)

// ---------------------------------------------------------------------------
// openapi.json fixtures
// ---------------------------------------------------------------------------

type openAPISpec struct {
	Paths      map[string]map[string]openAPIOperation `json:"paths"`
	Components struct {
		Schemas map[string]openAPISchema `json:"components_schemas"`
	} `json:"-"`
	RawComponents struct {
		Schemas map[string]openAPISchema `json:"schemas"`
	} `json:"components"`
}

type openAPIOperation struct {
	Parameters  []openAPIParameter          `json:"parameters"`
	RequestBody *openAPIBody                `json:"requestBody"`
	Responses   map[string]openAPIBodyOuter `json:"responses"`
}

type openAPIParameter struct {
	Name string `json:"name"`
	In   string `json:"in"`
}

type openAPIBodyOuter struct {
	Content map[string]openAPIMedia `json:"content"`
}

type openAPIBody struct {
	Content map[string]openAPIMedia `json:"content"`
}

type openAPIMedia struct {
	Schema struct {
		Ref string `json:"$ref"`
	} `json:"schema"`
}

type openAPISchema struct {
	Required   []string                  `json:"required"`
	Properties map[string]openAPIPropDef `json:"properties"`
}

type openAPIPropDef struct {
	Type json.RawMessage `json:"type"`
}

func loadOpenAPI(t *testing.T) openAPISpec {
	t.Helper()
	raw, err := os.ReadFile("openapi.json")
	if err != nil {
		t.Fatalf("read openapi.json: %v", err)
	}
	var spec openAPISpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatalf("parse openapi.json: %v", err)
	}
	return spec
}

func (s openAPISpec) schema(t *testing.T, name string) openAPISchema {
	t.Helper()
	schema, ok := s.RawComponents.Schemas[name]
	if !ok {
		t.Fatalf("openapi.json declares no schema %q", name)
	}
	return schema
}

func responseRef(op openAPIOperation) string {
	return op.Responses["200"].Content["application/json"].Schema.Ref
}

// ---------------------------------------------------------------------------
// Wire shape, against openapi.json
// ---------------------------------------------------------------------------

// TestOpenAPI_SsoProvidersIsAGetWithNoBody asserts §12.1's row for the
// listing: a GET, no request body, answering PublicFederationProvidersResponse.
func TestOpenAPI_SsoProvidersIsAGetWithNoBody(t *testing.T) {
	spec := loadOpenAPI(t)
	op, ok := spec.Paths[testProvidersPath]["get"]
	if !ok {
		t.Fatalf("openapi.json declares no GET %s", testProvidersPath)
	}
	if op.RequestBody != nil {
		t.Fatal("SsoProviders is a GET and must have no request body (§12.1)")
	}
	if got, want := responseRef(op), "#/components/schemas/PublicFederationProvidersResponse"; got != want {
		t.Fatalf("response schema = %q, want %q", got, want)
	}
}

// TestOpenAPI_TheThreePosts asserts the method, media type and both schema
// names §12.1 gives each of the three POSTs.
func TestOpenAPI_TheThreePosts(t *testing.T) {
	spec := loadOpenAPI(t)
	for _, tc := range []struct{ path, request, response string }{
		{testOAuth2StartPath, "OAuth2StartRequest", "OAuth2StartResponse"},
		{testOAuth2CallbackPath, "OAuth2CallbackRequest", "SsoLoginSuccessResponse"},
		{testHandoffPath, "SsoHandoffRequest", "SsoLoginSuccessResponse"},
	} {
		op, ok := spec.Paths[tc.path]["post"]
		if !ok {
			t.Fatalf("openapi.json declares no POST %s", tc.path)
		}
		if op.RequestBody == nil {
			t.Fatalf("%s must declare a request body", tc.path)
		}
		got := op.RequestBody.Content["application/json"].Schema.Ref
		if want := "#/components/schemas/" + tc.request; got != want {
			t.Fatalf("%s request schema = %q, want %q", tc.path, got, want)
		}
		if got, want := responseRef(op), "#/components/schemas/"+tc.response; got != want {
			t.Fatalf("%s response schema = %q, want %q", tc.path, got, want)
		}
	}
}

// TestOpenAPI_ProviderIdentifiersAreQueryParameters asserts §12.1's parameter
// location. The neighbouring start operations take the same four identifiers
// in a JSON body, and the two are one copy-paste apart.
func TestOpenAPI_ProviderIdentifiersAreQueryParameters(t *testing.T) {
	spec := loadOpenAPI(t)
	params := spec.Paths[testProvidersPath]["get"].Parameters
	names := make([]string, 0, len(params))
	for _, p := range params {
		if p.In != "query" {
			t.Fatalf("%s must be a query parameter, not a %s field (§12.1)", p.Name, p.In)
		}
		names = append(names, p.Name)
	}
	sort.Strings(names)
	want := []string{"org_id", "org_slug", "tenant_id", "tenant_slug"}
	if len(names) != len(want) {
		t.Fatalf("parameters = %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("parameters = %v, want %v", names, want)
		}
	}
}

// TestOpenAPI_PublicProviderShape asserts the six required fields plus the
// nullable button_icon, and that none of the configuration a narrowed admin
// response would have leaked is present (§12.1 note 9).
func TestOpenAPI_PublicProviderShape(t *testing.T) {
	spec := loadOpenAPI(t)
	schema := spec.schema(t, "PublicFederationProvider")

	required := append([]string(nil), schema.Required...)
	sort.Strings(required)
	want := []string{"display_name", "has_bundled_mark", "id", "inherited", "protocol", "provider_kind"}
	if len(required) != len(want) {
		t.Fatalf("required = %v, want %v", required, want)
	}
	for i := range want {
		if required[i] != want[i] {
			t.Fatalf("required = %v, want %v", required, want)
		}
	}

	icon, ok := schema.Properties["button_icon"]
	if !ok {
		t.Fatal("button_icon is part of the shape even though it is nullable")
	}
	var iconType []string
	if err := json.Unmarshal(icon.Type, &iconType); err != nil {
		t.Fatalf("button_icon type is not a nullable-string union: %v", err)
	}
	nullable := false
	for _, entry := range iconType {
		if entry == "null" {
			nullable = true
		}
	}
	if !nullable {
		t.Fatal("button_icon must be nullable — absent for most providers")
	}

	for _, absent := range []string{"client_id", "client_secret", "metadata_url", "token_endpoint"} {
		if _, present := schema.Properties[absent]; present {
			t.Fatalf("the unauthenticated provider response must not carry %s (§12.1 note 9)", absent)
		}
	}
}

// TestOpenAPI_OAuth2StartCarriesNoPKCE asserts §12.1 note 11: the verifier is
// generated and held server-side, so neither schema carries PKCE material and
// neither may the SDK.
func TestOpenAPI_OAuth2StartCarriesNoPKCE(t *testing.T) {
	spec := loadOpenAPI(t)
	for _, name := range []string{"OAuth2StartRequest", "OAuth2StartResponse"} {
		schema := spec.schema(t, name)
		for _, pkce := range []string{"code_verifier", "code_challenge", "code_challenge_method"} {
			if _, present := schema.Properties[pkce]; present {
				t.Fatalf("%s must not carry %s: PKCE is server-side here (§12.1 note 11)", name, pkce)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// SsoProviders — wire shape and §12.1 note 9
// ---------------------------------------------------------------------------

// providerServer mounts the four federation endpoints plus the two start
// endpoints, recording every request path and query.
type providerServer struct {
	*httptest.Server
	Paths    []string
	Queries  []string
	Bodies   []map[string]any
	Handlers map[string]http.HandlerFunc
}

func newProviderServer(t *testing.T) *providerServer {
	t.Helper()
	ps := &providerServer{Handlers: map[string]http.HandlerFunc{}}
	mux := http.NewServeMux()
	record := func(w http.ResponseWriter, r *http.Request) bool {
		ps.Paths = append(ps.Paths, r.URL.Path)
		ps.Queries = append(ps.Queries, r.URL.RawQuery)
		var body map[string]any
		if r.Body != nil {
			_ = json.NewDecoder(r.Body).Decode(&body)
		}
		ps.Bodies = append(ps.Bodies, body)
		if handler, ok := ps.Handlers[r.URL.Path]; ok {
			handler(w, r)
			return true
		}
		return false
	}
	for _, path := range []string{
		testProvidersPath, testOidcStartPath, testOAuth2StartPath,
		testOAuth2CallbackPath, testHandoffPath,
	} {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			if !record(w, r) {
				w.WriteHeader(http.StatusNotImplemented)
			}
		})
	}
	ps.Server = httptest.NewServer(mux)
	t.Cleanup(ps.Close)
	return ps
}

func jsonHandler(t *testing.T, status int, body any) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if body != nil {
			_ = json.NewEncoder(w).Encode(body)
		}
	}
}

func sessionHandler(t *testing.T) http.HandlerFunc {
	t.Helper()
	token := makeAccessTokenWithOrgID(t, "66666666-6666-6666-6666-666666666666")
	return func(w http.ResponseWriter, _ *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "axiam_access", Value: token, Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: "axiam_csrf", Value: "federation-csrf", Path: "/"})
		writeJSON(t, w, map[string]any{
			"user_id":      "99999999-8888-7777-6666-555555555555",
			"session_id":   "12121212-3434-5656-7878-909090909090",
			"expires_in":   900,
			"redirect_uri": testRedirect,
		})
	}
}

func providerClient(t *testing.T, srv *providerServer) *Client {
	t.Helper()
	client, err := NewClient(srv.URL, "acme", WithOrgSlug("acme-org"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return client
}

// TestSsoProviders_SendsIdentifiersAsQueryParameters is the SDK half of the
// parameter-location assertion: query string, no body.
func TestSsoProviders_SendsIdentifiersAsQueryParameters(t *testing.T) {
	srv := newProviderServer(t)
	srv.Handlers[testProvidersPath] = jsonHandler(t, http.StatusOK, map[string]any{"providers": []any{}})
	client := providerClient(t, srv)

	if _, err := client.SsoProviders(context.Background(), SsoProvidersParams{
		OrgSlug:    "other-org",
		TenantSlug: "engineering",
	}); err != nil {
		t.Fatalf("SsoProviders: %v", err)
	}

	if got, want := srv.Queries[0], "org_slug=other-org&tenant_slug=engineering"; got != want {
		t.Fatalf("query = %q, want %q", got, want)
	}
	if srv.Bodies[0] != nil {
		t.Fatalf("SsoProviders is a GET with no body (§12.1), got %v", srv.Bodies[0])
	}
}

// TestSsoProviders_DefaultsWorkspaceFromClient asserts the §5.1 fallback.
func TestSsoProviders_DefaultsWorkspaceFromClient(t *testing.T) {
	srv := newProviderServer(t)
	srv.Handlers[testProvidersPath] = jsonHandler(t, http.StatusOK, map[string]any{"providers": []any{}})
	client := providerClient(t, srv)

	if _, err := client.SsoProviders(context.Background(), SsoProvidersParams{}); err != nil {
		t.Fatalf("SsoProviders: %v", err)
	}
	if got, want := srv.Queries[0], "org_slug=acme-org&tenant_slug=acme"; got != want {
		t.Fatalf("query = %q, want %q", got, want)
	}
}

// TestSsoProviders_EmptyListIsASuccess asserts §12.1 note 9. The three cases
// the endpoint makes indistinguishable — unknown organization, known-but-empty,
// and no workspace named — are all ordinary successes. Mapping any of them to
// an error would restore the two-valued answer the empty list removes, and
// with it the organization-slug oracle.
func TestSsoProviders_EmptyListIsASuccess(t *testing.T) {
	srv := newProviderServer(t)
	srv.Handlers[testProvidersPath] = jsonHandler(t, http.StatusOK, map[string]any{"providers": []any{}})
	client := providerClient(t, srv)

	for _, params := range []SsoProvidersParams{
		{OrgSlug: "no-such-organization"},
		{OrgSlug: "acme-org", TenantSlug: "acme"},
		{},
	} {
		list, err := client.SsoProviders(context.Background(), params)
		if err != nil {
			t.Fatalf("an empty provider list is a normal success (§12.1 note 9), got %v", err)
		}
		if len(list.Providers) != 0 {
			t.Fatalf("expected an empty list, got %d providers", len(list.Providers))
		}
	}
}

// TestSsoProviders_SendsRequestWithNoWorkspaceAtAll asserts the consequence of
// note 9 that is easiest to get wrong: unlike the start operations, a request
// resolving no workspace is SENT rather than refused client-side. A 400 for
// "you named nothing" against a 200 [] for an unknown slug would be that same
// two-valued answer by another route.
func TestSsoProviders_SendsRequestWithNoWorkspaceAtAll(t *testing.T) {
	srv := newProviderServer(t)
	srv.Handlers[testProvidersPath] = jsonHandler(t, http.StatusOK, map[string]any{"providers": []any{}})
	// A client with a tenant slug but NO organization: SsoStart refuses this
	// client-side, SsoProviders must not.
	client, err := NewClient(srv.URL, "acme")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	list, err := client.SsoProviders(context.Background(), SsoProvidersParams{})
	if err != nil {
		t.Fatalf("SsoProviders must send the request, got %v", err)
	}
	if len(srv.Paths) != 1 {
		t.Fatalf("expected exactly one wire call, got %v", srv.Paths)
	}
	if len(list.Providers) != 0 {
		t.Fatalf("expected an empty list, got %d", len(list.Providers))
	}
}

// TestSsoProviders_MapsEveryFieldIncludingButtonIcon asserts the faithful
// model, nullable button_icon included.
func TestSsoProviders_MapsEveryFieldIncludingButtonIcon(t *testing.T) {
	srv := newProviderServer(t)
	srv.Handlers[testProvidersPath] = jsonHandler(t, http.StatusOK, map[string]any{
		"providers": []any{
			map[string]any{
				"id": "33333333-3333-3333-3333-333333333333", "provider_kind": "google",
				"display_name": "Google", "protocol": ProtocolOidcConnect,
				"has_bundled_mark": true, "inherited": true, "button_icon": nil,
			},
			map[string]any{
				"id": "44444444-4444-4444-4444-444444444444", "provider_kind": "generic_oauth2",
				"display_name": "Acme SSO", "protocol": ProtocolOAuth2,
				"has_bundled_mark": false, "inherited": false,
				"button_icon": "data:image/png;base64,iVBORw0KGgo=",
			},
		},
	})
	client := providerClient(t, srv)

	list, err := client.SsoProviders(context.Background(), SsoProvidersParams{})
	if err != nil {
		t.Fatalf("SsoProviders: %v", err)
	}
	if len(list.Providers) != 2 {
		t.Fatalf("expected 2 providers, got %d", len(list.Providers))
	}
	google := list.Providers[0]
	if google.ProviderKind != "google" || google.Protocol != ProtocolOidcConnect {
		t.Fatalf("unexpected first provider: %+v", google)
	}
	if !google.HasBundledMark {
		t.Fatal("google ships a bundled mark")
	}
	// Inherited is reported so an admin surface can show that a provider is
	// not the tenant's to edit; nothing here computes it (§12.1 note 13).
	if !google.Inherited {
		t.Fatal("inherited must be reported, not dropped")
	}
	if google.ButtonIcon != "" {
		t.Fatalf("button_icon is absent for most providers, got %q", google.ButtonIcon)
	}
	acme := list.Providers[1]
	if acme.ButtonIcon != "data:image/png;base64,iVBORw0KGgo=" {
		t.Fatalf("button_icon = %q", acme.ButtonIcon)
	}
	if acme.HasBundledMark {
		t.Fatal("a generic provider ships no bundled mark")
	}
}

// ---------------------------------------------------------------------------
// §12.1 note 10 — Protocol selects the start operation
// ---------------------------------------------------------------------------

// TestProtocolSelectsTheStartOperation covers all three branches, asserted on
// which endpoint the resulting call reached.
//
// ProviderKind is deliberately misleading in this fixture: the Saml row is
// "google", the kind whose OIDC connector everybody assumes. A dispatch that
// read the kind would send it to the OIDC start endpoint and be caught by the
// recorded-path assertion.
func TestProtocolSelectsTheStartOperation(t *testing.T) {
	srv := newProviderServer(t)
	srv.Handlers[testProvidersPath] = jsonHandler(t, http.StatusOK, map[string]any{
		"providers": []any{
			map[string]any{
				"id": "55555555-5555-5555-5555-555555555555", "provider_kind": "microsoft",
				"display_name": "Microsoft", "protocol": ProtocolOidcConnect,
				"has_bundled_mark": true, "inherited": false,
			},
			map[string]any{
				"id": "66666666-6666-6666-6666-666666666666", "provider_kind": "github",
				"display_name": "GitHub", "protocol": ProtocolOAuth2,
				"has_bundled_mark": true, "inherited": false,
			},
			map[string]any{
				"id": "77777777-7777-7777-7777-777777777777", "provider_kind": "google",
				"display_name": "Corporate SAML", "protocol": ProtocolSaml,
				"has_bundled_mark": true, "inherited": false,
			},
		},
	})
	startBody := map[string]any{
		"authorize_url": "https://upstream.test/authorize", "state": "s", "expires_in_secs": 600,
	}
	srv.Handlers[testOidcStartPath] = jsonHandler(t, http.StatusOK, startBody)
	srv.Handlers[testOAuth2StartPath] = jsonHandler(t, http.StatusOK, startBody)
	client := providerClient(t, srv)

	list, err := client.SsoProviders(context.Background(), SsoProvidersParams{})
	if err != nil {
		t.Fatalf("SsoProviders: %v", err)
	}

	samlSeen := false
	for _, p := range list.Providers {
		switch p.Protocol {
		case ProtocolOidcConnect:
			if _, err := client.SsoStart(context.Background(), SsoStartParams{
				FederationConfigID: p.ID, RedirectURI: testRedirect,
			}); err != nil {
				t.Fatalf("OidcConnect must dispatch to SsoStart: %v", err)
			}
		case ProtocolOAuth2:
			if _, err := client.SsoStartOauth2(context.Background(), SsoStartOauth2Params{
				FederationConfigID: p.ID, RedirectURI: testRedirect,
			}); err != nil {
				t.Fatalf("OAuth2 must dispatch to SsoStartOauth2: %v", err)
			}
		case ProtocolSaml:
			// Saml goes to the SAML login endpoint, which §12.1 note 10 says
			// is NOT a §12 vocabulary operation. The branch exists so that a
			// Saml provider is never quietly handed to one of the other two.
			samlSeen = true
		default:
			t.Fatalf("unknown protocol %q", p.Protocol)
		}
	}
	if !samlSeen {
		t.Fatal("the Saml branch must be reachable")
	}

	want := []string{testProvidersPath, testOidcStartPath, testOAuth2StartPath}
	if len(srv.Paths) != len(want) {
		t.Fatalf("paths = %v, want %v", srv.Paths, want)
	}
	for i := range want {
		if srv.Paths[i] != want[i] {
			t.Fatalf("paths = %v, want %v", srv.Paths, want)
		}
	}
}

// ---------------------------------------------------------------------------
// SsoStartOauth2
// ---------------------------------------------------------------------------

// TestSsoStartOauth2_PostsBodyAndSendsNoPKCE asserts the request shape and,
// deliberately, the absence §12.1 note 11 requires.
func TestSsoStartOauth2_PostsBodyAndSendsNoPKCE(t *testing.T) {
	srv := newProviderServer(t)
	srv.Handlers[testOAuth2StartPath] = jsonHandler(t, http.StatusOK, map[string]any{
		"authorize_url":   "https://github.com/login/oauth/authorize?state=abc",
		"state":           "abc",
		"expires_in_secs": 600,
	})
	client := providerClient(t, srv)

	result, err := client.SsoStartOauth2(context.Background(), SsoStartOauth2Params{
		FederationConfigID: testConfigID, RedirectURI: testRedirect,
	})
	if err != nil {
		t.Fatalf("SsoStartOauth2: %v", err)
	}

	body := srv.Bodies[0]
	if body["federation_config_id"] != testConfigID || body["redirect_uri"] != testRedirect {
		t.Fatalf("unexpected body: %v", body)
	}
	if body["tenant_slug"] != "acme" || body["org_slug"] != "acme-org" {
		t.Fatalf("§5.1 context missing from body: %v", body)
	}
	// §12.1 note 11: the verifier is server-side. Its absence is the contract.
	for _, pkce := range []string{"code_verifier", "code_challenge", "code_challenge_method"} {
		if _, present := body[pkce]; present {
			t.Fatalf("the SDK must not send %s: PKCE is server-side here", pkce)
		}
	}
	if result.State != "abc" || result.ExpiresInSecs != 600 {
		t.Fatalf("unexpected result: %+v", result)
	}
}

// TestSsoStartOauth2_RefusesClientSideWithoutOrgContext asserts the §5.1
// client-side refusal — and that no wire call is made.
func TestSsoStartOauth2_RefusesClientSideWithoutOrgContext(t *testing.T) {
	srv := newProviderServer(t)
	client, err := NewClient(srv.URL, "acme")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	_, err = client.SsoStartOauth2(context.Background(), SsoStartOauth2Params{
		FederationConfigID: testConfigID, RedirectURI: testRedirect,
	})
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("expected *AuthError, got %T: %v", err, err)
	}
	if len(srv.Paths) != 0 {
		t.Fatalf("no wire call may be made, got %v", srv.Paths)
	}
}

// ---------------------------------------------------------------------------
// §12.1 rule 12a — a 400 from a start call is a configuration refusal
// ---------------------------------------------------------------------------

// TestRule12a_A400FromAStartCallIsNetworkErrorAndIsNotRetried asserts rule 12a.
//
// On the SAML and Apple flows the identity provider never validates the SPA
// redirect_uri, so the server confines it to its own issuer origin plus
// AXIAM__AUTH__SSO_SPA_ORIGINS and answers 400 otherwise.
//
// That 400 is a CONFIGURATION refusal — §2's 400 row, whose taxonomy member in
// this SDK is *NetworkError ("malformed request / SDK programming error"), as
// distinct from the *AuthError an unknown workspace gets. It must not be
// retried: the deployment will refuse the same origin every time.
//
// Asserted on both start operations, because Apple arrives over the OIDC one
// and a caller can reach the refusal from either entry point.
func TestRule12a_A400FromAStartCallIsNetworkErrorAndIsNotRetried(t *testing.T) {
	for _, path := range []string{testOidcStartPath, testOAuth2StartPath} {
		srv := newProviderServer(t)
		srv.Handlers[path] = jsonHandler(t, http.StatusBadRequest, map[string]any{
			"message": "redirect_uri origin is not permitted for this deployment",
		})
		client := providerClient(t, srv)

		var err error
		if path == testOidcStartPath {
			_, err = client.SsoStart(context.Background(), SsoStartParams{
				FederationConfigID: testConfigID, RedirectURI: "https://attacker.example/",
			})
		} else {
			_, err = client.SsoStartOauth2(context.Background(), SsoStartOauth2Params{
				FederationConfigID: testConfigID, RedirectURI: "https://attacker.example/",
			})
		}

		var netErr *NetworkError
		if !errors.As(err, &netErr) {
			t.Fatalf("%s: rule 12a wants a configuration refusal (*NetworkError), got %T: %v", path, err, err)
		}
		var authErr *AuthError
		if errors.As(err, &authErr) {
			t.Fatalf("%s: rule 12a's 400 must not collapse into the 401 case", path)
		}
		if len(srv.Paths) != 1 {
			t.Fatalf("%s: the refusal must not be retried, got %v", path, srv.Paths)
		}
	}
}

// TestA401FromAStartCallStaysAnAuthError keeps the uniform "unknown workspace
// or provider" answer a DIFFERENT taxonomy member from the rule-12a 400, so
// the two cannot quietly collapse into one.
func TestA401FromAStartCallStaysAnAuthError(t *testing.T) {
	srv := newProviderServer(t)
	srv.Handlers[testOAuth2StartPath] = jsonHandler(t, http.StatusUnauthorized, map[string]any{
		"message": "unauthorized",
	})
	client := providerClient(t, srv)

	_, err := client.SsoStartOauth2(context.Background(), SsoStartOauth2Params{
		FederationConfigID: testConfigID, RedirectURI: testRedirect,
	})
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("expected *AuthError for a 401, got %T: %v", err, err)
	}
}

// ---------------------------------------------------------------------------
// The two completions, and §12.1 note 12
// ---------------------------------------------------------------------------

// TestSsoCompleteOauth2_PostsStateAndCode asserts the request body and the
// mapped result — which carries no token material (§12.1 note 6).
func TestSsoCompleteOauth2_PostsStateAndCode(t *testing.T) {
	srv := newProviderServer(t)
	srv.Handlers[testOAuth2CallbackPath] = sessionHandler(t)
	client := providerClient(t, srv)

	result, err := client.SsoCompleteOauth2(context.Background(), SsoCompleteOauth2Params{
		State: "abc", Code: "provider-code",
	})
	if err != nil {
		t.Fatalf("SsoCompleteOauth2: %v", err)
	}
	body := srv.Bodies[0]
	if body["state"] != "abc" || body["code"] != "provider-code" || len(body) != 2 {
		t.Fatalf("unexpected body: %v", body)
	}
	if result.UserID != "99999999-8888-7777-6666-555555555555" || result.RedirectURI != testRedirect {
		t.Fatalf("unexpected result: %+v", result)
	}
}

// TestSsoCompleteHandoff_PostsJustTheCode asserts the handoff request shape.
func TestSsoCompleteHandoff_PostsJustTheCode(t *testing.T) {
	srv := newProviderServer(t)
	srv.Handlers[testHandoffPath] = sessionHandler(t)
	client := providerClient(t, srv)

	result, err := client.SsoCompleteHandoff(context.Background(), SsoCompleteHandoffParams{
		Code: "handoff-code",
	})
	if err != nil {
		t.Fatalf("SsoCompleteHandoff: %v", err)
	}
	body := srv.Bodies[0]
	if body["code"] != "handoff-code" || len(body) != 1 {
		t.Fatalf("unexpected body: %v", body)
	}
	if result.SessionID != "12121212-3434-5656-7878-909090909090" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

// TestHandoff401IsTerminalAndNotRetried asserts §12.1 note 12. Unknown,
// expired and already-redeemed all answer the same 401, on purpose. The code
// is spent either way, so a retry cannot succeed and would only widen the
// window in which it sits in a log.
func TestHandoff401IsTerminalAndNotRetried(t *testing.T) {
	srv := newProviderServer(t)
	srv.Handlers[testHandoffPath] = jsonHandler(t, http.StatusUnauthorized, map[string]any{
		"message": "unauthorized",
	})
	client := providerClient(t, srv)

	_, err := client.SsoCompleteHandoff(context.Background(), SsoCompleteHandoffParams{
		Code: "spent-or-expired-or-never-existed",
	})
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("expected *AuthError for a 401, got %T: %v", err, err)
	}
	if len(srv.Paths) != 1 {
		t.Fatalf("the redemption must not be retried: the code is gone either way, got %v", srv.Paths)
	}
}

// TestHandoffConstantsMatchTheContract pins the two values a caller codes
// against: it reads the code out of ?axiam_handoff= and has 60 seconds.
func TestHandoffConstantsMatchTheContract(t *testing.T) {
	if HandoffQueryParam != "axiam_handoff" {
		t.Fatalf("HandoffQueryParam = %q", HandoffQueryParam)
	}
	if HandoffCodeTTL.Seconds() != 60 {
		t.Fatalf("HandoffCodeTTL = %v", HandoffCodeTTL)
	}
}
