package middleware

// CONTRACT.md §28.9 required tests 3 (401 with the challenge), 4 (403
// insufficient_scope) and 5 (a token whose aud is not the resource), plus
// the off-by-default regression — the four §28.9 assertions that need a
// real *http.ServeMux/Middleware chain. Tests 1 (document shape) and 2
// (challenge quoting) are framework-independent and live in the root
// package's mcp_test.go.
//
// The fixture is the SAME one used there (mirrored as constants, since Go
// has no cross-package unexported-const sharing) — §28.9 asks for the same
// assertions, on the same fixtures, in every SDK repository, so a
// divergence between this port and the TypeScript reference implementation
// (T9b) shows up as a different expected value rather than as a different
// test.

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	axiam "github.com/ilpanich/axiam-go-sdk"
)

const (
	mcpFixtureResource     = "https://mcp.example.com/mcp"
	mcpFixtureAuthServer   = "https://axiam.example.com"
	mcpFixtureDocs         = "https://mcp.example.com/docs"
	mcpFixtureMetadataPath = "/.well-known/oauth-protected-resource/mcp"
	mcpFixtureMetadataURL  = "https://mcp.example.com" + mcpFixtureMetadataPath
	mcpFixtureExpectedAud  = "https://mcp.example.com/mcp"
	mcpTenant              = "tenant-mcp"

	mcpVectorNoCredential      = `Bearer resource_metadata="` + mcpFixtureMetadataURL + `"`
	mcpVectorInvalidToken      = `Bearer error="invalid_token", resource_metadata="` + mcpFixtureMetadataURL + `"`
	mcpVectorInsufficientScope = `Bearer error="insufficient_scope", scope="mcp:tools", resource_metadata="` + mcpFixtureMetadataURL + `"`
)

func mcpFixtureMetadata(t *testing.T) axiam.MCPResourceMetadata {
	t.Helper()
	metadata, err := axiam.ProtectedResourceMetadata(axiam.ProtectedResourceMetadataOptions{
		Resource:               mcpFixtureResource,
		AuthorizationServers:   []string{mcpFixtureAuthServer},
		ScopesSupported:        []string{"mcp:read", "mcp:tools"},
		BearerMethodsSupported: []string{"header"},
		ResourceDocumentation:  mcpFixtureDocs,
	})
	if err != nil {
		t.Fatalf("axiam.ProtectedResourceMetadata: %v", err)
	}
	return metadata
}

// mcpToken signs a token with the given aud (nil omits the claim) and,
// optionally, an expired exp.
func mcpToken(t *testing.T, priv ed25519.PrivateKey, aud any, expired bool) string {
	t.Helper()
	claims := testClaims{
		Subject:  "user-1",
		TenantID: mcpTenant,
		Roles:    []string{"mcp:read"},
		Audience: aud,
	}
	if expired {
		claims.Exp = at(time.Now().Add(-10 * time.Minute))
	} else {
		claims.Exp = at(time.Now().Add(time.Hour))
	}
	return signTestToken(t, priv, "mcp-kid", claims)
}

// fakeDecisionChecker implements both AccessChecker and
// AccessDecisionChecker so tests can control ReasonCode.
type fakeDecisionChecker struct {
	result axiam.AccessResult
	err    error
}

func (f *fakeDecisionChecker) CheckAccessAs(_ context.Context, _, _, _ string, _ ...string) (bool, string, error) {
	if f.err != nil {
		return false, "", f.err
	}
	return f.result.Allowed, f.result.Reason, nil
}

func (f *fakeDecisionChecker) CheckAccessDecision(_ context.Context, _, _, _ string, _ ...string) (axiam.AccessResult, error) {
	if f.err != nil {
		return axiam.AccessResult{}, f.err
	}
	return f.result, nil
}

// mcpApp is the deployment shape §28 describes: the §10 guard mounted
// globally over a mux, the metadata document served on it (unless
// serve=false), a plain protected route at /mcp, and — when checker is
// non-nil — a /tool route guarded by RequireAccess.
type mcpApp struct {
	handler http.Handler
}

type mcpAppOptions struct {
	resourceMetadataURL string // "" = §28 off
	expectedAudience    string
	serve               bool // register ServeProtectedResourceMetadata
	checker             *fakeDecisionChecker
	scope               string // RequireAccess's own WithScope
}

func buildMCPApp(t *testing.T, verifier jwksVerifier, opts mcpAppOptions) mcpApp {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /mcp", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})

	if opts.serve {
		metadata := mcpFixtureMetadata(t)
		var guard []MCPGuardConfig
		if opts.resourceMetadataURL != "" {
			guard = []MCPGuardConfig{{ExpectedAudience: opts.expectedAudience, ResourceMetadataURL: opts.resourceMetadataURL}}
		}
		if _, err := ServeProtectedResourceMetadata(mux, metadata, guard...); err != nil {
			t.Fatalf("ServeProtectedResourceMetadata: %v", err)
		}
	}

	if opts.checker != nil {
		var reqOpts []RequireOption
		if opts.scope != "" {
			reqOpts = append(reqOpts, WithScope(opts.scope))
		}
		if opts.resourceMetadataURL != "" {
			reqOpts = append(reqOpts, WithRequireResourceMetadataURL(opts.resourceMetadataURL))
		}
		mux.Handle("GET /tool", RequireAccess(opts.checker, "mcp:invoke", StaticResource("tool-1"), reqOpts...)(
			http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"ok":true}`))
			}),
		))
	}

	var mwOpts []Option
	mwOpts = append(mwOpts, WithExpectedAudience(opts.expectedAudience))
	if opts.resourceMetadataURL != "" {
		mwOpts = append(mwOpts, WithResourceMetadataURL(opts.resourceMetadataURL))
	}

	return mcpApp{handler: Middleware(verifier, mcpTenant, mwOpts...)(mux)}
}

func (a mcpApp) do(method, path string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	a.handler.ServeHTTP(w, req)
	return w
}

func bearerHeader(token string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + token}
}

// ---------------------------------------------------------------------------
// §28.9 test 3 — 401 with the challenge
// ---------------------------------------------------------------------------

func TestMCP_401CarriesChallenge(t *testing.T) {
	priv, pubJWK := generateTestKey(t, "mcp-kid")
	jwksSrv := newTestJWKSServer(t, pubJWK)
	verifier := newTestVerifier(t, jwksSrv)

	app := buildMCPApp(t, verifier, mcpAppOptions{
		resourceMetadataURL: mcpFixtureMetadataURL,
		expectedAudience:    mcpFixtureExpectedAud,
		serve:               true,
	})

	t.Run("no Authorization header answers vector 1", func(t *testing.T) {
		w := app.do(http.MethodGet, "/mcp", nil)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", w.Code)
		}
		if got := w.Header().Get("WWW-Authenticate"); got != mcpVectorNoCredential {
			t.Fatalf("WWW-Authenticate = %q, want %q", got, mcpVectorNoCredential)
		}
		if strings.Contains(w.Header().Get("WWW-Authenticate"), "error=") {
			t.Fatal("no credential is not a bad credential: must carry no error parameter")
		}
		var body map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("body not JSON: %v", err)
		}
		if body["error"] != "authentication_failed" || body["message"] != "missing authentication credentials" {
			t.Fatalf("§10 body changed: %v", body)
		}
	})

	t.Run("expired token answers vector 2 and says nothing else about why", func(t *testing.T) {
		token := mcpToken(t, priv, mcpFixtureExpectedAud, true)
		w := app.do(http.MethodGet, "/mcp", bearerHeader(token))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", w.Code)
		}
		challenge := w.Header().Get("WWW-Authenticate")
		if challenge != mcpVectorInvalidToken {
			t.Fatalf("WWW-Authenticate = %q, want %q", challenge, mcpVectorInvalidToken)
		}
		if strings.Contains(challenge, "error_description") || strings.Contains(challenge, "expired") {
			t.Fatalf("challenge must not leak the failure reason: %q", challenge)
		}
	})

	t.Run("serves the document with no credential, guard registered globally", func(t *testing.T) {
		w := app.do(http.MethodGet, mcpFixtureMetadataPath, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", w.Code)
		}
		if got := w.Header().Get("WWW-Authenticate"); got != "" {
			t.Fatalf("metadata document must never itself 401/carry a challenge, got %q", got)
		}
		if got := w.Header().Get("Content-Type"); got != "application/json" {
			t.Fatalf("Content-Type = %q", got)
		}
		if got := w.Header().Get("Cache-Control"); got != "public, max-age=3600" {
			t.Fatalf("Cache-Control = %q", got)
		}
		if got := w.Header().Get("Access-Control-Allow-Origin"); got != "*" {
			t.Fatalf("Access-Control-Allow-Origin = %q", got)
		}
		if got := w.Header().Get("Access-Control-Allow-Credentials"); got != "" {
			t.Fatalf("Access-Control-Allow-Credentials must be absent, got %q", got)
		}

		var doc map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
			t.Fatalf("body not JSON: %v", err)
		}
		want := map[string]any{
			"resource":                 mcpFixtureResource,
			"authorization_servers":    []any{mcpFixtureAuthServer},
			"scopes_supported":         []any{"mcp:read", "mcp:tools"},
			"bearer_methods_supported": []any{"header"},
			"resource_documentation":   mcpFixtureDocs,
		}
		for k, v := range want {
			gotJSON, _ := json.Marshal(doc[k])
			wantJSON, _ := json.Marshal(v)
			if string(gotJSON) != string(wantJSON) {
				t.Errorf("document[%q] = %s, want %s", k, gotJSON, wantJSON)
			}
		}
	})

	t.Run("serves identical bytes to an authenticated and an anonymous caller", func(t *testing.T) {
		anon := app.do(http.MethodGet, mcpFixtureMetadataPath, nil)
		token := mcpToken(t, priv, mcpFixtureExpectedAud, false)
		authed := app.do(http.MethodGet, mcpFixtureMetadataPath, bearerHeader(token))
		if anon.Body.String() != authed.Body.String() {
			t.Fatalf("document must not vary on the request:\nanon:  %s\nauthed: %s", anon.Body.String(), authed.Body.String())
		}
	})
}

// ---------------------------------------------------------------------------
// §28.9 test 4 — 403 insufficient_scope
// ---------------------------------------------------------------------------

func TestMCP_403InsufficientScope(t *testing.T) {
	priv, pubJWK := generateTestKey(t, "mcp-kid")
	jwksSrv := newTestJWKSServer(t, pubJWK)
	verifier := newTestVerifier(t, jwksSrv)

	denial := func(t *testing.T, result axiam.AccessResult, scope string) *httptest.ResponseRecorder {
		t.Helper()
		app := buildMCPApp(t, verifier, mcpAppOptions{
			resourceMetadataURL: mcpFixtureMetadataURL,
			expectedAudience:    mcpFixtureExpectedAud,
			checker:             &fakeDecisionChecker{result: result},
			scope:               scope,
		})
		token := mcpToken(t, priv, mcpFixtureExpectedAud, false)
		return app.do(http.MethodGet, "/tool", bearerHeader(token))
	}

	t.Run("no_grant on a scoped route answers vector 3, body unchanged", func(t *testing.T) {
		w := denial(t, axiam.AccessResult{Allowed: false, Reason: "no matching grant", ReasonCode: axiam.ReasonCodeNoGrant}, "mcp:tools")
		if w.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", w.Code)
		}
		if got := w.Header().Get("WWW-Authenticate"); got != mcpVectorInsufficientScope {
			t.Fatalf("WWW-Authenticate = %q, want %q", got, mcpVectorInsufficientScope)
		}
		var body map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("body not JSON: %v", err)
		}
		if body["error"] != "authorization_denied" {
			t.Fatalf("§11 body changed: %v", body)
		}
		if strings.Contains(w.Body.String(), "insufficient_scope") {
			t.Fatal("insufficient_scope must appear only in the header, never the body")
		}
	})

	t.Run("names the scope verbatim", func(t *testing.T) {
		w := denial(t, axiam.AccessResult{Allowed: false, Reason: "no matching grant", ReasonCode: axiam.ReasonCodeNoGrant}, "urn:example:tools.invoke")
		want := `Bearer error="insufficient_scope", scope="urn:example:tools.invoke", resource_metadata="` + mcpFixtureMetadataURL + `"`
		if got := w.Header().Get("WWW-Authenticate"); got != want {
			t.Fatalf("WWW-Authenticate = %q, want %q", got, want)
		}
	})

	t.Run("carries no challenge on denied_by_rule, an absent code, an unknown code, or no scope argument", func(t *testing.T) {
		byRule := denial(t, axiam.AccessResult{Allowed: false, Reason: "denied", ReasonCode: axiam.ReasonCodeDeniedByRule}, "mcp:tools")
		if byRule.Code != http.StatusForbidden || byRule.Header().Get("WWW-Authenticate") != "" {
			t.Fatalf("denied_by_rule: status=%d header=%q", byRule.Code, byRule.Header().Get("WWW-Authenticate"))
		}

		noCode := denial(t, axiam.AccessResult{Allowed: false, Reason: "denied"}, "mcp:tools")
		if noCode.Header().Get("WWW-Authenticate") != "" {
			t.Fatalf("absent reason_code: header=%q", noCode.Header().Get("WWW-Authenticate"))
		}

		unknownCode := denial(t, axiam.AccessResult{Allowed: false, Reason: "denied", ReasonCode: "quota_exhausted"}, "mcp:tools")
		if unknownCode.Header().Get("WWW-Authenticate") != "" {
			t.Fatalf("unrecognised reason_code: header=%q", unknownCode.Header().Get("WWW-Authenticate"))
		}

		noScope := denial(t, axiam.AccessResult{Allowed: false, Reason: "denied", ReasonCode: axiam.ReasonCodeNoGrant}, "")
		if noScope.Code != http.StatusForbidden || noScope.Header().Get("WWW-Authenticate") != "" {
			t.Fatalf("no scope argument: status=%d header=%q", noScope.Code, noScope.Header().Get("WWW-Authenticate"))
		}
	})

	t.Run("touches no other response — a 2xx gains nothing", func(t *testing.T) {
		w := denial(t, axiam.AccessResult{Allowed: true, ReasonCode: axiam.ReasonCodeAllowed}, "mcp:tools")
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", w.Code)
		}
		if got := w.Header().Get("WWW-Authenticate"); got != "" {
			t.Fatalf("a success must gain no challenge, got %q", got)
		}
	})

	t.Run("a §11 guard's own missing-identity 401 carries the challenge and picks the vector from the request", func(t *testing.T) {
		mux := http.NewServeMux()
		checker := &fakeDecisionChecker{result: axiam.AccessResult{Allowed: true}}
		mux.Handle("GET /unguarded", RequireAccess(checker, "mcp:invoke", StaticResource("tool-1"),
			WithRequireResourceMetadataURL(mcpFixtureMetadataURL),
		)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})))

		anon := httptest.NewRecorder()
		mux.ServeHTTP(anon, httptest.NewRequest(http.MethodGet, "/unguarded", nil))
		if anon.Code != http.StatusUnauthorized || anon.Header().Get("WWW-Authenticate") != mcpVectorNoCredential {
			t.Fatalf("anonymous: status=%d header=%q", anon.Code, anon.Header().Get("WWW-Authenticate"))
		}

		token := mcpToken(t, priv, mcpFixtureExpectedAud, false)
		withCred := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/unguarded", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		mux.ServeHTTP(withCred, req)
		if withCred.Code != http.StatusUnauthorized || withCred.Header().Get("WWW-Authenticate") != mcpVectorInvalidToken {
			t.Fatalf("with credential: status=%d header=%q", withCred.Code, withCred.Header().Get("WWW-Authenticate"))
		}
	})

	t.Run("a requireRole failure carries no challenge on its 403", func(t *testing.T) {
		priv, pubJWK := generateTestKey(t, "mcp-kid-role")
		jwksSrv := newTestJWKSServer(t, pubJWK)
		verifier := newTestVerifier(t, jwksSrv)

		mux := http.NewServeMux()
		mux.Handle("GET /admin", RequireRole("admin")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})))
		handler := Middleware(verifier, mcpTenant,
			WithExpectedAudience(mcpFixtureExpectedAud),
			WithResourceMetadataURL(mcpFixtureMetadataURL),
		)(mux)

		claims := testClaims{Subject: "user-1", TenantID: mcpTenant, Roles: []string{"mcp:read"}, Audience: mcpFixtureExpectedAud, Exp: at(time.Now().Add(time.Hour))}
		token := signTestToken(t, priv, "mcp-kid-role", claims)
		req := httptest.NewRequest(http.MethodGet, "/admin", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", w.Code)
		}
		if got := w.Header().Get("WWW-Authenticate"); got != "" {
			t.Fatalf("a role denial must carry no challenge, got %q", got)
		}
	})
}

// ---------------------------------------------------------------------------
// §28.9 test 5 — a token whose aud is not the resource is refused
// ---------------------------------------------------------------------------

func TestMCP_AudienceMismatchRefused(t *testing.T) {
	priv, pubJWK := generateTestKey(t, "mcp-kid")
	jwksSrv := newTestJWKSServer(t, pubJWK)
	verifier := newTestVerifier(t, jwksSrv)

	app := buildMCPApp(t, verifier, mcpAppOptions{
		resourceMetadataURL: mcpFixtureMetadataURL,
		expectedAudience:    mcpFixtureExpectedAud,
	})

	t.Run("refuses a token minted for another resource server", func(t *testing.T) {
		token := mcpToken(t, priv, "https://other.example.com/mcp", false)
		w := app.do(http.MethodGet, "/mcp", bearerHeader(token))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", w.Code)
		}
		if got := w.Header().Get("WWW-Authenticate"); got != mcpVectorInvalidToken {
			t.Fatalf("WWW-Authenticate = %q, want %q", got, mcpVectorInvalidToken)
		}
	})

	t.Run("refuses a general-purpose axiam:user token identically", func(t *testing.T) {
		token := mcpToken(t, priv, "axiam:user", false)
		w := app.do(http.MethodGet, "/mcp", bearerHeader(token))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", w.Code)
		}
		if got := w.Header().Get("WWW-Authenticate"); got != mcpVectorInvalidToken {
			t.Fatalf("WWW-Authenticate = %q, want %q", got, mcpVectorInvalidToken)
		}
	})

	t.Run("admits a token whose aud is this resource", func(t *testing.T) {
		token := mcpToken(t, priv, mcpFixtureExpectedAud, false)
		w := app.do(http.MethodGet, "/mcp", bearerHeader(token))
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", w.Code)
		}
		if got := w.Header().Get("WWW-Authenticate"); got != "" {
			t.Fatalf("an admitted request must carry no challenge, got %q", got)
		}
	})

	t.Run("refuses at construction when resourceMetadataURL is set with no expected audience", func(t *testing.T) {
		defer func() {
			r := recover()
			if r == nil {
				t.Fatal("expected Middleware to panic")
			}
			msg, _ := r.(string)
			if !strings.Contains(msg, "WithResourceMetadataURL") || !strings.Contains(msg, "WithExpectedAudience") {
				t.Fatalf("panic message must name both options, got %q", msg)
			}
		}()
		Middleware(verifier, mcpTenant, WithResourceMetadataURL(mcpFixtureMetadataURL))
	})
}

// ---------------------------------------------------------------------------
// The regression that matters more than all five
// ---------------------------------------------------------------------------

func TestMCP_OffByDefault(t *testing.T) {
	priv, pubJWK := generateTestKey(t, "mcp-kid")
	jwksSrv := newTestJWKSServer(t, pubJWK)
	verifier := newTestVerifier(t, jwksSrv)

	t.Run("emits no WWW-Authenticate on any response when ResourceMetadataURL is unset", func(t *testing.T) {
		app := buildMCPApp(t, verifier, mcpAppOptions{
			expectedAudience: mcpFixtureExpectedAud,
			checker:          &fakeDecisionChecker{result: axiam.AccessResult{Allowed: false, Reason: "no matching grant", ReasonCode: axiam.ReasonCodeNoGrant}},
			scope:            "mcp:tools",
		})

		unauth := app.do(http.MethodGet, "/mcp", nil)
		if unauth.Code != http.StatusUnauthorized || unauth.Header().Get("WWW-Authenticate") != "" {
			t.Fatalf("unauthenticated: status=%d header=%q", unauth.Code, unauth.Header().Get("WWW-Authenticate"))
		}
		var body map[string]any
		_ = json.Unmarshal(unauth.Body.Bytes(), &body)
		if body["error"] != "authentication_failed" || body["message"] != "missing authentication credentials" {
			t.Fatalf("§10 body changed: %v", body)
		}

		token := mcpToken(t, priv, mcpFixtureExpectedAud, false)
		authed := app.do(http.MethodGet, "/mcp", bearerHeader(token))
		if authed.Code != http.StatusOK || authed.Header().Get("WWW-Authenticate") != "" {
			t.Fatalf("authenticated: status=%d header=%q", authed.Code, authed.Header().Get("WWW-Authenticate"))
		}

		denied := app.do(http.MethodGet, "/tool", bearerHeader(token))
		if denied.Code != http.StatusForbidden || denied.Header().Get("WWW-Authenticate") != "" {
			t.Fatalf("denied: status=%d header=%q", denied.Code, denied.Header().Get("WWW-Authenticate"))
		}
		var deniedBody map[string]any
		_ = json.Unmarshal(denied.Body.Bytes(), &deniedBody)
		if deniedBody["error"] != "authorization_denied" {
			t.Fatalf("§11 body changed: %v", deniedBody)
		}
	})

	t.Run("exempts no path when ResourceMetadataURL is unset", func(t *testing.T) {
		app := buildMCPApp(t, verifier, mcpAppOptions{expectedAudience: mcpFixtureExpectedAud})
		// The metadata route was never registered (serve defaults false),
		// so this exercises Middleware's own exemption logic directly: with
		// no ResourceMetadataURL, there is no path to exempt, and this is
		// an ordinary guarded (and, since nothing is registered for it,
		// unmatched) request.
		w := app.do(http.MethodGet, mcpFixtureMetadataPath, nil)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", w.Code)
		}
		if got := w.Header().Get("WWW-Authenticate"); got != "" {
			t.Fatalf("must carry no challenge, got %q", got)
		}
	})
}

// ---------------------------------------------------------------------------
// ServeProtectedResourceMetadata — Go-specific *http.ServeMux mechanics
// ---------------------------------------------------------------------------

func TestServeProtectedResourceMetadata_ExactMatchNotSubtree(t *testing.T) {
	// A resource with a trailing slash derives a metadataPath that also
	// ends in "/" — to *http.ServeMux that is ordinarily an anonymous
	// "..." wildcard (a subtree match). §28.3 registers exactly one route
	// at exactly that path, so ServeProtectedResourceMetadata must pin it
	// with {$} rather than let it become a subtree.
	metadata, err := axiam.ProtectedResourceMetadata(axiam.ProtectedResourceMetadataOptions{
		Resource:             "https://mcp.example.com/mcp/",
		AuthorizationServers: []string{mcpFixtureAuthServer},
	})
	if err != nil {
		t.Fatalf("ProtectedResourceMetadata: %v", err)
	}
	if metadata.MetadataPath != "/.well-known/oauth-protected-resource/mcp/" {
		t.Fatalf("MetadataPath = %q", metadata.MetadataPath)
	}

	mux := http.NewServeMux()
	if _, err := ServeProtectedResourceMetadata(mux, metadata); err != nil {
		t.Fatalf("ServeProtectedResourceMetadata: %v", err)
	}

	exact := httptest.NewRecorder()
	mux.ServeHTTP(exact, httptest.NewRequest(http.MethodGet, metadata.MetadataPath, nil))
	if exact.Code != http.StatusOK {
		t.Fatalf("exact path: status = %d, want 200", exact.Code)
	}

	subtree := httptest.NewRecorder()
	mux.ServeHTTP(subtree, httptest.NewRequest(http.MethodGet, metadata.MetadataPath+"anything", nil))
	if subtree.Code == http.StatusOK {
		t.Fatal("a subtree path must NOT be served — exactly one route, at exactly the derived path")
	}
}

func TestServeProtectedResourceMetadata_RefusesMismatchedGuard(t *testing.T) {
	metadata := mcpFixtureMetadata(t)

	t.Run("resourceMetadataURL mismatch", func(t *testing.T) {
		mux := http.NewServeMux()
		_, err := ServeProtectedResourceMetadata(mux, metadata, MCPGuardConfig{
			ExpectedAudience:    mcpFixtureExpectedAud,
			ResourceMetadataURL: mcpFixtureMetadataURL + "/",
		})
		if err == nil {
			t.Fatal("expected a refusal")
		}
	})

	t.Run("expectedAudience mismatch", func(t *testing.T) {
		mux := http.NewServeMux()
		_, err := ServeProtectedResourceMetadata(mux, metadata, MCPGuardConfig{
			ExpectedAudience:    mcpFixtureExpectedAud + "/",
			ResourceMetadataURL: mcpFixtureMetadataURL,
		})
		if err == nil {
			t.Fatal("expected a refusal")
		}
	})

	t.Run("the two strings compared are different strings — matching config is accepted", func(t *testing.T) {
		mux := http.NewServeMux()
		_, err := ServeProtectedResourceMetadata(mux, metadata, MCPGuardConfig{
			ExpectedAudience:    mcpFixtureExpectedAud,
			ResourceMetadataURL: mcpFixtureMetadataURL,
		})
		if err != nil {
			t.Fatalf("expected the correct configuration to be accepted: %v", err)
		}
	})
}
