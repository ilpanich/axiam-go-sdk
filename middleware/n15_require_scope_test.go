package middleware

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

// RequireScope (CONTRACT.md §11.2 rule 11 d) reads the "scope" claim only.

func TestRequireScope_N15_ScopeClaimGrants(t *testing.T) {
	// The first N15 token: scope "openid admin", no roles claim.
	code, ran := n15Serve(t, RequireScope("admin"), n15Claims(nil, "openid admin"))
	if code != http.StatusOK || !ran {
		t.Fatalf("scope \"openid admin\" must satisfy RequireScope(\"admin\"), got %d (handler ran: %v)", code, ran)
	}
}

func TestRequireScope_N15_RolesClaimIsNotAScope(t *testing.T) {
	code, ran := n15Serve(t, RequireScope("admin"), n15Claims([]string{"admin"}, "openid"))
	if code != http.StatusForbidden || ran {
		t.Fatalf("roles [admin] must not satisfy RequireScope(\"admin\"), got %d (handler ran: %v)", code, ran)
	}
}

func TestRequireScope_N15_NoScopeClaimFailsClosed(t *testing.T) {
	code, ran := n15Serve(t, RequireScope("admin"), n15Claims([]string{"admin"}, ""))
	if code != http.StatusForbidden || ran {
		t.Fatalf("a token with no scope claim must fail RequireScope, got %d", code)
	}
}

func TestRequireScope_N15_ExactCaseSensitiveAnyOf(t *testing.T) {
	if code, _ := n15Serve(t, RequireScope("ADMIN", "adm"), n15Claims(nil, "openid admin")); code != http.StatusForbidden {
		t.Fatalf("scope match must be exact and case-sensitive, got %d", code)
	}
	if code, ran := n15Serve(t, RequireScope("write", "openid"), n15Claims(nil, "openid admin")); code != http.StatusOK || !ran {
		t.Fatalf("any one of the given scopes must suffice, got %d", code)
	}
	if code, _ := n15Serve(t, RequireScope(), n15Claims(nil, "openid admin")); code != http.StatusForbidden {
		t.Fatalf("RequireScope with no scopes is a programming error and must deny, got %d", code)
	}
}

// §11.2 rule 11 g's literal case, and rule 11 d's split "on single spaces"
// (GO-R1-8): a scope token never matches a prefix of itself, and no
// whitespace other than U+0020 separates scope tokens.
func TestRequireScope_N15_ContractLiteralCases(t *testing.T) {
	if code, ran := n15Serve(t, RequireScope("admin"), n15Claims(nil, "administrator")); code != http.StatusForbidden || ran {
		t.Fatalf(`scope "administrator" must not pass RequireScope("admin"), got %d (handler ran: %v)`, code, ran)
	}
	if code, ran := n15Serve(t, RequireScope("admin"), n15Claims(nil, "openid\tadmin")); code != http.StatusForbidden || ran {
		t.Fatalf(`a tab is not a scope separator: scope "openid\tadmin" must not pass RequireScope("admin"), got %d (handler ran: %v)`, code, ran)
	}
	if code, ran := n15Serve(t, RequireScope("admin"), n15Claims(nil, "openid  admin")); code != http.StatusOK || !ran {
		t.Fatalf(`empty entries between single spaces are dropped: "openid  admin" must pass RequireScope("admin"), got %d`, code)
	}
}

func TestRequireScope_N15_NoIdentityIs401(t *testing.T) {
	rec := &recordingHandler{}
	w := httptest.NewRecorder()
	RequireScope("admin")(rec.handler()).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusUnauthorized || rec.called {
		t.Fatalf("no identity must be 401, got %d", w.Code)
	}
}

func TestMiddleware_N15_IdentityKeepsRolesAndScopesApart(t *testing.T) {
	priv, pubJWK := generateTestKey(t, "kid-1")
	verifier := newTestVerifier(t, newTestJWKSServer(t, pubJWK))
	var got *User
	h := Middleware(verifier, testConfiguredTenant)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got, _ = UserFromContext(r.Context())
	}))
	for _, tc := range []struct {
		name      string
		claims    testClaims
		wantHas   bool
		wantRoles int
	}{
		{"roles absent", n15Claims(nil, "openid roles"), false, 0},
		{"roles empty", n15Claims([]string{}, "openid roles"), true, 0},
		{"roles present", n15Claims([]string{"admin"}, "openid roles"), true, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got = nil
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Authorization", "Bearer "+signTestToken(t, priv, "kid-1", tc.claims))
			h.ServeHTTP(httptest.NewRecorder(), req)
			if got == nil {
				t.Fatal("no identity injected")
			}
			if got.HasRoles != tc.wantHas || len(got.Roles) != tc.wantRoles {
				t.Fatalf("HasRoles=%v Roles=%v, want HasRoles=%v and %d roles", got.HasRoles, got.Roles, tc.wantHas, tc.wantRoles)
			}
			if len(got.Scopes) != 2 || got.Scopes[0] != "openid" || got.Scopes[1] != "roles" {
				t.Fatalf("Scopes = %v", got.Scopes)
			}
		})
	}
}

// N14 through the guard: a purpose-bearing token and a differently-typed
// token are 401 at Middleware; a normal token passes (CONTRACT.md §10.1
// rules 10-12).
func TestMiddleware_N14_RefusesPurposeAndMistypedTokens(t *testing.T) {
	priv, pubJWK := generateTestKey(t, "kid-1")
	verifier := newTestVerifier(t, newTestJWKSServer(t, pubJWK))
	base := `"sub":"user-123","tenant_id":"` + testConfiguredTenant + `","exp":` + strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
	sign := func(typ, extra string) string {
		hdr := jws.NewHeaders()
		if typ != "" {
			_ = hdr.Set("typ", typ)
		}
		pk, _ := jwk.Import(priv)
		_ = pk.Set(jwk.KeyIDKey, "kid-1")
		signed, err := jws.Sign([]byte(`{`+base+extra+`}`), jws.WithKey(jwa.EdDSA(), pk, jws.WithProtectedHeaders(hdr)))
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		return string(signed)
	}
	for _, tc := range []struct {
		name, token string
		want        int
	}{
		{"normal at+jwt token", sign("at+jwt", ""), http.StatusOK},
		{"purpose claim", sign("at+jwt", `,"purpose":"mfa_challenge"`), http.StatusUnauthorized},
		{"typ axiam-webauthn-state+jwt", sign("axiam-webauthn-state+jwt", ""), http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recordingHandler{}
			h := Middleware(verifier, testConfiguredTenant)(rec.handler())
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("Authorization", "Bearer "+tc.token)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != tc.want || rec.called != (tc.want == http.StatusOK) {
				t.Fatalf("got %d (handler ran: %v), want %d", w.Code, rec.called, tc.want)
			}
		})
	}
}
