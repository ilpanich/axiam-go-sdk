package middleware

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// N15 (CONTRACT.md §11.2 rule 11, contract 1.68; D-1): RequireRole reads the
// verified token's `roles` claim and nothing else. An OAuth2 scope is chosen
// by the client and says nothing about what the user holds, so a scope that
// happens to be named like a role must never satisfy RequireRole, and an
// absent `roles` claim fails closed with 403.

// n15Serve runs one request carrying token through Middleware and then guard,
// against a handler that records whether it ran.
func n15Serve(t *testing.T, guard func(http.Handler) http.Handler, claims testClaims) (code int, ran bool) {
	t.Helper()
	priv, pubJWK := generateTestKey(t, "kid-1")
	verifier := newTestVerifier(t, newTestJWKSServer(t, pubJWK))
	rec := &recordingHandler{}
	h := Middleware(verifier, testConfiguredTenant)(guard(rec.handler()))

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.Header.Set("Authorization", "Bearer "+signTestToken(t, priv, "kid-1", claims))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w.Code, rec.called
}

func n15Claims(roles []string, scope string) testClaims {
	return testClaims{
		Subject:  "user-123",
		TenantID: testConfiguredTenant,
		OrgID:    "org-xyz",
		Roles:    roles,
		Scope:    scope,
		Exp:      at(time.Now().Add(time.Hour)),
	}
}

func TestRequireRole_N15_ScopeNamedLikeARoleIsNotARole(t *testing.T) {
	code, ran := n15Serve(t, RequireRole("admin"), n15Claims(nil, "openid admin"))
	if code != http.StatusForbidden || ran {
		t.Fatalf("scope %q with no roles claim must be refused 403 by RequireRole(\"admin\"), got %d (handler ran: %v)", "openid admin", code, ran)
	}
}

func TestRequireRole_N15_RolesClaimGrants(t *testing.T) {
	code, ran := n15Serve(t, RequireRole("admin"), n15Claims([]string{"admin"}, "openid"))
	if code != http.StatusOK || !ran {
		t.Fatalf("roles [admin] must satisfy RequireRole(\"admin\"), got %d (handler ran: %v)", code, ran)
	}
}

func TestRequireRole_N15_RolesClaimGrantsWithoutScope(t *testing.T) {
	code, ran := n15Serve(t, RequireRole("admin"), n15Claims([]string{"admin"}, ""))
	if code != http.StatusOK || !ran {
		t.Fatalf("a token with roles [admin] and no scope claim must satisfy RequireRole, got %d", code)
	}
}

func TestRequireRole_N15_EmptyRolesArrayFailsClosed(t *testing.T) {
	code, ran := n15Serve(t, RequireRole("admin"), n15Claims([]string{}, "openid admin"))
	if code != http.StatusForbidden || ran {
		t.Fatalf("roles [] must fail every RequireRole, got %d (handler ran: %v)", code, ran)
	}
}

func TestRequireRole_N15_RolesMatchIsExactAndCaseSensitive(t *testing.T) {
	code, ran := n15Serve(t, RequireRole("admin"), n15Claims([]string{"Admin", "administrator"}, ""))
	if code != http.StatusForbidden || ran {
		t.Fatalf("roles [Admin administrator] must not satisfy RequireRole(\"admin\"), got %d", code)
	}
}

func TestRequireRole_N15_RolesClaimNotAnArrayFailsClosed(t *testing.T) {
	priv, pubJWK := generateTestKey(t, "kid-1")
	verifier := newTestVerifier(t, newTestJWKSServer(t, pubJWK))
	for name, payload := range map[string]string{
		"string": `"admin"`,
		"object": `{"admin":true}`,
		"mixed":  `["reader",7]`,
		// GO-R1-3: encoding/json decodes a null element into a []string as
		// "", so this used to read as the array ["admin",""].
		"null element":         `["admin",null]`,
		"leading null element": `[null,"admin"]`,
		"nested":               `[["admin"]]`,
		"null":                 `null`,
		"boolean":              `true`,
		"a number":             `1`,
	} {
		t.Run(name, func(t *testing.T) {
			rec := &recordingHandler{}
			h := Middleware(verifier, testConfiguredTenant)(RequireRole("admin")(rec.handler()))
			body := `{"sub":"user-123","tenant_id":"` + testConfiguredTenant + `","exp":` + strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10) + `,"scope":"openid admin","roles":` + payload + `}`
			req := httptest.NewRequest(http.MethodGet, "/admin", nil)
			req.Header.Set("Authorization", "Bearer "+signTestTokenRaw(t, priv, "kid-1", []byte(body)))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != http.StatusForbidden || rec.called {
				t.Fatalf("roles %s must fail closed 403, got %d (handler ran: %v)", payload, w.Code, rec.called)
			}
		})
	}
}
