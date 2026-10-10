package axiam

// Contract 1.60's two §34.4 "verify" rows for §12: a refresh's response scope
// is the token's scope (§12.1, "A refresh may narrow scope"), and the four
// revocation / introspection discovery members decode as optional (§21.5).

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"testing"
)

// The scope of an oidc_refresh response replaces the token set's scope — never
// the original grant's, nor the scope the refresh asked for — and a response
// without one yields no scope rather than a remembered one.
func TestOidcRefresh_TheResponseScopeIsTheTokensScopeNeverTheGrants(t *testing.T) {
	srv := newOidcTestServer(t)
	narrowed := true
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		body := map[string]any{"access_token": "new-access", "token_type": "Bearer", "expires_in": 900}
		if narrowed {
			// The registration lost "email" and "openid" since the grant.
			body["scope"] = "profile"
		}
		writeJSON(t, w, body)
	}
	client, err := NewClient(srv.URL, "acme", WithOidcClientID(testClientID))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	ctx := context.Background()
	set, err := client.OidcRefresh(ctx, OidcRefreshParams{RefreshToken: Sensitive("old-refresh"),
		TenantID: testTenantID, Scope: "openid profile email"})
	if err != nil {
		t.Fatalf("OidcRefresh: %v", err)
	}
	if set.Scope != "profile" {
		t.Fatalf("the response's narrowed scope is the token's scope, got %q", set.Scope)
	}

	narrowed = false
	set, err = client.OidcRefresh(ctx, OidcRefreshParams{RefreshToken: Sensitive("next-refresh"),
		TenantID: testTenantID, Scope: "openid profile email"})
	if err != nil {
		t.Fatalf("OidcRefresh: %v", err)
	}
	if set.Scope != "" {
		t.Fatalf("no scope in the response is no scope, not the requested one: %q", set.Scope)
	}
}

// §21.5 (contract 1.60): the four members decode when present, and both vector
// A (abridged, without them) and a pre-1.0.0 document still decode.
func TestOidcConfiguration_TheFourRevocationAndIntrospectionMembersAreOptional(t *testing.T) {
	var a OidcConfiguration
	if err := json.Unmarshal(vectorA(t), &a); err != nil {
		t.Fatalf("vector A decodes: %v", err)
	}
	if a.RevocationEndpointAuthMethodsSupported != nil || a.IntrospectionEndpointAuthMethodsSupported != nil ||
		a.RevocationEndpointAuthSigningAlgValuesSupported != nil || a.IntrospectionEndpointAuthSigningAlgValuesSupported != nil {
		t.Fatalf("absent members are nil: %+v", a)
	}

	var old OidcConfiguration
	if err := json.Unmarshal([]byte(`{"issuer":"https://idp.example","token_endpoint":"https://idp.example/oauth2/token"}`), &old); err != nil {
		t.Fatalf("a pre-1.0.0 document decodes: %v", err)
	}

	algs := []string{"PS256", "ES256", "EdDSA"}
	doc := map[string]any{
		"issuer":         "https://idp.example",
		"token_endpoint": "https://idp.example/oauth2/token",
		"revocation_endpoint_auth_methods_supported":               []string{"client_secret_basic", "private_key_jwt", "none"},
		"introspection_endpoint_auth_methods_supported":            []string{"client_secret_basic", "private_key_jwt"},
		"revocation_endpoint_auth_signing_alg_values_supported":    algs,
		"introspection_endpoint_auth_signing_alg_values_supported": algs,
	}
	var now OidcConfiguration
	if err := json.Unmarshal([]byte(mustJSON(t, doc)), &now); err != nil {
		t.Fatalf("a 1.60 document decodes: %v", err)
	}
	if !reflect.DeepEqual(now.RevocationEndpointAuthMethodsSupported, []string{"client_secret_basic", "private_key_jwt", "none"}) ||
		!reflect.DeepEqual(now.IntrospectionEndpointAuthMethodsSupported, []string{"client_secret_basic", "private_key_jwt"}) ||
		!reflect.DeepEqual(now.RevocationEndpointAuthSigningAlgValuesSupported, algs) ||
		!reflect.DeepEqual(now.IntrospectionEndpointAuthSigningAlgValuesSupported, algs) {
		t.Fatalf("the four members decode: %+v", now)
	}
}
