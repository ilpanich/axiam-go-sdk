package axiam

// Contract 1.40 -> 1.42 re-sync regressions.
//
// Three rules, each pinned here because the Go SDK's current behaviour is
// already right and the point is to keep it that way:
//
//   - §21.5 / RFC 8414 §2. The two discovery members added in 1.42 decode,
//     and an OP that OMITS them yields nil rather than a synthesised
//     ["S256"]. RFC 8414 defines no default for code_challenge_methods_supported,
//     so "absent" and "S256" are different answers and the type must keep
//     them apart.
//   - RFC 9449 §10.1. dpop_jkt reaches the PAR form when the caller supplies
//     one, and is absent from the wire entirely when they do not — not sent
//     as an empty value. And request_uri is never pushed: RFC 9126 §2.1
//     forbids exactly that parameter at this endpoint.
//   - §12.1 note 2 / §12.3 rule 4. As of contract 1.42 the server's discovery
//     document may ALREADY carry ?tenant_id= on the advertised token /
//     revocation / introspection / device-authorization / PAR / end-session
//     URLs. The SDK resolves its own tenant onto that URL, so the builder has
//     to REPLACE the parameter rather than append a second one — and has to
//     leave every other query parameter on the endpoint alone (RFC 6749
//     §3.1/§3.2).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// §21.5 — the two discovery members added in contract 1.42
// ---------------------------------------------------------------------------

// TestOidcDiscover_DecodesContract142Members proves the 1.42 additions land
// in the typed discovery model.
func TestOidcDiscover_DecodesContract142Members(t *testing.T) {
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		doc := discoveryDoc(srv.URL)
		doc.CodeChallengeMethodsSupported = []string{"S256"}
		doc.TokenEndpointAuthSigningAlgValuesSupported = []string{"PS256", "ES256", "EdDSA"}
		writeJSON(t, w, doc)
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()

	client, err := NewClient(srv.URL, "acme")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	got, err := client.OidcDiscover(context.Background())
	if err != nil {
		t.Fatalf("OidcDiscover: %v", err)
	}

	if len(got.CodeChallengeMethodsSupported) != 1 || got.CodeChallengeMethodsSupported[0] != "S256" {
		t.Fatalf("code_challenge_methods_supported: got %v", got.CodeChallengeMethodsSupported)
	}
	want := []string{"PS256", "ES256", "EdDSA"}
	if len(got.TokenEndpointAuthSigningAlgValuesSupported) != len(want) {
		t.Fatalf("token_endpoint_auth_signing_alg_values_supported: got %v", got.TokenEndpointAuthSigningAlgValuesSupported)
	}
	for i, alg := range want {
		if got.TokenEndpointAuthSigningAlgValuesSupported[i] != alg {
			t.Fatalf("token_endpoint_auth_signing_alg_values_supported[%d]: got %q, want %q",
				i, got.TokenEndpointAuthSigningAlgValuesSupported[i], alg)
		}
	}
}

// TestOidcDiscover_AbsentContract142MembersAreNilNotDefaulted is the half
// that matters. openapi.json marks both members required as of 1.42, but the
// model keeps them optional: a non-AXIAM OP that omits them must still parse,
// and §21.5 is explicit that absence "does not mean S256".
func TestOidcDiscover_AbsentContract142MembersAreNilNotDefaulted(t *testing.T) {
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		// A deliberately foreign, minimal document: neither member present.
		writeJSON(t, w, map[string]any{
			"issuer":                 srv.URL,
			"authorization_endpoint": srv.URL + "/authorize",
			"token_endpoint":         srv.URL + "/token",
			"jwks_uri":               srv.URL + "/jwks",
		})
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()

	client, err := NewClient(srv.URL, "acme")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	got, err := client.OidcDiscover(context.Background())
	if err != nil {
		t.Fatalf("a document omitting the 1.42 members must still parse: %v", err)
	}
	if got.CodeChallengeMethodsSupported != nil {
		t.Fatalf("absent code_challenge_methods_supported must stay absent, got %v", got.CodeChallengeMethodsSupported)
	}
	if got.TokenEndpointAuthSigningAlgValuesSupported != nil {
		t.Fatalf("absent token_endpoint_auth_signing_alg_values_supported must stay absent, got %v",
			got.TokenEndpointAuthSigningAlgValuesSupported)
	}
}

// ---------------------------------------------------------------------------
// RFC 9449 §10.1 — dpop_jkt on the pushed authorization request
// ---------------------------------------------------------------------------

func TestOidcPar_SendsDPoPJKTOnlyWhenSet(t *testing.T) {
	const jkt = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"

	t.Run("present when the caller supplies one", func(t *testing.T) {
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
			TenantID:      parTenantUUID,
			DPoPJKT:       jkt,
			Configuration: &configuration,
		}); err != nil {
			t.Fatalf("OidcPar: %v", err)
		}
		if got := capture.forms[0].Get("dpop_jkt"); got != jkt {
			t.Fatalf("dpop_jkt: got %q, want %q", got, jkt)
		}
	})

	t.Run("omitted entirely when the caller does not", func(t *testing.T) {
		server, capture := parServer(t, parCreated)
		client := parClient(t, server, WithOidcClientSecret(parSecret))
		if _, _, err := parPush(t, client, server); err != nil {
			t.Fatalf("OidcPar: %v", err)
		}
		if capture.forms[0].Has("dpop_jkt") {
			t.Fatalf("an unset dpop_jkt must not appear on the wire at all, got %q",
				capture.forms[0].Get("dpop_jkt"))
		}
	})
}

// TestOidcPar_NeverPushesRequestURI pins RFC 9126 §2.1: request_uri is the
// one authorization parameter a client MUST NOT send to the PAR endpoint.
// The SDK exposes no way to set it, and this asserts none appears by any
// other route.
func TestOidcPar_NeverPushesRequestURI(t *testing.T) {
	server, capture := parServer(t, parCreated)
	client := parClient(t, server, WithOidcClientSecret(parSecret))
	if _, _, err := parPush(t, client, server); err != nil {
		t.Fatalf("OidcPar: %v", err)
	}
	if capture.forms[0].Has("request_uri") {
		t.Fatal("RFC 9126 §2.1 forbids request_uri on a pushed authorization request")
	}
}

// ---------------------------------------------------------------------------
// §12.1 note 2 — a discovery endpoint that already carries tenant_id
// ---------------------------------------------------------------------------

// TestOidcEndpointURL_ReplacesAdvertisedTenantID is the contract-1.42
// regression. The server now scopes the advertised token / revocation /
// introspection / device-authorization / PAR / end-session URLs with
// ?tenant_id= when the discovery request named a tenant. An SDK that APPENDS
// its own parameter would put two tenant_id values on the wire; Go's builder
// uses url.Values.Set, which replaces, so exactly one survives — and the
// endpoint's own unrelated parameters survive with it.
func TestOidcEndpointURL_ReplacesAdvertisedTenantID(t *testing.T) {
	const advertised = "22222222-2222-2222-2222-222222222222"
	const resolved = "11111111-1111-1111-1111-111111111111"

	client, err := NewClient("https://idp.test", "acme")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	cases := []struct {
		name     string
		endpoint string
	}{
		{"already tenant-scoped", "https://idp.test/oauth2/token?tenant_id=" + advertised},
		{"tenant-scoped plus an unrelated parameter", "https://idp.test/oauth2/token?audience=api&tenant_id=" + advertised},
		{"unrelated parameter only", "https://idp.test/oauth2/token?audience=api"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			built, err := client.oidcEndpointURL(tc.endpoint, resolved)
			if err != nil {
				t.Fatalf("oidcEndpointURL: %v", err)
			}
			parsed, err := url.Parse(built)
			if err != nil {
				t.Fatalf("parse %q: %v", built, err)
			}
			values := parsed.Query()

			// Exactly one tenant_id, and it is the resolved one: the value the
			// caller/session actually authenticated against wins.
			if got := values["tenant_id"]; len(got) != 1 {
				t.Fatalf("expected exactly one tenant_id on the wire, got %v (url %q)", got, built)
			}
			if got := values.Get("tenant_id"); got != resolved {
				t.Fatalf("tenant_id: got %q, want the resolved %q", got, resolved)
			}
			if strings.Contains(tc.endpoint, "audience=api") && values.Get("audience") != "api" {
				t.Fatalf("an unrelated endpoint query parameter must be preserved (RFC 6749 §3.1/§3.2), got %q", built)
			}
		})
	}
}

// TestOidcPar_SingleTenantIDAgainstATenantScopedDiscoveryDocument is the same
// rule proved end-to-end on a real request, rather than against the URL
// builder in isolation: the PAR endpoint the document advertises already
// carries a tenant_id, and the push must still arrive with one.
func TestOidcPar_SingleTenantIDAgainstATenantScopedDiscoveryDocument(t *testing.T) {
	const advertised = "22222222-2222-2222-2222-222222222222"

	server, capture := parServer(t, parCreated)
	client := parClient(t, server, WithOidcClientSecret(parSecret))

	configuration := discoveryDoc(server.URL)
	// What contract 1.42's tenant_scoped() now publishes.
	configuration.PushedAuthorizationRequestEndpoint = server.URL + "/oauth2/par?tenant_id=" + advertised

	request, err := client.OidcBegin(configuration, OidcBeginParams{RedirectURI: parRedirectURI})
	if err != nil {
		t.Fatalf("OidcBegin: %v", err)
	}
	if _, err := client.OidcPar(context.Background(), OidcParParams{
		Request:       request,
		RedirectURI:   parRedirectURI,
		TenantID:      parTenantUUID,
		Configuration: &configuration,
	}); err != nil {
		t.Fatalf("OidcPar: %v", err)
	}

	if got := capture.queries[0]["tenant_id"]; len(got) != 1 {
		t.Fatalf("expected exactly one tenant_id on the pushed request, got %v", got)
	}
	if got := capture.queries[0].Get("tenant_id"); got != parTenantUUID {
		t.Fatalf("tenant_id: got %q, want the resolved %q", got, parTenantUUID)
	}
}

// TestLogoutURL_PreservesAnAdvertisedTenantID is the other side of the same
// coin. LogoutURL adds no tenant_id of its own — end_session is a front-channel
// redirect, not an SDK-issued request — so a tenant_id the server put on the
// advertised end_session_endpoint must survive into the browser URL
// unduplicated and unchanged.
func TestLogoutURL_PreservesAnAdvertisedTenantID(t *testing.T) {
	const advertised = "22222222-2222-2222-2222-222222222222"

	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		doc := discoveryDoc(srv.URL)
		doc.EndSessionEndpoint = srv.URL + "/oauth2/end_session?tenant_id=" + advertised
		writeJSON(t, w, doc)
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()

	client, err := NewClient(srv.URL, "acme")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	built, err := client.LogoutURL(context.Background(), LogoutURLParams{IDToken: Sensitive("id-token")})
	if err != nil {
		t.Fatalf("LogoutURL: %v", err)
	}
	parsed, err := url.Parse(built)
	if err != nil {
		t.Fatalf("parse %q: %v", built, err)
	}
	if got := parsed.Query()["tenant_id"]; len(got) != 1 || got[0] != advertised {
		t.Fatalf("the advertised tenant_id must survive exactly once, got %v (url %q)", got, built)
	}
}

// ---------------------------------------------------------------------------
// #1 — the ID token no longer carries tenant_id / org_id / email
// ---------------------------------------------------------------------------

// TestIDTokenClaims_NoTypedTenantOrgOrEmail pins WHY contract 1.42's
// ID-token change (OIDC Core §5.4: those three stopped being emitted) needed
// no code change here. The Go SDK models none of them as typed claims; an OP
// that still sends them gets them preserved in the open extras map, and an OP
// that does not leaves nothing empty-but-present behind.
func TestIDTokenClaims_NoTypedTenantOrgOrEmail(t *testing.T) {
	payload, err := json.Marshal(map[string]any{
		"iss":       "https://idp.test",
		"sub":       "user-1",
		"aud":       "client-1",
		"exp":       1,
		"iat":       1,
		"tenant_id": "11111111-1111-1111-1111-111111111111",
		"org_id":    "22222222-2222-2222-2222-222222222222",
		"email":     "user@example.test",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Whatever the OP sends beyond the modelled set stays in the open map...
	extra := extractExtraClaims(payload)
	for _, claim := range []string{"tenant_id", "org_id", "email"} {
		if _, ok := extra[claim]; !ok {
			t.Fatalf("%q must be preserved in the open extras map", claim)
		}
	}

	// ...and none of the three is a modelled claim, so AXIAM dropping them
	// cannot silently empty a typed field.
	for _, claim := range []string{"tenant_id", "org_id", "email"} {
		if containsString(idTokenKnownClaimKeys, claim) {
			t.Fatalf("%q must not be a typed ID-token claim: contract 1.42 stopped emitting it "+
				"(OIDC Core §5.4), and a typed field would now read empty on every login", claim)
		}
	}
}
