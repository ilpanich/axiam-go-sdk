package axiam

// UMA 2.0 — CONTRACT.md §20.7 required assertions.
//
// Like §15, most of §20 is a list of things an SDK must NOT helpfully do, so
// most of these tests assert an absence. The centrepiece is §20.2 rule 6: a
// permission ticket is never retried.
//
// That rule is the one documented exception to §16, and the only way to assert
// it is to count requests. A ticket is consumed BEFORE the exchange is
// evaluated, so a failed exchange has already spent it — and under concurrency
// a retry is precisely the concurrent redemption a server whose storage engine
// this SDK cannot attest may admit twice (ilpanich/axiam#302). "Exactly one
// request" is a security assertion here, not a performance one.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const (
	testPAT           = "pat-token-value"
	testTicket        = "ticket-value"
	testClaimToken    = "claim-token-value"
	testRPT           = "rpt-token-value"
	testUmaResourceID = "99999999-8888-7777-6666-555555555555"
)

func newUmaClient(t *testing.T, srv *oidcTestServer, withSecret bool) *Client {
	t.Helper()
	opts := []Option{WithOidcClientID("orders-resource-server")}
	if withSecret {
		opts = append(opts, WithOidcClientSecret("resource-server-secret"))
	}
	client, err := NewClient(srv.URL, "acme", opts...)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return client
}

func resourceSetBody(scopes ...string) map[string]any {
	return map[string]any{
		"_id":             testUmaResourceID,
		"name":            "invoice-7",
		"type":            "document",
		"resource_scopes": scopes,
	}
}

func rptBody(overrides map[string]any) map[string]any {
	body := map[string]any{
		"access_token": testRPT,
		"token_type":   "Bearer",
		"expires_in":   300,
	}
	for k, v := range overrides {
		body[k] = v
	}
	return body
}

// ---------------------------------------------------------------------------
// §20.1 the Protection API
// ---------------------------------------------------------------------------

func TestUmaRegistrationRoundTripsAndTheIDIsUsableAsATicketResourceID(t *testing.T) {
	srv := newOidcTestServer(t)
	srv.RregHandler = func(w http.ResponseWriter, r *http.Request) {
		writeStatusJSON(w, http.StatusCreated, resourceSetBody("view"))
	}
	var ticketBody []map[string]any
	srv.PermHandler = func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&ticketBody)
		writeStatusJSON(w, http.StatusCreated, map[string]any{"ticket": testTicket})
	}

	client := newUmaClient(t, srv, true)
	registered, err := client.UmaRegisterResource(context.Background(), Sensitive(testPAT), ResourceSet{
		Name:           "invoice-7",
		Type:           "document",
		ResourceScopes: []string{"view"},
	})
	if err != nil {
		t.Fatalf("UmaRegisterResource: %v", err)
	}
	if registered.ID != testUmaResourceID {
		t.Fatalf("registered id: got %q, want %q", registered.ID, testUmaResourceID)
	}

	// §20.1: `_id` IS the AXIAM resource id, not a parallel identifier — it
	// goes straight back out as a requested permission with no translation.
	ticket, err := client.UmaRequestTicket(context.Background(), Sensitive(testPAT), []RequestedPermission{
		{ResourceID: registered.ID, ResourceScopes: []string{"view"}},
	})
	if err != nil {
		t.Fatalf("UmaRequestTicket: %v", err)
	}
	if ticket.expose() != testTicket {
		t.Errorf("ticket: got %q", ticket.expose())
	}
	if len(ticketBody) != 1 || ticketBody[0]["resource_id"] != testUmaResourceID {
		t.Errorf("permission body: got %+v", ticketBody)
	}
}

func TestUmaRegisterOmitsAnEmptyTypeRatherThanSendingItBlank(t *testing.T) {
	srv := newOidcTestServer(t)
	var sent map[string]any
	srv.RregHandler = func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&sent)
		writeStatusJSON(w, http.StatusCreated, resourceSetBody("view"))
	}

	_, err := newUmaClient(t, srv, true).UmaRegisterResource(context.Background(), Sensitive(testPAT), ResourceSet{
		Name:           "invoice-7",
		ResourceScopes: []string{"view"},
	})
	if err != nil {
		t.Fatalf("UmaRegisterResource: %v", err)
	}

	// §12.1: an absent optional field is omitted, never sent empty — here so
	// the server applies its own `uma_resource` default rather than storing "".
	if _, present := sent["type"]; present {
		t.Errorf("an empty Type must be omitted from the payload, got %+v", sent)
	}
}

func TestUmaUpdateSendsExactlyTheScopesGivenWithNoReadFirst(t *testing.T) {
	srv := newOidcTestServer(t)
	var method string
	var sent map[string]any
	srv.RregHandler = func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		_ = json.NewDecoder(r.Body).Decode(&sent)
		writeStatusJSON(w, http.StatusOK, resourceSetBody("view"))
	}

	updated, err := newUmaClient(t, srv, true).UmaUpdateResource(context.Background(), Sensitive(testPAT), testUmaResourceID, ResourceSet{
		Name:           "invoice-7",
		Type:           "document",
		ResourceScopes: []string{"view"},
	})
	if err != nil {
		t.Fatalf("UmaUpdateResource: %v", err)
	}

	// §20.2 rule 8: the update replaces the scope list. A read-modify-write
	// would show up here as two rreg calls, and would silently make removing a
	// scope impossible through the SDK.
	if calls := srv.RregCalls(); calls != 1 {
		t.Errorf("rreg calls: got %d, want 1 — an update must not read the current scopes first", calls)
	}
	if method != http.MethodPut {
		t.Errorf("method: got %s, want PUT", method)
	}
	scopes, _ := sent["resource_scopes"].([]any)
	if len(scopes) != 1 || scopes[0] != "view" {
		t.Errorf("resource_scopes: got %+v, want exactly [view]", sent["resource_scopes"])
	}
	if len(updated.ResourceScopes) != 1 {
		t.Errorf("updated scopes: got %+v", updated.ResourceScopes)
	}
}

func TestUmaRequestTicketSurfacesAnUndeclaredScope400Unchanged(t *testing.T) {
	srv := newOidcTestServer(t)
	srv.PermHandler = func(w http.ResponseWriter, r *http.Request) {
		writeStatusJSON(w, http.StatusBadRequest, map[string]any{"message": "scope not declared on resource"})
	}

	_, err := newUmaClient(t, srv, true).UmaRequestTicket(context.Background(), Sensitive(testPAT), []RequestedPermission{
		{ResourceID: testUmaResourceID, ResourceScopes: []string{"delete"}},
	})

	var netErr *NetworkError
	if !errors.As(err, &netErr) {
		t.Fatalf("want *NetworkError for a 400, got %T: %v", err, err)
	}
	if calls := srv.PermCalls(); calls != 1 {
		t.Errorf("perm calls: got %d, want 1", calls)
	}
}

func TestUmaProtectionApiSurfacesA403FromATokenThatIsNotAPAT(t *testing.T) {
	srv := newOidcTestServer(t)
	srv.PermHandler = func(w http.ResponseWriter, r *http.Request) {
		writeStatusJSON(w, http.StatusForbidden, map[string]any{
			"error":   "authorization_denied",
			"message": "the protection API requires the 'uma_protection' scope",
		})
	}

	// §20.2 rule 1: a user access token is not a PAT. The SDK does not
	// pre-judge the token's subject kind — it lets the server's refusal
	// through as an *AuthzError, the §2 mapping for a 403, rather than an
	// OAuth2 protocol error (those rows belong to the token endpoint, §20.4).
	_, err := newUmaClient(t, srv, true).UmaRequestTicket(context.Background(), Sensitive("a-user-token"), []RequestedPermission{
		{ResourceID: testUmaResourceID, ResourceScopes: []string{"view"}},
	})

	var authzErr *AuthzError
	if !errors.As(err, &authzErr) {
		t.Fatalf("want *AuthzError for a Protection API 403, got %T: %v", err, err)
	}
}

func TestUmaProtectionApiSendsThePATAndNotTheAdoptedSessionToken(t *testing.T) {
	srv := newOidcTestServer(t)
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		writeStatusJSON(w, http.StatusOK, map[string]any{
			"access_token": "session-access", "token_type": "Bearer", "expires_in": 3600,
		})
	}
	var auth string
	srv.RregHandler = func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		writeStatusJSON(w, http.StatusOK, []string{testUmaResourceID})
	}

	client := newUmaClient(t, srv, true)
	// Adopt an ordinary session credential first, so the PAT has something to
	// beat.
	if _, err := client.LoginClientCredentials(context.Background(), LoginClientCredentialsParams{
		TenantID: testTenantUUID, AdoptAsCredential: true,
	}); err != nil {
		t.Fatalf("LoginClientCredentials: %v", err)
	}

	ids, err := client.UmaListResources(context.Background(), Sensitive(testPAT))
	if err != nil {
		t.Fatalf("UmaListResources: %v", err)
	}
	if len(ids) != 1 || ids[0] != testUmaResourceID {
		t.Errorf("ids: got %+v", ids)
	}
	// §20.2 rule 1: a minted ticket is bound to the client_id that minted it,
	// so the Protection API credential is the caller's explicit PAT — never a
	// silent fallback to whatever this client's session happens to hold.
	if auth != "Bearer "+testPAT {
		t.Errorf("Authorization: got %q, want the PAT", auth)
	}
}

func TestUmaProtectionApiRefusesAnEmptyPATClientSide(t *testing.T) {
	srv := newOidcTestServer(t)

	err := newUmaClient(t, srv, true).UmaDeleteResource(context.Background(), "", testUmaResourceID)

	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("want *AuthError, got %T: %v", err, err)
	}
	// The refusal is client-side: an omitted PAT must not become "send it with
	// whatever credential is lying around" (§20.2 rule 1).
	if calls := srv.RregCalls(); calls != 0 {
		t.Errorf("rreg calls: got %d, want 0", calls)
	}
}

func TestUmaDeleteAndReadUseTheirOwnMethodsAndPaths(t *testing.T) {
	srv := newOidcTestServer(t)
	var seen []string
	srv.RregHandler = func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.Path)
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeStatusJSON(w, http.StatusOK, resourceSetBody("view", "edit"))
	}

	client := newUmaClient(t, srv, true)
	resource, err := client.UmaReadResource(context.Background(), Sensitive(testPAT), testUmaResourceID)
	if err != nil {
		t.Fatalf("UmaReadResource: %v", err)
	}
	// §20.6: scopes and the resource id are NOT sensitive and must stay
	// readable — an application cannot act on a resource it may not inspect.
	if len(resource.ResourceScopes) != 2 {
		t.Errorf("scopes: got %+v", resource.ResourceScopes)
	}
	if err := client.UmaDeleteResource(context.Background(), Sensitive(testPAT), testUmaResourceID); err != nil {
		t.Fatalf("UmaDeleteResource: %v", err)
	}

	want := []string{
		"GET /uma2/rreg/resource_set/" + testUmaResourceID,
		"DELETE /uma2/rreg/resource_set/" + testUmaResourceID,
	}
	if strings.Join(seen, "|") != strings.Join(want, "|") {
		t.Errorf("requests: got %v, want %v", seen, want)
	}
}

// ---------------------------------------------------------------------------
// §20.2 rule 6 — the ticket grant is never retried
// ---------------------------------------------------------------------------

func TestUmaExchangeTicketIsNotRetriedOnA5xx(t *testing.T) {
	srv := newOidcTestServer(t)
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}

	_, err := newUmaClient(t, srv, true).UmaExchangeTicket(context.Background(), UmaExchangeTicketParams{
		Ticket: Sensitive(testTicket), ClaimToken: Sensitive(testClaimToken), TenantID: testTenantUUID,
	})
	if err == nil {
		t.Fatal("expected the 500 to surface")
	}

	if calls := srv.TokenCalls(); calls != 1 {
		t.Errorf("token calls: got %d, want 1 — retrying a spent ticket is the concurrent "+
			"redemption ilpanich/axiam#302 describes", calls)
	}
}

func TestUmaExchangeTicketIsNotRetriedOnATransportFailure(t *testing.T) {
	// A server that hangs up mid-response is the timeout case §20.2 rule 6
	// names explicitly: a failed exchange may well have reached the server and
	// spent the ticket. Silence is not evidence it did not.
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/oauth2/token") {
			calls++
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				t.Fatal("test server does not support hijacking")
			}
			conn, _, err := hijacker.Hijack()
			if err != nil {
				t.Fatalf("hijack: %v", err)
			}
			_ = conn.Close()
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	client, err := NewClient(srv.URL, "acme",
		WithOidcClientID("orders-resource-server"), WithOidcClientSecret("resource-server-secret"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	configuration := discoveryDoc(srv.URL)
	_, err = client.UmaExchangeTicket(context.Background(), UmaExchangeTicketParams{
		Ticket: Sensitive(testTicket), ClaimToken: Sensitive(testClaimToken),
		TenantID: testTenantUUID, Configuration: &configuration,
	})
	if err == nil {
		t.Fatal("expected the transport failure to surface")
	}
	if calls != 1 {
		t.Errorf("token calls: got %d, want 1", calls)
	}
}

func TestUmaExchangeTicketIsNotRetriedOnInvalidGrant(t *testing.T) {
	srv := newOidcTestServer(t)
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		writeStatusJSON(w, http.StatusBadRequest, oauthErrorBody("invalid_grant"))
	}

	_, err := newUmaClient(t, srv, true).UmaExchangeTicket(context.Background(), UmaExchangeTicketParams{
		Ticket: Sensitive(testTicket), ClaimToken: Sensitive(testClaimToken), TenantID: testTenantUUID,
	})

	var protoErr *OAuthProtocolError
	if !errors.As(err, &protoErr) {
		t.Fatalf("want *OAuthProtocolError, got %T: %v", err, err)
	}
	// §20.4: unknown, expired, already-used and wrong-client all collapse into
	// this one code, and the SDK must not re-derive which — the server
	// withheld the distinction because it lets a caller probe for live tickets.
	if protoErr.ErrorCode != "invalid_grant" {
		t.Errorf("error code: got %q", protoErr.ErrorCode)
	}
	if calls := srv.TokenCalls(); calls != 1 {
		t.Errorf("token calls: got %d, want 1", calls)
	}
}

func TestUmaExchangeTicketSurfacesA403AccessDeniedAndDoesNotAutoNarrow(t *testing.T) {
	srv := newOidcTestServer(t)
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		writeStatusJSON(w, http.StatusForbidden, oauthErrorBody("access_denied"))
	}

	_, err := newUmaClient(t, srv, true).UmaExchangeTicket(context.Background(), UmaExchangeTicketParams{
		Ticket: Sensitive(testTicket), ClaimToken: Sensitive(testClaimToken), TenantID: testTenantUUID,
	})

	// §20.4: access_denied answers HTTP 403 here, where RFC 8628's answers
	// 400. Dispatching on the `error` field rather than the status is what
	// keeps this correct — the shared /oauth2 mapper gates its rows to 400/401
	// and would have produced an *AuthzError.
	var protoErr *OAuthProtocolError
	if !errors.As(err, &protoErr) {
		t.Fatalf("want *OAuthProtocolError for a 403 access_denied, got %T: %v", err, err)
	}
	if protoErr.ErrorCode != "access_denied" {
		t.Errorf("error code: got %q", protoErr.ErrorCode)
	}
	// §20.2 rule 3: a partial grant is refused whole. Whether two-of-three
	// permissions is useful is the application's judgement, not this SDK's.
	if calls := srv.TokenCalls(); calls != 1 {
		t.Errorf("token calls: got %d, want 1 — a refused ticket must not be re-requested with fewer scopes", calls)
	}
}

func TestUmaGrantErrorMappingDoesNotSwallowANonOAuth2Body(t *testing.T) {
	srv := newOidcTestServer(t)
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("<html>gateway</html>"))
	}

	_, err := newUmaClient(t, srv, true).UmaExchangeTicket(context.Background(), UmaExchangeTicketParams{
		Ticket: Sensitive(testTicket), ClaimToken: Sensitive(testClaimToken), TenantID: testTenantUUID,
	})

	// The widened `error`-field dispatch must not turn a proxy's HTML 502 into
	// an *OAuthProtocolError with an empty code.
	var protoErr *OAuthProtocolError
	if errors.As(err, &protoErr) {
		t.Fatalf("a non-OAuth2 body must fall through to the §2 status mapping, got %+v", protoErr)
	}
	var netErr *NetworkError
	if !errors.As(err, &netErr) {
		t.Fatalf("want *NetworkError, got %T: %v", err, err)
	}
}

// ---------------------------------------------------------------------------
// §20.1/§20.2 — what the grant sends, and what the result is not
// ---------------------------------------------------------------------------

func TestUmaExchangeTicketSendsTheRequiredClaimTokenAndItsFormat(t *testing.T) {
	srv := newOidcTestServer(t)
	var form url.Values
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		form = r.PostForm
		writeStatusJSON(w, http.StatusOK, rptBody(nil))
	}

	rpt, err := newUmaClient(t, srv, true).UmaExchangeTicket(context.Background(), UmaExchangeTicketParams{
		Ticket: Sensitive(testTicket), ClaimToken: Sensitive(testClaimToken), TenantID: testTenantUUID,
	})
	if err != nil {
		t.Fatalf("UmaExchangeTicket: %v", err)
	}

	if got := form.Get("grant_type"); got != "urn:ietf:params:oauth:grant-type:uma-ticket" {
		t.Errorf("grant_type: got %q", got)
	}
	if got := form.Get("ticket"); got != testTicket {
		t.Errorf("ticket: got %q", got)
	}
	// §20.2 rule 2: required, never defaulted — it is the only channel that
	// names the requesting party, and defaulting it to the resource server's
	// own PAT would mint an RPT for the resource server instead of the user.
	if got := form.Get("claim_token"); got != testClaimToken {
		t.Errorf("claim_token: got %q", got)
	}
	if got := form.Get("claim_token_format"); got != "urn:ietf:params:oauth:token-type:access_token" {
		t.Errorf("claim_token_format: got %q", got)
	}
	// A token-endpoint grant: the client authenticates through the body.
	if got := form.Get("client_secret"); got != "resource-server-secret" {
		t.Errorf("client_secret: got %q", got)
	}

	if rpt.AccessToken.expose() != testRPT {
		t.Errorf("access token: got %q", rpt.AccessToken.expose())
	}
	if rpt.ExpiresIn != 300 {
		t.Errorf("expires_in: got %d", rpt.ExpiresIn)
	}
}

func TestUmaExchangeTicketRefusesAnAbsentClaimTokenWithNoWireCall(t *testing.T) {
	srv := newOidcTestServer(t)

	_, err := newUmaClient(t, srv, true).UmaExchangeTicket(context.Background(), UmaExchangeTicketParams{
		Ticket: Sensitive(testTicket), TenantID: testTenantUUID,
	})

	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("want *AuthError, got %T: %v", err, err)
	}
	// Refusing client-side keeps the ticket unspent for a request that could
	// not have succeeded (§20.2 rules 2 and 6 together).
	if calls := srv.TokenCalls(); calls != 0 {
		t.Errorf("token calls: got %d, want 0", calls)
	}
}

func TestUmaExchangeTicketByAPublicClientFailsClientSideWithNoWireCall(t *testing.T) {
	srv := newOidcTestServer(t)

	_, err := newUmaClient(t, srv, false).UmaExchangeTicket(context.Background(), UmaExchangeTicketParams{
		Ticket: Sensitive(testTicket), ClaimToken: Sensitive(testClaimToken), TenantID: testTenantUUID,
	})

	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("want *AuthError, got %T: %v", err, err)
	}
	if calls := srv.TokenCalls(); calls != 0 {
		t.Errorf("token calls: got %d, want 0 — no ticket should be spent on a request that cannot succeed", calls)
	}
}

func TestUmaExchangeTicketSurfacesNoRefreshTokenEvenWhenTheServerSendsOne(t *testing.T) {
	srv := newOidcTestServer(t)
	// Deliberately hostile fixture: the grant issues no refresh token, so the
	// result type has no field for one and there is nothing to synthesise.
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		writeStatusJSON(w, http.StatusOK, rptBody(map[string]any{"refresh_token": "should-not-exist"}))
	}

	rpt, err := newUmaClient(t, srv, true).UmaExchangeTicket(context.Background(), UmaExchangeTicketParams{
		Ticket: Sensitive(testTicket), ClaimToken: Sensitive(testClaimToken), TenantID: testTenantUUID,
	})
	if err != nil {
		t.Fatalf("UmaExchangeTicket: %v", err)
	}

	if rendered := fmt.Sprintf("%#v", rpt); strings.Contains(rendered, "should-not-exist") {
		t.Errorf("a server-sent refresh token must not be surfaced: %s", rendered)
	}
}

func TestUmaExchangeTicketDoesNotAdoptTheRPTAsTheClientsCredential(t *testing.T) {
	srv := newOidcTestServer(t)
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		writeStatusJSON(w, http.StatusOK, rptBody(nil))
	}
	var auth string
	srv.RregHandler = func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		writeStatusJSON(w, http.StatusOK, []string{})
	}

	client := newUmaClient(t, srv, true)
	if _, err := client.UmaExchangeTicket(context.Background(), UmaExchangeTicketParams{
		Ticket: Sensitive(testTicket), ClaimToken: Sensitive(testClaimToken), TenantID: testTenantUUID,
	}); err != nil {
		t.Fatalf("UmaExchangeTicket: %v", err)
	}
	if _, err := client.UmaListResources(context.Background(), Sensitive(testPAT)); err != nil {
		t.Fatalf("UmaListResources: %v", err)
	}

	// §20.2 rule 4: the RPT is the REQUESTING PARTY's token. Adopting it would
	// re-privilege every later call this resource server makes as that user.
	if strings.Contains(auth, testRPT) {
		t.Errorf("the RPT must never become this client's credential, got %q", auth)
	}
}

// ---------------------------------------------------------------------------
// §20.3 the challenge helpers
// ---------------------------------------------------------------------------

func TestUmaParseChallengeParsesAWellFormedHeader(t *testing.T) {
	challenge, ok := UmaParseChallenge(`UMA realm="example", as_uri="https://id.example", ticket="` + testTicket + `"`)
	if !ok {
		t.Fatal("expected a UMA challenge")
	}
	if challenge.Realm != "example" {
		t.Errorf("realm: got %q", challenge.Realm)
	}
	if challenge.AsURI != "https://id.example" {
		t.Errorf("as_uri: got %q", challenge.AsURI)
	}
	if challenge.Ticket.expose() != testTicket {
		t.Errorf("ticket: got %q", challenge.Ticket.expose())
	}
}

func TestUmaParseChallengeRejectsASchemeThatMerelyStartsWithUMA(t *testing.T) {
	for _, header := range []string{`Bearer realm="example"`, `UMAX realm="example"`} {
		if _, ok := UmaParseChallenge(header); ok {
			t.Errorf("%q must not parse as a UMA challenge", header)
		}
	}
}

func TestUmaParseChallengePerformsNoExchange(t *testing.T) {
	srv := newOidcTestServer(t)

	challenge, ok := UmaParseChallenge(fmt.Sprintf(`UMA realm="example", as_uri=%q, ticket=%q`, srv.URL, testTicket))
	if !ok {
		t.Fatal("expected a UMA challenge")
	}
	if challenge.Ticket.expose() != testTicket {
		t.Errorf("ticket: got %q", challenge.Ticket.expose())
	}
	// §20.3: the as_uri names an authorization server this client has not
	// chosen to trust. Auto-exchanging would send the requesting party's
	// claim_token to whatever host answered the 401.
	if calls := srv.TokenCalls(); calls != 0 {
		t.Errorf("token calls: got %d, want 0", calls)
	}
}

func TestUmaChallengeRoundTripsThroughTheEmitHalf(t *testing.T) {
	header := UmaChallengeHeader("example", "https://id.example", Sensitive(testTicket))

	challenge, ok := UmaParseChallenge(header)
	if !ok {
		t.Fatalf("emitted header did not parse: %q", header)
	}
	if challenge.AsURI != "https://id.example" || challenge.Ticket.expose() != testTicket {
		t.Errorf("round trip: got %+v from %q", challenge, header)
	}
}

// ---------------------------------------------------------------------------
// §20.6 redaction
// ---------------------------------------------------------------------------

func TestUmaSecretsDoNotRenderWhenFormattedOrSerialized(t *testing.T) {
	srv := newOidcTestServer(t)
	srv.PermHandler = func(w http.ResponseWriter, r *http.Request) {
		writeStatusJSON(w, http.StatusCreated, map[string]any{"ticket": testTicket})
	}
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		writeStatusJSON(w, http.StatusOK, rptBody(nil))
	}

	client := newUmaClient(t, srv, true)
	ticket, err := client.UmaRequestTicket(context.Background(), Sensitive(testPAT), []RequestedPermission{
		{ResourceID: testUmaResourceID, ResourceScopes: []string{"view"}},
	})
	if err != nil {
		t.Fatalf("UmaRequestTicket: %v", err)
	}
	rpt, err := client.UmaExchangeTicket(context.Background(), UmaExchangeTicketParams{
		Ticket: ticket, ClaimToken: Sensitive(testClaimToken), TenantID: testTenantUUID,
	})
	if err != nil {
		t.Fatalf("UmaExchangeTicket: %v", err)
	}
	challenge, _ := UmaParseChallenge(`UMA ticket="` + testTicket + `"`)

	// §20.6: the ticket's 60-second lifetime is exactly what invites treating
	// it as harmless. For those 60 seconds it is the credential that converts
	// into an RPT.
	for name, subject := range map[string]any{"ticket": ticket, "rpt": rpt, "challenge": challenge} {
		encoded, err := json.Marshal(subject)
		if err != nil {
			t.Fatalf("marshal %s: %v", name, err)
		}
		for _, secret := range []string{testTicket, testRPT} {
			if strings.Contains(string(encoded), secret) {
				t.Errorf("%s JSON leaked %q: %s", name, secret, encoded)
			}
			for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
				if rendered := fmt.Sprintf(verb, subject); strings.Contains(rendered, secret) {
					t.Errorf("%s %s leaked %q: %s", name, verb, secret, rendered)
				}
			}
		}
	}
}

func TestUmaFailedExchangeNeverEchoesTheTicketOrClaimToken(t *testing.T) {
	srv := newOidcTestServer(t)
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		writeStatusJSON(w, http.StatusBadRequest, oauthErrorBody("invalid_grant"))
	}

	_, err := newUmaClient(t, srv, true).UmaExchangeTicket(context.Background(), UmaExchangeTicketParams{
		Ticket: Sensitive(testTicket), ClaimToken: Sensitive(testClaimToken), TenantID: testTenantUUID,
	})
	if err == nil {
		t.Fatal("expected invalid_grant")
	}

	// A failed exchange is exactly when a naive implementation logs the body.
	for _, secret := range []string{testTicket, testClaimToken} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("error message leaked %q: %s", secret, err.Error())
		}
	}
}
