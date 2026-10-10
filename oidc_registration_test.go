package axiam

// RFC 7592 client configuration — CONTRACT.md §28.12.6's five required tests,
// plus the decoding and origin rules they rest on.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"
)

const dcrClient = "dcr-client-1"

func registrationPath() string { return "/oauth2/register/" + dcrClient }

func registrationURI(base string) string {
	return base + registrationPath() + "?tenant_id=" + tenantID.String()
}

func registrationBody(base string, extra map[string]any) string {
	body := map[string]any{
		"client_id":                  dcrClient,
		"client_id_issued_at":        1700000000,
		"client_name":                "Agent",
		"redirect_uris":              []string{"https://agent.example.test/cb"},
		"grant_types":                []string{"authorization_code"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "private_key_jwt",
		"scope":                      "openid",
		"registration_client_uri":    registrationURI(base),
		"jwks_uri":                   "https://agent.example.test/jwks",
	}
	for k, v := range extra {
		body[k] = v
	}
	encoded, _ := json.Marshal(body)
	return string(encoded)
}

func decodeRegistration(t *testing.T, body string) ClientRegistration {
	t.Helper()
	var r ClientRegistration
	if err := json.Unmarshal([]byte(body), &r); err != nil {
		t.Fatalf("decode registration: %v", err)
	}
	return r
}

// ── 1. Origin refusal ───────────────────────────────────────────────────────

func TestClientRegistration_AnotherOriginIsRefusedLocallyAndNothingIsSent(t *testing.T) {
	srv, c := managementServer(t)
	reads := srv.mount(http.MethodGet, registrationPath(), 200, "{}")
	puts := srv.mount(http.MethodPut, registrationPath(), 200, "{}")
	deletes := srv.mount(http.MethodDelete, registrationPath(), 204, "")
	token := Sensitive(randomSecret(t, "rat-"))

	base, _ := url.Parse(srv.server.URL)
	port := base.Port()
	otherHost := "http://localhost:" + port + registrationPath()
	otherPort := fmt.Sprintf("http://127.0.0.1:%d%s", mustAtoi(t, port)+1, registrationPath())
	ctx := context.Background()
	for _, uri := range []string{otherHost, otherPort, "ftp://127.0.0.1:" + port + "/x", "/oauth2/register/c1", "::"} {
		var verr *ValidationError
		if _, err := c.ReadClientRegistration(ctx, uri, token); !errors.As(err, &verr) {
			t.Fatalf("read: want a local ValidationError, got %T", err)
		}
		if err := c.DeleteClientRegistration(ctx, uri, token); !errors.As(err, &verr) {
			t.Fatalf("delete: want a local ValidationError, got %T", err)
		}
		if _, err := c.UpdateClientRegistration(ctx, uri, token, ClientRegistration{}); !errors.As(err, &verr) {
			t.Fatalf("update: want a local ValidationError, got %T", err)
		}
	}

	// http against an https base URL.
	https, err := NewClient("https://iam.example.test", "acme")
	if err != nil {
		t.Fatal(err)
	}
	var verr *ValidationError
	if _, err := https.ReadClientRegistration(ctx, "http://iam.example.test/oauth2/register/x", token); !errors.As(err, &verr) {
		t.Fatalf("http against https: want a ValidationError, got %T", err)
	}
	// http on a non-loopback http base is refused too.
	plain, err := NewClient("http://iam.internal:8080", "acme")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plain.ReadClientRegistration(ctx, "http://iam.internal:8080/oauth2/register/x", token); !errors.As(err, &verr) {
		t.Fatalf("http on a routable host: want a ValidationError, got %T", err)
	}

	if reads.calls()+puts.calls()+deletes.calls() != 0 {
		t.Fatal("a refused URI must send nothing")
	}
}

func mustAtoi(t *testing.T, s string) int {
	t.Helper()
	var n int
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		t.Fatalf("atoi: %v", err)
	}
	return n
}

func TestClientRegistration_SameOriginAcceptsTheDefaultPortSpelledOut(t *testing.T) {
	c, err := NewClient("https://IAM.example.test", "acme")
	if err != nil {
		t.Fatal(err)
	}
	u, err := c.checkSameOrigin("op", "registration_client_uri", "https://iam.example.test:443/oauth2/register/c1?tenant_id=t")
	if err != nil {
		t.Fatalf("same origin refused: %v", err)
	}
	if u.RawQuery != "tenant_id=t" {
		t.Fatalf("query not kept verbatim: %q", u.RawQuery)
	}
}

// ── 2. Header only ──────────────────────────────────────────────────────────

func TestClientRegistration_ReadAndDeleteSendTheBearerOnlyAndKeepTheQuery(t *testing.T) {
	srv, c := managementServer(t)
	if c.cookieValue(accessCookie) == "" {
		t.Fatal("precondition: the client must hold a real session")
	}
	sessionAccess := c.cookieValue(accessCookie)
	reads := srv.mount(http.MethodGet, registrationPath(), 200, registrationBody(srv.server.URL, nil))
	deletes := srv.mount(http.MethodDelete, registrationPath(), 204, "")
	token := randomSecret(t, "rat-")
	ctx := context.Background()

	read, err := c.ReadClientRegistration(ctx, registrationURI(srv.server.URL), Sensitive(token))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if read.ClientID != dcrClient || read.RegistrationAccessToken != "" {
		t.Fatal("a read carries the client id and no token")
	}
	if err := c.DeleteClientRegistration(ctx, registrationURI(srv.server.URL), Sensitive(token)); err != nil {
		t.Fatalf("a 204 on delete returns normally: %v", err)
	}

	seen := append(append([]*recordedRequest{}, reads.requests...), deletes.requests...)
	if len(seen) != 2 {
		t.Fatalf("expected two requests, got %d", len(seen))
	}
	for _, r := range seen {
		if r.header.Get("Authorization") != "Bearer "+token {
			t.Fatalf("%s: the Authorization header is not the registration bearer", r.method)
		}
		if strings.Contains(r.header.Get("Authorization"), sessionAccess) {
			t.Fatalf("%s: the SDK's access token was sent", r.method)
		}
		if r.header.Get("Cookie") != "" {
			t.Fatalf("%s: a session cookie was sent", r.method)
		}
		if r.header.Get("X-CSRF-Token") != "" {
			t.Fatalf("%s: a CSRF header was sent", r.method)
		}
		if len(r.body) != 0 {
			t.Fatalf("%s: a body was sent", r.method)
		}
		if got := r.query.Encode(); got != "tenant_id="+tenantID.String() {
			t.Fatalf("%s: the query is not the URI's own, verbatim", r.method)
		}
	}
}

func TestClientRegistration_ARedirectIsNotFollowed(t *testing.T) {
	srv, c := managementServer(t)
	followed := srv.mount(http.MethodGet, "/elsewhere", 200, "{}")
	srv.mountFunc(http.MethodGet, registrationPath(), func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	})
	_, err := c.ReadClientRegistration(context.Background(), registrationURI(srv.server.URL), Sensitive(randomSecret(t, "rat-")))
	if err == nil {
		t.Fatal("a 302 is not a registration")
	}
	if followed.calls() != 0 {
		t.Fatal("the redirect was followed with the bearer")
	}
}

// ── 3. Update body ──────────────────────────────────────────────────────────

func TestClientRegistration_UpdateDropsTheFiveServerStatedMembersAndReturnsTheRotatedToken(t *testing.T) {
	srv, c := managementServer(t)
	rotated := randomSecret(t, "rot-")
	puts := srv.mount(http.MethodPut, registrationPath(), 200,
		registrationBody(srv.server.URL, map[string]any{"registration_access_token": rotated}))

	metadata := decodeRegistration(t, registrationBody(srv.server.URL, map[string]any{
		"registration_access_token":       randomSecret(t, "old-"),
		"client_secret":                   randomSecret(t, "sec-"),
		"client_secret_expires_at":        0,
		"backchannel_token_delivery_mode": "poll",
		"jwks":                            map[string]any{"keys": []any{}},
	}))
	name := "Agent v2"
	metadata.ClientName = &name

	updated, err := c.UpdateClientRegistration(context.Background(), registrationURI(srv.server.URL),
		Sensitive(randomSecret(t, "rat-")), metadata)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.RegistrationAccessToken.Expose() != rotated {
		t.Fatal("the rotated token must be returned")
	}
	if puts.calls() != 1 {
		t.Fatalf("expected one PUT, got %d", puts.calls())
	}
	body := puts.last(t).jsonBody(t)
	for _, gone := range serverStatedRegistrationMembers {
		if _, present := body[gone]; present {
			t.Fatalf("%s must not be sent", gone)
		}
	}
	if body["client_id"] != dcrClient || body["client_name"] != "Agent v2" ||
		body["jwks_uri"] != "https://agent.example.test/jwks" {
		t.Fatalf("the update body lost a member: %v", sortedKeys(body))
	}
	if body["backchannel_token_delivery_mode"] != "poll" {
		t.Fatal("unknown members must round-trip")
	}
	if _, ok := body["jwks"].(map[string]any); !ok {
		t.Fatal("jwks must round-trip")
	}
}

func TestClientRegistration_WritesAreNotRetriedAndTheReadIs(t *testing.T) {
	srv, c := managementServer(t)
	puts := srv.mount(http.MethodPut, registrationPath(), 503, "")
	deletes := srv.mount(http.MethodDelete, registrationPath(), 503, "")
	reads := srv.mount(http.MethodGet, registrationPath(), 503, "")
	token := Sensitive(randomSecret(t, "rat-"))
	ctx := context.Background()
	uri := registrationURI(srv.server.URL)

	_, err := c.UpdateClientRegistration(ctx, uri, token, decodeRegistration(t, registrationBody(srv.server.URL, nil)))
	var netErr *NetworkError
	if !errors.As(err, &netErr) {
		t.Fatalf("update 503: want NetworkError, got %T", err)
	}
	if puts.calls() != 1 {
		t.Fatalf("update: exactly one request, got %d", puts.calls())
	}
	if err := c.DeleteClientRegistration(ctx, uri, token); !errors.As(err, &netErr) {
		t.Fatalf("delete 503: want NetworkError, got %T", err)
	}
	if deletes.calls() != 1 {
		t.Fatalf("delete: exactly one request, got %d", deletes.calls())
	}
	if _, err := c.ReadClientRegistration(ctx, uri, token); !errors.As(err, &netErr) {
		t.Fatalf("read 503: want NetworkError, got %T", err)
	}
	if reads.calls() != MaxAttempts {
		t.Fatalf("the read MAY be retried per §16: got %d requests", reads.calls())
	}
}

func TestClientRegistration_AReadIsNeverRetriedOnABodiless400(t *testing.T) {
	srv, c := managementServer(t)
	reads := srv.mount(http.MethodGet, registrationPath(), 400, "")
	_, err := c.ReadClientRegistration(context.Background(), registrationURI(srv.server.URL), Sensitive(randomSecret(t, "rat-")))
	var netErr *NetworkError
	if !errors.As(err, &netErr) {
		t.Fatalf("a bodiless 400 maps to NetworkError per §2, got %T", err)
	}
	if reads.calls() != 1 {
		t.Fatalf("a 4xx is decisive: exactly one request, got %d", reads.calls())
	}
}

// ── 4. Errors ───────────────────────────────────────────────────────────────

func TestClientRegistration_A401InvalidTokenIsAnOAuthProtocolErrorAndRefreshesNothing(t *testing.T) {
	srv, c := managementServer(t)
	refreshes := srv.mount(http.MethodPost, "/api/v1/auth/refresh", 500, "")
	srv.mountFunc(http.MethodGet, registrationPath(), func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_token","error_description":"no"}`))
	})
	_, err := c.ReadClientRegistration(context.Background(), registrationURI(srv.server.URL), Sensitive(randomSecret(t, "rat-")))
	var protocolErr *OAuthProtocolError
	if !errors.As(err, &protocolErr) || protocolErr.ErrorCode != "invalid_token" {
		t.Fatalf("want OAuthProtocolError invalid_token, got %T", err)
	}
	if !errors.Is(err, ErrAuth) {
		t.Fatal("an OAuthProtocolError is an AuthError")
	}
	if refreshes.calls() != 0 {
		t.Fatal("§9 must not be entered")
	}
}

func TestClientRegistration_A400InvalidClientMetadataIsAnOAuthProtocolError(t *testing.T) {
	srv, c := managementServer(t)
	// No error_description: the decoder tolerates its absence.
	srv.mount(http.MethodPut, registrationPath(), 400, `{"error":"invalid_client_metadata"}`)
	_, err := c.UpdateClientRegistration(context.Background(), registrationURI(srv.server.URL),
		Sensitive(randomSecret(t, "rat-")), decodeRegistration(t, registrationBody(srv.server.URL, nil)))
	var protocolErr *OAuthProtocolError
	if !errors.As(err, &protocolErr) || protocolErr.ErrorCode != "invalid_client_metadata" {
		t.Fatalf("want OAuthProtocolError invalid_client_metadata, got %T", err)
	}
	if protocolErr.ErrorDescription != "" {
		t.Fatal("no description was sent")
	}
}

func TestClientRegistration_AnErrorBodyAtAnyStatusIsAnOAuthProtocolError(t *testing.T) {
	srv, c := managementServer(t)
	srv.mount(http.MethodDelete, registrationPath(), 429, `{"error":"rate_limit_exceeded"}`)
	err := c.DeleteClientRegistration(context.Background(), registrationURI(srv.server.URL), Sensitive(randomSecret(t, "rat-")))
	var protocolErr *OAuthProtocolError
	if !errors.As(err, &protocolErr) || protocolErr.ErrorCode != "rate_limit_exceeded" {
		t.Fatalf("want OAuthProtocolError at 429, got %T", err)
	}
}

func TestClientRegistration_AClosedClientRefuses(t *testing.T) {
	_, c := managementServer(t)
	_ = c.Close()
	token := Sensitive(randomSecret(t, "rat-"))
	ctx := context.Background()
	if _, err := c.ReadClientRegistration(ctx, "https://x", token); err == nil {
		t.Fatal("read after close")
	}
	if _, err := c.UpdateClientRegistration(ctx, "https://x", token, ClientRegistration{}); err == nil {
		t.Fatal("update after close")
	}
	if err := c.DeleteClientRegistration(ctx, "https://x", token); err == nil {
		t.Fatal("delete after close")
	}
}

func TestClientRegistration_ATransportFailureAndAnUndecodableBodyAreNetworkErrors(t *testing.T) {
	gone := httptest.NewServer(http.NotFoundHandler())
	base := gone.URL
	gone.Close()
	c, err := NewClient(base, "acme", WithRetryDisabled())
	if err != nil {
		t.Fatal(err)
	}
	var netErr *NetworkError
	if _, err := c.ReadClientRegistration(context.Background(), registrationURI(base), Sensitive(randomSecret(t, "rat-"))); !errors.As(err, &netErr) {
		t.Fatalf("a refused connection is a NetworkError, got %T", err)
	}

	srv, c2 := managementServer(t)
	srv.mount(http.MethodGet, registrationPath(), 200, `[]`)
	if _, err := c2.ReadClientRegistration(context.Background(), registrationURI(srv.server.URL), Sensitive(randomSecret(t, "rat-"))); !errors.As(err, &netErr) {
		t.Fatalf("a non-object body is a NetworkError, got %T", err)
	}
}

// ── 5. Redaction ────────────────────────────────────────────────────────────

func TestClientRegistration_NeitherTheTokenNorTheSecretReachesAnyRendering(t *testing.T) {
	srv, c := managementServer(t)
	token := randomSecret(t, "rat-")
	secret := randomSecret(t, "sec-")
	registration := decodeRegistration(t, registrationBody(srv.server.URL, map[string]any{
		"registration_access_token": token, "client_secret": secret,
	}))
	if registration.RegistrationAccessToken.Expose() != token || registration.ClientSecret.Expose() != secret {
		t.Fatal("both secrets decode")
	}
	assertNoFragmentIn(t, registration, token, "registration")
	assertNoFragmentIn(t, registration, secret, "registration")
	assertNoFragmentIn(t, &registration, token, "registration pointer")

	srv.mount(http.MethodGet, registrationPath(), 401, `{"error":"invalid_token"}`)
	_, err := c.ReadClientRegistration(context.Background(), registrationURI(srv.server.URL), Sensitive(token))
	if err == nil {
		t.Fatal("expected the 401")
	}
	assertNoFragment(t, errorRenderings(err), token, "401 error")
	_, refused := c.ReadClientRegistration(context.Background(), "https://elsewhere.example.test/r", Sensitive(token))
	assertNoFragment(t, errorRenderings(refused), token, "origin refusal")
}

// ── Decoding ────────────────────────────────────────────────────────────────

func TestClientRegistration_DecodingKeepsUnknownAndMistypedMembers(t *testing.T) {
	r := decodeRegistration(t, `{"client_id":"c1","client_secret":"s-value-x","registration_access_token":"t-value-x",
		"backchannel_token_delivery_mode":"poll","client_id_issued_at":"not-a-number","scope":7,
		"redirect_uris":["https://a",3],"grant_types":"oops","jwks":null,"client_name":null}`)
	if string(r.Extra["backchannel_token_delivery_mode"]) != `"poll"` ||
		string(r.Extra["client_id_issued_at"]) != `"not-a-number"` ||
		string(r.Extra["scope"]) != `7` || string(r.Extra["grant_types"]) != `"oops"` {
		t.Fatalf("unknown or mistyped members must be kept: %v", sortedRawKeys(r.Extra))
	}
	// A list with a non-string item is of unexpected shape: kept in Extra as
	// read, its field nil (contract 1.60, P12.4 / A2).
	if r.RedirectURIs != nil || string(r.Extra["redirect_uris"]) != `["https://a",3]` || r.JWKS != nil || r.ClientName != nil {
		t.Fatal("known members decode")
	}
	body := r.updateBody()
	if string(body["redirect_uris"]) != `["https://a",3]` || string(body["grant_types"]) != `"oops"` {
		t.Fatalf("a list of unexpected shape goes back as read: %s %s", body["redirect_uris"], body["grant_types"])
	}
	if _, present := body["client_id_issued_at"]; present {
		t.Fatal("a mistyped server-stated member is still never sent")
	}
	if string(body["backchannel_token_delivery_mode"]) != `"poll"` {
		t.Fatal("extras ride along")
	}
	encoded, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), redacted) {
		t.Fatal("MarshalJSON renders the secrets redacted")
	}

	for _, bad := range []string{`[]`, `{"x":1}`, `{"client_id":5}`, `null`} {
		var r ClientRegistration
		if err := json.Unmarshal([]byte(bad), &r); err == nil {
			t.Fatalf("a body without a string client_id must be refused (case %d)", len(bad))
		}
	}
}

// Contract 1.60 A2 / R-23 (§28.12.2 rule 4, §34.2 P12.4): the replacement body
// is built from what the read carried.
func TestClientRegistration_A2_UpdateBodyIsBuiltFromWhatTheReadCarried(t *testing.T) {
	// A read that lacked all three lists: none of them is sent, and no list
	// becomes [] because the read lacked it.
	bare := decodeRegistration(t, `{"client_id":"c1","client_name":"Agent"}`)
	body := bare.updateBody()
	for _, member := range []string{"redirect_uris", "grant_types", "response_types"} {
		if raw, present := body[member]; present {
			t.Fatalf("%s was not read, so it is not sent (got %s)", member, raw)
		}
	}
	if string(body["client_name"]) != `"Agent"` {
		t.Fatal("the members the read carried are sent")
	}

	// A null member is a member the read did not carry.
	nulled := decodeRegistration(t, `{"client_id":"c1","redirect_uris":null}`)
	if _, present := nulled.updateBody()["redirect_uris"]; present {
		t.Fatal("a null list is not sent as []")
	}

	// A list the read carried empty is sent empty.
	empty := decodeRegistration(t, `{"client_id":"c1","redirect_uris":[]}`)
	if got := string(empty.updateBody()["redirect_uris"]); got != `[]` {
		t.Fatalf("a present, empty list is sent as read, got %s", got)
	}

	// Members of unexpected shape are sent as read, and no non-string item is
	// dropped (the mixed list keeps its number, its null and its object).
	odd := decodeRegistration(t,
		`{"client_id":"c1","redirect_uris":["https://a",3,null,{"k":1}],"grant_types":"oops","response_types":{"x":1}}`)
	oddBody := odd.updateBody()
	if got := string(oddBody["redirect_uris"]); got != `["https://a",3,null,{"k":1}]` {
		t.Fatalf("redirect_uris must go back as read, got %s", got)
	}
	if string(oddBody["grant_types"]) != `"oops"` || string(oddBody["response_types"]) != `{"x":1}` {
		t.Fatalf("members of unexpected shape must go back as read: %s %s", oddBody["grant_types"], oddBody["response_types"])
	}

	// A caller's own edit still wins.
	edited := decodeRegistration(t, `{"client_id":"c1","redirect_uris":["https://a"]}`)
	edited.RedirectURIs = append(edited.RedirectURIs, "https://b")
	if got := string(edited.updateBody()["redirect_uris"]); got != `["https://a","https://b"]` {
		t.Fatalf("an edited list is sent, got %s", got)
	}

	// On the wire: one PUT whose body lacks the lists.
	srv, c := managementServer(t)
	puts := srv.mount(http.MethodPut, registrationPath(), 200, registrationBody(srv.server.URL, nil))
	if _, err := c.UpdateClientRegistration(context.Background(), registrationURI(srv.server.URL),
		Sensitive(randomSecret(t, "rat-")), bare); err != nil {
		t.Fatalf("update: %v", err)
	}
	sent := puts.last(t).jsonBody(t)
	for _, member := range []string{"redirect_uris", "grant_types", "response_types"} {
		if _, present := sent[member]; present {
			t.Fatalf("%s must not reach the wire", member)
		}
	}
}

func sortedRawKeys(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
