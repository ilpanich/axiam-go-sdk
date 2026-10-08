package axiam

// The saml management namespace — CONTRACT.md §29.8's eight required tests.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func samlPath() string { return "/api/v1/tenants/" + tenantID.String() + "/saml" }

func spBody(extra map[string]any) map[string]any {
	body := map[string]any{
		"id": uuid.New(), "tenant_id": tenantID, "enabled": true,
		"display_name": "Payroll", "entity_id": "https://payroll.example/sp",
		"acs_urls": []any{map[string]any{"url": "https://payroll.example/acs", "binding": "http_post",
			"index": 0, "is_default": true}},
		"slo_url": nil, "slo_binding": nil, "name_id_format": "persistent",
		"sign_responses": true, "encrypt_assertions": false,
		"sp_signing_cert_pem": nil, "sp_encryption_cert_pem": nil,
		"want_authn_requests_signed": false, "allow_idp_initiated": false,
		"attribute_mappings": []any{}, "allowed_groups": []any{},
		"created_at": "2026-10-04T00:00:00Z", "updated_at": "2026-10-04T00:00:00Z",
	}
	for k, v := range extra {
		body[k] = v
	}
	return body
}

func credentialBody(status string, extra map[string]any) map[string]any {
	body := map[string]any{
		"id": uuid.New(), "tenant_id": tenantID, "issuer_ca_id": uuid.New(),
		"certificate_pem": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
		"serial":          "0a1b", "fingerprint": strings.Repeat("ab", 32),
		"not_before": "2026-10-04T00:00:00Z", "not_after": "2027-10-04T00:00:00Z",
		"status": status, "created_at": "2026-10-04T00:00:00Z", "retired_at": nil,
	}
	for k, v := range extra {
		body[k] = v
	}
	return body
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

func samlInput() SAMLServiceProviderInput {
	return NewSAMLServiceProviderInput(
		[]AcsEndpoint{{Binding: SAMLBindingHTTPPost, Index: 0, IsDefault: ptr(true), URL: "https://payroll.example/acs"}},
		"Payroll", "https://payroll.example/sp")
}

// ── 1. Replacement ──────────────────────────────────────────────────────────

func TestSAML_UpdateServiceProviderPutsTheWholeRegistration(t *testing.T) {
	srv, c := managementServer(t)
	id := uuid.New()
	route := srv.mount(http.MethodPut, samlPath()+"/service-providers/"+id.String(), 200, mustJSON(t, spBody(nil)))

	// Non-empty lists: an empty Go slice is omitted, which the server reads as
	// its default — the empty list — so only a populated one proves carriage.
	read := spBody(map[string]any{
		"allowed_groups":     []any{uuid.New()},
		"attribute_mappings": []any{map[string]any{"saml_name": "mail", "source": "email"}},
	})
	var current SAMLServiceProvider
	if err := json.Unmarshal([]byte(mustJSON(t, read)), &current); err != nil {
		t.Fatal(err)
	}
	body := current.ToInput()
	body.DisplayName = "Payroll (EU)"
	sp, err := c.SAML().UpdateServiceProvider(context.Background(), id, body)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if sp.EntityID != "https://payroll.example/sp" {
		t.Fatal("a 200 decodes to SAMLServiceProvider")
	}
	sent := route.last(t).jsonBody(t)
	for _, member := range []string{"acs_urls", "allow_idp_initiated", "allowed_groups", "attribute_mappings", "display_name",
		"enabled", "encrypt_assertions", "entity_id", "name_id_format", "sign_responses", "want_authn_requests_signed"} {
		if _, ok := sent[member]; !ok {
			t.Fatalf("%s not sent", member)
		}
	}
	if sent["display_name"] != "Payroll (EU)" {
		t.Fatal("the changed member is sent")
	}
	// The three required members are NewSAMLServiceProviderInput's arguments:
	// an input built the documented way cannot omit one.
}

// ── 2. No signing switch, open decoding ─────────────────────────────────────

func TestSAML_SignAssertionsDoesNotExistAndUnknownValuesDecode(t *testing.T) {
	srv, c := managementServer(t)
	id := uuid.New()
	body := spBody(map[string]any{"sign_assertions": false, "some_future_member": 1})
	body["acs_urls"].([]any)[0].(map[string]any)["binding"] = "http_artifact"
	srv.mount(http.MethodGet, samlPath()+"/service-providers/"+id.String(), 200, mustJSON(t, body))
	put := srv.mount(http.MethodPut, samlPath()+"/service-providers/"+id.String(), 200, mustJSON(t, spBody(nil)))

	sp, err := c.SAML().GetServiceProvider(context.Background(), id)
	if err != nil {
		t.Fatalf("decodes: %v", err)
	}
	if sp.AcsUrls[0].Binding != SAMLBinding("http_artifact") {
		t.Fatal("an unknown binding decodes verbatim")
	}
	if _, has := reflect.TypeOf(SAMLServiceProviderInput{}).FieldByName("SignAssertions"); has {
		t.Fatal("there is no sign_assertions switch")
	}
	// An unknown value decodes but MUST NOT be sent: replace it first.
	input := sp.ToInput()
	input.AcsUrls[0].Binding = SAMLBindingHTTPPost
	if _, err := c.SAML().UpdateServiceProvider(context.Background(), id, input); err != nil {
		t.Fatalf("update: %v", err)
	}
	sent := put.last(t).jsonBody(t)
	if _, ok := sent["sign_assertions"]; ok {
		t.Fatal("sign_assertions sent")
	}
	if _, ok := sent["some_future_member"]; ok {
		t.Fatal("an unknown member was sent")
	}
	if sp.AcsUrls[0].Binding != SAMLBinding("http_artifact") {
		t.Fatal("ToInput must copy, not alias, the ACS list")
	}
}

// ── 3. Draft round trip ─────────────────────────────────────────────────────

func TestSAML_ParseSpMetadataSendsExactlyOneMemberAndTheDraftCreates(t *testing.T) {
	srv, c := managementServer(t)
	draft := map[string]any{
		"service_provider": map[string]any{
			"display_name": "Imported", "entity_id": "https://imported.example/sp",
			"acs_urls": []any{map[string]any{"url": "https://imported.example/acs", "binding": "http_post",
				"index": 1, "is_default": false}},
			"want_authn_requests_signed": true,
			"sp_signing_cert_pem":        "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
		},
		"signing_certificate_fingerprint":    strings.Repeat("cd", 32),
		"encryption_certificate_fingerprint": nil,
		"warnings":                           []string{"the metadata's signature was not evaluated"},
	}
	parsed := srv.mount(http.MethodPost, samlPath()+"/parse-sp-metadata", 200, mustJSON(t, draft))
	created := srv.mount(http.MethodPost, samlPath()+"/service-providers", 201, mustJSON(t, spBody(nil)))
	ctx := context.Background()

	fromURL, err := c.SAML().ParseSpMetadata(ctx, ParseSAMLSpMetadataFromURL("https://imported.example/metadata"))
	if err != nil {
		t.Fatalf("url: %v", err)
	}
	if _, err := c.SAML().ParseSpMetadata(ctx, ParseSAMLSpMetadataFromXML("<EntityDescriptor/>")); err != nil {
		t.Fatalf("xml: %v", err)
	}
	both := ParseSAMLSpMetadata{MetadataURL: ptr("https://a"), MetadataXml: ptr("<x/>")}
	for i, bad := range []ParseSAMLSpMetadata{both, {}} {
		_, err := c.SAML().ParseSpMetadata(ctx, bad)
		var verr *ValidationError
		if !errors.As(err, &verr) {
			t.Fatalf("case %d: want a local ValidationError, got %T", i, err)
		}
	}
	if parsed.calls() != 2 {
		t.Fatalf("the refused calls sent nothing: %d requests", parsed.calls())
	}
	if got := parsed.requests[0].jsonBody(t); len(got) != 1 || got["metadata_url"] != "https://imported.example/metadata" {
		t.Fatal("exactly {metadata_url} is sent")
	}
	if got := parsed.requests[1].jsonBody(t); len(got) != 1 || got["metadata_xml"] != "<EntityDescriptor/>" {
		t.Fatal("exactly {metadata_xml} is sent")
	}

	if _, err := c.SAML().CreateServiceProvider(ctx, fromURL.ServiceProvider); err != nil {
		t.Fatalf("the draft is accepted unchanged: %v", err)
	}
	var sent, want any
	_ = json.Unmarshal(created.last(t).body, &sent)
	_ = json.Unmarshal([]byte(mustJSON(t, draft["service_provider"])), &want)
	if !reflect.DeepEqual(sent, want) {
		t.Fatalf("the draft must be sent unchanged:\n got %v\nwant %v", sent, want)
	}
}

// ── 4. Credentials carry no key ─────────────────────────────────────────────

func TestSAML_ACredentialHasNoKeyMemberAndPromotionMayRetireNothing(t *testing.T) {
	srv, c := managementServer(t)
	leaked := randomSecret(t, "private-key-")
	id := uuid.New()
	srv.mount(http.MethodPost, samlPath()+"/idp-credentials/"+id.String()+"/retire", 200,
		mustJSON(t, credentialBody("retired", map[string]any{"private_key_pem": leaked})))
	srv.mount(http.MethodPost, samlPath()+"/idp-credentials/"+id.String()+"/promote", 200,
		mustJSON(t, map[string]any{"active": credentialBody("active", nil), "retired": nil}))

	credential, err := c.SAML().RetireIdpCredential(context.Background(), id)
	if err != nil {
		t.Fatalf("decodes: %v", err)
	}
	rendered := renderings(credential)
	if strings.Contains(rendered, leaked) || strings.Contains(rendered, "private_key_pem") {
		t.Fatal("the leaked key value appears in a rendering")
	}
	if _, has := reflect.TypeOf(credential).FieldByName("PrivateKeyPEM"); has {
		t.Fatal("SAMLIdpCredential must declare no key member")
	}
	promotion, err := c.SAML().PromoteIdpCredential(context.Background(), id)
	if err != nil {
		t.Fatalf("promote: %v", err)
	}
	if promotion.Retired != nil || promotion.Active.Status != SAMLIdpCredentialStatusActive {
		t.Fatal("a promotion may retire nothing")
	}
}

// ── 5. Pagination ───────────────────────────────────────────────────────────

func TestSAML_ServiceProvidersPageWithSearchAndCredentialsAreAPlainList(t *testing.T) {
	srv, c := managementServer(t)
	var queries []string
	srv.mountFunc(http.MethodGet, samlPath()+"/service-providers", func(w http.ResponseWriter, r *http.Request) {
		queries = append(queries, r.URL.RawQuery)
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		items := []any{}
		if offset < 2 {
			items = append(items, spBody(nil))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, mustJSON(t, map[string]any{"items": items, "total": 2, "offset": offset, "limit": 1}))
	})
	srv.mount(http.MethodGet, samlPath()+"/idp-credentials", 200,
		mustJSON(t, []any{credentialBody("next", nil), credentialBody("active", nil)}))
	ctx := context.Background()

	page, err := c.SAML().ListServiceProviders(ctx, Matching(1, "payroll"))
	if err != nil || page.Total != 2 {
		t.Fatalf("page: %v %d", err, page.Total)
	}
	all, err := c.SAML().ListServiceProvidersAll(ctx, Matching(1, "payroll"))
	if err != nil || len(all) != 2 {
		t.Fatalf("walk: %v %d", err, len(all))
	}
	for _, q := range queries {
		if !strings.Contains(q, "search=payroll") {
			t.Fatalf("every page carries search: %q", q)
		}
	}
	var credentials []SAMLIdpCredential
	credentials, err = c.SAML().ListIdpCredentials(ctx)
	if err != nil || len(credentials) != 2 {
		t.Fatalf("credentials: %v %d", err, len(credentials))
	}
}

// ── 6. No retry ─────────────────────────────────────────────────────────────

func TestSAML_NoneOfTheSevenWritesIsRetriedOn503(t *testing.T) {
	srv, c := managementServer(t)
	id := uuid.New()
	routes := []*mountedRoute{
		srv.mount(http.MethodPost, samlPath()+"/service-providers", 503, ""),
		srv.mount(http.MethodPut, samlPath()+"/service-providers/"+id.String(), 503, ""),
		srv.mount(http.MethodDelete, samlPath()+"/service-providers/"+id.String(), 503, ""),
		srv.mount(http.MethodPost, samlPath()+"/parse-sp-metadata", 503, ""),
		srv.mount(http.MethodPost, samlPath()+"/idp-credentials", 503, ""),
		srv.mount(http.MethodPost, samlPath()+"/idp-credentials/"+id.String()+"/promote", 503, ""),
		srv.mount(http.MethodPost, samlPath()+"/idp-credentials/"+id.String()+"/retire", 503, ""),
	}
	ctx := context.Background()
	s := c.SAML()
	_, e1 := s.CreateServiceProvider(ctx, samlInput())
	_, e2 := s.UpdateServiceProvider(ctx, id, samlInput())
	e3 := s.DeleteServiceProvider(ctx, id)
	_, e4 := s.ParseSpMetadata(ctx, ParseSAMLSpMetadataFromURL("https://m"))
	_, e5 := s.IssueIdpCredential(ctx, IssueSAMLIdpCredential{IssuerCAID: uuid.New(), Slot: SAMLIdpSlotNext})
	_, e6 := s.PromoteIdpCredential(ctx, id)
	_, e7 := s.RetireIdpCredential(ctx, id)
	for i, err := range []error{e1, e2, e3, e4, e5, e6, e7} {
		var netErr *NetworkError
		if !errors.As(err, &netErr) {
			t.Fatalf("write %d: want NetworkError, got %T", i, err)
		}
	}
	for i, r := range routes {
		if r.calls() != 1 {
			t.Fatalf("write %d: exactly one request, got %d", i, r.calls())
		}
	}
}

// ── 7. Errors ───────────────────────────────────────────────────────────────

func TestSAML_StatusesMapPerSection2(t *testing.T) {
	srv, c := managementServer(t)
	id := uuid.New()
	srv.mount(http.MethodPost, samlPath()+"/service-providers", 409, `{"error":"conflict","message":"entity_id"}`)
	srv.mount(http.MethodPut, samlPath()+"/service-providers/"+id.String(), 400,
		`{"error":"validation_error","message":"entity_id is immutable: register a new service provider"}`)
	srv.mount(http.MethodGet, samlPath()+"/service-providers/"+id.String(), 404, `{"error":"not_found","message":"no"}`)
	srv.mount(http.MethodPost, samlPath()+"/idp-credentials/"+id.String()+"/promote", 409, `{"error":"conflict","message":"not next"}`)
	srv.mount(http.MethodPost, samlPath()+"/parse-sp-metadata", 503, `{"error":"service_unavailable","message":"saml"}`)
	srv.mount(http.MethodDelete, samlPath()+"/service-providers/"+id.String(), 401, `{"error":"unauthorized"}`)
	ctx := context.Background()
	s := c.SAML()

	if _, err := s.CreateServiceProvider(ctx, samlInput()); !errors.Is(err, ErrConflict) {
		t.Fatalf("409: %T", err)
	}
	_, err := s.UpdateServiceProvider(ctx, id, samlInput())
	var verr *ValidationError
	if !errors.As(err, &verr) || !strings.Contains(verr.Message, "immutable") {
		t.Fatalf("400: %T", err)
	}
	if _, err := s.GetServiceProvider(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("404: %T", err)
	}
	if _, err := s.PromoteIdpCredential(ctx, id); !errors.Is(err, ErrConflict) {
		t.Fatalf("409 promote: %T", err)
	}
	_, err = s.ParseSpMetadata(ctx, ParseSAMLSpMetadataFromURL("https://m"))
	var netErr *NetworkError
	if !errors.As(err, &netErr) || errors.Is(err, ErrValidation) {
		t.Fatalf("503: want a plain NetworkError, got %T", err)
	}
	var authErr *AuthError
	if err := s.DeleteServiceProvider(ctx, id); !errors.As(err, &authErr) {
		t.Fatalf("401: want AuthError, got %T", err)
	}
}

// ── 8. Readiness is read, not cached ────────────────────────────────────────

func TestSAML_GetIdpIsNeverCachedAndKeepsNullApartFromAbsent(t *testing.T) {
	srv, c := managementServer(t)
	active := uuid.New()
	// The configured tenant, in the path: GetIdp takes no tenant argument.
	route := srv.mount(http.MethodGet, samlPath()+"/idp", 200, mustJSON(t, map[string]any{
		"tenant_id": tenantID, "saml_available": true, "saml_idp_enabled": false,
		"metadata_served": true, "entity_id": "https://iam.example/saml/v2/t",
		"metadata_url": "https://iam.example/saml/v2/t/metadata",
		"sso_url":      "https://iam.example/saml/v2/t/sso", "slo_url": "https://iam.example/saml/v2/t/slo",
		"active_credential_id": active, "next_credential_id": nil,
	}))
	ctx := context.Background()
	info, err := c.SAML().GetIdp(ctx)
	if err != nil {
		t.Fatalf("get_idp: %v", err)
	}
	if _, err := c.SAML().GetIdp(ctx); err != nil {
		t.Fatalf("again: %v", err)
	}
	if route.calls() != 2 {
		t.Fatalf("two calls, two requests: got %d", route.calls())
	}
	if got, ok := info.ActiveCredentialID.Get(); !ok || got != active {
		t.Fatal("the active credential decodes")
	}
	if !info.NextCredentialID.IsNull() {
		t.Fatal("null, not absent")
	}
	if !info.SAMLAvailable || !info.MetadataServed || info.SAMLIdpEnabled {
		t.Fatal("the flags decode")
	}

	var without SAMLIdpInfo
	if err := json.Unmarshal([]byte(`{"tenant_id":"`+tenantID.String()+`","saml_available":true,`+
		`"saml_idp_enabled":false,"metadata_served":false,"entity_id":"e","metadata_url":"m","sso_url":"s","slo_url":"l"}`), &without); err != nil {
		t.Fatal(err)
	}
	if !without.NextCredentialID.IsAbsent() || !without.ActiveCredentialID.IsAbsent() {
		t.Fatal("absent stays absent")
	}
}
