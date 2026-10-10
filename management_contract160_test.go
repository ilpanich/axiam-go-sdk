package axiam

// CONTRACT §27.15 (contract 1.60) — the three additive members and the
// federation.update_config null rule, against the wire:
//
//   - note 1: notification_rules' window_minutes is passed through, never
//     clamped, omitted when unset, and decoded from a response;
//   - notes 6 and 7: the federation configuration's allow_sha1_signatures and
//     idp_metadata_signing_cert_pem are sent only when the caller sets them,
//     and an older server's response without them decodes (false / nil);
//   - note 8: every nullable member of UpdateFederationConfigRequest is
//     cleared by an explicit null and left by an omitted one — §27.4 rule 5's
//     exact key-set test for one cleared member.

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
)

const notificationRulesPath = "/api/v1/notification-rules"

const notificationRuleJSON = `{"created_at":"2026-10-05T00:00:00Z","description":"d","enabled":true,` +
	`"events":[],"id":"11111111-1111-4111-8111-111111111111","name":"n","recipient_emails":[],` +
	`"tenant_id":"11111111-1111-4111-8111-111111111111","updated_at":"2026-10-05T00:00:00Z","window_minutes":45}`

// §27.15 note 1's one required test: create with window_minutes sends it as
// given, create without it sends no such key, and a response carrying it
// decodes it. The values sent are outside 1 … 1440 on purpose — the server is
// the one that answers 400, and a client-side clamp would be a silently
// different request.
func TestContract160_NotificationRuleWindowMinutesIsPassedThroughNeverClamped(t *testing.T) {
	srv, c := managementServer(t)
	route := srv.mount(http.MethodPost, notificationRulesPath, 201, notificationRuleJSON)
	ctx := context.Background()
	body := func(window *int) CreateNotificationRuleRequest {
		return CreateNotificationRuleRequest{Description: "d", Events: []NotificationEventType{},
			Name: "n", RecipientEmails: []string{}, WindowMinutes: window}
	}

	for _, given := range []int{45, 0, 5000} {
		if _, err := c.NotificationRules().Create(ctx, body(ptr(given))); err != nil {
			t.Fatalf("create %d: %v", given, err)
		}
		if got := route.last(t).jsonBody(t)["window_minutes"]; got != float64(given) {
			t.Fatalf("window_minutes %d is sent as given, got %v", given, got)
		}
	}
	rule, err := c.NotificationRules().Create(ctx, body(nil))
	if err != nil {
		t.Fatalf("create without: %v", err)
	}
	if _, has := route.last(t).jsonBody(t)["window_minutes"]; has {
		t.Fatal("an unset window_minutes sends no key")
	}
	if rule.WindowMinutes != 45 {
		t.Fatalf("the response's window_minutes decodes: %d", rule.WindowMinutes)
	}

	// update is sparse: the same pass-through, and absent is not sent.
	id := rule.ID
	update := srv.mount(http.MethodPut, notificationRulesPath+"/"+id.String(), 200, notificationRuleJSON)
	if _, err := c.NotificationRules().Update(ctx, id, UpdateNotificationRuleRequest{WindowMinutes: ptr(1441)}); err != nil {
		t.Fatalf("update: %v", err)
	}
	if keys := update.last(t).keys(t); !reflect.DeepEqual(keys, []string{"window_minutes"}) {
		t.Fatalf("exact key set: %v", keys)
	}
	if got := update.last(t).jsonBody(t)["window_minutes"]; got != float64(1441) {
		t.Fatalf("sent as given on update: %v", got)
	}
}

const federationConfigsPath = "/api/v1/federation-configs"

// federationConfigJSON is a FederationConfigResponse; extra is spliced in
// before the closing brace (an older server's body when empty).
func federationConfigJSON(extra string) string {
	return `{"allow_tenant_inheritance":true,"allowed_algorithms":[],"allowed_issuer_tenants":[],` +
		`"attribute_map":{},"client_id":"rp","created_at":"2026-10-05T00:00:00Z","effective_scopes":[],` +
		`"enabled":true,"has_bundled_mark":false,"id":"11111111-1111-4111-8111-111111111111",` +
		`"mints_client_secret":false,"pkce_required":false,"protocol":"Saml","provider":"idp",` +
		`"provider_kind":"generic_saml","scopes":[],"tenant_id":"11111111-1111-4111-8111-111111111111",` +
		`"token_exchange":{"accepted_audiences":[],"enabled":false,"max_token_age_secs":1,"scope_map":{},` +
		`"subject_mapping":"email"},"updated_at":"2026-10-05T00:00:00Z"` + extra + `}`
}

// Notes 6 and 7: both members are sent only when the caller sets them, on
// create and on update; a response without them (an older server) decodes as
// false and nil, and one carrying them decodes them.
func TestContract160_FederationSHA1AndMetadataCertAreSentOnlyWhenSet(t *testing.T) {
	srv, c := managementServer(t)
	ctx := context.Background()
	create := srv.mount(http.MethodPost, federationConfigsPath, 201, federationConfigJSON(""))
	secret := Sensitive(randomSecret(t, "fed-"))
	base := CreateFederationConfigRequest{ClientID: "rp", ClientSecret: secret, Protocol: "Saml", Provider: "idp"}

	old, err := c.Federation().CreateConfig(ctx, base)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	sent := create.last(t).jsonBody(t)
	for _, k := range []string{"allow_sha1_signatures", "idp_metadata_signing_cert_pem"} {
		if _, has := sent[k]; has {
			t.Fatalf("an unset %s sends no key", k)
		}
	}
	if old.AllowSha1Signatures || old.IdpMetadataSigningCertPEM != nil {
		t.Fatalf("an older server's response decodes as false / nil: %+v", old)
	}

	const pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
	withBoth := base
	withBoth.AllowSha1Signatures = ptr(false)
	withBoth.IdpMetadataSigningCertPEM = ptr(pem)
	if _, err := c.Federation().CreateConfig(ctx, withBoth); err != nil {
		t.Fatalf("create with both: %v", err)
	}
	sent = create.last(t).jsonBody(t)
	if v, has := sent["allow_sha1_signatures"]; !has || v != false {
		t.Fatalf("a set false is sent, not dropped: %v", v)
	}
	if sent["idp_metadata_signing_cert_pem"] != pem {
		t.Fatalf("the metadata certificate is sent as given: %v", sent["idp_metadata_signing_cert_pem"])
	}

	id := old.ID
	srv.mount(http.MethodGet, federationConfigsPath+"/"+id.String(), 200,
		federationConfigJSON(`,"allow_sha1_signatures":true,"idp_metadata_signing_cert_pem":`+mustJSON(t, pem)))
	got, err := c.Federation().GetConfig(ctx, id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !got.AllowSha1Signatures || got.IdpMetadataSigningCertPEM == nil || *got.IdpMetadataSigningCertPEM != pem {
		t.Fatalf("a response carrying both decodes them: %+v", got)
	}

	update := srv.mount(http.MethodPut, federationConfigsPath+"/"+id.String(), 200, federationConfigJSON(""))
	if _, err := c.Federation().UpdateConfig(ctx, id, UpdateFederationConfigRequest{AllowSha1Signatures: ptr(true)}); err != nil {
		t.Fatalf("update: %v", err)
	}
	if keys := update.last(t).keys(t); !reflect.DeepEqual(keys, []string{"allow_sha1_signatures"}) {
		t.Fatalf("exact key set: %v", keys)
	}
}

// Note 8: each of the ten nullable members is cleared by an explicit null and
// left by an omitted one — "unset" and "set to null" are different requests,
// asserted on the exact key set (§27.4 rule 5).
func TestContract160_FederationUpdateNullClearsAndAbsentLeaves(t *testing.T) {
	srv, c := managementServer(t)
	ctx := context.Background()
	cfg := uuid.New()
	update := srv.mount(http.MethodPut, federationConfigsPath+"/"+cfg.String(), 200, federationConfigJSON(""))

	// One cleared member: the body is exactly {"metadata_url": null}.
	if _, err := c.Federation().UpdateConfig(ctx, cfg, UpdateFederationConfigRequest{MetadataURL: NullOf[string]()}); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if raw := strings.TrimSpace(string(update.last(t).body)); raw != `{"metadata_url":null}` {
		t.Fatalf("an explicit null is the whole body: %s", raw)
	}

	// Nothing set: an empty body — absent leaves every member.
	if _, err := c.Federation().UpdateConfig(ctx, cfg, UpdateFederationConfigRequest{}); err != nil {
		t.Fatalf("empty: %v", err)
	}
	if keys := update.last(t).keys(t); len(keys) != 0 {
		t.Fatalf("absent sends nothing: %v", keys)
	}

	// A value, a null and an absent member side by side.
	if _, err := c.Federation().UpdateConfig(ctx, cfg, UpdateFederationConfigRequest{
		IdpMetadataSigningCertPEM: NullOf[string](),
		ButtonIcon:                ValueOf("https://idp.example/icon.svg"),
	}); err != nil {
		t.Fatalf("mixed: %v", err)
	}
	sent := update.last(t).jsonBody(t)
	if keys := update.last(t).keys(t); !reflect.DeepEqual(keys, []string{"button_icon", "idp_metadata_signing_cert_pem"}) {
		t.Fatalf("exact key set: %v", keys)
	}
	if v, has := sent["idp_metadata_signing_cert_pem"]; !has || v != nil {
		t.Fatalf("null is sent as null: %v", v)
	}

	// Every one of the ten clears: each NullOf sends exactly that key as null.
	ten := map[string]func(*UpdateFederationConfigRequest){
		"metadata_url":                  func(r *UpdateFederationConfigRequest) { r.MetadataURL = NullOf[string]() },
		"idp_signing_cert_pem":          func(r *UpdateFederationConfigRequest) { r.IdpSigningCertPEM = NullOf[string]() },
		"idp_metadata_signing_cert_pem": func(r *UpdateFederationConfigRequest) { r.IdpMetadataSigningCertPEM = NullOf[string]() },
		"provider_slug":                 func(r *UpdateFederationConfigRequest) { r.ProviderSlug = NullOf[string]() },
		"authorization_endpoint":        func(r *UpdateFederationConfigRequest) { r.AuthorizationEndpoint = NullOf[string]() },
		"token_endpoint":                func(r *UpdateFederationConfigRequest) { r.TokenEndpoint = NullOf[string]() },
		"userinfo_endpoint":             func(r *UpdateFederationConfigRequest) { r.UserinfoEndpoint = NullOf[string]() },
		"apple_team_id":                 func(r *UpdateFederationConfigRequest) { r.AppleTeamID = NullOf[string]() },
		"apple_key_id":                  func(r *UpdateFederationConfigRequest) { r.AppleKeyID = NullOf[string]() },
		"button_icon":                   func(r *UpdateFederationConfigRequest) { r.ButtonIcon = NullOf[string]() },
	}
	for key, set := range ten {
		var r UpdateFederationConfigRequest
		set(&r)
		raw, err := json.Marshal(r.toWire())
		if err != nil {
			t.Fatal(err)
		}
		if string(raw) != `{"`+key+`":null}` {
			t.Fatalf("%s: clearing it sends exactly that null, got %s", key, raw)
		}
	}
}
