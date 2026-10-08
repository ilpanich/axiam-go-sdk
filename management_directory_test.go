package axiam

// The directory management namespace — CONTRACT.md §30.8's six required tests,
// plus the Nullable explicit-null type the sparse update rests on.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func directoryPath() string { return "/api/v1/tenants/" + tenantID.String() + "/directory" }

func directoryConfigBody(extra map[string]any) string {
	body := map[string]any{
		"id": uuid.New(), "tenant_id": tenantID, "enabled": true, "kind": "active_directory",
		"url": "ldaps://dc.corp.example", "start_tls": false, "bind_dn": "cn=svc,dc=corp",
		"base_dn": "dc=corp", "user_filter": "(sAMAccountName={username})",
		"user_attribute_map": map[string]any{"username": "sAMAccountName", "email": "mail",
			"display_name": "displayName", "external_id": "objectGUID"},
		"group_base_dn": nil, "group_filter": nil, "group_member_attribute": "member",
		"group_nesting_depth": 5, "group_mappings": []any{}, "sync_interval_secs": 3600,
		"jit_provisioning": false, "trust_anchors_pem": []any{},
		"created_at": "2026-10-04T00:00:00Z", "updated_at": "2026-10-04T00:00:00Z",
	}
	for k, v := range extra {
		body[k] = v
	}
	encoded, _ := json.Marshal(body)
	return string(encoded)
}

func setDirectoryBody(secret string) SetDirectoryConfig {
	body := NewSetDirectoryConfig("dc=corp", "cn=svc,dc=corp", true, DirectoryKindActiveDirectory,
		false, "ldaps://dc.corp.example", "(sAMAccountName={username})")
	if secret != "" {
		s := Sensitive(secret)
		body.BindSecret = &s
	}
	return body
}

// ── 1. Redaction ────────────────────────────────────────────────────────────

func TestDirectory_TheBindSecretReachesTheWireAndNoRendering(t *testing.T) {
	srv, c := managementServer(t)
	secret := randomSecret(t, "bind-")
	set := setDirectoryBody(secret)
	s := Sensitive(secret)
	update := UpdateDirectoryConfig{BindSecret: &s}
	assertNoFragmentIn(t, set, secret, "SetDirectoryConfig")
	assertNoFragmentIn(t, update, secret, "UpdateDirectoryConfig")

	route := srv.mount(http.MethodPut, directoryPath(), 400,
		`{"error":"validation_error","message":"url: plaintext LDAP is refused"}`)
	_, err := c.Directory().Set(context.Background(), set)
	if err == nil {
		t.Fatal("expected the 400")
	}
	assertNoFragment(t, errorRenderings(err), secret, "set error")
	if route.last(t).jsonBody(t)["bind_secret"] != secret {
		t.Fatal("the secret must be on the wire")
	}
}

// ── 2. No secret on the response ────────────────────────────────────────────

func TestDirectory_ABindSecretInAResponseIsDropped(t *testing.T) {
	srv, c := managementServer(t)
	leaked := randomSecret(t, "bind-")
	srv.mount(http.MethodGet, directoryPath(), 200, directoryConfigBody(map[string]any{"bind_secret": leaked}))
	config, err := c.Directory().Get(context.Background())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	assertNoFragmentIn(t, config, leaked, "DirectoryConfig")
	if _, has := reflect.TypeOf(config).FieldByName("BindSecret"); has {
		t.Fatal("DirectoryConfig must declare no secret member")
	}
	if config.URL != "ldaps://dc.corp.example" {
		t.Fatal("the rest decodes")
	}
}

// ── 3. Sparse update ────────────────────────────────────────────────────────

func TestDirectory_UpdateSendsExactlyTheMembersItWasGiven(t *testing.T) {
	srv, c := managementServer(t)
	route := srv.mount(http.MethodPatch, directoryPath(), 200, directoryConfigBody(nil))
	secret := randomSecret(t, "bind-")
	ctx := context.Background()

	if _, err := c.Directory().Update(ctx, UpdateDirectoryConfig{Enabled: ptr(false)}); err != nil {
		t.Fatalf("disable: %v", err)
	}
	s := Sensitive(secret)
	if _, err := c.Directory().Update(ctx, UpdateDirectoryConfig{URL: ptr("ldaps://dc2.corp.example"), BindSecret: &s}); err != nil {
		t.Fatalf("move with the secret: %v", err)
	}
	if _, err := c.Directory().Update(ctx, UpdateDirectoryConfig{GroupFilter: NullOf[string]()}); err != nil {
		t.Fatalf("clear the filter: %v", err)
	}
	if _, err := c.Directory().Update(ctx, UpdateDirectoryConfig{GroupBaseDn: ValueOf("ou=groups,dc=corp")}); err != nil {
		t.Fatalf("set the group base: %v", err)
	}

	sent := route.requests
	if len(sent) != 4 {
		t.Fatalf("expected four requests, got %d", len(sent))
	}
	if string(sent[0].body) != `{"enabled":false}` {
		t.Fatal("first update: only enabled")
	}
	if got := sent[1].keys(t); !reflect.DeepEqual(got, []string{"bind_secret", "url"}) {
		t.Fatalf("second update keys: %v", got)
	}
	if sent[1].jsonBody(t)["bind_secret"] != secret {
		t.Fatal("the secret must be on the wire")
	}
	if string(sent[2].body) != `{"group_filter":null}` {
		t.Fatal("an explicit null must be sent as null, and nothing else")
	}
	if string(sent[3].body) != `{"group_base_dn":"ou=groups,dc=corp"}` {
		t.Fatal("a value is sent as the value")
	}
}

// ── 4. Replacement ──────────────────────────────────────────────────────────

func TestDirectory_SetSendsEveryRequiredMemberAndDecodes201And200(t *testing.T) {
	for _, status := range []int{201, 200} {
		srv, c := managementServer(t)
		route := srv.mount(http.MethodPut, directoryPath(), status, directoryConfigBody(nil))
		config, err := c.Directory().Set(context.Background(), setDirectoryBody(""))
		if err != nil {
			t.Fatalf("%d: set: %v", status, err)
		}
		if !config.Enabled {
			t.Fatalf("%d: decoded", status)
		}
		body := route.last(t).jsonBody(t)
		for _, required := range []string{"enabled", "kind", "url", "start_tls", "bind_dn", "base_dn", "user_filter"} {
			if _, ok := body[required]; !ok {
				t.Fatalf("%d: %s missing", status, required)
			}
		}
		if _, ok := body["bind_secret"]; ok {
			t.Fatalf("%d: absent keeps the stored secret, so it must not be sent", status)
		}
	}
}

// ── 5. No retry ─────────────────────────────────────────────────────────────

func TestDirectory_NoWriteIsRetriedOn503(t *testing.T) {
	srv, c := managementServer(t)
	put := srv.mount(http.MethodPut, directoryPath(), 503, "")
	patch := srv.mount(http.MethodPatch, directoryPath(), 503, "")
	del := srv.mount(http.MethodDelete, directoryPath(), 503, "")
	link := srv.mount(http.MethodPost, directoryPath()+"/links", 503, "")
	ctx := context.Background()
	d := c.Directory()

	_, err1 := d.Set(ctx, setDirectoryBody(randomSecret(t, "bind-")))
	_, err2 := d.Update(ctx, UpdateDirectoryConfig{})
	err3 := d.Delete(ctx)
	_, err4 := d.LinkAccount(ctx, LinkDirectoryAccount{UserID: uuid.New()})
	for i, err := range []error{err1, err2, err3, err4} {
		var netErr *NetworkError
		if !errors.As(err, &netErr) {
			t.Fatalf("write %d: want NetworkError, got %T", i, err)
		}
	}
	for name, route := range map[string]*mountedRoute{"set": put, "update": patch, "delete": del, "link": link} {
		if route.calls() != 1 {
			t.Fatalf("%s: exactly one request, got %d", name, route.calls())
		}
	}
}

// ── 6. Errors and link_account ──────────────────────────────────────────────

func TestDirectory_ErrorsMapAndLinkAccountSendsOnlyTheUserID(t *testing.T) {
	srv, c := managementServer(t)
	srv.mount(http.MethodPut, directoryPath(), 400,
		`{"error":"validation_error","message":"url: changing the connection requires entering the bind secret again"}`)
	srv.mount(http.MethodPatch, directoryPath(), 409, `{"error":"conflict","message":"opaque_mode"}`)
	srv.mount(http.MethodGet, directoryPath(), 404, `{"error":"not_found","message":"none"}`)
	ctx := context.Background()

	_, err := c.Directory().Set(ctx, setDirectoryBody(""))
	var verr *ValidationError
	if !errors.As(err, &verr) || !strings.Contains(verr.Message, "bind secret again") {
		t.Fatalf("400: want ValidationError with the message, got %T", err)
	}
	if _, err := c.Directory().Update(ctx, UpdateDirectoryConfig{Enabled: ptr(true)}); !errors.Is(err, ErrConflict) {
		t.Fatalf("409: want ConflictError, got %T", err)
	}
	if _, err := c.Directory().Get(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("404: want NotFoundError, got %T", err)
	}

	user := uuid.New()
	link := srv.mount(http.MethodPost, directoryPath()+"/links", 200,
		`{"user_id":"`+user.String()+`","directory_external_id":"3f2a-objectguid",`+
			`"webauthn_credentials_deleted":2,"certificates_revoked":1,"was_already_linked":false}`)
	result, err := c.Directory().LinkAccount(ctx, LinkDirectoryAccount{UserID: user})
	if err != nil {
		t.Fatalf("link: %v", err)
	}
	if string(link.last(t).body) != `{"user_id":"`+user.String()+`"}` {
		t.Fatal("link_account must send exactly {user_id}")
	}
	if result.UserID != user || result.DirectoryExternalID != "3f2a-objectguid" ||
		result.WebauthnCredentialsDeleted != 2 || result.CertificatesRevoked != 1 || result.WasAlreadyLinked {
		t.Fatalf("all five DirectoryLinkResult members decode: %+v", result)
	}
}

func TestDirectory_SyncStatusDecodesAnUnknownResultAndTheFirstRunNulls(t *testing.T) {
	srv, c := managementServer(t)
	srv.mount(http.MethodGet, directoryPath()+"/sync-status", 200,
		`{"last_result":"something_new","last_attempt_at":null,"last_full_run_at":null,"full_required":true,"has_watermark":false}`)
	status, err := c.Directory().GetSyncStatus(context.Background())
	if err != nil {
		t.Fatalf("sync status: %v", err)
	}
	if status.LastResult == nil || *status.LastResult != "something_new" || !status.FullRequired || status.HasWatermark {
		t.Fatalf("decoded: %+v", status)
	}
}

func TestDirectory_AReadConvertsIntoTheReplacementBodyWithoutASecret(t *testing.T) {
	var config DirectoryConfig
	if err := json.Unmarshal([]byte(directoryConfigBody(nil)), &config); err != nil {
		t.Fatal(err)
	}
	body := config.ToInput()
	if body.BindSecret != nil {
		t.Fatal("absent keeps the stored secret")
	}
	if body.URL != config.URL || *body.GroupNestingDepth != 5 || *body.SyncIntervalSecs != 3600 ||
		body.Kind != DirectoryKindActiveDirectory || body.UserAttributeMap == nil {
		t.Fatalf("every member carried over: %+v", body)
	}
}

// ── Nullable ────────────────────────────────────────────────────────────────

func TestNullable_ThreeStatesRoundTrip(t *testing.T) {
	var absent Nullable[string]
	if !absent.IsAbsent() || !absent.IsZero() || absent.IsNull() {
		t.Fatal("the zero value is absent")
	}
	if _, ok := absent.Get(); ok {
		t.Fatal("absent carries no value")
	}
	if b, _ := json.Marshal(absent); string(b) != "null" {
		t.Fatal("an absent Nullable marshalled directly is null")
	}
	null := NullOf[string]()
	if !null.IsNull() || null.IsAbsent() {
		t.Fatal("NullOf is null")
	}
	v := ValueOf("x")
	if got, ok := v.Get(); !ok || got != "x" {
		t.Fatal("ValueOf carries its value")
	}

	var decoded struct {
		A Nullable[uuid.UUID] `json:"a,omitzero"`
		B Nullable[uuid.UUID] `json:"b,omitzero"`
		C Nullable[uuid.UUID] `json:"c,omitzero"`
	}
	id := uuid.New()
	if err := json.Unmarshal([]byte(`{"a":null,"b":"`+id.String()+`"}`), &decoded); err != nil {
		t.Fatal(err)
	}
	if !decoded.A.IsNull() || !decoded.C.IsAbsent() {
		t.Fatal("null stays apart from absent")
	}
	if got, ok := decoded.B.Get(); !ok || got != id {
		t.Fatal("a value decodes")
	}
	if err := json.Unmarshal([]byte(`{"a":5}`), &decoded); err == nil {
		t.Fatal("a mistyped value is a decode error")
	}
}
