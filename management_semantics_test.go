package axiam

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// CONTRACT §27.4, §27.5 and §27.2 semantics — the §27.9 required tests.
//
// Every assertion here exists because the thing it checks is easy to get wrong
// and silent when wrong. Where §27.9 says to assert on the request PATH rather
// than on the arguments, these do.

// ---------------------------------------------------------------------------
// §27.4 rule 1 — the authentication precondition
// ---------------------------------------------------------------------------

func TestManagement_NoSessionMakesNoWireCall(t *testing.T) {
	srv, anonymous := anonymousManagementServer(t)
	route := srv.mount(http.MethodGet, "/api/v1/users", 200, `{"items":[],"total":0}`)

	_, err := anonymous.Users().List(context.Background(), PageRequest{})
	if err == nil {
		t.Fatal("expected a refusal with no session")
	}
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("want an auth error, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "no active session") {
		t.Fatalf("error should name the missing session, got %q", err)
	}
	if route.calls() != 0 {
		t.Fatalf("expected zero wire calls, got %d", route.calls())
	}
}

// ---------------------------------------------------------------------------
// §27.4 rule 3 — implicit path context
// ---------------------------------------------------------------------------

func orgBody(id uuid.UUID, name, slug string) string {
	return fmt.Sprintf(`{"id":%q,"name":%q,"slug":%q,"metadata":{},`+
		`"created_at":"2026-08-26T00:00:00Z","updated_at":"2026-08-26T00:00:00Z"}`, id, name, slug)
}

func TestManagement_OrgAndTenantComeFromTheClientAndLandInThePath(t *testing.T) {
	srv, c := managementServer(t)
	orgRoute := srv.mount(http.MethodGet, "/api/v1/organizations/"+orgID.String(), 200,
		orgBody(orgID, "Acme", "acme"))
	tenantRoute := srv.mount(http.MethodGet, "/api/v1/tenants/"+tenantID.String()+"/settings", 200, `{}`)

	if _, err := c.Organizations().Get(context.Background()); err != nil {
		t.Fatalf("organizations.get: %v", err)
	}
	if _, err := c.Settings().GetTenantOverride(context.Background()); err != nil {
		t.Fatalf("settings.get_tenant_override: %v", err)
	}

	if got := orgRoute.last(t).path; got != "/api/v1/organizations/"+orgID.String() {
		t.Fatalf("org path was %q", got)
	}
	if got := tenantRoute.last(t).path; got != "/api/v1/tenants/"+tenantID.String()+"/settings" {
		t.Fatalf("tenant path was %q", got)
	}
}

func TestManagement_AnExplicitOverrideChangesThePath(t *testing.T) {
	otherOrg := uuid.MustParse("44444444-4444-4444-8444-444444444444")
	otherTenant := uuid.MustParse("55555555-5555-4555-8555-555555555555")
	srv, c := managementServer(t)
	orgRoute := srv.mount(http.MethodGet, "/api/v1/organizations/"+otherOrg.String(), 200,
		orgBody(otherOrg, "Other", "other"))
	tenantRoute := srv.mount(http.MethodGet, "/api/v1/tenants/"+otherTenant.String()+"/settings", 200, `{}`)

	if _, err := c.Organizations().InOrg(otherOrg).Get(context.Background()); err != nil {
		t.Fatalf("organizations.get in another org: %v", err)
	}
	if _, err := c.Settings().ForTenant(otherTenant).GetTenantOverride(context.Background()); err != nil {
		t.Fatalf("settings.get_tenant_override for another tenant: %v", err)
	}
	if orgRoute.calls() != 1 || tenantRoute.calls() != 1 {
		t.Fatalf("overridden routes were not both reached: org=%d tenant=%d",
			orgRoute.calls(), tenantRoute.calls())
	}
}

func TestManagement_TheOverrideDoesNotMutateTheOriginalHandle(t *testing.T) {
	otherOrg := uuid.MustParse("44444444-4444-4444-8444-444444444444")
	srv, c := managementServer(t)
	base := c.Organizations()
	scoped := base.InOrg(otherOrg)
	if base == scoped {
		t.Fatal("InOrg returned the same handle")
	}
	route := srv.mount(http.MethodGet, "/api/v1/organizations/"+orgID.String(), 200,
		orgBody(orgID, "Acme", "acme"))
	if _, err := base.Get(context.Background()); err != nil {
		t.Fatalf("the original handle should still address the client's own org: %v", err)
	}
	if route.calls() != 1 {
		t.Fatalf("original handle reached the wrong route")
	}
}

func TestManagement_ASlugOnlyClientRefusesATenantRouteWithoutCalling(t *testing.T) {
	srv, anonymous := anonymousManagementServer(t)
	route := srv.mount(http.MethodGet, "/api/v1/tenants/"+tenantID.String()+"/settings", 200, `{}`)

	// Not logged in, so no tenant UUID has been resolved from a token claim.
	_, err := anonymous.Settings().GetTenantOverride(context.Background())
	if err == nil {
		t.Fatal("expected a refusal with no resolved tenant UUID")
	}
	if route.calls() != 0 {
		t.Fatalf("expected zero wire calls, got %d", route.calls())
	}
}

func TestManagement_TenantHeaderIsStillPresent(t *testing.T) {
	srv, c := managementServer(t)
	route := srv.mount(http.MethodGet, "/api/v1/users", 200,
		`{"items":[],"total":0,"offset":0,"limit":50}`)
	if _, err := c.Users().List(context.Background(), PageRequest{}); err != nil {
		t.Fatalf("users.list: %v", err)
	}
	if got := route.last(t).header.Get("X-Tenant-ID"); got != "acme" {
		t.Fatalf("X-Tenant-ID was %q; §5 rule 2 does not lapse on this surface", got)
	}
}

// ---------------------------------------------------------------------------
// §27.4 rule 4 — pagination
// ---------------------------------------------------------------------------

func userBody(index int) string {
	return fmt.Sprintf(`{"id":"%08d-1111-4111-8111-111111111111","username":"user%d",`+
		`"email":"user%d@example.test","email_verified":true,"failed_login_attempts":0,`+
		`"is_locked":false,"metadata":{},"mfa_enabled":false,"status":"Active",`+
		`"tenant_id":%q,"created_at":"2026-08-26T00:00:00Z","updated_at":"2026-08-26T00:00:00Z"}`,
		index, index, index, tenantID)
}

func TestManagement_TotalIsTheWholeSetNotThePage(t *testing.T) {
	srv, c := managementServer(t)
	srv.mount(http.MethodGet, "/api/v1/users", 200, fmt.Sprintf(
		`{"items":[%s,%s],"total":57,"offset":0,"limit":2}`, userBody(1), userBody(2)))

	page, err := c.Users().List(context.Background(), Limited(2))
	if err != nil {
		t.Fatalf("users.list: %v", err)
	}
	if len(page.Items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(page.Items))
	}
	if page.Total != 57 {
		t.Fatalf("Total was %d; a Page reporting len(Items) passes every single-page fixture", page.Total)
	}
	if !page.HasMore() {
		t.Fatal("HasMore should be true with 2 of 57")
	}
}

func TestManagement_ListAllWalksEveryPageWithTheExpectedOffsets(t *testing.T) {
	srv, c := managementServer(t)
	var offsets []string
	srv.mountFunc(http.MethodGet, "/api/v1/users", func(w http.ResponseWriter, r *http.Request) {
		offset := r.URL.Query().Get("offset")
		offsets = append(offsets, offset)
		var start int
		_, _ = fmt.Sscanf(offset, "%d", &start)
		var items []string
		for i := start; i < start+2 && i < 5; i++ {
			items = append(items, userBody(i))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"items":[%s],"total":5,"offset":%d,"limit":2}`,
			strings.Join(items, ","), start)
	})

	everyone, err := c.Users().ListAll(context.Background(), Limited(2))
	if err != nil {
		t.Fatalf("users.list_all: %v", err)
	}
	if len(everyone) != 5 {
		t.Fatalf("expected 5 users, got %d", len(everyone))
	}
	want := []string{"0", "2", "4"}
	if strings.Join(offsets, ",") != strings.Join(want, ",") {
		t.Fatalf("offsets were %v, want %v", offsets, want)
	}
}

func TestManagement_ListAllStopsOnAnEmptyPageEvenWhenTotalInsists(t *testing.T) {
	srv, c := managementServer(t)
	calls := 0
	srv.mountFunc(http.MethodGet, "/api/v1/users", func(w http.ResponseWriter, r *http.Request) {
		calls++
		items := ""
		if calls == 1 {
			items = userBody(1)
		}
		offset := r.URL.Query().Get("offset")
		var start int
		_, _ = fmt.Sscanf(offset, "%d", &start)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"items":[%s],"total":99,"offset":%d,"limit":1}`, items, start)
	})

	everyone, err := c.Users().ListAll(context.Background(), Limited(1))
	if err != nil {
		t.Fatalf("users.list_all: %v", err)
	}
	if len(everyone) != 1 {
		t.Fatalf("expected 1 user, got %d", len(everyone))
	}
	if calls != 2 {
		t.Fatalf("expected the walk to stop after the empty page, made %d requests", calls)
	}
}

func TestManagement_ABareArrayOperationIsNotAPage(t *testing.T) {
	srv, c := managementServer(t)
	srv.mount(http.MethodGet, "/api/v1/resources/"+exampleID.String()+"/scopes", 200, fmt.Sprintf(
		`[{"id":%q,"name":"draft","description":"Unpublished","resource_id":%q,"tenant_id":%q,`+
			`"created_at":"2026-08-26T00:00:00Z","updated_at":"2026-08-26T00:00:00Z"}]`,
		exampleID, exampleID, tenantID))

	scopes, err := c.Scopes().List(context.Background(), exampleID)
	if err != nil {
		t.Fatalf("scopes.list: %v", err)
	}
	// The compiler is the assertion: a []Scope has no Total, and if the
	// generator had modelled this as a page this line would not build.
	if len(scopes) != 1 {
		t.Fatalf("expected 1 scope, got %d", len(scopes))
	}
}

// ---------------------------------------------------------------------------
// §27.4 rule 5 — update shapes
// ---------------------------------------------------------------------------

func TestManagement_ASparseUpdateSendsExactlyTheOneKeyItWasGiven(t *testing.T) {
	srv, c := managementServer(t)
	route := srv.mount(http.MethodPut, "/api/v1/users/"+exampleID.String(), 200, userBody(1))

	if _, err := c.Users().Update(context.Background(), exampleID,
		UpdateUserRequest{Email: ptr("new@example.test")}); err != nil {
		t.Fatalf("users.update: %v", err)
	}

	keys := route.last(t).keys(t)
	if len(keys) != 1 || keys[0] != "email" {
		t.Fatalf("wire body carried %v; asserting one key is present would pass "+
			"even when every other field went along as null", keys)
	}
}

func TestManagement_AReplacementBodyHasAConstructorTakingEveryRequiredField(t *testing.T) {
	// §27.9 asks that a replacement type not compile with a field omitted. Go
	// cannot express that on a struct literal, so the guarantee is the
	// constructor: it takes every required field, and dropping one is a compile
	// error at the call site.
	anchor := NewSetMTLSTrustAnchor(true)
	if !anchor.Enabled {
		t.Fatal("constructor did not carry its argument")
	}
	policy := NewWebauthnAttestationPolicy(true, AttestationModeDirectRequired, true)
	if policy.Mode != AttestationModeDirectRequired {
		t.Fatalf("constructor did not carry its argument, mode was %q", policy.Mode)
	}

	// And the whole required key set reaches the wire, not just the one field
	// the caller was thinking about.
	encoded, err := json.Marshal(policy)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, want := range []string{"block_revoked_status", "mode", "require_fido_certified"} {
		if _, ok := got[want]; !ok {
			t.Fatalf("replacement body omitted %q; a PUT that replaces would clear it", want)
		}
	}
}

// ---------------------------------------------------------------------------
// §27.4 rule 7 — error mapping
// ---------------------------------------------------------------------------

func TestManagement_404MapsToNotFoundWhichIsStillAnAuthzError(t *testing.T) {
	srv, c := managementServer(t)
	srv.mount(http.MethodGet, "/api/v1/users/"+exampleID.String(), 404, `{"message":"gone"}`)

	_, err := c.Users().Get(context.Background(), exampleID)
	var notFound *NotFoundError
	if !errors.As(err, &notFound) {
		t.Fatalf("want *NotFoundError, got %T: %v", err, err)
	}
	if notFound.Operation != "users.get" {
		t.Fatalf("operation was %q", notFound.Operation)
	}
	if !errors.Is(err, ErrAuthz) {
		t.Fatal("a 404 must still match ErrAuthz: code written before §27 catches it that way")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Fatal("a 404 must match ErrNotFound")
	}
}

func TestManagement_409MapsToConflictAndIssuesTheWriteExactlyOnce(t *testing.T) {
	srv, c := managementServer(t)
	route := srv.mount(http.MethodPost, "/api/v1/roles", 409, `{"message":"role name already taken"}`)

	_, err := c.Roles().Create(context.Background(),
		CreateRoleRequest{Name: "Editor", Description: "Edits", IsGlobal: false})
	var conflict *ConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("want *ConflictError, got %T: %v", err, err)
	}
	if !errors.Is(err, ErrAuthz) {
		t.Fatal("a 409 must still match ErrAuthz")
	}
	if !strings.Contains(err.Error(), "already taken") {
		t.Fatalf("the server's complaint should reach the message, got %q", err)
	}
	if route.calls() != 1 {
		t.Fatalf("a 409 must not be retried; the write went out %d times", route.calls())
	}
}

func TestManagement_400MapsToValidationErrorWithFieldDetail(t *testing.T) {
	srv, c := managementServer(t)
	srv.mount(http.MethodPost, "/api/v1/users", 400,
		`{"message":"invalid","errors":[{"field":"email","message":"not an email"}]}`)

	_, err := c.Users().Create(context.Background(), CreateUserRequest{
		Username: "bob", Email: "nope", Password: Sensitive("hunter2hunter2"),
	})
	var invalid *ValidationError
	if !errors.As(err, &invalid) {
		t.Fatalf("want *ValidationError, got %T: %v", err, err)
	}
	if !errors.Is(err, ErrNetwork) {
		t.Fatal("§2 maps 400 to the network category; §27 narrows it without moving it")
	}
	if invalid.Status != 400 {
		t.Fatalf("status was %d", invalid.Status)
	}
	if len(invalid.Fields) != 1 || invalid.Fields[0].Field != "email" {
		t.Fatalf("field detail was %+v", invalid.Fields)
	}
}

func TestManagement_422IsValidationErrorTooInTheObjectKeyedShape(t *testing.T) {
	srv, c := managementServer(t)
	srv.mount(http.MethodPost, "/api/v1/users", 422, `{"errors":{"username":"already taken"}}`)

	_, err := c.Users().Create(context.Background(), CreateUserRequest{
		Username: "bob", Email: "b@example.test", Password: Sensitive("hunter2hunter2"),
	})
	var invalid *ValidationError
	if !errors.As(err, &invalid) {
		t.Fatalf("want *ValidationError, got %T: %v", err, err)
	}
	if invalid.Status != 422 {
		t.Fatalf("status was %d", invalid.Status)
	}
	if len(invalid.Fields) != 1 || invalid.Fields[0].Field != "username" {
		t.Fatalf("field detail was %+v", invalid.Fields)
	}
}

func TestManagement_AnOrdinary403StaysAPlainAuthzError(t *testing.T) {
	srv, c := managementServer(t)
	srv.mount(http.MethodGet, "/api/v1/users/"+exampleID.String(), 403, `{"message":"nope"}`)

	_, err := c.Users().Get(context.Background(), exampleID)
	if !errors.Is(err, ErrAuthz) {
		t.Fatalf("want an authz error, got %T", err)
	}
	var notFound *NotFoundError
	var conflict *ConflictError
	if errors.As(err, &notFound) || errors.As(err, &conflict) {
		t.Fatal("§27 classifies three statuses and widens the taxonomy no further")
	}
}

func TestManagement_ARepeatedDeleteIsNotSwallowedIntoSuccess(t *testing.T) {
	srv, c := managementServer(t)
	srv.mount(http.MethodDelete, "/api/v1/users/"+exampleID.String(), 404, `{"message":"gone"}`)

	err := c.Users().Delete(context.Background(), exampleID)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("a second delete must report the 404, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// §27.4 rule 8 — retry
// ---------------------------------------------------------------------------

func TestManagement_AWriteIsIssuedExactlyOnceOnA503(t *testing.T) {
	srv, c := managementServer(t)
	route := srv.mount(http.MethodPost, "/api/v1/roles", 503, `{"message":"unavailable"}`)

	_, err := c.Roles().Create(context.Background(),
		CreateRoleRequest{Name: "Editor", Description: "Edits", IsGlobal: false})
	if err == nil {
		t.Fatal("expected the 503 to surface")
	}
	if route.calls() != 1 {
		t.Fatalf("no write on this surface is retried, even one that looks idempotent; "+
			"it went out %d times", route.calls())
	}
}

// ---------------------------------------------------------------------------
// §27.5 — secrets
// ---------------------------------------------------------------------------

func TestManagement_AReturnedOneTimeSecretIsRedactedFromEveryRendering(t *testing.T) {
	srv, c := managementServer(t)
	srv.mount(http.MethodPost, "/api/v1/scim-tokens", 201, fmt.Sprintf(
		`{"id":%q,"name":"provisioning","created_by":%q,"user_id":%q,"tenant_id":%q,`+
			`"status":"active","created_at":"2026-08-26T00:00:00Z",`+
			`"expires_at":"2026-09-26T00:00:00Z","provisioning_token":"scim_live_supersecret"}`,
		exampleID, exampleID, exampleID, tenantID))

	created, err := c.SCIMTokens().Create(context.Background(),
		CreateSCIMTokenRequest{Name: "provisioning", UserID: exampleID})
	if err != nil {
		t.Fatalf("scim_tokens.create: %v", err)
	}

	for _, rendering := range []string{
		fmt.Sprintf("%v", created),
		fmt.Sprintf("%+v", created),
		fmt.Sprintf("%#v", created),
		fmt.Sprintf("%s", created.ProvisioningToken),
	} {
		if strings.Contains(rendering, "scim_live_supersecret") {
			t.Fatalf("the secret leaked into a rendering: %s", rendering)
		}
	}
	encoded, err := json.Marshal(created)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(encoded), "scim_live_supersecret") {
		t.Fatalf("the secret leaked into JSON: %s", encoded)
	}
	if created.ProvisioningToken.expose() != "scim_live_supersecret" {
		t.Fatal("the secret is not reachable through the one accessor that should reach it")
	}
}

func TestManagement_ASuppliedPasswordIsRedactedButStillSent(t *testing.T) {
	srv, c := managementServer(t)
	route := srv.mount(http.MethodPost, "/api/v1/users", 201, userBody(1))

	body := CreateUserRequest{
		Username: "bob", Email: "bob@example.test", Password: Sensitive("hunter2hunter2"),
	}
	if strings.Contains(fmt.Sprintf("%+v", body), "hunter2hunter2") {
		t.Fatal("the password leaked into the struct's own rendering")
	}
	if _, err := c.Users().Create(context.Background(), body); err != nil {
		t.Fatalf("users.create: %v", err)
	}

	sent := route.last(t).jsonBody(t)
	if sent["password"] != "hunter2hunter2" {
		t.Fatalf("wrapping a secret must not stop it reaching the server; sent %v", sent["password"])
	}
}

// ---------------------------------------------------------------------------
// §27.2 — handle rules
// ---------------------------------------------------------------------------

func TestManagement_AcquiringAHandlePerformsNoIO(t *testing.T) {
	srv, c := managementServer(t)
	before := len(srv.unknown)

	_ = c.Users()
	_ = c.Roles()
	_ = c.Groups()
	_ = c.Certificates()
	_ = c.Platform()
	_ = c.Manifest()

	if len(srv.unknown) != before {
		t.Fatalf("acquiring handles reached the network: %v", srv.unknown)
	}
}

func TestManagement_AClosedClientRejectsEveryOperation(t *testing.T) {
	srv, c := managementServer(t)
	route := srv.mount(http.MethodGet, "/api/v1/users", 200, `{"items":[],"total":0}`)
	if err := c.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	_, err := c.Users().List(context.Background(), PageRequest{})
	if err == nil || !strings.Contains(err.Error(), "client is closed") {
		t.Fatalf("want a use-after-close refusal, got %v", err)
	}
	if route.calls() != 0 {
		t.Fatalf("a closed client must not reach the network")
	}
}
