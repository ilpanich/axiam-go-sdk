package axiam

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// The §27 paths the semantics suites reach past, exercised deliberately.
//
// Nothing here is incidental: each case covers a branch that is easy to get
// wrong and would otherwise ship untested — the scoped handles on every
// namespace that has them, the error strings, the reconciler's converged-tenant
// reads, and the filter arguments on the two audit reads.

// ---------------------------------------------------------------------------
// Scoped handles, on every namespace that has one
// ---------------------------------------------------------------------------

func TestManagement_EveryScopedNamespaceCanBeRedirected(t *testing.T) {
	otherOrg := uuid.MustParse("44444444-4444-4444-8444-444444444444")
	otherTenant := uuid.MustParse("55555555-5555-4555-8555-555555555555")
	_, c := managementServer(t)

	// InOrg exists on every namespace whose routes carry {org_id}.
	if c.Organizations().InOrg(otherOrg) == c.Organizations() {
		t.Fatal("organizations.InOrg returned the same handle")
	}
	if c.Tenants().InOrg(otherOrg) == c.Tenants() {
		t.Fatal("tenants.InOrg returned the same handle")
	}
	if c.CACertificates().InOrg(otherOrg) == c.CACertificates() {
		t.Fatal("ca_certificates.InOrg returned the same handle")
	}
	if c.Settings().InOrg(otherOrg) == c.Settings() {
		t.Fatal("settings.InOrg returned the same handle")
	}
	if c.EmailConfig().InOrg(otherOrg) == c.EmailConfig() {
		t.Fatal("email_config.InOrg returned the same handle")
	}

	// ForTenant exists on the three namespaces where {tenant_id} names the
	// calling context rather than the object.
	if c.Settings().ForTenant(otherTenant) == c.Settings() {
		t.Fatal("settings.ForTenant returned the same handle")
	}
	if c.EmailConfig().ForTenant(otherTenant) == c.EmailConfig() {
		t.Fatal("email_config.ForTenant returned the same handle")
	}
	if c.WebauthnPolicy().ForTenant(otherTenant) == c.WebauthnPolicy() {
		t.Fatal("webauthn_policy.ForTenant returned the same handle")
	}
}

func TestManagement_ResolvedIdentifiersAreReadable(t *testing.T) {
	_, c := managementServer(t)

	got, ok := c.ResolvedOrgID()
	if !ok || got != orgID {
		t.Fatalf("ResolvedOrgID() = %v, %v; want %v, true", got, ok, orgID)
	}
	gotTenant, ok := c.ResolvedTenantID()
	if !ok || gotTenant != tenantID {
		t.Fatalf("ResolvedTenantID() = %v, %v; want %v, true", gotTenant, ok, tenantID)
	}

	// A client that has not logged in has neither.
	_, anonymous := anonymousManagementServer(t)
	if _, ok := anonymous.ResolvedTenantID(); ok {
		t.Fatal("a client that never logged in should have no resolved tenant UUID")
	}
}

// ---------------------------------------------------------------------------
// The error sub-types' own strings
// ---------------------------------------------------------------------------

func TestManagement_ErrorStringsNameTheOperation(t *testing.T) {
	notFound := &NotFoundError{Operation: "users.get", Message: "users.get: not found"}
	if !strings.Contains(notFound.Error(), "users.get") {
		t.Fatalf("NotFoundError.Error() = %q", notFound.Error())
	}
	conflict := &ConflictError{Operation: "roles.create", Message: "roles.create: conflict"}
	if !strings.Contains(conflict.Error(), "roles.create") {
		t.Fatalf("ConflictError.Error() = %q", conflict.Error())
	}
	invalid := &ValidationError{Operation: "users.create", Status: 400, Message: "users.create: rejected"}
	if !strings.Contains(invalid.Error(), "users.create") {
		t.Fatalf("ValidationError.Error() = %q", invalid.Error())
	}
	if !errors.Is(invalid, ErrValidation) || !errors.Is(invalid, ErrNetwork) {
		t.Fatal("a ValidationError must match both its own sentinel and §2's network one")
	}
	if !errors.Is(conflict, ErrConflict) || !errors.Is(conflict, ErrAuthz) {
		t.Fatal("a ConflictError must match both its own sentinel and §2's authz one")
	}
}

func TestManagement_FieldErrorsOfAnUnrecognisedBodyAreEmpty(t *testing.T) {
	for _, body := range []string{
		`null`, `"just a string"`, `{"errors":42}`,
		`{"errors":[{"no_field":"x"}]}`, `{"errors":{"field":42}}`, `not json at all`,
	} {
		if got := parseFieldErrors([]byte(body)); len(got) != 0 {
			t.Fatalf("parseFieldErrors(%s) = %+v, want none", body, got)
		}
	}
}

func TestManagement_ANonJSONErrorBodyReachesTheMessage(t *testing.T) {
	srv, c := managementServer(t)
	srv.mount(http.MethodGet, "/api/v1/users/"+exampleID.String(), 404, "")
	srv.mountFunc(http.MethodGet, "/api/v1/users/"+exampleID.String(),
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(404)
			_, _ = w.Write([]byte("no such user, plainly"))
		})

	_, err := c.Users().Get(context.Background(), exampleID)
	if err == nil || !strings.Contains(err.Error(), "no such user, plainly") {
		t.Fatalf("a plain-text body should reach the message, got %v", err)
	}
}

func TestManagement_AnErrorKeyedBodyReachesTheMessage(t *testing.T) {
	srv, c := managementServer(t)
	srv.mount(http.MethodGet, "/api/v1/users/"+exampleID.String(), 409, `{"error":"still referenced"}`)

	_, err := c.Users().Get(context.Background(), exampleID)
	if err == nil || !strings.Contains(err.Error(), "still referenced") {
		t.Fatalf("an {\"error\": ...} body should reach the message, got %v", err)
	}
}

func TestManagement_AnEmptyErrorBodyStillProducesAUsefulMessage(t *testing.T) {
	srv, c := managementServer(t)
	srv.mount(http.MethodGet, "/api/v1/users/"+exampleID.String(), 404, "")

	_, err := c.Users().Get(context.Background(), exampleID)
	if err == nil || !strings.Contains(err.Error(), "users.get") {
		t.Fatalf("an empty body should still name the operation, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Wire helpers
// ---------------------------------------------------------------------------

func TestManagement_ExposeOptionalPreservesAbsence(t *testing.T) {
	if got := exposeOptional(nil); got != nil {
		t.Fatalf("an unset secret must stay unset, got %v", *got)
	}
	secret := Sensitive("value")
	got := exposeOptional(&secret)
	if got == nil || *got != "value" {
		t.Fatalf("a set secret must reach the wire, got %v", got)
	}
}

// ---------------------------------------------------------------------------
// Filters
// ---------------------------------------------------------------------------

func TestManagement_AuditFiltersReachTheQueryAndUnsetOnesDoNot(t *testing.T) {
	srv, c := managementServer(t)
	route := srv.mount(http.MethodGet, "/api/v1/audit-logs", 200,
		`{"items":[],"total":0,"offset":0,"limit":50}`)

	if _, err := c.Audit().List(context.Background(),
		AuditListFilter{ActorID: exampleID.String(), Action: "user.create"}, Limited(50)); err != nil {
		t.Fatalf("audit.list: %v", err)
	}

	query := route.last(t).query
	if got := query.Get("actor_id"); got != exampleID.String() {
		t.Fatalf("actor_id was %q", got)
	}
	if got := query.Get("action"); got != "user.create" {
		t.Fatalf("action was %q", got)
	}
	for _, unset := range []string{"outcome", "resource_id"} {
		if _, present := query[unset]; present {
			t.Fatalf("%q was unset and must not be sent at all", unset)
		}
	}
}

func TestManagement_SystemAuditFiltersReachTheQuery(t *testing.T) {
	srv, c := managementServer(t)
	route := srv.mount(http.MethodGet, "/api/v1/audit-logs/system", 200,
		`{"items":[],"total":0,"offset":0,"limit":50}`)

	if _, err := c.Audit().ListSystem(context.Background(),
		AuditListSystemFilter{Action: "tenant.create"}, Limited(50)); err != nil {
		t.Fatalf("audit.list_system: %v", err)
	}
	if got := route.last(t).query.Get("action"); got != "tenant.create" {
		t.Fatalf("action was %q", got)
	}
}

// ---------------------------------------------------------------------------
// Replacement-body constructors
// ---------------------------------------------------------------------------

func TestManagement_ReplacementConstructorsCarryEveryRequiredField(t *testing.T) {
	email := NewSetOrgEmailConfig(true, "noreply@example.test", "Acme",
		ProviderConfig{Kind: "smtp"})
	if !email.Enabled || email.FromEmail != "noreply@example.test" || email.FromName != "Acme" {
		t.Fatalf("NewSetOrgEmailConfig did not carry its arguments: %+v", email)
	}

	settings := NewSetOrgSettings(900, true, 365, 24, true, true, 2.0, 300, 825, 5, 3600,
		300, false, 12, 5, 86400, true, true, true, true)
	if settings.AccessTokenLifetimeSecs != 900 || settings.MinLength != 12 {
		t.Fatalf("NewSetOrgSettings did not carry its arguments: %+v", settings)
	}
}

// ---------------------------------------------------------------------------
// The builder's remaining forms and refusals
// ---------------------------------------------------------------------------

func TestManifest_BuilderSupportsAGlobalRole(t *testing.T) {
	m, err := NewManifest().GlobalRole("admin", "Admin", "Tenant-wide").Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(m.Roles) != 1 || !m.Roles[0].IsGlobal {
		t.Fatalf("GlobalRole did not mark the role global: %+v", m.Roles)
	}
}

func TestManifest_BuilderRefusesEveryForwardReference(t *testing.T) {
	for name, build := range map[string]func() (ManagementManifest, error){
		"grant before role": func() (ManagementManifest, error) {
			return NewManifest().Permission("read", "a:read", "A").Grant("nope", "read", "").Build()
		},
		"role before user": func() (ManagementManifest, error) {
			return NewManifest().Role("editor", "Editor", "E").AssignRole("nobody", "editor").Build()
		},
		"group before user": func() (ManagementManifest, error) {
			return NewManifest().Group("staff", "Staff", "S").AddToGroup("nobody", "staff").Build()
		},
	} {
		if _, err := build(); err == nil {
			t.Fatalf("%s: expected a forward-reference refusal", name)
		}
	}
}

// ---------------------------------------------------------------------------
// The reconciler against a tenant that already has things in it
// ---------------------------------------------------------------------------

// mountPopulatedTenant answers the planning reads with a tenant that already
// holds everything the sample manifest declares, so the reconciler takes its
// "already exists" branches — including the sub-reads for scopes, role grants,
// role bindings and group members that an empty tenant never reaches.
func mountPopulatedTenant(srv *managementTestServer) {
	stamps := `"created_at":"2026-08-26T00:00:00Z","updated_at":"2026-08-26T00:00:00Z"`
	srv.mount(http.MethodGet, "/api/v1/resources", 200, fmt.Sprintf(
		`{"items":[{"id":%q,"name":"documents","resource_type":"collection","parent_id":null,`+
			`"metadata":{},"tenant_id":%q,%s}],"total":1,"offset":0,"limit":200}`,
		resourceID, tenantID, stamps))
	srv.mount(http.MethodGet, "/api/v1/resources/"+resourceID.String()+"/scopes", 200, fmt.Sprintf(
		`[{"id":%q,"name":"draft","description":"Unpublished","resource_id":%q,"tenant_id":%q,%s}]`,
		exampleID, resourceID, tenantID, stamps))
	srv.mount(http.MethodGet, "/api/v1/permissions", 200, fmt.Sprintf(
		`{"items":[{"id":%q,"action":"document:read","description":"Read","tenant_id":%q,%s}],`+
			`"total":1,"offset":0,"limit":200}`, permissionID, tenantID, stamps))
	srv.mount(http.MethodGet, "/api/v1/roles", 200, fmt.Sprintf(
		`{"items":[%s],"total":1,"offset":0,"limit":200}`, roleBody(roleID, "Editor", "Edits documents")))
	srv.mount(http.MethodGet, "/api/v1/roles/"+roleID.String()+"/permissions", 200, fmt.Sprintf(
		`[{"effect":"allow","permission":{"id":%q,"action":"document:read","description":"Read",`+
			`"tenant_id":%q,%s},"scope_ids":[],"scopes":[]}]`, permissionID, tenantID, stamps))
	srv.mount(http.MethodGet, "/api/v1/roles/"+roleID.String()+"/users", 200, fmt.Sprintf(
		`[{"resource_id":null,"user":{"id":%q,"username":"alice","email":"alice@example.test",`+
			`"email_verified":true,"failed_login_attempts":0,"is_locked":false,"metadata":{},`+
			`"mfa_enabled":false,"status":"Active","tenant_id":%q,%s}}]`, memberID, tenantID, stamps))
	srv.mount(http.MethodGet, "/api/v1/roles/"+roleID.String()+"/groups", 200, fmt.Sprintf(
		`[{"resource_id":null,"group":{"id":%q,"name":"Staff","description":"Everyone",`+
			`"metadata":{},"tenant_id":%q,%s}}]`, groupID, tenantID, stamps))
	srv.mount(http.MethodGet, "/api/v1/groups", 200, fmt.Sprintf(
		`{"items":[{"id":%q,"name":"Staff","description":"Everyone","metadata":{},"tenant_id":%q,%s}],`+
			`"total":1,"offset":0,"limit":200}`, groupID, tenantID, stamps))
	srv.mount(http.MethodGet, "/api/v1/groups/"+groupID.String()+"/members", 200, fmt.Sprintf(
		`{"items":[{"id":%q,"username":"alice","email":"alice@example.test","email_verified":true,`+
			`"failed_login_attempts":0,"is_locked":false,"metadata":{},"mfa_enabled":false,`+
			`"status":"Active","tenant_id":%q,%s}],"total":1,"offset":0,"limit":200}`,
		memberID, tenantID, stamps))
	srv.mount(http.MethodGet, "/api/v1/users", 200, fmt.Sprintf(
		`{"items":[{"id":%q,"username":"alice","email":"alice@example.test","email_verified":true,`+
			`"failed_login_attempts":0,"is_locked":false,"metadata":{},"mfa_enabled":false,`+
			`"status":"Active","tenant_id":%q,%s}],"total":1,"offset":0,"limit":200}`,
		memberID, tenantID, stamps))
}

func TestManifest_AFullyConvergedTenantPlansNothingAtAll(t *testing.T) {
	srv, c := managementServer(t)
	mountPopulatedTenant(srv)

	// The sample manifest minus the child resource the populated tenant has no
	// counterpart for, so every remaining spec should match something.
	m, err := NewManifest().
		Resource("docs", "documents", "collection").
		Scope("docs", "draft", "draft", "Unpublished").
		Permission("read", "document:read", "Read").
		Role("editor", "Editor", "Edits documents").
		Grant("editor", "read", "").
		Group("staff", "Staff", "Everyone", "editor").
		User("alice", "alice", "alice@example.test", Sensitive("unused")).
		AssignRole("alice", "editor").
		AddToGroup("alice", "staff").
		Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	plan, err := c.Manifest().Plan(context.Background(), m)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if !plan.IsConverged() {
		t.Fatalf("a tenant that already matches should plan nothing; got %+v", plan.Changes())
	}

	// §27.6 rule 6: applying a converged manifest sends nothing and reports
	// every step as unchanged.
	report, err := c.Manifest().Apply(context.Background(), m)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if report.ChangedCount() != 0 {
		t.Fatalf("a converged apply changed %d step(s)", report.ChangedCount())
	}
	for _, s := range report.Steps {
		if s.Outcome.Status != StatusUnchanged {
			t.Fatalf("step %q was %q, want unchanged", s.Action.Summary, s.Outcome.Status)
		}
	}
}

func TestManifest_AChildResourceMatchesOnItsParentNotJustItsName(t *testing.T) {
	// A root resource named "archive" must NOT satisfy a spec for an "archive"
	// beneath "documents" — matching on name alone would adopt the wrong node.
	srv, c := managementServer(t)
	stamps := `"created_at":"2026-08-26T00:00:00Z","updated_at":"2026-08-26T00:00:00Z"`
	srv.mount(http.MethodGet, "/api/v1/resources", 200, fmt.Sprintf(
		`{"items":[{"id":%q,"name":"documents","resource_type":"collection","parent_id":null,`+
			`"metadata":{},"tenant_id":%q,%s},`+
			`{"id":%q,"name":"archive","resource_type":"collection","parent_id":null,`+
			`"metadata":{},"tenant_id":%q,%s}],"total":2,"offset":0,"limit":200}`,
		resourceID, tenantID, stamps, exampleID, tenantID, stamps))
	srv.mount(http.MethodGet, "/api/v1/resources/"+resourceID.String()+"/scopes", 200, `[]`)
	srv.mount(http.MethodGet, "/api/v1/resources/"+exampleID.String()+"/scopes", 200, `[]`)
	for _, path := range []string{"permissions", "roles", "groups", "users"} {
		srv.mount(http.MethodGet, "/api/v1/"+path, 200, emptyPage)
	}

	m, err := NewManifest().
		Resource("docs", "documents", "collection").
		ChildResource("archive", "archive", "collection", "docs").
		Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	plan, err := c.Manifest().Plan(context.Background(), m)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}

	var archive *PlannedAction
	for i := range plan.Actions {
		if plan.Actions[i].Key == "archive" {
			archive = &plan.Actions[i]
		}
	}
	if archive == nil || archive.Change != ChangeCreate {
		t.Fatalf("the child must be created, not matched against the root of the same name; got %+v", archive)
	}
}

func TestManifest_APlanningReadFailureSurfaces(t *testing.T) {
	srv, c := managementServer(t)
	srv.mount(http.MethodGet, "/api/v1/resources", 503, `{"message":"unavailable"}`)

	if _, err := c.Manifest().Plan(context.Background(), sampleManifest(t)); err == nil {
		t.Fatal("a failed planning read must surface, not produce an empty plan")
	}
	if _, err := c.Manifest().Apply(context.Background(), sampleManifest(t)); err == nil {
		t.Fatal("a failed planning read must stop the apply before it writes anything")
	}
}
