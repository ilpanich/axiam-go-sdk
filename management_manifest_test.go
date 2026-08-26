package axiam

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// CONTRACT §27.6 — the declarative layer's reconciler.
//
// The rules under test, in order: Plan writes nothing and is stable across
// runs; validation precedes every request; ordering is derived; drift is an
// update and omission is never a deletion; Apply converges, and stops at the
// first failure while reporting what it did not attempt.

const emptyPage = `{"items":[],"total":0,"offset":0,"limit":200}`

var (
	roleID       = uuid.MustParse("66666666-6666-4666-8666-666666666666")
	resourceID   = uuid.MustParse("77777777-7777-4777-8777-777777777777")
	permissionID = uuid.MustParse("88888888-8888-4888-8888-888888888888")
	groupID      = uuid.MustParse("99999999-9999-4999-8999-999999999999")
	memberID     = uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
)

func mountEmptyTenant(srv *managementTestServer) {
	for _, path := range []string{"resources", "permissions", "roles", "groups", "users"} {
		srv.mount(http.MethodGet, "/api/v1/"+path, 200, emptyPage)
	}
}

func sampleManifest(t *testing.T) ManagementManifest {
	t.Helper()
	m, err := NewManifest().
		Resource("docs", "documents", "collection").
		Scope("docs", "draft", "draft", "Unpublished").
		ChildResource("archive", "archive", "collection", "docs").
		Permission("read", "document:read", "Read").
		Role("editor", "Editor", "Edits documents").
		Grant("editor", "read", "", "draft").
		Group("staff", "Staff", "Everyone", "editor").
		User("alice", "alice", "alice@example.test", Sensitive("correct-horse-battery")).
		AssignRole("alice", "editor").
		AddToGroup("alice", "staff").
		Build()
	if err != nil {
		t.Fatalf("build manifest: %v", err)
	}
	return m
}

// ---------------------------------------------------------------------------
// Rule 1 — plan writes nothing
// ---------------------------------------------------------------------------

func TestManifest_PlanIssuesNoWrite(t *testing.T) {
	srv, c := managementServer(t)
	mountEmptyTenant(srv)

	if _, err := c.Manifest().Plan(context.Background(), sampleManifest(t)); err != nil {
		t.Fatalf("plan: %v", err)
	}
	for key, route := range srv.routes {
		if strings.HasPrefix(key, http.MethodGet) {
			continue
		}
		if route.calls() > 0 {
			t.Fatalf("plan issued a write: %s", key)
		}
	}
}

func TestManifest_PlanIsStableAcrossRuns(t *testing.T) {
	srv, c := managementServer(t)
	mountEmptyTenant(srv)
	m := sampleManifest(t)

	first, err := c.Manifest().Plan(context.Background(), m)
	if err != nil {
		t.Fatalf("first plan: %v", err)
	}
	second, err := c.Manifest().Plan(context.Background(), m)
	if err != nil {
		t.Fatalf("second plan: %v", err)
	}
	if len(first.Actions) != len(second.Actions) {
		t.Fatalf("plans differ in length: %d vs %d", len(first.Actions), len(second.Actions))
	}
	for i := range first.Actions {
		if first.Actions[i] != second.Actions[i] {
			t.Fatalf("step %d differs between runs: %+v vs %+v", i, first.Actions[i], second.Actions[i])
		}
	}
}

// ---------------------------------------------------------------------------
// Rule 5 — derived ordering
// ---------------------------------------------------------------------------

func indexOfTarget(plan ManagementPlan, target Target) int {
	for i, a := range plan.Actions {
		if a.Target == target {
			return i
		}
	}
	return -1
}

func TestManifest_OrderingIsDerived(t *testing.T) {
	srv, c := managementServer(t)
	mountEmptyTenant(srv)

	plan, err := c.Manifest().Plan(context.Background(), sampleManifest(t))
	if err != nil {
		t.Fatalf("plan: %v", err)
	}

	// A parent resource precedes its child.
	var resourceKeys []string
	for _, a := range plan.Actions {
		if a.Target == TargetResource {
			resourceKeys = append(resourceKeys, a.Key)
		}
	}
	parent, child := -1, -1
	for i, k := range resourceKeys {
		if k == "docs" {
			parent = i
		}
		if k == "archive" {
			child = i
		}
	}
	if parent < 0 || child < 0 || parent > child {
		t.Fatalf("parent must precede child, got %v", resourceKeys)
	}

	// Producers precede consumers.
	for _, pair := range []struct{ before, after Target }{
		{TargetPermission, TargetRoleGrant},
		{TargetRole, TargetRoleGrant},
		{TargetGroup, TargetGroupRole},
		{TargetUser, TargetUserRole},
		{TargetUser, TargetGroupMember},
	} {
		b, a := indexOfTarget(plan, pair.before), indexOfTarget(plan, pair.after)
		if b < 0 || a < 0 || b > a {
			t.Fatalf("%s (%d) must precede %s (%d)", pair.before, b, pair.after, a)
		}
	}
}

// ---------------------------------------------------------------------------
// Rule 2 — validation precedes every request
// ---------------------------------------------------------------------------

func TestManifest_ADanglingReferenceIsRefusedBeforeCalling(t *testing.T) {
	srv, c := managementServer(t)
	mountEmptyTenant(srv)
	before := 0
	for _, r := range srv.routes {
		before += r.calls()
	}

	m := ManagementManifest{Roles: []RoleSpec{{
		Key: "editor", Name: "Editor", Description: "Edits",
		Grants: []GrantSpec{{Permission: "nope"}},
	}}}
	_, err := c.Manifest().Plan(context.Background(), m)
	if err == nil || !strings.Contains(err.Error(), "which no permission declares") {
		t.Fatalf("want a dangling-reference refusal, got %v", err)
	}
	after := 0
	for _, r := range srv.routes {
		after += r.calls()
	}
	if after != before {
		t.Fatal("validation must precede every request")
	}
}

func TestManifest_AResourceCycleIsRefusedRatherThanLooped(t *testing.T) {
	srv, c := managementServer(t)
	mountEmptyTenant(srv)

	m := ManagementManifest{Resources: []ResourceSpec{
		{Key: "a", Name: "a", ResourceType: "c", Parent: "b"},
		{Key: "b", Name: "b", ResourceType: "c", Parent: "a"},
	}}
	_, err := c.Manifest().Plan(context.Background(), m)
	if err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("want a cycle refusal, got %v", err)
	}
}

func TestManifest_EveryProblemIsReportedNotJustTheFirst(t *testing.T) {
	srv, c := managementServer(t)
	mountEmptyTenant(srv)

	m := ManagementManifest{
		Roles: []RoleSpec{{Key: "r", Name: "R", Description: "R",
			Grants: []GrantSpec{{Permission: "missing", Scopes: []string{"nope"}}}}},
		Groups: []GroupSpec{{Key: "g", Name: "G", Description: "G", Roles: []string{"absent"}}},
	}
	_, err := c.Manifest().Plan(context.Background(), m)
	if err == nil || !strings.Contains(err.Error(), "3 problem(s)") {
		t.Fatalf("want all three problems reported, got %v", err)
	}
}

func TestManifest_ADuplicateKeyIsRefused(t *testing.T) {
	srv, c := managementServer(t)
	mountEmptyTenant(srv)

	m := ManagementManifest{Permissions: []PermissionSpec{
		{Key: "read", Action: "a:read", Description: "A"},
		{Key: "read", Action: "b:read", Description: "B"},
	}}
	_, err := c.Manifest().Plan(context.Background(), m)
	if err == nil || !strings.Contains(err.Error(), "declared more than once") {
		t.Fatalf("want a duplicate-key refusal, got %v", err)
	}
}

func TestManifest_AUserThatMustBeCreatedNeedsAPasswordBeforeAnyRequest(t *testing.T) {
	srv, c := managementServer(t)
	mountEmptyTenant(srv)

	m := ManagementManifest{Users: []UserSpec{{Key: "bob", Username: "bob", Email: "bob@example.test"}}}
	_, err := c.Manifest().Plan(context.Background(), m)
	if err == nil || !strings.Contains(err.Error(), "no InitialPassword") {
		t.Fatalf("want a missing-password refusal before any request, got %v", err)
	}
}

func TestManifest_TheBuilderRefusesAForwardReference(t *testing.T) {
	// The builder can catch an ordering mistake the struct form cannot: naming
	// a resource before declaring it.
	_, err := NewManifest().Scope("docs", "draft", "draft", "Unpublished").Build()
	if err == nil || !strings.Contains(err.Error(), "which no Resource call has declared yet") {
		t.Fatalf("want a forward-reference refusal, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Rules 3 and 4 — drift and pruning
// ---------------------------------------------------------------------------

func roleBody(id uuid.UUID, name, description string) string {
	return fmt.Sprintf(`{"id":%q,"name":%q,"description":%q,"is_global":false,"tenant_id":%q,`+
		`"created_at":"2026-08-26T00:00:00Z","updated_at":"2026-08-26T00:00:00Z"}`,
		id, name, description, tenantID)
}

func mountTenantWithOneRole(srv *managementTestServer, description string) {
	for _, path := range []string{"resources", "permissions", "groups", "users"} {
		srv.mount(http.MethodGet, "/api/v1/"+path, 200, emptyPage)
	}
	srv.mount(http.MethodGet, "/api/v1/roles", 200, fmt.Sprintf(
		`{"items":[%s],"total":1,"offset":0,"limit":200}`, roleBody(roleID, "Editor", description)))
	for _, sub := range []string{"permissions", "users", "groups"} {
		srv.mount(http.MethodGet, "/api/v1/roles/"+roleID.String()+"/"+sub, 200, `[]`)
	}
}

var oneRole = ManagementManifest{
	Roles: []RoleSpec{{Key: "editor", Name: "Editor", Description: "Edits documents"}},
}

func TestManifest_AConvergedTenantPlansNothing(t *testing.T) {
	srv, c := managementServer(t)
	mountTenantWithOneRole(srv, "Edits documents")

	plan, err := c.Manifest().Plan(context.Background(), oneRole)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if !plan.IsConverged() {
		t.Fatalf("expected convergence, got %+v", plan.Changes())
	}
	if len(plan.Actions) == 0 {
		t.Fatal("a converged plan still reports its no-op steps")
	}
}

func TestManifest_ADriftedFieldIsAnUpdate(t *testing.T) {
	srv, c := managementServer(t)
	mountTenantWithOneRole(srv, "something else")

	plan, err := c.Manifest().Plan(context.Background(), oneRole)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	changes := plan.Changes()
	if len(changes) != 1 || changes[0].Change != ChangeUpdate || changes[0].Target != TargetRole {
		t.Fatalf("want one role update, got %+v", changes)
	}
}

func TestManifest_ARoleTheManifestOmitsIsNeverDeleted(t *testing.T) {
	srv, c := managementServer(t)
	mountTenantWithOneRole(srv, "Edits documents")

	plan, err := c.Manifest().Plan(context.Background(), ManagementManifest{})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if len(plan.Actions) != 0 {
		t.Fatalf("a manifest describes what should exist, not what should not; got %+v", plan.Actions)
	}
}

// ---------------------------------------------------------------------------
// Rules 6 and 7 — apply
// ---------------------------------------------------------------------------

func mountCreates(srv *managementTestServer) {
	stamps := `"created_at":"2026-08-26T00:00:00Z","updated_at":"2026-08-26T00:00:00Z"`
	srv.mount(http.MethodPost, "/api/v1/resources", 201, fmt.Sprintf(
		`{"id":%q,"name":"documents","resource_type":"collection","parent_id":null,`+
			`"metadata":{},"tenant_id":%q,%s}`, resourceID, tenantID, stamps))
	srv.mount(http.MethodPost, "/api/v1/resources/"+resourceID.String()+"/scopes", 201, fmt.Sprintf(
		`{"id":%q,"name":"draft","description":"Unpublished","resource_id":%q,"tenant_id":%q,%s}`,
		exampleID, resourceID, tenantID, stamps))
	srv.mount(http.MethodPost, "/api/v1/permissions", 201, fmt.Sprintf(
		`{"id":%q,"action":"document:read","description":"Read","tenant_id":%q,%s}`,
		permissionID, tenantID, stamps))
	srv.mount(http.MethodPost, "/api/v1/roles", 201, roleBody(roleID, "Editor", "Edits documents"))
	srv.mount(http.MethodPost, "/api/v1/groups", 201, fmt.Sprintf(
		`{"id":%q,"name":"Staff","description":"Everyone","metadata":{},"tenant_id":%q,%s}`,
		groupID, tenantID, stamps))
	srv.mount(http.MethodPost, "/api/v1/users", 201, fmt.Sprintf(
		`{"id":%q,"username":"alice","email":"alice@example.test","email_verified":false,`+
			`"failed_login_attempts":0,"is_locked":false,"metadata":{},"mfa_enabled":false,`+
			`"status":"Active","tenant_id":%q,%s}`, memberID, tenantID, stamps))
	srv.mount(http.MethodPost, "/api/v1/roles/"+roleID.String()+"/permissions", 204, "")
	srv.mount(http.MethodPost, "/api/v1/roles/"+roleID.String()+"/users", 204, "")
	srv.mount(http.MethodPost, "/api/v1/roles/"+roleID.String()+"/groups", 204, "")
	srv.mount(http.MethodPost, "/api/v1/groups/"+groupID.String()+"/members", 204, "")
}

func TestManifest_ApplyCreatesEverythingAndReportsEveryStep(t *testing.T) {
	srv, c := managementServer(t)
	mountEmptyTenant(srv)
	mountCreates(srv)

	report, err := c.Manifest().Apply(context.Background(), sampleManifest(t))
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !report.IsComplete() {
		failure, _ := report.Failure()
		t.Fatalf("apply stopped at %q: %s", failure.Action.Summary, failure.Message)
	}
	for _, s := range report.Steps {
		if s.Outcome.Status != StatusCreated {
			t.Fatalf("step %q was %q, want created", s.Action.Summary, s.Outcome.Status)
		}
	}
	if report.ChangedCount() != len(report.Steps) {
		t.Fatalf("changed %d of %d steps", report.ChangedCount(), len(report.Steps))
	}
}

func TestManifest_ApplyStopsAtTheFirstFailureAndSaysWhatWasNotAttempted(t *testing.T) {
	srv, c := managementServer(t)
	mountEmptyTenant(srv)
	mountCreates(srv)
	srv.mount(http.MethodPost, "/api/v1/permissions", 409, `{"message":"already exists"}`)

	report, err := c.Manifest().Apply(context.Background(), sampleManifest(t))
	if err != nil {
		t.Fatalf("apply returned a hard error rather than a report: %v", err)
	}
	if report.IsComplete() {
		t.Fatal("expected the apply to stop at the permission")
	}
	failure, ok := report.Failure()
	if !ok || failure.Action.Target != TargetPermission {
		t.Fatalf("failure was %+v", failure)
	}

	// Everything after the failure is reported as never attempted — §27.6 rule 7
	// is that there is no transaction, so the report says exactly what ran.
	seenFailure := false
	for _, s := range report.Steps {
		if s.Outcome.Status == StatusFailed {
			seenFailure = true
			continue
		}
		if seenFailure && s.Outcome.Status != StatusNotAttempted {
			t.Fatalf("step %q after the failure was %q, want not-attempted",
				s.Action.Summary, s.Outcome.Status)
		}
	}
}

func TestManifest_ApplyingAnEmptyManifestIsClean(t *testing.T) {
	srv, c := managementServer(t)
	mountEmptyTenant(srv)

	report, err := c.Manifest().Apply(context.Background(), ManagementManifest{})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(report.Steps) != 0 || !report.IsComplete() || report.ChangedCount() != 0 {
		t.Fatalf("nothing declared should mean nothing planned; got %+v", report)
	}
}

func TestManifest_APasswordIsNeverSentForAUserThatAlreadyExists(t *testing.T) {
	srv, c := managementServer(t)
	for _, path := range []string{"resources", "permissions", "roles", "groups"} {
		srv.mount(http.MethodGet, "/api/v1/"+path, 200, emptyPage)
	}
	srv.mount(http.MethodGet, "/api/v1/users", 200, fmt.Sprintf(
		`{"items":[{"id":%q,"username":"alice","email":"alice@example.test","email_verified":true,`+
			`"failed_login_attempts":0,"is_locked":false,"metadata":{},"mfa_enabled":false,`+
			`"status":"Active","tenant_id":%q,"created_at":"2026-08-26T00:00:00Z",`+
			`"updated_at":"2026-08-26T00:00:00Z"}],"total":1,"offset":0,"limit":200}`,
		memberID, tenantID))
	created := srv.mount(http.MethodPost, "/api/v1/users", 201, "")

	m := ManagementManifest{Users: []UserSpec{{
		Key: "alice", Username: "alice", Email: "alice@example.test",
		InitialPassword: Sensitive("would-be-a-reset"),
	}}}
	report, err := c.Manifest().Apply(context.Background(), m)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if created.calls() != 0 {
		t.Fatal("a config file mentioning a password is not a request to reset one")
	}
	if len(report.Steps) != 1 || report.Steps[0].Outcome.Status != StatusUnchanged {
		t.Fatalf("want one unchanged step, got %+v", report.Steps)
	}
}

func TestManifest_ADenyGrantTravelsAsDeny(t *testing.T) {
	// AXIAM's RBAC engine is deny-override, so a manifest that says deny must
	// put "deny" on the wire rather than quietly dropping the effect.
	srv, c := managementServer(t)
	mountEmptyTenant(srv)
	mountCreates(srv)
	grant := srv.mount(http.MethodPost, "/api/v1/roles/"+roleID.String()+"/permissions", 204, "")

	m, err := NewManifest().
		Permission("purge", "document:purge", "Permanently delete").
		Role("editor", "Editor", "Edits documents").
		Grant("editor", "purge", "deny").
		Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if _, err := c.Manifest().Apply(context.Background(), m); err != nil {
		t.Fatalf("apply: %v", err)
	}

	body := grant.last(t).jsonBody(t)
	if body["effect"] != "deny" {
		t.Fatalf("effect reached the wire as %v, want \"deny\"", body["effect"])
	}
}

func TestManifest_ASparseUpdateFromTheReconcilerCarriesOnlyTheDriftedField(t *testing.T) {
	srv, c := managementServer(t)
	mountTenantWithOneRole(srv, "something else")
	update := srv.mount(http.MethodPut, "/api/v1/roles/"+roleID.String(), 200,
		roleBody(roleID, "Editor", "Edits documents"))

	if _, err := c.Manifest().Apply(context.Background(), oneRole); err != nil {
		t.Fatalf("apply: %v", err)
	}
	keys := update.last(t).keys(t)
	got, err := json.Marshal(keys)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(got) != `["description","is_global"]` {
		t.Fatalf("reconciler update body carried %s", got)
	}
}
