package axiam

// The scim_targets management namespace — CONTRACT.md §31.8's six required
// tests, plus the open-union refusal and the read-modify-write conversion.

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

const scimTargetsPath = "/api/v1/scim-targets"

func scimTargetBody(extra map[string]any) map[string]any {
	body := map[string]any{
		"id": uuid.New(), "tenant_id": tenantID, "name": "Downstream",
		"base_url": "https://idp.example/scim/v2", "enabled": true,
		"auth": map[string]any{"type": "bearer"}, "scope": map[string]any{"type": "all_users"},
		"push_groups": false, "user_name_from": "username", "deprovision": "deactivate",
		"created_at": "2026-10-05T00:00:00Z", "updated_at": "2026-10-05T00:00:00Z",
		"state": map[string]any{"last_success_at": nil, "last_failure_at": nil,
			"last_failure_reason": nil, "consecutive_failures": 0,
			"dead_lettered_total": 0, "last_reconciled_at": nil},
	}
	for k, v := range extra {
		body[k] = v
	}
	return body
}

func scimInput(credential string) SCIMTargetInput {
	body := NewSCIMTargetInput(SCIMTargetAuth{Type: "bearer"}, "https://idp.example/scim/v2",
		"Downstream", SCIMTargetScope{Type: "all_users"})
	if credential != "" {
		s := Sensitive(credential)
		body.Credential = &s
	}
	return body
}

// ── 1. Redaction ────────────────────────────────────────────────────────────

func TestSCIMTargets_TheCredentialIsOnTheWireAndInNoRendering(t *testing.T) {
	srv, c := managementServer(t)
	credential := randomSecret(t, "scim-")
	body := scimInput(credential)
	assertNoFragmentIn(t, body, credential, "SCIMTargetInput")

	route := srv.mount(http.MethodPost, scimTargetsPath, 400, `{"error":"validation_error","message":"base_url: refused"}`)
	_, err := c.SCIMTargets().Create(context.Background(), body)
	if err == nil {
		t.Fatal("expected the 400")
	}
	assertNoFragment(t, errorRenderings(err), credential, "create error")
	if route.last(t).jsonBody(t)["credential"] != credential {
		t.Fatal("the credential must be on the wire")
	}
}

// ── 2. No credential on the response ────────────────────────────────────────

func TestSCIMTargets_ACredentialInAResponseIsDropped(t *testing.T) {
	srv, c := managementServer(t)
	leaked := randomSecret(t, "scim-")
	id := uuid.New()
	srv.mount(http.MethodGet, scimTargetsPath+"/"+id.String(), 200,
		mustJSON(t, scimTargetBody(map[string]any{"credential": leaked, "credential_set": true})))
	target, err := c.SCIMTargets().Get(context.Background(), id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	assertNoFragmentIn(t, target, leaked, "SCIMTargetResponse")
	if _, has := reflect.TypeOf(target).FieldByName("Credential"); has {
		t.Fatal("SCIMTargetResponse must declare no credential member")
	}
	if target.Name != "Downstream" {
		t.Fatal("the rest decodes")
	}
}

// ── 3. Replacement and the omitted credential ───────────────────────────────

func TestSCIMTargets_UpdateWithoutACredentialSendsNoKeyAndTheVariantsKeepTheirShape(t *testing.T) {
	srv, c := managementServer(t)
	id := uuid.New()
	route := srv.mount(http.MethodPut, scimTargetsPath+"/"+id.String(), 200, mustJSON(t, scimTargetBody(nil)))
	credential := randomSecret(t, "scim-")
	ctx := context.Background()
	if _, err := c.SCIMTargets().Update(ctx, id, scimInput("")); err != nil {
		t.Fatalf("keep: %v", err)
	}
	if _, err := c.SCIMTargets().Update(ctx, id, scimInput(credential)); err != nil {
		t.Fatalf("replace: %v", err)
	}
	if _, has := route.requests[0].jsonBody(t)["credential"]; has {
		t.Fatal("an absent credential sends no key")
	}
	if route.requests[1].jsonBody(t)["credential"] != credential {
		t.Fatal("a given credential is sent")
	}

	for i, tc := range []struct {
		value any
		want  string
	}{
		{SCIMTargetAuth{Type: "bearer"}, `{"type":"bearer"}`},
		{SCIMTargetAuth{Type: "oauth2_client_credentials", ClientID: ptr("axiam"), Scope: ptr("scim"),
			TokenURL: ptr("https://idp.example/token")},
			`{"type":"oauth2_client_credentials","client_id":"axiam","scope":"scim","token_url":"https://idp.example/token"}`},
		{SCIMTargetScope{Type: "all_users"}, `{"type":"all_users"}`},
		{SCIMTargetScope{Type: "groups", GroupIDs: []uuid.UUID{uuid.Nil}},
			`{"type":"groups","group_ids":["00000000-0000-0000-0000-000000000000"]}`},
	} {
		got, err := json.Marshal(tc.value)
		if err != nil || string(got) != tc.want {
			t.Fatalf("shape %d: got %s (%v)", i, got, err)
		}
	}
}

// ── 4. Open decoding and pagination ─────────────────────────────────────────

func TestSCIMTargets_UnknownValuesDecodeAndThePagerCarriesSearch(t *testing.T) {
	srv, c := managementServer(t)
	odd := scimTargetBody(map[string]any{
		"auth":        map[string]any{"type": "mtls", "certificate_id": uuid.New()},
		"deprovision": "archive", "user_name_from": "employee_number", "state": nil,
	})
	failing := scimTargetBody(map[string]any{"state": map[string]any{
		"last_success_at": nil, "last_failure_at": "2026-10-05T01:00:00Z",
		"last_failure_reason":  "a reason this SDK has never seen",
		"consecutive_failures": 3, "dead_lettered_total": 1, "last_reconciled_at": nil}})
	var queries []string
	srv.mountFunc(http.MethodGet, scimTargetsPath, func(w http.ResponseWriter, r *http.Request) {
		queries = append(queries, r.URL.RawQuery)
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		items := []any{}
		switch offset {
		case 0:
			items = append(items, odd)
		case 1:
			items = append(items, failing)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, mustJSON(t, map[string]any{"items": items, "total": 2, "offset": offset, "limit": 1}))
	})
	ctx := context.Background()
	page, err := c.SCIMTargets().List(ctx, Matching(1, "downstream"))
	if err != nil || page.Total != 2 {
		t.Fatalf("page: %v", err)
	}
	first := page.Items[0]
	if first.Auth.Type != "mtls" || first.Deprovision != DeprovisionPolicy("archive") ||
		first.UserNameFrom != UserNameSource("employee_number") || first.State != nil {
		t.Fatalf("unknown values decode: %+v", first)
	}
	all, err := c.SCIMTargets().ListAll(ctx, Matching(1, "downstream"))
	if err != nil || len(all) != 2 {
		t.Fatalf("walk: %v", err)
	}
	if all[1].State == nil || all[1].State.LastFailureReason == nil ||
		*all[1].State.LastFailureReason != "a reason this SDK has never seen" {
		t.Fatal("an unknown failure reason decodes")
	}
	for _, q := range queries {
		if !strings.Contains(q, "search=downstream") {
			t.Fatalf("every page carries search: %q", q)
		}
	}

	// An unknown variant decodes, and rendering it for a log line never fails
	// (contract 1.59, §34.2 P12.2): it renders its discriminator — and no
	// member it does not declare (P12.1).
	for name, v := range map[string]any{
		"auth": first.Auth, "scope": SCIMTargetScope{Type: "everyone"}, "response": first,
	} {
		rendered, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("an unknown %s arm renders for a log line: %v", name, err)
		}
		if strings.Contains(string(rendered), "certificate_id") {
			t.Fatalf("an unknown %s arm keeps no undeclared member: %s", name, rendered)
		}
	}
	if rendered, _ := json.Marshal(first.Auth); string(rendered) != `{"type":"mtls"}` {
		t.Fatalf("the unknown arm renders its discriminator: %s", rendered)
	}
	if rendered := fmt.Sprintf("%+v", first); !strings.Contains(rendered, "mtls") {
		t.Fatalf("and through fmt: %s", rendered)
	}
	// It is never sent: refused locally, before any request, with the request
	// path's client-side-refusal shape (a *NetworkError, as for every body the
	// SDK refuses to encode).
	id := uuid.New()
	update := srv.mount(http.MethodPut, scimTargetsPath+"/"+id.String(), 200, mustJSON(t, scimTargetBody(nil)))
	_, err = c.SCIMTargets().Update(ctx, id, first.ToInput())
	var netErr *NetworkError
	if !errors.As(err, &netErr) || !strings.Contains(err.Error(), "not one this SDK knows") {
		t.Fatalf("an unknown union is refused locally, got %T", err)
	}
	if update.calls() != 0 {
		t.Fatal("nothing is sent")
	}
	create := srv.mount(http.MethodPost, scimTargetsPath, 201, mustJSON(t, scimTargetBody(nil)))
	input := NewSCIMTargetInput(SCIMTargetAuth{Type: "bearer"}, "https://idp.example/scim/v2",
		"Downstream", SCIMTargetScope{Type: "everyone"})
	input.Credential = ptr(Sensitive(randomSecret(t, "scim-")))
	if _, err := c.SCIMTargets().Create(ctx, input); !errors.As(err, &netErr) ||
		!strings.Contains(err.Error(), "not one this SDK knows") {
		t.Fatalf("an unknown scope is refused locally on create, got %v", err)
	}
	if create.calls() != 0 {
		t.Fatal("nothing is sent on create either")
	}
}

// ── 5. No retry ─────────────────────────────────────────────────────────────

func TestSCIMTargets_NoWriteIsRetriedOn503(t *testing.T) {
	srv, c := managementServer(t)
	id := uuid.New()
	routes := []*mountedRoute{
		srv.mount(http.MethodPost, scimTargetsPath, 503, ""),
		srv.mount(http.MethodPut, scimTargetsPath+"/"+id.String(), 503, ""),
		srv.mount(http.MethodDelete, scimTargetsPath+"/"+id.String(), 503, ""),
		srv.mount(http.MethodPost, scimTargetsPath+"/"+id.String()+"/reconcile", 503, ""),
	}
	ctx := context.Background()
	s := c.SCIMTargets()
	_, e1 := s.Create(ctx, scimInput(randomSecret(t, "scim-")))
	_, e2 := s.Update(ctx, id, scimInput(""))
	e3 := s.Delete(ctx, id)
	_, e4 := s.Reconcile(ctx, id)
	for i, err := range []error{e1, e2, e3, e4} {
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

// ── 6. Errors and reconcile ─────────────────────────────────────────────────

func TestSCIMTargets_StatusesMapAndReconcileIsABodiless202(t *testing.T) {
	srv, c := managementServer(t)
	id, other := uuid.New(), uuid.New()
	srv.mount(http.MethodPost, scimTargetsPath, 400, `{"error":"validation_error","message":"credential: required on create"}`)
	srv.mount(http.MethodPut, scimTargetsPath+"/"+id.String(), 409, `{"error":"conflict","message":"the SCIM target changed since it was read"}`)
	srv.mount(http.MethodPost, scimTargetsPath+"/"+other.String()+"/reconcile", 409, `{"error":"conflict","message":"a run holds the claim"}`)
	srv.mount(http.MethodGet, scimTargetsPath+"/"+id.String(), 404, `{"error":"not_found","message":"no"}`)
	srv.mount(http.MethodDelete, scimTargetsPath+"/"+id.String(), 401, `{"error":"unauthorized","message":"human only"}`)
	reconcile := srv.mount(http.MethodPost, scimTargetsPath+"/"+id.String()+"/reconcile", 202,
		`{"target_id":"`+id.String()+`","status":"started"}`)
	ctx := context.Background()
	s := c.SCIMTargets()

	_, err := s.Create(ctx, scimInput(""))
	var verr *ValidationError
	if !errors.As(err, &verr) || !strings.Contains(verr.Message, "credential") {
		t.Fatalf("400: %T", err)
	}
	if _, err := s.Update(ctx, id, scimInput("")); !errors.Is(err, ErrConflict) {
		t.Fatalf("409 update: %T", err)
	}
	if _, err := s.Reconcile(ctx, other); !errors.Is(err, ErrConflict) {
		t.Fatalf("409 reconcile: %T", err)
	}
	if _, err := s.Get(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("404: %T", err)
	}
	var authErr *AuthError
	if err := s.Delete(ctx, id); !errors.As(err, &authErr) {
		t.Fatalf("401: %T", err)
	}
	accepted, err := s.Reconcile(ctx, id)
	if err != nil {
		t.Fatalf("a 202 is success: %v", err)
	}
	if accepted.TargetID != id || accepted.Status != "started" {
		t.Fatalf("decoded: %+v", accepted)
	}
	if len(reconcile.last(t).body) != 0 {
		t.Fatal("reconcile sends no body")
	}
}

func TestSCIMTargets_AReadConvertsIntoTheReplacementBodyWithoutACredential(t *testing.T) {
	var target SCIMTargetResponse
	if err := json.Unmarshal([]byte(mustJSON(t, scimTargetBody(nil))), &target); err != nil {
		t.Fatal(err)
	}
	body := target.ToInput()
	if body.Credential != nil {
		t.Fatal("absent keeps the stored credential")
	}
	if body.BaseURL != target.BaseURL || body.Enabled == nil || !*body.Enabled ||
		*body.Deprovision != DeprovisionPolicyDeactivate || *body.UserNameFrom != UserNameSourceUsername {
		t.Fatalf("every member carried over: %+v", body)
	}
}
