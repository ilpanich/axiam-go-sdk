package axiam

// Contract 1.34 §5.2.2 and contract 1.35 §5.2.3 — the acting tenant vs the
// principal tenant, and tenant-scoped role assignments.
//
// Two of these rules are the kind an SDK breaks silently rather than loudly,
// which is why they are pinned here rather than left to the generated surface
// test:
//
//   - §5.2.2 rule 2. A registration record for the caller's OWN password is
//     sealed against the tenant the account lives in, not the one the client is
//     pointed at. Get it wrong and the server answers "the OPAQUE session was
//     issued for a different tenant" — but only for an organization-level
//     principal that has switched tenant, so it passes every test written
//     against an ordinary account.
//   - §5.2.3 rule 1. tenant_scope: [] is refused with 400. Go is the one
//     language in this fan-out where the natural encoding already does the
//     right thing — encoding/json's omitempty drops a zero-length slice — so
//     the test here exists to keep it that way, not to prove a fix.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

// fixturePassword mints a throwaway credential per call.
//
// Deliberately not a literal: a password spelled out in source is a finding for
// every secret scanner that looks at this repository, and it stays one wherever
// the file gets copied. Nothing here depends on the value — the login stub
// answers 200 regardless, so what is under test is which tenant the body names,
// never whether a credential matched.
func fixturePassword(t *testing.T) string {
	t.Helper()
	var entropy [8]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		t.Fatalf("mint password: %v", err)
	}
	return "fixture-" + hex.EncodeToString(entropy[:])
}

// loginStub answers /auth/login with the given user object and records every
// register/start body it sees.
type loginStub struct {
	userExtra           map[string]any
	registerStartBodies []map[string]any
}

func (s *loginStub) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/auth/opaque/register/start":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode register/start body: %v", err)
			}
			s.registerStartBodies = append(s.registerStartBodies, body)
			// Refused after capture: the tenant the body names is the whole
			// assertion, and the OPAQUE exchange beyond it is covered by
			// opaque_test.go.
			w.WriteHeader(http.StatusNotFound)
		case "/api/v1/auth/login":
			user := map[string]any{
				"id":       "11111111-1111-1111-1111-111111111111",
				"username": "alice",
				"email":    "alice@example.com",
			}
			for k, v := range s.userExtra {
				user[k] = v
			}
			w.Header().Set("Content-Type", "application/json")
			http.SetCookie(w, &http.Cookie{
				Name:  "axiam_access",
				Value: makeAccessTokenWithOrgID(t, "44444444-4444-4444-4444-444444444444"),
				Path:  "/",
			})
			_ = json.NewEncoder(w).Encode(map[string]any{
				"user":       user,
				"session_id": "22222222-2222-2222-2222-222222222222",
				"expires_in": 900,
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func loggedIn(t *testing.T, stub *loginStub) *Client {
	t.Helper()
	srv := stub.server(t)
	client, err := NewClient(srv.URL, "acme", WithOrgSlug("acme"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.Login(context.Background(), "alice@example.com", fixturePassword(t)); err != nil {
		t.Fatalf("Login: %v", err)
	}
	return client
}

// ---------------------------------------------------------------------------
// §5.2.2 — acting tenant vs principal tenant
// ---------------------------------------------------------------------------

// §5.2.2 rule 1: absent means EQUAL, not unknown. A server older than contract
// 1.34 omits principal_tenant_id and cannot switch the acting tenant either, so
// reading tenant_id there is not a guess — it is the only value it could be.
func TestAbsentPrincipalTenantReadsAsActingTenant(t *testing.T) {
	acting := uuid.New()
	stub := &loginStub{userExtra: map[string]any{"tenant_id": acting.String()}}
	srv := stub.server(t)
	client, err := NewClient(srv.URL, "acme", WithOrgSlug("acme"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	result, err := client.Login(context.Background(), "alice@example.com", fixturePassword(t))
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	if result.PrincipalTenantID == nil || *result.PrincipalTenantID != acting {
		t.Fatalf("PrincipalTenantID = %v, want the acting tenant %v", result.PrincipalTenantID, acting)
	}
}

// The whole point of the field: for an organization-level principal that has
// selected another tenant, the two differ and must not be collapsed.
func TestDivergentPrincipalTenantIsReportedSeparately(t *testing.T) {
	acting, principal, orgID := uuid.New(), uuid.New(), uuid.New()
	stub := &loginStub{userExtra: map[string]any{
		"tenant_id":             acting.String(),
		"principal_tenant_id":   principal.String(),
		"principal_tenant_slug": "organization",
		"org_id":                orgID.String(),
		"organization_level":    true,
	}}
	srv := stub.server(t)
	client, err := NewClient(srv.URL, "acme", WithOrgSlug("acme"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	result, err := client.Login(context.Background(), "alice@example.com", fixturePassword(t))
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	if result.TenantID == nil || *result.TenantID != acting {
		t.Errorf("TenantID = %v, want %v", result.TenantID, acting)
	}
	if result.PrincipalTenantID == nil || *result.PrincipalTenantID != principal {
		t.Errorf("PrincipalTenantID = %v, want %v", result.PrincipalTenantID, principal)
	}
	if result.PrincipalTenantSlug == nil || *result.PrincipalTenantSlug != "organization" {
		t.Errorf("PrincipalTenantSlug = %v, want organization", result.PrincipalTenantSlug)
	}
	// Rule 3: read the organization from the session rather than resolving a
	// slug through the super-admin-only GET /api/v1/organizations.
	if result.OrgID == nil || *result.OrgID != orgID {
		t.Errorf("OrgID = %v, want %v", result.OrgID, orgID)
	}
}

// A narrowed principal still reports OrganizationLevel: true, which is exactly
// why gating on that flag alone offers tenants the server refuses.
func TestReachableTenantIDsNarrowsAnOrganizationLevelPrincipal(t *testing.T) {
	reachable := uuid.New()
	stub := &loginStub{userExtra: map[string]any{
		"tenant_id":            uuid.New().String(),
		"organization_level":   true,
		"reachable_tenant_ids": []string{reachable.String()},
	}}
	srv := stub.server(t)
	client, err := NewClient(srv.URL, "acme", WithOrgSlug("acme"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	result, err := client.Login(context.Background(), "alice@example.com", fixturePassword(t))
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	if !result.OrganizationLevel {
		t.Error("OrganizationLevel = false, want true — a narrowed account is still organization-level")
	}
	if len(result.ReachableTenantIDs) != 1 || result.ReachableTenantIDs[0] != reachable {
		t.Fatalf("ReachableTenantIDs = %v, want [%v]", result.ReachableTenantIDs, reachable)
	}
}

// Nil, never an empty slice: an empty one would read as "reaches nothing",
// the opposite of what an omitted field means here.
func TestAbsentReachableTenantIDsIsUnrestricted(t *testing.T) {
	stub := &loginStub{userExtra: map[string]any{"tenant_id": uuid.New().String()}}
	srv := stub.server(t)
	client, err := NewClient(srv.URL, "acme", WithOrgSlug("acme"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	result, err := client.Login(context.Background(), "alice@example.com", fixturePassword(t))
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	if result.ReachableTenantIDs != nil {
		t.Fatalf("ReachableTenantIDs = %v, want nil (unrestricted)", result.ReachableTenantIDs)
	}
}

// ---------------------------------------------------------------------------
// §5.2.2 rule 2 — which tenant a registration record is sealed against
// ---------------------------------------------------------------------------

// Creating ANOTHER account seals against the tenant it is created in — the one
// this client was pointed at.
func TestOpaqueEnrollmentSealsAgainstTheActingTenant(t *testing.T) {
	stub := &loginStub{userExtra: map[string]any{
		"tenant_id":           uuid.New().String(),
		"principal_tenant_id": uuid.New().String(),
	}}
	client := loggedIn(t, stub)

	// The 404 is expected: the body is captured before it is refused.
	_, _ = client.OpaqueEnrollment(context.Background(), fixturePassword(t))

	if len(stub.registerStartBodies) != 1 {
		t.Fatalf("register/start bodies = %d, want 1", len(stub.registerStartBodies))
	}
	body := stub.registerStartBodies[0]
	if body["tenant_slug"] != "acme" {
		t.Errorf("tenant_slug = %v, want acme", body["tenant_slug"])
	}
	if _, present := body["tenant_id"]; present {
		t.Error("tenant_id present — nothing should override the acting tenant here")
	}
}

// The caller's OWN password change seals against the tenant the account lives
// in. A record sealed against the acting tenant is refused with "the OPAQUE
// session was issued for a different tenant".
func TestOpaqueEnrollmentForSelfSealsAgainstThePrincipalTenant(t *testing.T) {
	principal := uuid.New()
	stub := &loginStub{userExtra: map[string]any{
		"tenant_id":           uuid.New().String(),
		"principal_tenant_id": principal.String(),
		"organization_level":  true,
	}}
	client := loggedIn(t, stub)

	_, _ = client.OpaqueEnrollmentForSelf(context.Background(), fixturePassword(t))

	if len(stub.registerStartBodies) != 1 {
		t.Fatalf("register/start bodies = %d, want 1", len(stub.registerStartBodies))
	}
	body := stub.registerStartBodies[0]
	if body["tenant_id"] != principal.String() {
		t.Errorf("tenant_id = %v, want the principal tenant %v", body["tenant_id"], principal)
	}
	// The acting tenant's slug must not travel alongside the principal
	// tenant's id, or it out-votes it server-side.
	if _, present := body["tenant_slug"]; present {
		t.Error("tenant_slug present alongside the principal tenant's id")
	}
}

// Before a login there is no principal tenant to seal against, and guessing the
// acting one is exactly the bug this method exists to prevent.
func TestOpaqueEnrollmentForSelfRefusesBeforeALogin(t *testing.T) {
	stub := &loginStub{}
	srv := stub.server(t)
	client, err := NewClient(srv.URL, "acme", WithOrgSlug("acme"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	if _, err := client.OpaqueEnrollmentForSelf(context.Background(), fixturePassword(t)); err == nil {
		t.Fatal("want an error before any login")
	} else if _, ok := err.(*NetworkError); !ok {
		t.Fatalf("error = %T, want *NetworkError", err)
	}
}

// ---------------------------------------------------------------------------
// §5.2.3 rules 1 and 2 — tenant_scope on an assignment
// ---------------------------------------------------------------------------

// Rule 1. Go's omitempty already drops a zero-length slice, so this pins the
// behaviour rather than a fix: switching TenantScope to a pointer, or dropping
// omitempty, would put the shape the server refuses with 400 back on the wire.
func TestAnEmptyTenantScopeNeverReachesTheWire(t *testing.T) {
	for name, body := range map[string]any{
		"nil":   AssignRoleToUserRequest{UserID: uuid.New()},
		"empty": AssignRoleToUserRequest{UserID: uuid.New(), TenantScope: []uuid.UUID{}},
	} {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("%s: marshal: %v", name, err)
		}
		var decoded map[string]any
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			t.Fatalf("%s: unmarshal: %v", name, err)
		}
		if _, present := decoded["tenant_scope"]; present {
			t.Errorf("%s: tenant_scope present; the server refuses an empty one with 400", name)
		}
	}
}

// Rule 2. Dropping a scope the caller DID name would turn a refusal they need
// to see into a success that silently applied no restriction.
func TestANamedTenantScopeIsSent(t *testing.T) {
	scoped := uuid.New()

	for name, body := range map[string]any{
		"users":            AssignRoleToUserRequest{UserID: uuid.New(), TenantScope: []uuid.UUID{scoped}},
		"groups":           AssignRoleToGroupRequest{GroupID: uuid.New(), TenantScope: []uuid.UUID{scoped}},
		"service accounts": AssignRoleToServiceAccountRequest{ServiceAccountID: uuid.New(), TenantScope: []uuid.UUID{scoped}},
	} {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("%s: marshal: %v", name, err)
		}
		var decoded map[string]any
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			t.Fatalf("%s: unmarshal: %v", name, err)
		}
		scope, present := decoded["tenant_scope"].([]any)
		if !present || len(scope) != 1 || scope[0] != scoped.String() {
			t.Errorf("%s: tenant_scope = %v, want [%v]", name, decoded["tenant_scope"], scoped)
		}
	}
}
