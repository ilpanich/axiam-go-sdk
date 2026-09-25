package axiam

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/google/uuid"
)

// CONTRACT §27.13 (contract 1.51) — pinning the generated DTOs the re-vendor
// commit (85ca08a) touched, which nothing else in this branch exercised
// against the wire: SubjectAltName's externally-tagged oneOf shape and the
// open CertificateType enum on the read side, and the `inherit`
// absent-means-true default on the write and read sides. Mirrors the Rust
// reference's tests/contract_151_models_test.rs.

// ---------------------------------------------------------------------------
// 1. CertificateType is an OPEN enum — an unknown value, and "Server", both
//    decode without failing the listing (§27.13 S-7 rule 2 / §27.11 rule 1).
// ---------------------------------------------------------------------------

func TestContract151Models_CertificatesListDecodesUnknownAndServerCertTypeVerbatim(t *testing.T) {
	srv, c := managementServer(t)

	item := func(certType, subject string) string {
		return `{"cert_type":"` + certType + `","created_at":"2026-01-01T00:00:00Z",` +
			`"fingerprint":"aa:bb","id":"` + uuid.New().String() + `",` +
			`"issuer_ca_id":"` + exampleID.String() + `","key_algorithm":"Ed25519",` +
			`"metadata":{},"not_after":"2027-01-01T00:00:00Z","not_before":"2026-01-01T00:00:00Z",` +
			`"public_cert_pem":"-----BEGIN CERTIFICATE-----","status":"Active",` +
			`"subject":"` + subject + `","tenant_id":"` + tenantID.String() + `"}`
	}
	body := `{"items":[` + item("gadget", "unknown-type-cert") + `,` + item("Server", "server-cert") +
		`],"total":2,"offset":0,"limit":200}`
	srv.mount(http.MethodGet, "/api/v1/certificates", http.StatusOK, body)

	page, err := c.Certificates().List(context.Background(), PageRequest{})
	if err != nil {
		t.Fatalf("List must not fail on an unrecognised cert_type, got %v", err)
	}
	if len(page.Items) != 2 {
		t.Fatalf("got %d items, want 2", len(page.Items))
	}
	if page.Items[0].CertType != CertificateType("gadget") {
		t.Fatalf("unknown cert_type must round-trip VERBATIM as the raw string, got %q", page.Items[0].CertType)
	}
	if page.Items[1].CertType != CertificateTypeServer {
		t.Fatalf("CertType = %q, want %q", page.Items[1].CertType, CertificateTypeServer)
	}
}

// ---------------------------------------------------------------------------
// 2 & 3. SubjectAltName's wire shape — externally tagged, one key per
//    element, never {} and never both keys in one element (§27.13 S-7 rule 1).
// ---------------------------------------------------------------------------

func TestContract151Models_GenerateSendsSubjectAltNamesExternallyTagged(t *testing.T) {
	srv, c := managementServer(t)
	route := srv.mount(http.MethodPost, "/api/v1/certificates", http.StatusCreated,
		`{"cert_type":"Server","created_at":"2026-01-01T00:00:00Z","fingerprint":"aa",`+
			`"id":"`+exampleID.String()+`","issuer_ca_id":"`+exampleID.String()+`",`+
			`"key_algorithm":"Ed25519","metadata":{},"not_after":"2027-01-01T00:00:00Z",`+
			`"not_before":"2026-01-01T00:00:00Z","private_key_pem":"[SENSITIVE]",`+
			`"public_cert_pem":"-----BEGIN CERTIFICATE-----","status":"Active",`+
			`"subject":"api.example.internal","tenant_id":"`+tenantID.String()+`"}`)

	_, err := c.Certificates().Generate(context.Background(), CreateCertificateRequest{
		CertType: CertificateTypeServer, IssuerCAID: exampleID, KeyAlgorithm: KeyAlgorithmEd25519,
		Subject: "api.example.internal", ValidityDays: 365,
		SubjectAltNames: []SubjectAltName{
			NewSubjectAltNameDNS("api.example.internal"),
			NewSubjectAltNameIP("10.0.0.5"),
		},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	rec := route.last(t)
	body := rec.jsonBody(t)
	raw, ok := body["subject_alt_names"]
	if !ok {
		t.Fatal("expected a subject_alt_names key on the wire")
	}
	names, ok := raw.([]any)
	if !ok || len(names) != 2 {
		t.Fatalf("subject_alt_names = %#v, want a 2-element array", raw)
	}

	dns, ok := names[0].(map[string]any)
	if !ok {
		t.Fatalf("element 0 is not an object: %#v", names[0])
	}
	if keys := sortedKeys(dns); len(keys) != 1 || keys[0] != "dns" {
		t.Fatalf("element 0 keys = %v, want exactly [\"dns\"] — never {} and never both dns+ip in one element", keys)
	}
	if dns["dns"] != "api.example.internal" {
		t.Fatalf("dns = %v, want api.example.internal", dns["dns"])
	}

	ip, ok := names[1].(map[string]any)
	if !ok {
		t.Fatalf("element 1 is not an object: %#v", names[1])
	}
	if keys := sortedKeys(ip); len(keys) != 1 || keys[0] != "ip" {
		t.Fatalf("element 1 keys = %v, want exactly [\"ip\"]", keys)
	}
	if ip["ip"] != "10.0.0.5" {
		t.Fatalf("ip = %v, want 10.0.0.5", ip["ip"])
	}
}

func TestContract151Models_LeafRequestWithoutNamesOmitsSubjectAltNamesKey(t *testing.T) {
	srv, c := managementServer(t)
	route := srv.mount(http.MethodPost, "/api/v1/certificates", http.StatusCreated,
		`{"cert_type":"User","created_at":"2026-01-01T00:00:00Z","fingerprint":"aa",`+
			`"id":"`+exampleID.String()+`","issuer_ca_id":"`+exampleID.String()+`",`+
			`"key_algorithm":"Ed25519","metadata":{},"not_after":"2027-01-01T00:00:00Z",`+
			`"not_before":"2026-01-01T00:00:00Z","private_key_pem":"[SENSITIVE]",`+
			`"public_cert_pem":"-----BEGIN CERTIFICATE-----","status":"Active",`+
			`"subject":"alice","tenant_id":"`+tenantID.String()+`"}`)

	_, err := c.Certificates().Generate(context.Background(), CreateCertificateRequest{
		CertType: CertificateTypeUser, IssuerCAID: exampleID, KeyAlgorithm: KeyAlgorithmEd25519,
		Subject: "alice", ValidityDays: 365,
		// SubjectAltNames deliberately left nil.
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	keys := route.last(t).keys(t)
	for _, k := range keys {
		if k == "subject_alt_names" {
			t.Fatalf("a leaf request with no names must OMIT subject_alt_names entirely, got keys %v", keys)
		}
	}
}

// ---------------------------------------------------------------------------
// CONTRACT.md 1.52 N3 (C-12) — a SubjectAltName naming NEITHER or BOTH
// branches must be refused client-side, before any request. Go has no sum
// type: SubjectAltName{} (neither) and SubjectAltName{DNS: &d, IP: &i}
// (both) both compile, and before this fix both serialized silently — {}
// or {"dns":...,"ip":...} — rather than being refused. The
// New<Type><Tag> constructors were already correct; this closes the gap for
// a value assembled by struct literal instead, which nothing stopped.
// ---------------------------------------------------------------------------

func TestContract151Models_GenerateRefusesSubjectAltNameNamingNeitherBranch(t *testing.T) {
	srv, c := managementServer(t)
	route := srv.mount(http.MethodPost, "/api/v1/certificates", http.StatusCreated, `{}`)

	dns := "api.example.internal"
	_, err := c.Certificates().Generate(context.Background(), CreateCertificateRequest{
		CertType: CertificateTypeServer, IssuerCAID: exampleID, KeyAlgorithm: KeyAlgorithmEd25519,
		Subject: "api.example.internal", ValidityDays: 365,
		SubjectAltNames: []SubjectAltName{
			NewSubjectAltNameDNS(dns),
			{}, // neither dns nor ip — must be refused, not sent as {}
		},
	})
	if err == nil {
		t.Fatal("Generate must refuse a SubjectAltName naming neither branch, client-side")
	}
	var netErr *NetworkError
	if !errors.As(err, &netErr) {
		t.Fatalf("got %T, want *NetworkError (§27.4 rule 2's client-side-refusal shape): %v", err, err)
	}
	if route.calls() != 0 {
		t.Fatalf("must refuse BEFORE any request; the server received %d call(s)", route.calls())
	}
}

func TestContract151Models_GenerateRefusesSubjectAltNameNamingBothBranches(t *testing.T) {
	srv, c := managementServer(t)
	route := srv.mount(http.MethodPost, "/api/v1/certificates", http.StatusCreated, `{}`)

	dns, ip := "api.example.internal", "10.0.0.5"
	_, err := c.Certificates().Generate(context.Background(), CreateCertificateRequest{
		CertType: CertificateTypeServer, IssuerCAID: exampleID, KeyAlgorithm: KeyAlgorithmEd25519,
		Subject: "api.example.internal", ValidityDays: 365,
		SubjectAltNames: []SubjectAltName{
			{DNS: &dns, IP: &ip}, // both branches — must be refused, not sent as {"dns":...,"ip":...}
		},
	})
	if err == nil {
		t.Fatal("Generate must refuse a SubjectAltName naming both branches, client-side")
	}
	var netErr *NetworkError
	if !errors.As(err, &netErr) {
		t.Fatalf("got %T, want *NetworkError (§27.4 rule 2's client-side-refusal shape): %v", err, err)
	}
	if route.calls() != 0 {
		t.Fatalf("must refuse BEFORE any request; the server received %d call(s)", route.calls())
	}
}

// TestContract151Models_GenerateSendsSubjectAltNamesExternallyTagged (above)
// is this fix's I4 twin: SubjectAltName values built through the
// New<Type><Tag> constructors — the only correct shape before this fix —
// must keep working exactly as before.

func TestContract151Models_SubjectAltNameDecodesFromTheDocumentedShape(t *testing.T) {
	var dns SubjectAltName
	if err := json.Unmarshal([]byte(`{"dns":"api.lakeside.internal"}`), &dns); err != nil {
		t.Fatalf("decode dns shape: %v", err)
	}
	if dns.DNS == nil || *dns.DNS != "api.lakeside.internal" {
		t.Fatalf("DNS = %v, want api.lakeside.internal", dns.DNS)
	}
	if dns.IP != nil {
		t.Fatalf("IP must be nil for a dns-only element, got %v", *dns.IP)
	}

	var ip SubjectAltName
	if err := json.Unmarshal([]byte(`{"ip":"10.0.0.5"}`), &ip); err != nil {
		t.Fatalf("decode ip shape: %v", err)
	}
	if ip.IP == nil || *ip.IP != "10.0.0.5" {
		t.Fatalf("IP = %v, want 10.0.0.5", ip.IP)
	}
	if ip.DNS != nil {
		t.Fatalf("DNS must be nil for an ip-only element, got %v", *ip.DNS)
	}
}

// ---------------------------------------------------------------------------
// 5, 6 & 7. `inherit` — sent only when stated false; read as inheriting
//    (true) when absent, on both the role-side listings (required-on-the-
//    wire Inherit *bool + Inherits()) and the subject-side one (optional
//    Inherit) (§27.13 S-10 rules 1 and 3).
// ---------------------------------------------------------------------------

func TestContract151Models_AssignRequestSendsInheritOnlyWhenStatedFalse(t *testing.T) {
	srv, c := managementServer(t)
	route := srv.mount(http.MethodPost, "/api/v1/roles/"+roleID.String()+"/users", http.StatusNoContent, "")

	t.Run("Inherit unset (nil): no inherit key at all", func(t *testing.T) {
		if err := c.Roles().AssignToUser(context.Background(), roleID, AssignRoleToUserRequest{UserID: memberID}); err != nil {
			t.Fatalf("AssignToUser: %v", err)
		}
		keys := route.last(t).keys(t)
		for _, k := range keys {
			if k == "inherit" {
				t.Fatalf("Inherit == nil must send NO inherit key (absent means true), got keys %v", keys)
			}
		}
	})

	t.Run("Inherit explicitly false: inherit:false is sent", func(t *testing.T) {
		falseVal := false
		if err := c.Roles().AssignToUser(context.Background(), roleID, AssignRoleToUserRequest{UserID: memberID, Inherit: &falseVal}); err != nil {
			t.Fatalf("AssignToUser: %v", err)
		}
		rec := route.last(t)
		body := rec.jsonBody(t)
		v, ok := body["inherit"]
		if !ok || v != false {
			t.Fatalf("expected inherit:false on the wire, got body %v", body)
		}
	})
}

func TestContract151Models_RoleSideListingsReadAbsentInheritAsTrue(t *testing.T) {
	srv, c := managementServer(t)

	t.Run("roles.ListUsers", func(t *testing.T) {
		srv.mount(http.MethodGet, "/api/v1/roles/"+roleID.String()+"/users", http.StatusOK,
			`[{"user":{"id":"`+memberID.String()+`","username":"alice","email":"alice@example.test",`+
				`"status":"Active","tenant_id":"`+tenantID.String()+`","created_at":"","updated_at":""}},`+
				`{"user":{"id":"`+exampleID.String()+`","username":"bob","email":"bob@example.test",`+
				`"status":"Active","tenant_id":"`+tenantID.String()+`","created_at":"","updated_at":""},"inherit":false}]`)
		assignments, err := c.Roles().ListUsers(context.Background(), roleID)
		if err != nil {
			t.Fatalf("ListUsers: %v", err)
		}
		if len(assignments) != 2 {
			t.Fatalf("got %d assignments, want 2", len(assignments))
		}
		if !assignments[0].Inherits() {
			t.Fatal("an assignment omitting inherit must read Inherits() == true")
		}
		if assignments[1].Inherits() {
			t.Fatal("an assignment stating inherit:false must read Inherits() == false")
		}
	})

	t.Run("roles.ListGroups", func(t *testing.T) {
		srv.mount(http.MethodGet, "/api/v1/roles/"+roleID.String()+"/groups", http.StatusOK,
			`[{"group":{"id":"`+groupID.String()+`","name":"staff","description":"",`+
				`"tenant_id":"`+tenantID.String()+`","created_at":"","updated_at":""}},`+
				`{"group":{"id":"`+exampleID.String()+`","name":"eng","description":"",`+
				`"tenant_id":"`+tenantID.String()+`","created_at":"","updated_at":""},"inherit":false}]`)
		assignments, err := c.Roles().ListGroups(context.Background(), roleID)
		if err != nil {
			t.Fatalf("ListGroups: %v", err)
		}
		if len(assignments) != 2 {
			t.Fatalf("got %d assignments, want 2", len(assignments))
		}
		if !assignments[0].Inherits() {
			t.Fatal("an assignment omitting inherit must read Inherits() == true")
		}
		if assignments[1].Inherits() {
			t.Fatal("an assignment stating inherit:false must read Inherits() == false")
		}
	})

	t.Run("roles.ListServiceAccounts", func(t *testing.T) {
		srv.mount(http.MethodGet, "/api/v1/roles/"+roleID.String()+"/service-accounts", http.StatusOK,
			`[{"service_account":{"id":"`+memberID.String()+`","name":"fleet","client_id":"c1",`+
				`"status":"Active","tenant_id":"`+tenantID.String()+`","created_at":"","updated_at":""}},`+
				`{"service_account":{"id":"`+exampleID.String()+`","name":"other","client_id":"c2",`+
				`"status":"Active","tenant_id":"`+tenantID.String()+`","created_at":"","updated_at":""},"inherit":false}]`)
		assignments, err := c.Roles().ListServiceAccounts(context.Background(), roleID)
		if err != nil {
			t.Fatalf("ListServiceAccounts: %v", err)
		}
		if len(assignments) != 2 {
			t.Fatalf("got %d assignments, want 2", len(assignments))
		}
		if !assignments[0].Inherits() {
			t.Fatal("an assignment omitting inherit must read Inherits() == true")
		}
		if assignments[1].Inherits() {
			t.Fatal("an assignment stating inherit:false must read Inherits() == false")
		}
	})
}

func TestContract151Models_SubjectSideListingReadsAbsentInheritAsInheriting(t *testing.T) {
	srv, c := managementServer(t)
	srv.mount(http.MethodGet, "/api/v1/users/"+memberID.String()+"/roles", http.StatusOK,
		`[{"role":{"id":"`+roleID.String()+`","name":"editor","description":"",`+
			`"is_global":false,"tenant_id":"`+tenantID.String()+`","created_at":"","updated_at":""}}]`)

	assignments, err := c.Users().ListRoles(context.Background(), memberID)
	if err != nil {
		t.Fatalf("ListRoles: %v", err)
	}
	if len(assignments) != 1 {
		t.Fatalf("got %d assignments, want 1", len(assignments))
	}
	if !assignments[0].Inherits() {
		t.Fatal("a subject-side assignment omitting inherit must read Inherits() == true — absent means inheriting, both here and pre-1.51")
	}
}
