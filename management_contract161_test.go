package axiam

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"
)

// CONTRACT §34.5 (contract 1.61), the rows every SDK that ships `certificates`
// owes: §27.11 rule 5, Certificate.user_id and the optional request member on
// certificates.generate and certificates.sign_csr (the one required test).
//
// SsfStreamInput.expected_updated_at and the three meanings of events_requested
// are §32.8 test 1's and live in management_ssf_test.go. CibaPendingList is a
// console surface no operation returns (§33.3 rule 16); this SDK models neither
// it nor CibaApprovalPage.

// certificateJSON is a User certificate body; userID is the raw JSON of the
// user_id member, or "" to leave the member out altogether.
func certificateJSON(userID string, extra string) string {
	member := ""
	if userID != "" {
		member = `"user_id":` + userID + `,`
	}
	return `{` + member + extra + `"cert_type":"User","created_at":"2026-10-13T00:00:00Z",` +
		`"fingerprint":"ab:cd","id":"` + uuid.New().String() + `",` +
		`"issuer_ca_id":"` + exampleID.String() + `","key_algorithm":"Ed25519","metadata":{},` +
		`"not_after":"2027-10-13T00:00:00Z","not_before":"2026-10-13T00:00:00Z",` +
		`"public_cert_pem":"pem","status":"Active","subject":"ada","tenant_id":"` + tenantID.String() + `"}`
}

func generateRequest(userID *string) CreateCertificateRequest {
	return CreateCertificateRequest{
		CertType: CertificateTypeUser, IssuerCAID: exampleID, KeyAlgorithm: KeyAlgorithmEd25519,
		Subject: "ada", ValidityDays: 90, UserID: userID,
	}
}

func signRequest(userID *string) SignCertificateCSRRequest {
	return SignCertificateCSRRequest{
		CertType: CertificateTypeUser, CSRPEM: "csr", IssuerCAID: exampleID,
		ValidityDays: 90, UserID: userID,
	}
}

// Required test, first half: both requests send the user_id the caller set
// exactly as given and, without one, no user_id key — not null.
func TestContract161_GenerateAndSignCSRSendUserIDAsGivenAndOmitTheKeyWhenUnset(t *testing.T) {
	srv, c := managementServer(t)
	generate := srv.mount(http.MethodPost, "/api/v1/certificates", http.StatusCreated,
		certificateJSON("", `"private_key_pem":"k",`))
	sign := srv.mount(http.MethodPost, "/api/v1/certificates/sign-csr", http.StatusCreated,
		certificateJSON("", ""))
	ctx := context.Background()
	account := uuid.New().String()

	if _, err := c.Certificates().Generate(ctx, generateRequest(&account)); err != nil {
		t.Fatalf("generate: %v", err)
	}
	if _, err := c.Certificates().Generate(ctx, generateRequest(nil)); err != nil {
		t.Fatalf("generate: %v", err)
	}
	if _, err := c.Certificates().SignCSR(ctx, signRequest(&account)); err != nil {
		t.Fatalf("sign_csr: %v", err)
	}
	if _, err := c.Certificates().SignCSR(ctx, signRequest(nil)); err != nil {
		t.Fatalf("sign_csr: %v", err)
	}

	for name, route := range map[string]*mountedRoute{"generate": generate, "sign_csr": sign} {
		if route.calls() != 2 {
			t.Fatalf("%s: want two requests, got %d", name, route.calls())
		}
		if got := route.requests[0].jsonBody(t)["user_id"]; got != account {
			t.Fatalf("%s: user_id = %v, want %s exactly as given", name, got, account)
		}
		if bytes.Contains(route.requests[1].body, []byte("user_id")) {
			t.Fatalf("%s: unset user_id must be absent, never null: %s", name, route.requests[1].body)
		}
	}
}

// Required test, second half: a Certificate body carrying a UUID, one carrying
// null and one lacking the member each decode, and the last two give "no
// account named".
func TestContract161_ACertificateDecodesAUUIDANullAndAnAbsentUserID(t *testing.T) {
	account := uuid.New()
	decode := func(body string) Certificate {
		t.Helper()
		var cert Certificate
		if err := json.Unmarshal([]byte(body), &cert); err != nil {
			t.Fatalf("decode %s: %v", body, err)
		}
		return cert
	}

	if named := decode(certificateJSON(`"`+account.String()+`"`, "")); named.UserID == nil || *named.UserID != account {
		t.Fatalf("a UUID decodes: %v", named.UserID)
	}
	if got := decode(certificateJSON("null", "")); got.UserID != nil {
		t.Fatalf("null is no account named, got %v", got.UserID)
	}
	if got := decode(certificateJSON("", "")); got.UserID != nil {
		t.Fatalf("an absent member is no account named, got %v", got.UserID)
	}
	// Never synthesised: a metadata.user_id is free-form metadata.
	var fromMetadata Certificate
	body := `{"cert_type":"User","created_at":"x","fingerprint":"f","id":"` + uuid.New().String() + `",` +
		`"issuer_ca_id":"` + exampleID.String() + `","key_algorithm":"Ed25519","metadata":{"user_id":"` + account.String() + `"},` +
		`"not_after":"x","not_before":"x","public_cert_pem":"p","status":"Active","subject":"ada","tenant_id":"` + tenantID.String() + `"}`
	if err := json.Unmarshal([]byte(body), &fromMetadata); err != nil {
		t.Fatal(err)
	}
	if fromMetadata.UserID != nil {
		t.Fatalf("metadata.user_id must not become user_id, got %v", fromMetadata.UserID)
	}
}

// generate answers a GeneratedCertificate and get a Certificate: the member
// reaches both, and a get costs one request.
func TestContract161_UserIDReachesAGeneratedCertificateAndAGet(t *testing.T) {
	srv, c := managementServer(t)
	account := uuid.New()
	certID := uuid.New()
	srv.mount(http.MethodPost, "/api/v1/certificates", http.StatusCreated,
		certificateJSON(`"`+account.String()+`"`, `"private_key_pem":"k",`))
	get := srv.mount(http.MethodGet, "/api/v1/certificates/"+certID.String(), http.StatusOK,
		certificateJSON(`"`+account.String()+`"`, ""))
	ctx := context.Background()

	accountText := account.String()
	generated, err := c.Certificates().Generate(ctx, generateRequest(&accountText))
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if generated.UserID == nil || *generated.UserID != account {
		t.Fatalf("GeneratedCertificate.UserID = %v", generated.UserID)
	}
	got, err := c.Certificates().Get(ctx, certID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.UserID == nil || *got.UserID != account || get.calls() != 1 {
		t.Fatalf("Certificate.UserID = %v after %d requests", got.UserID, get.calls())
	}
}
