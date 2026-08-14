package jwks

import (
	"errors"
	"strings"
	"testing"
)

// CONTRACT.md §10.1 rule 9 — sender-constrained (certificate-bound) access
// tokens (contract 1.15, RFC 8705 §3 / RFC 7800).
//
// Three negatives and one positive. The POSITIVE is the one that matters most:
// rule 9 must not become "every caller must present a certificate", which would
// break every deployment that does not use mTLS at all.

const (
	// A real 43-character base64url x5t#S256, and a different one.
	testThumbprint      = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	testOtherThumbprint = "bWluZS1ub3QteW91cnMtdGhpcy1pcy00My1jaGFyc18"
)

// The regression test that keeps rule 9 from becoming a certificate mandate.
func TestUnboundTokenIsAcceptedWithOrWithoutACertificate(t *testing.T) {
	unbound := Claims{Subject: "user-1"}
	for _, presented := range []string{"", testThumbprint} {
		if err := VerifyCertificateBinding(unbound, presented); err != nil {
			t.Fatalf("an unbound token must be accepted (presented=%q): %v", presented, err)
		}
	}
}

func TestBoundTokenIsAcceptedWithItsOwnCertificate(t *testing.T) {
	bound := Claims{Confirmation: &Confirmation{X5tS256: testThumbprint}}
	if err := VerifyCertificateBinding(bound, testThumbprint); err != nil {
		t.Fatalf("the bound token's own certificate must be accepted: %v", err)
	}
}

func TestBoundTokenIsRejectedWithNoCertificate(t *testing.T) {
	bound := Claims{Confirmation: &Confirmation{X5tS256: testThumbprint}}
	if err := VerifyCertificateBinding(bound, ""); !errors.Is(err, ErrNoClientCertificate) {
		t.Fatalf("want ErrNoClientCertificate, got %v", err)
	}
}

func TestBoundTokenIsRejectedWithADifferentCertificate(t *testing.T) {
	bound := Claims{Confirmation: &Confirmation{X5tS256: testThumbprint}}
	err := VerifyCertificateBinding(bound, testOtherThumbprint)
	if !errors.Is(err, ErrCertificateBindingMismatch) {
		t.Fatalf("want ErrCertificateBindingMismatch, got %v", err)
	}
}

// The subtle one. A cnf naming a confirmation method this SDK cannot check is
// an UNVERIFIABLE constraint, never NO constraint — read the other way, a
// sender-constrained token silently degrades to a bearer token the day a newer
// AXIAM issues a confirmation this SDK predates.
func TestUnverifiableConfirmationIsRejectedNotIgnored(t *testing.T) {
	dpopish := Claims{Confirmation: &Confirmation{}} // present, but no x5t#S256
	for _, presented := range []string{"", testThumbprint} {
		err := VerifyCertificateBinding(dpopish, presented)
		if !errors.Is(err, ErrUnverifiableConfirmation) {
			t.Fatalf("want ErrUnverifiableConfirmation (presented=%q), got %v", presented, err)
		}
	}
}

// A cnf naming another method must PARSE (so the token round-trips) but must
// not validate. The two halves are easy to conflate; this pins both.
func TestCnfNamingAnotherMethodParsesButDoesNotValidate(t *testing.T) {
	payload := []byte(`{"sub":"u","tenant_id":"t","exp":9999999999,` +
		`"cnf":{"jkt":"0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"}}`)
	claims, err := parseClaims(payload)
	if err != nil {
		t.Fatalf("a cnf naming another method must still parse: %v", err)
	}
	if claims.Confirmation == nil {
		t.Fatal("the cnf claim must be recorded as PRESENT, or rule 9 cannot fail closed on it")
	}
	if claims.Confirmation.X5tS256 != "" {
		t.Fatalf("no x5t#S256 was present, got %q", claims.Confirmation.X5tS256)
	}
	if !errors.Is(VerifyCertificateBinding(claims, testThumbprint), ErrUnverifiableConfirmation) {
		t.Fatal("...and it must not validate")
	}
}

func TestBoundClaimSurvivesParsing(t *testing.T) {
	payload := []byte(`{"sub":"u","tenant_id":"t","exp":9999999999,` +
		`"cnf":{"x5t#S256":"` + testThumbprint + `"}}`)
	claims, err := parseClaims(payload)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if claims.Confirmation == nil || claims.Confirmation.X5tS256 != testThumbprint {
		t.Fatalf("cnf.x5t#S256 did not survive parsing: %+v", claims.Confirmation)
	}
}

// ValidateClaims (rules 2-7) deliberately does NOT apply rule 9: it has no
// transport to ask for a peer certificate. Asserted so the split cannot be
// collapsed by accident.
func TestValidateClaimsDoesNotApplyRule9(t *testing.T) {
	exp := int64(1 << 40)
	claims := Claims{
		TenantID:     "acme",
		Exp:          &exp,
		Confirmation: &Confirmation{X5tS256: testThumbprint},
	}
	if err := ValidateClaims(claims, ValidationOptions{Tenant: "acme"}); err != nil {
		t.Fatalf("ValidateClaims checks rules 2-7, not rule 9: %v", err)
	}
	if err := VerifyCertificateBinding(claims, ""); err == nil {
		t.Fatal("...and rule 9, applied separately, does reject")
	}
}

// RFC 7515 §2 base64url: unpadded, '-'/'_' rather than '+'/'/'. A padded or
// standard-base64 value will not compare equal to what AXIAM put in the token.
func TestCertificateThumbprintIsUnpaddedBase64URL(t *testing.T) {
	der := make([]byte, 512)
	for i := range der {
		der[i] = 0x42
	}
	tp := CertificateThumbprintS256(der)
	if len(tp) != 43 {
		t.Fatalf("want 43 chars, got %d (%q)", len(tp), tp)
	}
	if strings.ContainsAny(tp, "=+/") {
		t.Fatalf("must be unpadded base64url, got %q", tp)
	}
	if CertificateThumbprintS256(der) != tp {
		t.Fatal("must be deterministic")
	}
}
