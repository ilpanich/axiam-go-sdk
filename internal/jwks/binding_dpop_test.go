// CONTRACT.md §10.1 rule 9 extended for DPoP (contract 1.16).
package jwks

import (
	"errors"
	"testing"
)

const (
	testThumb    = "bwcK0esC3yEWCTuAFrDPBqZ_hvIn0UbmJKlSjMbGZKM"
	testJkt      = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
	testOtherJkt = "sBjflhaR2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
)

func bound(c *Confirmation) Claims { return Claims{Confirmation: c} }

// THE POSITIVE REGRESSION TEST, and the one this change is most likely to
// break: an unbound token must still pass with no certificate and no proof.
// The likeliest wrong implementation of rule 9 demands evidence from everybody.
func TestUnboundTokenIsAcceptedWithNoProofsAtAll(t *testing.T) {
	if err := VerifyTokenBinding(Claims{}, PresentedProofs{}); err != nil {
		t.Fatalf("an unbound token must be accepted with no proofs: %v", err)
	}
	// ...and proofs it never asked for do not make it invalid.
	if err := VerifyTokenBinding(Claims{}, PresentedProofs{
		CertificateThumbprint: testThumb, DPoPThumbprint: testJkt,
	}); err != nil {
		t.Fatalf("unexpected proofs must not invalidate an unbound token: %v", err)
	}
}

func TestDPoPBoundTokenAcceptsTheMatchingKey(t *testing.T) {
	err := VerifyTokenBinding(bound(&Confirmation{Jkt: testJkt}),
		PresentedProofs{DPoPThumbprint: testJkt})
	if err != nil {
		t.Fatalf("matching jkt must verify: %v", err)
	}
}

func TestDPoPBoundTokenIsRejectedWithoutAProofOrWithTheWrongKey(t *testing.T) {
	if err := VerifyTokenBinding(bound(&Confirmation{Jkt: testJkt}),
		PresentedProofs{}); !errors.Is(err, ErrNoDPoPProof) {
		t.Errorf("got %v, want ErrNoDPoPProof", err)
	}
	if err := VerifyTokenBinding(bound(&Confirmation{Jkt: testJkt}),
		PresentedProofs{DPoPThumbprint: testOtherJkt}); !errors.Is(err, ErrDPoPBindingMismatch) {
		t.Errorf("got %v, want ErrDPoPBindingMismatch", err)
	}
}

// BOTH NAMED IS A CONJUNCTION. An operator who turned on two constraints asked
// for two; satisfying the more convenient one is not compliance. Each half is
// asserted to fail alone, because "check whichever we can" is the likeliest
// wrong implementation.
func TestCnfNamingBothMethodsRequiresBoth(t *testing.T) {
	both := bound(&Confirmation{X5tS256: testThumb, Jkt: testJkt})

	if err := VerifyTokenBinding(both, PresentedProofs{
		CertificateThumbprint: testThumb, DPoPThumbprint: testJkt,
	}); err != nil {
		t.Fatalf("both proofs present must verify: %v", err)
	}

	if err := VerifyTokenBinding(both,
		PresentedProofs{CertificateThumbprint: testThumb}); err == nil {
		t.Error("the certificate alone must not satisfy a two-method cnf")
	}
	if err := VerifyTokenBinding(both,
		PresentedProofs{DPoPThumbprint: testJkt}); err == nil {
		t.Error("the DPoP proof alone must not satisfy a two-method cnf")
	}
}

// An empty cnf names nothing checkable and is refused, not read as unbound.
// Over gRPC this is also how proto3 delivers an empty CnfClaim message, which
// is why §10.3 rule 3 spells it out separately.
func TestEmptyCnfIsRefusedRatherThanReadAsUnbound(t *testing.T) {
	if err := VerifyTokenBinding(bound(&Confirmation{}),
		PresentedProofs{}); !errors.Is(err, ErrUnverifiableConfirmation) {
		t.Fatalf("got %v, want ErrUnverifiableConfirmation", err)
	}
}

// The narrow entry point refuses a DPoP-bound token rather than ignoring the
// jkt it cannot check. That refusal is what lets it stay in the API without
// becoming a downgrade path.
func TestCertificateOnlyEntryPointRefusesDPoPBoundTokens(t *testing.T) {
	for _, presented := range []string{"", testThumb} {
		if err := VerifyCertificateBinding(bound(&Confirmation{Jkt: testJkt}),
			presented); !errors.Is(err, ErrUnverifiableConfirmation) {
			t.Errorf("presented %q: got %v, want ErrUnverifiableConfirmation", presented, err)
		}
	}
	// ...and a both-bound token likewise: it can establish one half and must
	// not answer for the whole.
	if err := VerifyCertificateBinding(
		bound(&Confirmation{X5tS256: testThumb, Jkt: testJkt}),
		testThumb); !errors.Is(err, ErrUnverifiableConfirmation) {
		t.Errorf("got %v, want ErrUnverifiableConfirmation", err)
	}
}

// A `cnf` whose members are of the wrong JSON type names nothing checkable, and
// so is refused rather than read as unbound. The wire shape decides accept versus
// reject here, so a non-string jkt must not quietly become "no jkt".
func TestCnfWithWronglyTypedMembersIsRefused(t *testing.T) {
	for _, payload := range []string{
		`{"sub":"u","tenant_id":"t","cnf":{"jkt":42}}`,
		`{"sub":"u","tenant_id":"t","cnf":{"x5t#S256":true}}`,
		`{"sub":"u","tenant_id":"t","cnf":{}}`,
	} {
		claims, err := parseClaims([]byte(payload))
		if err != nil {
			// A wrongly-typed member may fail at parse, which is also a rejection.
			continue
		}
		if err := VerifyTokenBinding(claims, PresentedProofs{
			CertificateThumbprint: testThumb, DPoPThumbprint: testJkt,
		}); !errors.Is(err, ErrUnverifiableConfirmation) {
			t.Errorf("payload %s: got %v, want ErrUnverifiableConfirmation", payload, err)
		}
	}
}

// The wire round trip: a cnf carrying both members parses into both fields, and
// the conjunction is enforced on the parsed result rather than on a hand-built
// struct. Without this, the parser and the rule could disagree unnoticed.
func TestBothBoundCnfSurvivesTheWireRoundTrip(t *testing.T) {
	payload := `{"sub":"u","tenant_id":"t","cnf":{"x5t#S256":"` + testThumb + `","jkt":"` + testJkt + `"}}`
	claims, err := parseClaims([]byte(payload))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if claims.Confirmation == nil || claims.Confirmation.X5tS256 != testThumb ||
		claims.Confirmation.Jkt != testJkt {
		t.Fatalf("both members must survive parsing, got %+v", claims.Confirmation)
	}

	if err := VerifyTokenBinding(claims, PresentedProofs{
		CertificateThumbprint: testThumb, DPoPThumbprint: testJkt,
	}); err != nil {
		t.Errorf("both proofs present must verify: %v", err)
	}
	if err := VerifyTokenBinding(claims,
		PresentedProofs{CertificateThumbprint: testThumb}); err == nil {
		t.Error("the certificate alone must not satisfy a parsed two-method cnf")
	}
}
