package jwks

import (
	"context"
	"errors"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// CONTRACT.md §10.1 rule 9 at the DEFAULT verification entry point
// (contract 1.51 fix).
//
// Before this fix, VerifyAccessToken — the ONLY method middleware.Middleware
// (this SDK's documented net/http route guard) ever called — applied rules
// 1-8 and never looked at "cnf" at all. A certificate-bound token (every
// device token minted under CONTRACT.md §6.1 by default) therefore verified
// successfully as an ordinary bearer credential through every guard this SDK
// ships, with no possession check whatsoever: a token lifted off a device
// opened any route.
//
// These tests exist because no earlier test in this package signed a real
// token carrying "cnf" and pushed it through VerifyAccessToken/
// VerifyAccessTokenWithProofs end to end — internal/jwks/rule9_test.go and
// binding_dpop_test.go exercise VerifyTokenBinding directly against a bare
// Claims value, which is correct but never proves the entry point wires it
// in. There was accordingly nothing here to "invert" — this is new coverage
// for a gap, not a relaxed assertion.
// ---------------------------------------------------------------------------

func TestVerifyAccessToken_RefusesACertificateBoundTokenWithNoEvidence(t *testing.T) {
	priv, pubJWK := generateKey(t, "kid-1")
	srv := newMutableJWKSServer(t, marshalSet(t, pubJWK))
	v, err := NewVerifier(context.Background(), srv.Server.URL, srv.Server.Client())
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	token := signEdDSA(t, priv, "kid-1", Claims{
		Subject: "device-1", TenantID: testTenant, Exp: at(time.Now().Add(time.Hour)),
		Confirmation: &Confirmation{X5tS256: "the-device-certificate-thumbprint"},
	})

	// The default, no-evidence entry point: this call has nothing to check
	// the confirmation against, so a bound token MUST be refused — rule 9's
	// "a different certificate, or none" row.
	if _, err := v.VerifyAccessToken(context.Background(), token, ValidationOptions{Tenant: testTenant}); err == nil {
		t.Fatal("SECURITY: VerifyAccessToken accepted a certificate-bound token with no possession evidence")
	}
}

func TestVerifyAccessToken_UnboundTokenIsUnaffectedByTheRule9Fix(t *testing.T) {
	// The required positive regression CONTRACT.md §10.1 names explicitly:
	// "an unbound token MUST still be accepted ... with or without a
	// certificate". This is the existing, pre-1.51 behaviour and MUST NOT
	// change.
	priv, pubJWK := generateKey(t, "kid-1")
	srv := newMutableJWKSServer(t, marshalSet(t, pubJWK))
	v, err := NewVerifier(context.Background(), srv.Server.URL, srv.Server.Client())
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	token := signEdDSA(t, priv, "kid-1", Claims{
		Subject: "user-1", TenantID: testTenant, Exp: at(time.Now().Add(time.Hour)),
	})

	if _, err := v.VerifyAccessToken(context.Background(), token, ValidationOptions{Tenant: testTenant}); err != nil {
		t.Fatalf("an unbound token must still verify through VerifyAccessToken, got %v", err)
	}
	if _, err := v.VerifyAccessTokenWithProofs(context.Background(), token, ValidationOptions{Tenant: testTenant}, PresentedProofs{}); err != nil {
		t.Fatalf("an unbound token must still verify through VerifyAccessTokenWithProofs with no proofs, got %v", err)
	}
	if _, err := v.VerifyAccessTokenWithProofs(context.Background(), token, ValidationOptions{Tenant: testTenant}, PresentedProofs{CertificateThumbprint: "anything"}); err != nil {
		t.Fatalf("an unbound token must still verify through VerifyAccessTokenWithProofs even WITH a certificate present, got %v", err)
	}
}

func TestVerifyAccessTokenWithProofs_AcceptsTheMatchingCertificateAndRejectsAnyOther(t *testing.T) {
	priv, pubJWK := generateKey(t, "kid-1")
	srv := newMutableJWKSServer(t, marshalSet(t, pubJWK))
	v, err := NewVerifier(context.Background(), srv.Server.URL, srv.Server.Client())
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	token := signEdDSA(t, priv, "kid-1", Claims{
		Subject: "device-1", TenantID: testTenant, Exp: at(time.Now().Add(time.Hour)),
		Confirmation: &Confirmation{X5tS256: "own-thumbprint"},
	})
	opts := ValidationOptions{Tenant: testTenant}

	t.Run("own certificate: accepted", func(t *testing.T) {
		if _, err := v.VerifyAccessTokenWithProofs(context.Background(), token, opts, PresentedProofs{CertificateThumbprint: "own-thumbprint"}); err != nil {
			t.Fatalf("expected acceptance with the matching certificate, got %v", err)
		}
	})

	t.Run("a different certificate: refused", func(t *testing.T) {
		if _, err := v.VerifyAccessTokenWithProofs(context.Background(), token, opts, PresentedProofs{CertificateThumbprint: "other-thumbprint"}); err == nil {
			t.Fatal("SECURITY: accepted a certificate-bound token against a DIFFERENT certificate")
		}
	})

	t.Run("no certificate: refused", func(t *testing.T) {
		if _, err := v.VerifyAccessTokenWithProofs(context.Background(), token, opts, PresentedProofs{}); err == nil {
			t.Fatal("expected refusal with no certificate presented")
		}
	})
}

func TestVerifyAccessTokenWithProofs_JktBoundTokenIsRefused(t *testing.T) {
	// This SDK's connection-level evidence is a TLS peer certificate only —
	// nothing here verifies a DPoP proof. A jkt-bound token must therefore
	// be refused even through the "with proofs" entry point, per §10.1
	// rule 9's "the SDK cannot verify DPoP proofs at all -> reject" row.
	priv, pubJWK := generateKey(t, "kid-1")
	srv := newMutableJWKSServer(t, marshalSet(t, pubJWK))
	v, err := NewVerifier(context.Background(), srv.Server.URL, srv.Server.Client())
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	token := signEdDSA(t, priv, "kid-1", Claims{
		Subject: "user-1", TenantID: testTenant, Exp: at(time.Now().Add(time.Hour)),
		Confirmation: &Confirmation{Jkt: "some-dpop-thumbprint"},
	})

	_, err = v.VerifyAccessTokenWithProofs(context.Background(), token, ValidationOptions{Tenant: testTenant}, PresentedProofs{})
	if err == nil {
		t.Fatal("expected a jkt-bound token to be refused with no DPoP proof verified")
	}
	if !errors.Is(err, ErrNoDPoPProof) {
		t.Fatalf("got %v, want ErrNoDPoPProof", err)
	}
}

func TestVerifyAccessTokenWithProofs_EmptyConfirmationIsRefusedNotUnbound(t *testing.T) {
	priv, pubJWK := generateKey(t, "kid-1")
	srv := newMutableJWKSServer(t, marshalSet(t, pubJWK))
	v, err := NewVerifier(context.Background(), srv.Server.URL, srv.Server.Client())
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	// Confirmation present, both members empty — the wire shape of {} on the
	// REST/local-verification side (§10.1 rule 9's own "present, but an
	// empty object {}" row).
	token := signEdDSA(t, priv, "kid-1", Claims{
		Subject: "user-1", TenantID: testTenant, Exp: at(time.Now().Add(time.Hour)),
		Confirmation: &Confirmation{},
	})

	_, err = v.VerifyAccessTokenWithProofs(context.Background(), token, ValidationOptions{Tenant: testTenant}, PresentedProofs{CertificateThumbprint: "anything", DPoPThumbprint: "anything"})
	if err == nil {
		t.Fatal("an empty cnf object must be refused even with proofs presented — it is unverifiable, not unbound")
	}
	if !errors.Is(err, ErrUnverifiableConfirmation) {
		t.Fatalf("got %v, want ErrUnverifiableConfirmation", err)
	}
}
