package jwks

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

// TestNewVerifierForURL_UsesExactURL proves NewVerifierForURL binds to the
// given jwksURL verbatim, with NO /oauth2/jwks path concatenation — the
// entry point the OIDC relying-party helpers use to read jwks_uri from a
// discovery document (CONTRACT.md §12.3 rule 6).
func TestNewVerifierForURL_UsesExactURL(t *testing.T) {
	priv, pub := generateKey(t, "kid-1")
	srv := newMutableJWKSServer(t, marshalSet(t, pub))

	exactURL := srv.Server.URL + "/oauth2/jwks"
	v, err := NewVerifierForURL(context.Background(), exactURL, srv.Server.Client())
	if err != nil {
		t.Fatalf("NewVerifierForURL: %v", err)
	}
	if v.jwksURL != exactURL {
		t.Fatalf("jwksURL = %q, want the exact URL passed in (%q)", v.jwksURL, exactURL)
	}

	token := signEdDSA(t, priv, "kid-1", Claims{Subject: "u", Exp: at(time.Now().Add(time.Hour))})
	payload, err := v.VerifyPayload(context.Background(), token)
	if err != nil {
		t.Fatalf("VerifyPayload: %v", err)
	}
	if len(payload) == 0 {
		t.Fatal("expected a non-empty payload")
	}
}

// TestVerifyPayload_HappyPath proves the raw-payload entry point returns the
// verified JWS payload bytes.
func TestVerifyPayload_HappyPath(t *testing.T) {
	priv, pub := generateKey(t, "kid-1")
	srv := newMutableJWKSServer(t, marshalSet(t, pub))
	v, err := NewVerifier(context.Background(), srv.Server.URL, srv.Server.Client())
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	token := signEdDSA(t, priv, "kid-1", Claims{Subject: "id-token-subject", Exp: at(time.Now().Add(time.Hour))})
	payload, err := v.VerifyPayload(context.Background(), token)
	if err != nil {
		t.Fatalf("VerifyPayload: %v", err)
	}
	if !strings.Contains(string(payload), "id-token-subject") {
		t.Fatalf("payload does not contain expected claim: %s", payload)
	}
}

// TestVerifyPayload_WrongAlg proves §12.4 rule 1: a non-EdDSA alg is
// rejected via ErrUnexpectedAlg, BEFORE any keyset lookup.
func TestVerifyPayload_WrongAlg(t *testing.T) {
	_, pub := generateKey(t, "kid-1")
	srv := newMutableJWKSServer(t, marshalSet(t, pub))
	v, err := NewVerifier(context.Background(), srv.Server.URL, srv.Server.Client())
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	before := srv.Hits()
	token := signHS256(t)
	_, err = v.VerifyPayload(context.Background(), token)
	if !errors.Is(err, ErrUnexpectedAlg) {
		t.Fatalf("expected ErrUnexpectedAlg, got %v", err)
	}
	if srv.Hits() != before {
		t.Fatalf("expected NO keyset lookup for a wrong-alg token")
	}
}

// TestVerifyPayload_NoSignatures proves the fail-closed branch for a
// malformed JWS carrying no usable signature is rejected (jws.Parse itself
// refuses to parse a JSON-serialized JWS with an empty "signatures" array,
// so this reaches VerifyPayload's own parse-error path rather than the
// ErrNoSignatures branch — both fail closed, which is what matters here).
func TestVerifyPayload_NoSignatures(t *testing.T) {
	_, pub := generateKey(t, "k1")
	srv := newMutableJWKSServer(t, marshalSet(t, pub))
	v, err := NewVerifier(context.Background(), srv.Server.URL, srv.Server.Client())
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	noSigToken := []byte(`{"payload":"eyJzdWIiOiJ1In0","signatures":[]}`)
	if _, err := v.VerifyPayload(context.Background(), noSigToken); err == nil {
		t.Fatal("expected a token with no signatures to be rejected")
	}
}

// TestVerifyPayload_MissingKidHeader proves §12 port addendum item 12: a
// missing kid header is classified identically to an unknown kid.
func TestVerifyPayload_MissingKidHeader(t *testing.T) {
	priv, pub := generateKey(t, "kid-1")
	srv := newMutableJWKSServer(t, marshalSet(t, pub))
	v, err := NewVerifier(context.Background(), srv.Server.URL, srv.Server.Client())
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	// Sign with NO kid set on the key at all.
	pk, err := jwk.Import(priv)
	if err != nil {
		t.Fatalf("jwk.Import: %v", err)
	}
	token, err := jws.Sign([]byte(`{"sub":"u"}`), jws.WithKey(jwa.EdDSA(), pk))
	if err != nil {
		t.Fatalf("jws.Sign: %v", err)
	}

	_, err = v.VerifyPayload(context.Background(), token)
	if !errors.Is(err, ErrUnknownKid) {
		t.Fatalf("expected ErrUnknownKid for a token with no kid header, got %v", err)
	}
}

// TestVerifyPayload_UnknownKidRefetchesOnceThenSucceeds mirrors
// TestJWKS_UnknownKidRefetchesOnce but through VerifyPayload.
func TestVerifyPayload_UnknownKidRefetchesOnceThenSucceeds(t *testing.T) {
	priv1, pub1 := generateKey(t, "kid-1")
	priv2, pub2 := generateKey(t, "kid-2")
	srv := newMutableJWKSServer(t, marshalSet(t, pub1))

	v, err := NewVerifier(context.Background(), srv.Server.URL, srv.Server.Client())
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	primeToken := signEdDSA(t, priv1, "kid-1", Claims{Subject: "priming", Exp: at(time.Now().Add(time.Hour))})
	if _, err := v.VerifyPayload(context.Background(), primeToken); err != nil {
		t.Fatalf("priming VerifyPayload: %v", err)
	}

	hitsBefore := srv.Hits()
	srv.setBody(marshalSet(t, pub1, pub2))
	token2 := signEdDSA(t, priv2, "kid-2", Claims{Subject: "user-456", Exp: at(time.Now().Add(time.Hour))})

	payload, err := v.VerifyPayload(context.Background(), token2)
	if err != nil {
		t.Fatalf("VerifyPayload after rotation: %v", err)
	}
	if !strings.Contains(string(payload), "user-456") {
		t.Fatalf("unexpected payload: %s", payload)
	}
	if got := srv.Hits() - hitsBefore; got != 1 {
		t.Fatalf("expected exactly ONE forced refetch, got %d", got)
	}

	// A kid unknown even after refetch must fail with ErrUnknownKid.
	priv3, _ := generateKey(t, "kid-3")
	stillUnknown := signEdDSA(t, priv3, "kid-3", Claims{Subject: "u", Exp: at(time.Now().Add(time.Hour))})
	if _, err := v.VerifyPayload(context.Background(), stillUnknown); !errors.Is(err, ErrUnknownKid) {
		t.Fatalf("expected ErrUnknownKid, got %v", err)
	}
}

// TestVerifyPayload_KnownKidBadSignature proves §12.4 rule 2 distinguishes
// invalid_signature (kid IS known) from unknown_kid.
func TestVerifyPayload_KnownKidBadSignature(t *testing.T) {
	priv, pub := generateKey(t, "kid-1")
	srv := newMutableJWKSServer(t, marshalSet(t, pub))
	v, err := NewVerifier(context.Background(), srv.Server.URL, srv.Server.Client())
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	token := signEdDSA(t, priv, "kid-1", Claims{Subject: "u", Exp: at(time.Now().Add(time.Hour))})

	// Flip a bit inside the DECODED signature bytes (not the base64url text)
	// so the compact serialization stays syntactically valid and jws.Parse
	// succeeds — only the cryptographic signature becomes wrong.
	parts := strings.Split(string(token), ".")
	if len(parts) != 3 {
		t.Fatalf("unexpected compact JWS shape: %q", token)
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode signature segment: %v", err)
	}
	sigBytes[0] ^= 0xFF
	parts[2] = base64.RawURLEncoding.EncodeToString(sigBytes)
	tampered := []byte(strings.Join(parts, "."))

	_, err = v.VerifyPayload(context.Background(), tampered)
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("expected ErrSignatureInvalid for a known kid with a bad signature, got %v", err)
	}
}

// TestVerifyPayload_RefetchFailsWhenServerBroken proves the lookupKeyID
// refetch-failure branch.
func TestVerifyPayload_RefetchFailsWhenServerBroken(t *testing.T) {
	knownPriv, knownPub := generateKey(t, "known-kid")
	srv := newMutableJWKSServer(t, marshalSet(t, knownPub))
	v, err := NewVerifier(context.Background(), srv.Server.URL, srv.Server.Client())
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	good := signEdDSA(t, knownPriv, "known-kid", Claims{Subject: "u", Exp: at(time.Now().Add(time.Hour))})
	if _, err := v.VerifyPayload(context.Background(), good); err != nil {
		t.Fatalf("priming VerifyPayload: %v", err)
	}

	srv.setBody([]byte("{ not a valid jwks"))
	unknownPriv, _ := generateKey(t, "rotated-kid")
	token := signEdDSA(t, unknownPriv, "rotated-kid", Claims{Subject: "u", Exp: at(time.Now().Add(time.Hour))})
	if _, err := v.VerifyPayload(context.Background(), token); !errors.Is(err, ErrUnknownKid) {
		t.Fatalf("expected ErrUnknownKid when the forced refetch itself fails, got %v", err)
	}
}

// TestVerifyPayload_InvalidToken proves a syntactically-invalid token
// returns a (non-sentinel) parse error rather than panicking.
func TestVerifyPayload_InvalidToken(t *testing.T) {
	_, pub := generateKey(t, "kid-1")
	srv := newMutableJWKSServer(t, marshalSet(t, pub))
	v, err := NewVerifier(context.Background(), srv.Server.URL, srv.Server.Client())
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if _, err := v.VerifyPayload(context.Background(), []byte("not a jws at all")); err == nil {
		t.Fatal("expected an error for a syntactically invalid token")
	}
}
