package jwks

import (
	"context"
	"crypto/ed25519"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

// signRawEdDSA signs an arbitrary payload (which need not be JSON) with an
// Ed25519 key tagged with kid, so tests can drive the post-verification
// parseClaims decode-error path with a signature-valid but non-JSON payload.
func signRawEdDSA(t *testing.T, priv ed25519.PrivateKey, kid string, payload []byte) []byte {
	t.Helper()
	pk, err := jwk.Import(priv)
	if err != nil {
		t.Fatalf("jwk.Import priv: %v", err)
	}
	if err := pk.Set(jwk.KeyIDKey, kid); err != nil {
		t.Fatalf("set kid: %v", err)
	}
	signed, err := jws.Sign(payload, jws.WithKey(jwa.EdDSA(), pk))
	if err != nil {
		t.Fatalf("jws.Sign: %v", err)
	}
	return signed
}

// TestNewVerifier_NilHTTPClient covers NewVerifier's nil-client branch: a nil
// *http.Client selects the default httprc client, which still fetches and
// verifies against a local (http) JWKS endpoint.
func TestNewVerifier_NilHTTPClient(t *testing.T) {
	priv, pub := generateKey(t, "nil-client-kid")
	srv := newMutableJWKSServer(t, marshalSet(t, pub))

	// hc == nil exercises the default-httprc-client construction path.
	v, err := NewVerifier(context.Background(), srv.Server.URL, nil)
	if err != nil {
		t.Fatalf("NewVerifier with nil client: %v", err)
	}
	if v.jwksURL != srv.Server.URL+"/oauth2/jwks" {
		t.Fatalf("unexpected jwksURL %q", v.jwksURL)
	}

	token := signEdDSA(t, priv, "nil-client-kid", Claims{Subject: "u", Exp: 9999999999})
	claims, err := v.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("Verify via default client: %v", err)
	}
	if claims.Subject != "u" {
		t.Fatalf("unexpected subject %q", claims.Subject)
	}
}

// TestVerify_NoSignatures covers Verify's fail-closed branch for a JWS carrying
// zero signatures (JSON serialization with an empty signatures array): it must
// be rejected before any keyset lookup rather than silently falling through.
func TestVerify_NoSignatures(t *testing.T) {
	_, pub := generateKey(t, "k1")
	srv := newMutableJWKSServer(t, marshalSet(t, pub))
	v, err := NewVerifier(context.Background(), srv.Server.URL, srv.Server.Client())
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	// A JWS General JSON Serialization with an empty "signatures" array.
	noSigToken := []byte(`{"payload":"eyJzdWIiOiJ1In0","signatures":[]}`)
	if _, err := v.Verify(context.Background(), noSigToken); err == nil {
		t.Fatal("expected a token with no signatures to be rejected")
	}
}

// TestVerify_ValidSignatureBadClaimsPayload covers parseClaims' decode-error
// branch reached through Verify: a token whose signature verifies but whose
// payload is not valid JSON surfaces a claims-parse error.
func TestVerify_ValidSignatureBadClaimsPayload(t *testing.T) {
	priv, pub := generateKey(t, "k1")
	srv := newMutableJWKSServer(t, marshalSet(t, pub))

	v, err := NewVerifier(context.Background(), srv.Server.URL, srv.Server.Client())
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	token := signRawEdDSA(t, priv, "k1", []byte("this is not json"))
	if _, err := v.Verify(context.Background(), token); err == nil {
		t.Fatal("expected a claims-parse error for a non-JSON verified payload")
	}
}

// TestVerify_RefetchFailsAfterUnknownKid covers Verify's forced-refetch failure
// branch: after an unknown-kid verification failure, if the JWKS refetch itself
// fails (the endpoint now serves an invalid body), Verify returns the combined
// failure rather than succeeding.
func TestVerify_RefetchFailsAfterUnknownKid(t *testing.T) {
	knownPriv, knownPub := generateKey(t, "known-kid")
	srv := newMutableJWKSServer(t, marshalSet(t, knownPub))

	v, err := NewVerifier(context.Background(), srv.Server.URL, srv.Server.Client())
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	// Prime the cache with a successful verification against the known key.
	good := signEdDSA(t, knownPriv, "known-kid", Claims{Subject: "u", Exp: 9999999999})
	if _, err := v.Verify(context.Background(), good); err != nil {
		t.Fatalf("priming Verify: %v", err)
	}

	// Now the endpoint starts serving an invalid JWKS body, so the forced
	// refetch triggered by an unknown kid will fail.
	srv.setBody([]byte("{ not a valid jwks"))

	unknownPriv, _ := generateKey(t, "rotated-kid")
	token := signEdDSA(t, unknownPriv, "rotated-kid", Claims{Subject: "u", Exp: 9999999999})
	if _, err := v.Verify(context.Background(), token); err == nil {
		t.Fatal("expected verification to fail when the forced JWKS refetch fails")
	}
}
