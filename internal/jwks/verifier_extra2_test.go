package jwks

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"
)

// TestNewVerifierForURL_RegisterFailure proves the cache.Register error
// branch: a URL the registration step itself rejects.
func TestNewVerifierForURL_RegisterFailure(t *testing.T) {
	if _, err := NewVerifierForURL(context.Background(), "://not-a-valid-url", nil); err == nil {
		t.Fatal("expected an error for a malformed jwks URL")
	}
}

// TestVerifyPayload_MissingAlgHeader proves algOrNone's "(absent)" branch: a
// compact JWS whose protected header carries no "alg" field at all.
func TestVerifyPayload_MissingAlgHeader(t *testing.T) {
	_, pub := generateKey(t, "kid-1")
	srv := newMutableJWKSServer(t, marshalSet(t, pub))
	v, err := NewVerifier(context.Background(), srv.Server.URL, srv.Server.Client())
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	// A syntactically valid compact JWS (header.payload.signature, all
	// base64url) whose protected header carries NO "alg" field at all —
	// built directly, without jws.Sign, which always sets alg. The
	// signature segment is arbitrary bytes: this token is never expected to
	// verify, only to reach the alg-check code path.
	headerJSON, err := json.Marshal(map[string]string{"typ": "JWT"})
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	token := []byte(enc(headerJSON) + "." + enc([]byte(`{"sub":"u"}`)) + "." + enc([]byte("sig")))

	if _, err := v.VerifyPayload(context.Background(), token); err == nil {
		t.Fatal("expected an error for a token with no alg header")
	}
}
