// CONTRACT.md §21.7.2 — DPoP proof verification, all ten checks.
//
// Each check gets a negative test, because §21.7.2's whole premise is that a
// verifier missing one of them still reports success. A suite that only proved
// a good proof passes would not distinguish this package from returning the
// thumbprint unconditionally.
package dpop

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

const (
	testMethod = "POST"
	testURI    = "https://rs.example.com/v1/things"
	testToken  = "eyJhbGciOiJFZERTQSJ9.e30.sig"
)

type testKey struct {
	priv ed25519.PrivateKey
	jwk  map[string]any
}

func newKey(t *testing.T) testKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return testKey{
		priv: priv,
		jwk: map[string]any{
			"kty": "OKP",
			"crv": "Ed25519",
			"x":   base64.RawURLEncoding.EncodeToString(pub),
		},
	}
}

var jtiSeq int

// signProof builds a proof by hand rather than through a JOSE library, so a
// test can put anything at all in the header — including the private material
// and bogus alg values a cooperative library would refuse to emit.
func signProof(t *testing.T, priv ed25519.PrivateKey, header, claims map[string]any) string {
	t.Helper()
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	input := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
	sig := ed25519.Sign(priv, []byte(input))
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func claimsWith(overrides map[string]any) map[string]any {
	jtiSeq++
	c := map[string]any{
		"htm": testMethod,
		"htu": testURI,
		"iat": time.Now().Unix(),
		"jti": fmt.Sprintf("jti-%d", jtiSeq),
		"ath": AccessTokenHash(testToken),
	}
	for k, v := range overrides {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	return c
}

func header(k testKey, overrides map[string]any) map[string]any {
	h := map[string]any{"typ": "dpop+jwt", "alg": "EdDSA", "jwk": k.jwk}
	for key, v := range overrides {
		if v == nil {
			delete(h, key)
		} else {
			h[key] = v
		}
	}
	return h
}

func goodProof(t *testing.T, k testKey) string {
	return signProof(t, k.priv, header(k, nil), claimsWith(nil))
}

func req() Request {
	return Request{Method: testMethod, URI: testURI, AccessToken: testToken}
}

// -----------------------------------------------------------------------------
// The happy path
// -----------------------------------------------------------------------------

func TestWellFormedProofVerifiesAndReturnsThumbprint(t *testing.T) {
	k := newKey(t)
	jkt, err := VerifyProof(goodProof(t, k), req(), NewInMemoryJtiStore())
	if err != nil {
		t.Fatalf("expected the proof to verify, got %v", err)
	}
	// Returning the thumbprint rather than a bare nil error is what lets a
	// guard pass a value onward that could only have come from a verified proof.
	want, _ := ThumbprintS256(k.jwk)
	if jkt != want {
		t.Errorf("thumbprint = %q, want %q", jkt, want)
	}
	if len(jkt) != 43 {
		t.Errorf("thumbprint length = %d, want 43", len(jkt))
	}
}

func TestQueryAndFragmentAreStrippedFromBothSidesOfHTU(t *testing.T) {
	k := newKey(t)
	r := req()
	r.URI = testURI + "?page=2#frag"
	if _, err := VerifyProof(goodProof(t, k), r, NewInMemoryJtiStore()); err != nil {
		t.Fatalf("query string must not matter: %v", err)
	}
}

// -----------------------------------------------------------------------------
// One negative test per check
// -----------------------------------------------------------------------------

// Without pinning typ, any other JWT signed by the same key — an access token,
// an ID token — is replayable as a proof.
func TestCheck1ProofWithoutDPoPTypIsRefused(t *testing.T) {
	k := newKey(t)
	p := signProof(t, k.priv, header(k, map[string]any{"typ": "JWT"}), claimsWith(nil))
	_, err := VerifyProof(p, req(), NewInMemoryJtiStore())
	if !errors.Is(err, ErrWrongTyp) {
		t.Fatalf("got %v, want ErrWrongTyp", err)
	}
}

func TestCheck1TypComparisonIsCaseInsensitive(t *testing.T) {
	k := newKey(t)
	p := signProof(t, k.priv, header(k, map[string]any{"typ": "DPoP+JWT"}), claimsWith(nil))
	if _, err := VerifyProof(p, req(), NewInMemoryJtiStore()); err != nil {
		t.Fatalf("typ is case-insensitive: %v", err)
	}
}

// The attack check 2 exists for, run for real.
//
// The attacker holds no private key. They take the PUBLIC key out of a proof
// they observed, use its raw bytes as an HMAC secret, sign a proof of their own
// with HS256, and embed the same public jwk. A verifier that reads alg from the
// header computes HMAC with that public key, gets a match, and reports success
// — the signature is valid, just not proof of anything.
func TestCheck2PublicKeyAsHMACSecretForgeryIsRefused(t *testing.T) {
	k := newKey(t)
	pubBytes, _ := base64.RawURLEncoding.DecodeString(k.jwk["x"].(string))

	hb, _ := json.Marshal(header(k, map[string]any{"alg": "HS256"}))
	cb, _ := json.Marshal(claimsWith(nil))
	input := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)

	mac := hmac.New(sha256.New, pubBytes)
	mac.Write([]byte(input))
	forged := input + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	if _, err := VerifyProof(forged, req(), NewInMemoryJtiStore()); err == nil {
		t.Fatal("the HMAC forgery was accepted — the header alg was believed")
	}
}

func TestCheck2UnpermittedKeyTypeIsRefused(t *testing.T) {
	k := newKey(t)
	h := header(k, map[string]any{
		"jwk": map[string]any{"kty": "EC", "crv": "P-521", "x": "AA", "y": "AA"},
	})
	_, err := VerifyProof(signProof(t, k.priv, h, claimsWith(nil)), req(), NewInMemoryJtiStore())
	if !errors.Is(err, ErrUnsupportedKey) {
		t.Fatalf("got %v, want ErrUnsupportedKey", err)
	}
}

func TestCheck3NoJWKOrForeignSignatureIsRefused(t *testing.T) {
	k := newKey(t)

	noJWK := signProof(t, k.priv, header(k, map[string]any{"jwk": nil}), claimsWith(nil))
	if _, err := VerifyProof(noJWK, req(), NewInMemoryJtiStore()); !errors.Is(err, ErrMalformedProof) {
		t.Fatalf("got %v, want ErrMalformedProof", err)
	}

	// Signed by a DIFFERENT key than the one it embeds.
	other := newKey(t)
	forged := signProof(t, other.priv, header(k, nil), claimsWith(nil))
	if _, err := VerifyProof(forged, req(), NewInMemoryJtiStore()); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("got %v, want ErrBadSignature", err)
	}
}

// RFC 9449 §4.3. Checked against the RAW header JSON, because many JWK
// libraries silently drop these members when parsing into a public-key type —
// the check would then pass because the library hid the evidence.
func TestCheck4PrivateKeyMaterialIsRefused(t *testing.T) {
	k := newKey(t)
	for _, member := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
		leaky := map[string]any{}
		for key, v := range k.jwk {
			leaky[key] = v
		}
		leaky[member] = "c2VjcmV0"
		p := signProof(t, k.priv, header(k, map[string]any{"jwk": leaky}), claimsWith(nil))
		if _, err := VerifyProof(p, req(), NewInMemoryJtiStore()); !errors.Is(err, ErrPrivateKeyInJWK) {
			t.Errorf("member %q was not caught: %v", member, err)
		}
	}
}

func TestCheck5ProofForAnotherMethodIsRefused(t *testing.T) {
	k := newKey(t)
	p := signProof(t, k.priv, header(k, nil), claimsWith(map[string]any{"htm": "GET"}))
	if _, err := VerifyProof(p, req(), NewInMemoryJtiStore()); !errors.Is(err, ErrHTMMismatch) {
		t.Fatalf("got %v, want ErrHTMMismatch", err)
	}
}

func TestCheck6ProofForAnotherURIIsRefused(t *testing.T) {
	k := newKey(t)
	p := signProof(t, k.priv, header(k, nil),
		claimsWith(map[string]any{"htu": "https://rs.example.com/v1/other"}))
	if _, err := VerifyProof(p, req(), NewInMemoryJtiStore()); !errors.Is(err, ErrHTUMismatch) {
		t.Fatalf("got %v, want ErrHTUMismatch", err)
	}
}

// A normalising comparison is where two unequal URIs become equal. Only query
// and fragment come off; case, default ports and trailing slashes are left
// exactly as they are.
func TestCheck6HTUIsComparedWithoutNormalisation(t *testing.T) {
	if got := CanonicalHTU("https://a.example/p?q=1#f"); got != "https://a.example/p" {
		t.Errorf("CanonicalHTU = %q", got)
	}
	for _, pair := range [][2]string{
		{"https://A.example/P", "https://a.example/p"},
		{"https://a.example:443/p", "https://a.example/p"},
		{"https://a.example/p/", "https://a.example/p"},
	} {
		if CanonicalHTU(pair[0]) == CanonicalHTU(pair[1]) {
			t.Errorf("%q and %q must not compare equal", pair[0], pair[1])
		}
	}
}

// Both directions. A proof from the future is as suspect as a stale one: it is
// how a one-sided skew allowance becomes a long-lived proof.
func TestCheck7StaleOrFutureProofIsRefused(t *testing.T) {
	k := newKey(t)
	now := time.Now()
	for _, offset := range []time.Duration{-IatLeeway - 5*time.Second, IatLeeway + 5*time.Second} {
		p := signProof(t, k.priv, header(k, nil),
			claimsWith(map[string]any{"iat": now.Add(offset).Unix()}))
		r := req()
		r.Now = now
		if _, err := VerifyProof(p, r, NewInMemoryJtiStore()); !errors.Is(err, ErrStaleProof) {
			t.Errorf("offset %s accepted: %v", offset, err)
		}
	}
}

// Freshness bounds the window; the jti guard is what makes the window unusable.
// Without this the same proof works repeatedly for a full minute.
func TestCheck8ReplayedProofIsRefused(t *testing.T) {
	k := newKey(t)
	store := NewInMemoryJtiStore()
	p := goodProof(t, k)
	if _, err := VerifyProof(p, req(), store); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if _, err := VerifyProof(p, req(), store); !errors.Is(err, ErrReplayedProof) {
		t.Fatalf("got %v, want ErrReplayedProof", err)
	}
}

// The jti claim is a mutation, so it runs last. Claiming it earlier would let
// an attacker burn arbitrary jti values out of the store using proofs that were
// never going to verify — turning the replay guard into a denial-of-service
// surface against legitimate proofs.
func TestCheck8JtiIsClaimedOnlyAfterEveryOtherCheckPasses(t *testing.T) {
	k := newKey(t)
	store := NewInMemoryJtiStore()
	doomed := signProof(t, k.priv, header(k, nil),
		claimsWith(map[string]any{"htm": "GET", "jti": "precious"}))

	if _, err := VerifyProof(doomed, req(), store); !errors.Is(err, ErrHTMMismatch) {
		t.Fatalf("got %v, want ErrHTMMismatch", err)
	}
	if !store.Claim("precious", time.Now().Add(time.Minute)) {
		t.Error("a failed proof must not burn its jti")
	}
}

// Without ath, a proof captured on one request can be re-aimed at a different
// token held by the same key.
func TestCheck9ProofAimedAtAnotherTokenIsRefused(t *testing.T) {
	k := newKey(t)
	p := signProof(t, k.priv, header(k, nil),
		claimsWith(map[string]any{"ath": AccessTokenHash("some.other.token")}))
	if _, err := VerifyProof(p, req(), NewInMemoryJtiStore()); !errors.Is(err, ErrATHMismatch) {
		t.Fatalf("got %v, want ErrATHMismatch", err)
	}
}

func TestCheck9ProofWithNoATHIsRefused(t *testing.T) {
	k := newKey(t)
	p := signProof(t, k.priv, header(k, nil), claimsWith(map[string]any{"ath": nil}))
	if _, err := VerifyProof(p, req(), NewInMemoryJtiStore()); !errors.Is(err, ErrMalformedProof) {
		t.Fatalf("got %v, want ErrMalformedProof", err)
	}
}

// This is the step that ties the proof to the token; the other nine are what
// make the proof mean anything.
func TestCheck10ProofByWrongKeyIsRefused(t *testing.T) {
	k := newKey(t)
	other := newKey(t)
	otherJkt, _ := ThumbprintS256(other.jwk)
	r := req()
	r.ExpectedJkt = otherJkt
	if _, err := VerifyProof(goodProof(t, k), r, NewInMemoryJtiStore()); !errors.Is(err, ErrThumbprintNoMatch) {
		t.Fatalf("got %v, want ErrThumbprintNoMatch", err)
	}
}

// -----------------------------------------------------------------------------
// Thumbprint and framing
// -----------------------------------------------------------------------------

// The RFC's own worked example. A thumbprint implementation that is
// self-consistent but wrong agrees with itself on every round trip, so the only
// useful test is against a published vector.
func TestThumbprintMatchesRFC7638AppendixA(t *testing.T) {
	got, err := ThumbprintS256(map[string]any{
		"kty": "RSA",
		"n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt" +
			"VT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn6" +
			"4tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FD" +
			"W2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n9" +
			"1CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINH" +
			"aQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
		"e": "AQAB",
	})
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	if want := "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"; got != want {
		t.Errorf("thumbprint = %q, want %q", got, want)
	}
}

// kid/use/alg/x5c are excluded by the spec — which is exactly what makes the
// thumbprint stable across two different encodings of the same key.
func TestThumbprintIgnoresMembersOutsideRFC7638Set(t *testing.T) {
	k := newKey(t)
	decorated := map[string]any{"kid": "abc", "use": "sig", "alg": "EdDSA", "x5c": []string{"zz"}}
	for key, v := range k.jwk {
		decorated[key] = v
	}
	a, _ := ThumbprintS256(k.jwk)
	b, _ := ThumbprintS256(decorated)
	if a != b {
		t.Errorf("decoration changed the thumbprint: %q vs %q", a, b)
	}
}

// RFC 9449 §4.2 makes exactly one the rule. Rejecting beats picking the first,
// which is how a verifier and a downstream parser end up reading different
// proofs.
func TestHeaderCarryingTwoProofsIsRefused(t *testing.T) {
	k := newKey(t)
	p := goodProof(t, k)
	_, err := VerifyProof(p+","+p, req(), NewInMemoryJtiStore())
	if !errors.Is(err, ErrMalformedProof) || !strings.Contains(err.Error(), "exactly one proof") {
		t.Fatalf("got %v, want the exactly-one-proof rejection", err)
	}
}

func TestMalformedProofIsRefusedRatherThanPanicking(t *testing.T) {
	for _, junk := range []string{"", "not-a-jwt", "a.b", "a.b.c.d", "!!!.###.$$$"} {
		if _, err := VerifyProof(junk, req(), NewInMemoryJtiStore()); err == nil {
			t.Errorf("accepted %q", junk)
		}
	}
}
