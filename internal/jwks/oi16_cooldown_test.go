package jwks

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// GO-R1-2 (D-4): CONTRACT.md §12.4 rule 2's conformance test for the
// unknown-kid cooldown, cited by §10.1 rule 12. Against a counting server and
// a warm cache, 50 tokens each with a different unknown kid, presented within
// one window (the injected clock held still), cause at most one JWKS fetch and
// are all rejected. Then, with the clock past the window and the server
// serving a rotated set, a token with the new kid is accepted after exactly
// one fetch. It runs against both verification entry points: the access-token
// path (VerifySignatureOnlyUnchecked, under every guard) and VerifyPayload
// (the ID-token and logout-token paths).

type cooldownPath struct {
	name   string
	verify func(v *Verifier, tok []byte) error
}

var cooldownPaths = []cooldownPath{
	{"VerifySignatureOnlyUnchecked", func(v *Verifier, tok []byte) error {
		_, err := v.VerifySignatureOnlyUnchecked(context.Background(), tok)
		return err
	}},
	{"VerifyPayload", func(v *Verifier, tok []byte) error {
		_, err := v.VerifyPayload(context.Background(), tok)
		return err
	}},
}

func TestJWKS_UnknownKidCooldown_FiftyKidsOneFetchThenRotation(t *testing.T) {
	for _, path := range cooldownPaths {
		t.Run(path.name, func(t *testing.T) {
			priv1, pub1 := generateKey(t, "kid-1")
			srv := newMutableJWKSServer(t, marshalSet(t, pub1))
			v, err := NewVerifier(context.Background(), srv.URL, srv.Client())
			if err != nil {
				t.Fatalf("NewVerifier: %v", err)
			}
			clock := time.Unix(1_900_000_000, 0)
			v.now = func() time.Time { return clock }

			claims := Claims{Subject: "s", TenantID: "t", OrgID: "o", Exp: at(time.Now().Add(time.Hour))}
			// Warm cache: one token with the served kid.
			if err := path.verify(v, signEdDSA(t, priv1, "kid-1", claims)); err != nil {
				t.Fatalf("warm-up verify: %v", err)
			}
			warm := srv.Hits()

			for i := 0; i < 50; i++ {
				kid := fmt.Sprintf("forged-%d", i)
				priv, _ := generateKey(t, kid)
				if err := path.verify(v, signEdDSA(t, priv, kid, claims)); err == nil {
					t.Fatalf("token %d with unknown kid %q was accepted", i, kid)
				}
			}
			if extra := srv.Hits() - warm; extra > 1 {
				t.Fatalf("50 unknown kids inside one cooldown window caused %d JWKS fetches, want at most 1", extra)
			}

			// A kid-less token is refused too, and fetches nothing inside the window.
			before := srv.Hits()
			if err := path.verify(v, n14Token(t, priv1, "", "", n14Claims(nil))); err == nil {
				t.Fatal("a token with no kid was accepted")
			}
			if srv.Hits() != before {
				t.Fatalf("a kid-less token inside the window caused %d fetches", srv.Hits()-before)
			}

			// Rotation: past the window, the server publishes kid-2.
			priv2, pub2 := generateKey(t, "kid-2")
			srv.setBody(marshalSet(t, pub1, pub2))
			clock = clock.Add(minRefetchInterval + time.Second)
			before = srv.Hits()
			if err := path.verify(v, signEdDSA(t, priv2, "kid-2", claims)); err != nil {
				t.Fatalf("a rotated key must be accepted after one fetch once the window has passed: %v", err)
			}
			if got := srv.Hits() - before; got != 1 {
				t.Fatalf("accepting the rotated key took %d fetches, want exactly 1", got)
			}
		})
	}
}

// The window also holds when the JWKS endpoint fails: a failed forced fetch
// opens it like a successful one, so an outage is not hammered either.
func TestJWKS_UnknownKidCooldown_HoldsWhenTheFetchFails(t *testing.T) {
	priv1, pub1 := generateKey(t, "kid-1")
	srv := newMutableJWKSServer(t, marshalSet(t, pub1))
	v, err := NewVerifier(context.Background(), srv.URL, srv.Client())
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	clock := time.Unix(1_900_000_000, 0)
	v.now = func() time.Time { return clock }
	claims := Claims{Subject: "s", TenantID: "t", OrgID: "o", Exp: at(time.Now().Add(time.Hour))}
	if _, err := v.VerifyPayload(context.Background(), signEdDSA(t, priv1, "kid-1", claims)); err != nil {
		t.Fatalf("warm-up: %v", err)
	}
	srv.setBody([]byte("not a jwks"))
	warm := srv.Hits()
	for i := 0; i < 10; i++ {
		kid := fmt.Sprintf("forged-%d", i)
		priv, _ := generateKey(t, kid)
		_, err := v.VerifyPayload(context.Background(), signEdDSA(t, priv, kid, claims))
		if !errors.Is(err, ErrUnknownKid) {
			t.Fatalf("want ErrUnknownKid, got %v", err)
		}
	}
	if extra := srv.Hits() - warm; extra > 1 {
		t.Fatalf("a failing JWKS endpoint was fetched %d times inside one window, want at most 1", extra)
	}
}
