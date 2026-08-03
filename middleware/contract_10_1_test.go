package middleware

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

// ---------------------------------------------------------------------------
// CONTRACT.md §10.1 — "Minimum local-verification set (normative)".
//
// This file is the complete required negative-test set for the §10 guard. It
// exists because SEC-071 and SEC-080 were the SAME defect found independently
// in two SDKs: each verified a different SUBSET of the token, and each subset
// looked complete in isolation. Coverage of one rule proves nothing about the
// others, so all seven are asserted here, together, against the real
// middleware and the real JWKS verifier — no stubs.
// ---------------------------------------------------------------------------

// signAlgNone hand-builds an `alg: none` JWS (a header, a payload, and an
// EMPTY signature segment). jws.Sign cannot produce one, which is the point:
// this shape only ever arrives from an attacker. It carries a kid the JWKS
// really does serve, so the only thing that can reject it is the alg pin
// running BEFORE the key lookup (§10.1 rule 1).
func signAlgNone(t *testing.T, kid string, claims testClaims) string {
	t.Helper()
	header, err := json.Marshal(map[string]any{"alg": "none", "typ": "JWT", "kid": kid})
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	payload := map[string]any{
		"sub":       claims.Subject,
		"tenant_id": claims.TenantID,
		"org_id":    claims.OrgID,
	}
	if claims.Exp != nil {
		payload["exp"] = *claims.Exp
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	enc := base64.RawURLEncoding
	return fmt.Sprintf("%s.%s.", enc.EncodeToString(header), enc.EncodeToString(body))
}

// signHS256WithKid mints an HS256 token whose `kid` names a key the JWKS
// serves as an Ed25519 key — the classic algorithm-confusion attempt. §10.1
// rule 1 requires it be rejected WITHOUT consulting that key.
func signHS256WithKid(t *testing.T, kid string, claims testClaims) string {
	t.Helper()
	payload := map[string]any{
		"sub":       claims.Subject,
		"tenant_id": claims.TenantID,
		"org_id":    claims.OrgID,
	}
	if claims.Exp != nil {
		payload["exp"] = *claims.Exp
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	key, err := jwk.Import([]byte("attacker-chosen-hmac-secret"))
	if err != nil {
		t.Fatalf("jwk.Import hmac: %v", err)
	}
	if err := key.Set(jwk.KeyIDKey, kid); err != nil {
		t.Fatalf("set kid: %v", err)
	}
	signed, err := jws.Sign(body, jws.WithKey(jwa.HS256(), key))
	if err != nil {
		t.Fatalf("jws.Sign HS256: %v", err)
	}
	return string(signed)
}

// assertRejected drives one token through the guard and asserts the wrapped
// handler is never reached and the response is the standardized 401 body.
func assertRejected(t *testing.T, mw func(http.Handler) http.Handler, token string) {
	t.Helper()
	rec := &recordingHandler{}
	h := mw(rec.handler())

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if rec.called {
		t.Fatal("SECURITY: the guard admitted a token §10.1 requires it to reject")
	}
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
	assertJSONErrorBody(t, w.Body.Bytes())
}

func assertAdmitted(t *testing.T, mw func(http.Handler) http.Handler, token string) {
	t.Helper()
	rec := &recordingHandler{}
	h := mw(rec.handler())

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if !rec.called {
		t.Fatalf("expected the guard to admit this token; got %d %s", w.Code, w.Body.String())
	}
}

// TestContract101_RequiredNegativeSet is the §10.1 "Required negative tests"
// list, in order.
func TestContract101_RequiredNegativeSet(t *testing.T) {
	priv, pubJWK := generateTestKey(t, "kid-1")
	jwksSrv := newTestJWKSServer(t, pubJWK)
	verifier := newTestVerifier(t, jwksSrv)
	mw := Middleware(verifier, testConfiguredTenant)

	t.Run("rule 2 — expired token", func(t *testing.T) {
		claims := validClaims()
		// Beyond ClockSkewLeeway, so the leeway cannot excuse it.
		claims.Exp = at(time.Now().Add(-2 * time.Hour))
		assertRejected(t, mw, signTestToken(t, priv, "kid-1", claims))
	})

	t.Run("rule 2 — token with NO exp claim", func(t *testing.T) {
		// The SEC-080 defect verbatim: a guard that only compares an exp it
		// found accepts this permanent credential outright.
		claims := validClaims()
		claims.Exp = nil
		token := signTestToken(t, priv, "kid-1", claims)

		// Guard rail on the fixture itself: prove the claim really is absent,
		// so a future refactor cannot make this test silently vacuous.
		if payload := decodeTestPayload(t, token); payload["exp"] != nil {
			t.Fatalf("fixture is vacuous: expected no exp claim, payload = %v", payload)
		}
		assertRejected(t, mw, token)
	})

	t.Run("rule 2 — non-numeric exp claim", func(t *testing.T) {
		// A JSON STRING is not a NumericDate. It must be rejected, not
		// coerced and not skipped.
		body := []byte(`{"sub":"user-123","tenant_id":"` + testConfiguredTenant + `","exp":"not-a-number"}`)
		assertRejected(t, mw, signTestTokenRaw(t, priv, "kid-1", body))
	})

	t.Run("rule 3 — nbf in the future", func(t *testing.T) {
		claims := validClaims()
		claims.Nbf = at(time.Now().Add(2 * time.Hour))
		assertRejected(t, mw, signTestToken(t, priv, "kid-1", claims))
	})

	t.Run("rule 4 — token for a DIFFERENT tenant", func(t *testing.T) {
		claims := validClaims()
		claims.TenantID = "tenant-somebody-else"
		assertRejected(t, mw, signTestToken(t, priv, "kid-1", claims))
	})

	t.Run("rule 4 — token with NO tenant_id claim", func(t *testing.T) {
		body := []byte(`{"sub":"user-123","exp":` + fmt.Sprint(time.Now().Add(time.Hour).Unix()) + `}`)
		assertRejected(t, mw, signTestTokenRaw(t, priv, "kid-1", body))
	})

	t.Run("rule 4 — guard with NO configured tenant fails closed", func(t *testing.T) {
		unconfigured := Middleware(verifier, "")
		// A perfectly good token, and it must STILL be rejected: an
		// unconfigured guard has nothing to assert tenant_id against.
		assertRejected(t, unconfigured, signTestToken(t, priv, "kid-1", validClaims()))
	})

	t.Run("rule 1 — alg: none", func(t *testing.T) {
		assertRejected(t, mw, signAlgNone(t, "kid-1", validClaims()))
	})

	t.Run("rule 1 — HS-signed token bearing an EdDSA key id", func(t *testing.T) {
		assertRejected(t, mw, signHS256WithKid(t, "kid-1", validClaims()))
	})
}

// TestContract101_IssuerIsConditional covers rule 5: unset means unchecked;
// once configured, a mismatch is rejected.
func TestContract101_IssuerIsConditional(t *testing.T) {
	priv, pubJWK := generateTestKey(t, "kid-1")
	jwksSrv := newTestJWKSServer(t, pubJWK)
	verifier := newTestVerifier(t, jwksSrv)

	t.Run("unconfigured — no issuer check at all", func(t *testing.T) {
		mw := Middleware(verifier, testConfiguredTenant)
		claims := validClaims()
		claims.Issuer = "https://whoever.example.com"
		assertAdmitted(t, mw, signTestToken(t, priv, "kid-1", claims))
	})

	t.Run("configured and matching", func(t *testing.T) {
		mw := Middleware(verifier, testConfiguredTenant, WithExpectedIssuer("https://axiam.example.com"))
		claims := validClaims()
		claims.Issuer = "https://axiam.example.com"
		assertAdmitted(t, mw, signTestToken(t, priv, "kid-1", claims))
	})

	t.Run("configured and MISMATCHED", func(t *testing.T) {
		mw := Middleware(verifier, testConfiguredTenant, WithExpectedIssuer("https://axiam.example.com"))
		claims := validClaims()
		claims.Issuer = "https://evil.example.com"
		assertRejected(t, mw, signTestToken(t, priv, "kid-1", claims))
	})

	t.Run("configured but the token carries NO iss — fails closed", func(t *testing.T) {
		mw := Middleware(verifier, testConfiguredTenant, WithExpectedIssuer("https://axiam.example.com"))
		assertRejected(t, mw, signTestToken(t, priv, "kid-1", validClaims()))
	})
}

// TestContract101_AudienceIsConditional covers rule 6, including the
// string-or-array shape RFC 7519 permits for `aud`.
func TestContract101_AudienceIsConditional(t *testing.T) {
	priv, pubJWK := generateTestKey(t, "kid-1")
	jwksSrv := newTestJWKSServer(t, pubJWK)
	verifier := newTestVerifier(t, jwksSrv)

	t.Run("unconfigured — no audience check at all", func(t *testing.T) {
		mw := Middleware(verifier, testConfiguredTenant)
		claims := validClaims()
		claims.Audience = "someone-elses-api"
		assertAdmitted(t, mw, signTestToken(t, priv, "kid-1", claims))
	})

	t.Run("configured, single-string aud, matching", func(t *testing.T) {
		mw := Middleware(verifier, testConfiguredTenant, WithExpectedAudience("axiam:user"))
		claims := validClaims()
		claims.Audience = "axiam:user"
		assertAdmitted(t, mw, signTestToken(t, priv, "kid-1", claims))
	})

	t.Run("configured, array aud containing the expectation", func(t *testing.T) {
		mw := Middleware(verifier, testConfiguredTenant, WithExpectedAudience("axiam:user"))
		claims := validClaims()
		claims.Audience = []string{"some-other-api", "axiam:user"}
		assertAdmitted(t, mw, signTestToken(t, priv, "kid-1", claims))
	})

	t.Run("configured and MISMATCHED", func(t *testing.T) {
		mw := Middleware(verifier, testConfiguredTenant, WithExpectedAudience("axiam:user"))
		claims := validClaims()
		claims.Audience = []string{"axiam:service"}
		assertRejected(t, mw, signTestToken(t, priv, "kid-1", claims))
	})

	t.Run("configured but the token carries NO aud — fails closed", func(t *testing.T) {
		mw := Middleware(verifier, testConfiguredTenant, WithExpectedAudience("axiam:user"))
		assertRejected(t, mw, signTestToken(t, priv, "kid-1", validClaims()))
	})
}

// TestContract101_PositiveShapes pins the shapes §10.1 explicitly calls
// VALID, so a future tightening cannot over-reject.
func TestContract101_PositiveShapes(t *testing.T) {
	priv, pubJWK := generateTestKey(t, "kid-1")
	jwksSrv := newTestJWKSServer(t, pubJWK)
	verifier := newTestVerifier(t, jwksSrv)
	mw := Middleware(verifier, testConfiguredTenant)

	t.Run("absent nbf is valid (rule 3)", func(t *testing.T) {
		claims := validClaims()
		claims.Nbf = nil
		assertAdmitted(t, mw, signTestToken(t, priv, "kid-1", claims))
	})

	t.Run("nbf already passed is valid", func(t *testing.T) {
		claims := validClaims()
		claims.Nbf = at(time.Now().Add(-time.Minute))
		assertAdmitted(t, mw, signTestToken(t, priv, "kid-1", claims))
	})

	t.Run("nbf inside the named clock skew is tolerated (rule 7)", func(t *testing.T) {
		claims := validClaims()
		claims.Nbf = at(time.Now().Add(30 * time.Second)) // < 60 s ClockSkewLeeway
		assertAdmitted(t, mw, signTestToken(t, priv, "kid-1", claims))
	})
}

func decodeTestPayload(t *testing.T, token string) map[string]any {
	t.Helper()
	msg, err := jws.Parse([]byte(token))
	if err != nil {
		t.Fatalf("jws.Parse: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(msg.Payload(), &out); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return out
}
