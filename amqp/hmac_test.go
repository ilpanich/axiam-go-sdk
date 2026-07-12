package amqp

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// fixtureSigningKey is the per-tenant AMQP signing subkey used across the
// amqp package's tests (also referenced by consumer_test.go).
const fixtureSigningKey = "consumer-test-signing-key"

// hmacHex computes hex(HMAC-SHA256(key, canonical)) — the exact operation the
// Rust server performs in sign_payload (crates/axiam-amqp/src/messages.rs).
// Tests construct `canonical` as an explicit byte literal in the server's
// field-DECLARATION order, so the resulting signature is independent of the
// verifier's own canonicalization (it is NOT re-derived the same way
// verifyHMAC re-serializes — that would be tautological).
func hmacHex(t *testing.T, key, canonical string) string {
	t.Helper()
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(canonical))
	return hex.EncodeToString(mac.Sum(nil))
}

// A realistic, full AuthzRequest whose DECLARATION order
// (correlation_id, tenant_id, subject_id, action, resource_id, key_version,
// nonce, issued_at) differs from ALPHABETICAL order (action, correlation_id,
// issued_at, key_version, nonce, resource_id, subject_id, tenant_id). This
// is the regression case the old buggy verifier (map re-marshal, which
// alphabetizes keys) got wrong: it would sign/verify over the alphabetical
// byte sequence, never the declaration-order sequence the server signed.
//
// NEW-4 (v2): nonce and issued_at are ALWAYS emitted (no skip_serializing_if
// on the server side), landing after key_version and before hmac_signature.
const (
	fixtureCorrelationID = "11111111-1111-1111-1111-111111111111"
	fixtureTenantID      = "22222222-2222-2222-2222-222222222222"
	fixtureSubjectID     = "33333333-3333-3333-3333-333333333333"
	fixtureResourceID    = "44444444-4444-4444-4444-444444444444"
	fixtureNonce         = "99999999-9999-9999-9999-999999999999"
	fixtureIssuedAt      = "2026-07-10T12:00:00Z"

	// Server-signed bytes: serde_json emits AuthzRequest in declaration
	// order, compact, with hmac_signature absent and key_version/nonce/
	// issued_at always present.
	fixtureCanonicalDeclOrder = `{"correlation_id":"11111111-1111-1111-1111-111111111111",` +
		`"tenant_id":"22222222-2222-2222-2222-222222222222",` +
		`"subject_id":"33333333-3333-3333-3333-333333333333",` +
		`"action":"read",` +
		`"resource_id":"44444444-4444-4444-4444-444444444444",` +
		`"key_version":2,` +
		`"nonce":"99999999-9999-9999-9999-999999999999",` +
		`"issued_at":"2026-07-10T12:00:00Z"}`

	// The byte sequence the OLD buggy Go verifier signed: the same fields
	// with keys sorted alphabetically (what json.Marshal(map[...]) produces).
	fixtureCanonicalAlphaOrder = `{"action":"read",` +
		`"correlation_id":"11111111-1111-1111-1111-111111111111",` +
		`"issued_at":"2026-07-10T12:00:00Z",` +
		`"key_version":2,` +
		`"nonce":"99999999-9999-9999-9999-999999999999",` +
		`"resource_id":"44444444-4444-4444-4444-444444444444",` +
		`"subject_id":"33333333-3333-3333-3333-333333333333",` +
		`"tenant_id":"22222222-2222-2222-2222-222222222222"}`
)

// wire builds an on-the-wire AuthzRequest body (declaration order, matching
// how the server actually serializes) with the given hmac_signature attached
// as the trailing field.
func wire(sig string) string {
	return `{"correlation_id":"11111111-1111-1111-1111-111111111111",` +
		`"tenant_id":"22222222-2222-2222-2222-222222222222",` +
		`"subject_id":"33333333-3333-3333-3333-333333333333",` +
		`"action":"read",` +
		`"resource_id":"44444444-4444-4444-4444-444444444444",` +
		`"key_version":2,` +
		`"nonce":"99999999-9999-9999-9999-999999999999",` +
		`"issued_at":"2026-07-10T12:00:00Z",` +
		`"hmac_signature":"` + sig + `"}`
}

// TestVerifyHMAC_DeclarationOrderAuthzRequest is the core regression test for
// SDK-Q01 / X-1: the verifier MUST canonicalize in the server's declaration
// order, not alphabetical order.
func TestVerifyHMAC_DeclarationOrderAuthzRequest(t *testing.T) {
	key := fixtureSigningKey

	t.Run("accepts a signature over the server's declaration-order bytes", func(t *testing.T) {
		sig := hmacHex(t, key, fixtureCanonicalDeclOrder)
		ok, meta := verifyHMAC([]byte(key), []byte(wire(sig)))
		if !ok {
			t.Fatal("verifyHMAC must accept a signature computed over the server's declaration-order bytes")
		}
		if meta.KeyVersion != 2 || meta.Nonce != fixtureNonce || meta.IssuedAt != fixtureIssuedAt {
			t.Fatalf("unexpected replayMeta: %+v", meta)
		}
	})

	t.Run("rejects a signature over alphabetically-ordered bytes (the old bug)", func(t *testing.T) {
		alphaSig := hmacHex(t, key, fixtureCanonicalAlphaOrder)
		// Sanity: declaration order and alphabetical order are genuinely
		// different byte sequences, so their signatures differ. If they were
		// equal the test would be meaningless.
		if declSig := hmacHex(t, key, fixtureCanonicalDeclOrder); alphaSig == declSig {
			t.Fatal("test fixture is degenerate: alphabetical and declaration order produced the same signature")
		}
		ok, _ := verifyHMAC([]byte(key), []byte(wire(alphaSig)))
		if ok {
			t.Fatal("verifyHMAC must REJECT a signature computed over alphabetically-ordered bytes")
		}
	})
}

func TestVerifyHMAC_RejectsTamperingAndMalformed(t *testing.T) {
	key := fixtureSigningKey
	validSig := hmacHex(t, key, fixtureCanonicalDeclOrder)

	t.Run("flipped signature byte fails verification", func(t *testing.T) {
		// Flip the first hex nibble of a valid signature.
		flipped := flipFirstHex(validSig)
		ok, _ := verifyHMAC([]byte(key), []byte(wire(flipped)))
		if ok {
			t.Fatal("expected verifyHMAC to return false when the signature is tampered")
		}
	})

	t.Run("wrong signing key fails verification", func(t *testing.T) {
		ok, _ := verifyHMAC([]byte("Consumer-test-signing-key"), []byte(wire(validSig)))
		if ok {
			t.Fatal("expected verifyHMAC to return false when the signing key is wrong")
		}
	})

	t.Run("tampered body field fails verification", func(t *testing.T) {
		// Keep the valid signature but change action read -> write.
		tampered := `{"correlation_id":"11111111-1111-1111-1111-111111111111",` +
			`"tenant_id":"22222222-2222-2222-2222-222222222222",` +
			`"subject_id":"33333333-3333-3333-3333-333333333333",` +
			`"action":"write",` +
			`"resource_id":"44444444-4444-4444-4444-444444444444",` +
			`"key_version":2,` +
			`"nonce":"99999999-9999-9999-9999-999999999999",` +
			`"issued_at":"2026-07-10T12:00:00Z",` +
			`"hmac_signature":"` + validSig + `"}`
		ok, _ := verifyHMAC([]byte(key), []byte(tampered))
		if ok {
			t.Fatal("expected verifyHMAC to return false when a signed field is tampered")
		}
	})

	t.Run("missing hmac_signature fails verification (strict default)", func(t *testing.T) {
		ok, _ := verifyHMAC([]byte(key), []byte(fixtureCanonicalDeclOrder))
		if ok {
			t.Fatal("expected verifyHMAC to return false when hmac_signature is absent (strict mode default)")
		}
	})

	t.Run("non-hex signature fails verification without panic", func(t *testing.T) {
		ok, _ := verifyHMAC([]byte(key), []byte(wire("not-hex-zzzz")))
		if ok {
			t.Fatal("expected verifyHMAC to return false for a non-hex signature")
		}
	})

	t.Run("wrong-length signature fails verification without panic", func(t *testing.T) {
		ok, _ := verifyHMAC([]byte(key), []byte(wire("5135")))
		if ok {
			t.Fatal("expected verifyHMAC to return false for a wrong-length signature")
		}
	})

	t.Run("malformed JSON body fails verification without panic", func(t *testing.T) {
		ok, _ := verifyHMAC([]byte(key), []byte("not valid json {{{"))
		if ok {
			t.Fatal("expected verifyHMAC to return false for malformed JSON")
		}
	})
}

// TestVerifyHMAC_DeclarationOrderAuditEvent exercises the second signed
// message layout (AuditEventMessage), whose declaration order also differs
// from alphabetical order, including an optional (omitted) field, the raw-
// JSON metadata field, and the NEW-4 nonce/issued_at fields.
func TestVerifyHMAC_DeclarationOrderAuditEvent(t *testing.T) {
	key := fixtureSigningKey

	// AuditEventMessage declaration order: tenant_id, actor_id, actor_type,
	// action, [resource_id], outcome, [ip_address], [metadata], key_version,
	// nonce, issued_at. Here resource_id and ip_address are omitted (None);
	// metadata present.
	canonical := `{"tenant_id":"22222222-2222-2222-2222-222222222222",` +
		`"actor_id":"55555555-5555-5555-5555-555555555555",` +
		`"actor_type":"user",` +
		`"action":"login",` +
		`"outcome":"success",` +
		`"metadata":{"ip":"10.0.0.1","attempts":3},` +
		`"key_version":2,` +
		`"nonce":"99999999-9999-9999-9999-999999999999",` +
		`"issued_at":"2026-07-10T12:00:00Z"}`
	sig := hmacHex(t, key, canonical)

	body := `{"tenant_id":"22222222-2222-2222-2222-222222222222",` +
		`"actor_id":"55555555-5555-5555-5555-555555555555",` +
		`"actor_type":"user",` +
		`"action":"login",` +
		`"outcome":"success",` +
		`"metadata":{"ip":"10.0.0.1","attempts":3},` +
		`"key_version":2,` +
		`"nonce":"99999999-9999-9999-9999-999999999999",` +
		`"issued_at":"2026-07-10T12:00:00Z",` +
		`"hmac_signature":"` + sig + `"}`

	ok, meta := verifyHMAC([]byte(key), []byte(body))
	if !ok {
		t.Fatal("verifyHMAC must accept an AuditEventMessage signed over its declaration-order bytes")
	}
	if meta.KeyVersion != 2 || meta.Nonce != fixtureNonce || meta.IssuedAt != fixtureIssuedAt {
		t.Fatalf("unexpected replayMeta: %+v", meta)
	}

	// An alphabetical-order signature over the same fields must be rejected.
	alpha := `{"action":"login",` +
		`"actor_id":"55555555-5555-5555-5555-555555555555",` +
		`"actor_type":"user",` +
		`"issued_at":"2026-07-10T12:00:00Z",` +
		`"key_version":2,` +
		`"metadata":{"ip":"10.0.0.1","attempts":3},` +
		`"nonce":"99999999-9999-9999-9999-999999999999",` +
		`"outcome":"success",` +
		`"tenant_id":"22222222-2222-2222-2222-222222222222"}`
	alphaSig := hmacHex(t, key, alpha)
	alphaBody := `{"tenant_id":"22222222-2222-2222-2222-222222222222",` +
		`"actor_id":"55555555-5555-5555-5555-555555555555",` +
		`"actor_type":"user",` +
		`"action":"login",` +
		`"outcome":"success",` +
		`"metadata":{"ip":"10.0.0.1","attempts":3},` +
		`"key_version":2,` +
		`"nonce":"99999999-9999-9999-9999-999999999999",` +
		`"issued_at":"2026-07-10T12:00:00Z",` +
		`"hmac_signature":"` + alphaSig + `"}`
	ok, _ = verifyHMAC([]byte(key), []byte(alphaBody))
	if ok {
		t.Fatal("verifyHMAC must REJECT an AuditEventMessage signature computed over alphabetically-ordered bytes")
	}
}

// referenceVectorsPath is the vendored copy of the cross-language AMQP v2
// reference vectors, GENERATED by the AXIAM server's sign path
// (axiam-amqp::messages) and shared verbatim by all 7 SDKs. `go test` runs a
// package with that package's own directory as the working directory, so this
// relative path resolves without any repo-root lookup.
const referenceVectorsPath = "testdata/v2_reference_vectors.json"

// referenceVector is one server-signed message from the fixture.
type referenceVector struct {
	// CanonicalSignedJSON is the exact byte sequence the server ran HMAC over:
	// the message in declared field order with hmac_signature ABSENT.
	CanonicalSignedJSON string `json:"canonical_signed_json"`
	// HMACSignatureHex is HMAC-SHA256(derived_subkey, CanonicalSignedJSON).
	HMACSignatureHex string `json:"hmac_signature_hex"`
	// Message is the on-the-wire form, held as raw bytes so the test verifies
	// the fixture's own encoding (alphabetical key order, hmac_signature
	// present) rather than something Go re-serialized for itself.
	Message json.RawMessage `json:"message"`
}

// replayFields are the fields verifyHMAC surfaces as replayMeta; parsed from
// the fixture so the expectations are never restated by hand.
type replayFields struct {
	// uint8 mirrors replayMeta.KeyVersion — the wire format caps key_version at
	// one byte (it is fed to HKDF as a single octet).
	KeyVersion uint8  `json:"key_version"`
	Nonce      string `json:"nonce"`
	IssuedAt   string `json:"issued_at"`
}

type referenceVectors struct {
	AuditEvent   referenceVector `json:"audit_event"`
	AuthzRequest referenceVector `json:"authz_request"`
	HKDF         struct {
		// DerivedSubkeyHex is the already-derived per-tenant subkey. The Go SDK
		// never performs HKDF itself — per §8.1 it receives this pre-derived
		// subkey from the management API and never sees the master key — so the
		// test consumes it directly, matching the package's runtime contract.
		DerivedSubkeyHex string `json:"derived_subkey_hex"`
	} `json:"hkdf"`
	// MasterSigningKeyHex and TenantID are the HKDF inputs the server consumed
	// to produce DerivedSubkeyHex. Unused by this SDK; loaded only so the
	// fixture's provenance stays legible here.
	MasterSigningKeyHex string `json:"master_signing_key_hex"`
	TenantID            string `json:"tenant_id"`
}

func loadReferenceVectors(t *testing.T) referenceVectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.FromSlash(referenceVectorsPath))
	if err != nil {
		t.Fatalf("failed to read reference vectors at %s: %v", referenceVectorsPath, err)
	}
	var vectors referenceVectors
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("failed to parse reference vectors at %s: %v", referenceVectorsPath, err)
	}
	return vectors
}

// TestVerifyHMAC_ReferenceVectors is the ground-truth cross-language parity
// test for NEW-4 (CONTRACT.md §8). It loads the server-generated vectors from
// testdata/v2_reference_vectors.json and asserts, for BOTH message types:
//
//  1. The Go canonical re-marshal reproduces the fixture's
//     `canonical_signed_json` byte-for-byte, and the HMAC recomputed over
//     those bytes lands on the fixture's `hmac_signature_hex` exactly.
//  2. verifyHMAC ACCEPTS the fixture's on-the-wire `message` bytes (given in
//     alphabetical key order — incoming field order must not matter) under the
//     fixture's derived subkey, and reports the expected replay metadata.
//
// Reading the fixture rather than transcribing it is the point: if the server
// regenerates these vectors, this test must move with them or fail loudly.
func TestVerifyHMAC_ReferenceVectors(t *testing.T) {
	vectors := loadReferenceVectors(t)

	subkey, err := hex.DecodeString(vectors.HKDF.DerivedSubkeyHex)
	if err != nil {
		t.Fatalf("fixture derived_subkey_hex is not valid hex: %v", err)
	}
	if len(subkey) == 0 {
		t.Fatal("fixture derived_subkey_hex is empty — the vectors did not load")
	}

	cases := []struct {
		name string
		vec  referenceVector
		// canonical returns a fresh zero value of the canonical struct that
		// this message type serializes through.
		canonical func() any
	}{
		{"authz_request", vectors.AuthzRequest, func() any { return new(authzRequestCanonical) }},
		{"audit_event", vectors.AuditEvent, func() any { return new(auditEventCanonical) }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.vec.CanonicalSignedJSON == "" || tc.vec.HMACSignatureHex == "" || len(tc.vec.Message) == 0 {
				t.Fatalf("fixture is missing the %s vector", tc.name)
			}

			// (1) Byte-for-byte canonical parity, then HMAC parity over those bytes.
			target := tc.canonical()
			if err := json.Unmarshal([]byte(tc.vec.CanonicalSignedJSON), target); err != nil {
				t.Fatalf("failed to unmarshal fixture canonical JSON: %v", err)
			}
			remarshaled, err := json.Marshal(target)
			if err != nil {
				t.Fatalf("failed to re-marshal canonical struct: %v", err)
			}
			if string(remarshaled) != tc.vec.CanonicalSignedJSON {
				t.Fatalf("Go canonical re-marshal does not match fixture canonical_signed_json byte-for-byte:\n got: %s\nwant: %s", remarshaled, tc.vec.CanonicalSignedJSON)
			}
			mac := hmac.New(sha256.New, subkey)
			mac.Write(remarshaled)
			if gotHMAC := hex.EncodeToString(mac.Sum(nil)); gotHMAC != tc.vec.HMACSignatureHex {
				t.Fatalf("recomputed HMAC does not match fixture hmac_signature_hex: got %s want %s", gotHMAC, tc.vec.HMACSignatureHex)
			}

			// (2) The fixture's on-the-wire bytes verify. Compact them first:
			// the file stores `message` pretty-printed, and the wire form has no
			// insignificant whitespace.
			var wireBody bytes.Buffer
			if err := json.Compact(&wireBody, tc.vec.Message); err != nil {
				t.Fatalf("failed to compact fixture message: %v", err)
			}
			ok, meta := verifyHMAC(subkey, wireBody.Bytes())
			if !ok {
				t.Fatalf("verifyHMAC must ACCEPT the server-signed v2 %s reference vector", tc.name)
			}

			var want replayFields
			if err := json.Unmarshal(tc.vec.Message, &want); err != nil {
				t.Fatalf("failed to read replay fields from fixture message: %v", err)
			}
			if meta.KeyVersion != want.KeyVersion || meta.Nonce != want.Nonce || meta.IssuedAt != want.IssuedAt {
				t.Fatalf("replayMeta does not match the fixture: got %+v, want %+v", meta, want)
			}
		})
	}
}

// flipFirstHex flips the first hex character of s to a different value so the
// resulting string stays valid hex but decodes to different bytes.
func flipFirstHex(s string) string {
	if len(s) == 0 {
		return s
	}
	first := s[0]
	var repl byte = '0'
	if first == '0' {
		repl = '1'
	}
	return string(repl) + s[1:]
}
