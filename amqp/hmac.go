// Package amqp implements the AXIAM AMQP event consumer: a closure-handler
// Consume loop that HMAC-SHA256-verifies every delivery BEFORE the caller's
// handler ever runs (CONTRACT.md §8, D-07, SC#4).
package amqp

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
)

// verifyHMAC reproduces the server's canonical HMAC-SHA256 protocol
// byte-for-byte (crates/axiam-amqp/src/messages.rs sign_payload/
// verify_payload, mirrored — never imported, since this SDK must not depend
// on server crates).
//
// CRITICAL canonicalization contract: the server's wire types
// (AuthzRequest, AuditEventMessage) are typed Rust structs, NOT maps.
// serde_json serializes a struct's fields in DECLARATION ORDER, not
// alphabetical order, emitting compact JSON (no spaces) with hmac_signature
// absent at signing time (the signature is computed first, then attached).
// Optional fields (`Option<T>` with `skip_serializing_if = "Option::is_none"`)
// are omitted entirely when absent; `key_version` (a `u8` with a serde
// default but NO skip) is ALWAYS emitted as a bare integer.
//
// Go's encoding/json sorts map keys ALPHABETICALLY, so re-marshaling a
// map[string]json.RawMessage would HMAC over a different byte sequence than
// the server signed and reject every real multi-field message. Instead we
// re-serialize into a Go struct whose json-tagged fields are declared in the
// server's exact field order (json.Marshal emits struct fields in
// declaration order), reproducing serde_json's bytes precisely. This mirrors
// the order-preserving canonicalization the Python and TypeScript SDKs get
// for free from their insertion-ordered JSON parsers.
//
// Steps:
//  1. Extract the received hmac_signature (order-independent). Its absence is
//     a verification failure in strict mode (the default, CONTRACT.md §8.3) —
//     never a silent pass-through.
//  2. Reconstruct the canonical signed bytes by unmarshaling the body into
//     each known signed message layout (AuthzRequest, AuditEventMessage) and
//     re-marshaling it in declaration order, with hmac_signature excluded.
//  3. Accept iff HMAC-SHA256(signingKey, canonical) equals the received
//     signature for one of those layouts. A cryptographic match is only
//     possible for the layout the server actually signed, so trying each is
//     safe (no false accept) and needs no separate discriminator field.
//  4. Compare using hmac.Equal — constant-time, never bytes.Equal/==.
//
// Returns (false, zero-value, nil) (never panics) for malformed JSON, a
// missing/non-string signature, a non-hex signature, or a body whose JSON
// object is ambiguous (see rejectAmbiguousKeys). On a successful match, the
// returned replayMeta carries the key_version/nonce/issued_at extracted from
// whichever layout matched, for the NEW-4 replay-protection checks the caller
// runs next (verifyAndDispatch) — the cryptographic check here is
// deliberately silent on those checks; they are a separate, later gate over
// an already-authentic message.
//
// The third result is the matched canonical bytes — exactly the bytes the
// HMAC was computed over (C2). It is the ONLY byte sequence a caller may build
// the handler's view from: the received body can carry keys the struct decode
// ignored or resolved differently (case-insensitively, last key winning), and
// a handler that read the body would then act on values the signature never
// covered.
func verifyHMAC(signingKey []byte, body []byte) (bool, replayMeta, []byte) {
	// Step 0 (C2): refuse a body whose object has duplicate keys, or keys
	// that differ only by case. Such a body is the only way the struct decode
	// below and any other decoder can disagree about which value a key holds.
	if rejectAmbiguousKeys(body) {
		return false, replayMeta{}, nil
	}

	// Step 1: extract the received signature, independent of field order.
	var envelope struct {
		HMACSignature *string `json:"hmac_signature"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return false, replayMeta{}, nil
	}
	if envelope.HMACSignature == nil {
		// Strict mode default (CONTRACT.md §8.3): a message with no
		// hmac_signature field (or a non-string value) is rejected, never
		// silently accepted.
		return false, replayMeta{}, nil
	}

	expected, err := hex.DecodeString(*envelope.HMACSignature)
	if err != nil {
		return false, replayMeta{}, nil
	}

	// Steps 2-4: try each known declaration-order layout; accept on the
	// first cryptographic match.
	for _, candidate := range canonicalCandidates(body) {
		mac := hmac.New(sha256.New, signingKey)
		mac.Write(candidate.bytes)
		if hmac.Equal(mac.Sum(nil), expected) {
			return true, candidate.meta, candidate.bytes
		}
	}
	return false, replayMeta{}, nil
}

// rejectAmbiguousKeys reports whether body is not a JSON object whose keys
// are unambiguous: an object with the same key twice at any depth, or two
// top-level keys that differ only by case (encoding/json matches struct
// fields case-insensitively, so "ACTION" and "action" name one field to the
// canonical decode and two to a map decode). It also reports true for
// anything it cannot tokenize, so malformed input is refused here rather than
// reaching a decoder that might be lenient about it.
//
// Case-folding is applied to the top-level object only: that is the one
// object decoded into a struct, and nested objects (audit `metadata`) are
// carried through as raw bytes, where keys that differ only by case are
// legitimate data.
func rejectAmbiguousKeys(body []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return true
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		// Not an object: leave the shape error to the caller's decode.
		return false
	}
	if scanObject(dec, true) {
		return true
	}
	// Anything after the object other than whitespace is malformed.
	if _, err := dec.Token(); err != io.EOF {
		return true
	}
	return false
}

// scanObject consumes tokens up to and including the closing brace of an
// object whose opening brace has already been read, reporting whether it saw a
// duplicate key (or, with top set, two keys equal under case folding) or hit
// a tokenization error.
func scanObject(dec *json.Decoder, top bool) (ambiguous bool) {
	seen := make(map[string]struct{})
	folded := make(map[string]struct{})
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return true
		}
		key, ok := keyTok.(string)
		if !ok {
			return true
		}
		if _, dup := seen[key]; dup {
			return true
		}
		seen[key] = struct{}{}
		if top {
			f := strings.ToLower(key)
			if _, dup := folded[f]; dup {
				return true
			}
			folded[f] = struct{}{}
		}
		if scanValue(dec) {
			return true
		}
	}
	// Closing brace.
	if _, err := dec.Token(); err != nil {
		return true
	}
	return false
}

// scanValue consumes one JSON value, recursing into objects and arrays.
func scanValue(dec *json.Decoder) (ambiguous bool) {
	tok, err := dec.Token()
	if err != nil {
		return true
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return false
	}
	switch d {
	case '{':
		return scanObject(dec, false)
	case '[':
		for dec.More() {
			if scanValue(dec) {
				return true
			}
		}
		_, err := dec.Token()
		return err != nil
	}
	return true
}

// authzRequestCanonical mirrors the server's AuthzRequest struct
// (crates/axiam-amqp/src/messages.rs) in EXACT field-declaration order.
// UUIDs are serialized by serde as JSON strings, so plain Go strings
// round-trip byte-identically. `scope` is optional (omitted when absent);
// `key_version` is always emitted. NEW-4: `nonce` and `issued_at` are ALWAYS
// emitted (no server-side skip_serializing_if) and MUST land after
// `key_version` and before `hmac_signature` in the signed bytes; both are
// plain Go strings and are never re-parsed/reformatted here, so the UUID and
// RFC3339 timestamp are echoed back byte-identically to what was received.
// `hmac_signature` is intentionally absent — it is not part of the signed
// bytes.
type authzRequestCanonical struct {
	CorrelationID string  `json:"correlation_id"`
	TenantID      string  `json:"tenant_id"`
	SubjectID     string  `json:"subject_id"`
	Action        string  `json:"action"`
	ResourceID    string  `json:"resource_id"`
	Scope         *string `json:"scope,omitempty"`
	KeyVersion    uint8   `json:"key_version"`
	Nonce         string  `json:"nonce"`
	IssuedAt      string  `json:"issued_at"`
}

// auditEventCanonical mirrors the server's AuditEventMessage struct
// (crates/axiam-amqp/src/messages.rs) in EXACT field-declaration order.
// `resource_id`, `ip_address`, and `metadata` are optional (omitted when
// absent); `metadata` is kept as raw JSON so its inner bytes/key order are
// preserved verbatim. `key_version` is always emitted. NEW-4: `nonce` and
// `issued_at` are ALWAYS emitted and MUST land after `key_version` and
// before `hmac_signature`; both are plain Go strings, echoed verbatim (never
// re-parsed/reformatted) so the signed bytes match exactly.
// `hmac_signature` is excluded from the signed bytes.
type auditEventCanonical struct {
	TenantID   string          `json:"tenant_id"`
	ActorID    string          `json:"actor_id"`
	ActorType  string          `json:"actor_type"`
	Action     string          `json:"action"`
	ResourceID *string         `json:"resource_id,omitempty"`
	Outcome    string          `json:"outcome"`
	IPAddress  *string         `json:"ip_address,omitempty"`
	Metadata   json.RawMessage `json:"metadata,omitempty"`
	KeyVersion uint8           `json:"key_version"`
	Nonce      string          `json:"nonce"`
	IssuedAt   string          `json:"issued_at"`
}

// replayMeta carries the NEW-4 replay-protection fields (key_version, nonce,
// issued_at) extracted from whichever canonical layout the HMAC verified
// against, so the caller (verifyAndDispatch) can enforce the key_version
// gate, the issued_at freshness window, and nonce dedup AFTER the
// cryptographic check succeeds.
type replayMeta struct {
	KeyVersion uint8
	Nonce      string
	IssuedAt   string
}

// canonicalCandidate pairs a re-marshaled canonical byte candidate with the
// replay-protection metadata extracted from the same layout.
type canonicalCandidate struct {
	bytes []byte
	meta  replayMeta
}

// canonicalCandidates reconstructs the server-signed canonical bytes for
// every known signed message layout. Each candidate is the body re-marshaled
// in the server's declaration order with hmac_signature excluded. Only the
// layout the server actually signed can produce bytes whose HMAC matches the
// received signature, so returning several is safe.
func canonicalCandidates(body []byte) []canonicalCandidate {
	candidates := make([]canonicalCandidate, 0, 2)

	var authz authzRequestCanonical
	if json.Unmarshal(body, &authz) == nil {
		if b, err := json.Marshal(&authz); err == nil {
			candidates = append(candidates, canonicalCandidate{
				bytes: b,
				meta: replayMeta{
					KeyVersion: authz.KeyVersion,
					Nonce:      authz.Nonce,
					IssuedAt:   authz.IssuedAt,
				},
			})
		}
	}

	var audit auditEventCanonical
	if json.Unmarshal(body, &audit) == nil {
		if b, err := json.Marshal(&audit); err == nil {
			candidates = append(candidates, canonicalCandidate{
				bytes: b,
				meta: replayMeta{
					KeyVersion: audit.KeyVersion,
					Nonce:      audit.Nonce,
					IssuedAt:   audit.IssuedAt,
				},
			})
		}
	}

	return candidates
}
