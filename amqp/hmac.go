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
	"unicode"
	"unicode/utf8"
)

// verifyHMAC verifies a delivery's HMAC-SHA256 signature over the RECEIVED
// BYTES (server #882, D-5) and returns the bytes it verified, which are the
// only bytes a caller may build the handler's view from (C2).
//
// The server writes every signed message (AuthzRequest, AuditEventMessage) as
// a typed serde_json struct: compact, in field-declaration order, with
// hmac_signature serialized LAST. So the bytes the HMAC covers are the
// received body with its trailing `,"hmac_signature":"<64 hex>"` member cut
// out of the closing brace — exactly what the authz requester checks
// (cutTrailingSignature). They are never rebuilt by decoding and
// re-encoding: encoding/json escapes <, >, &, U+2028 and U+2029 and rewrites
// \u escapes of printable characters, so a re-serialization fails to verify a
// genuine message whenever a value contains one of them, and it lets the
// handler be given a parse that differs from what was verified.
//
// Steps:
//  0. Refuse a body that is not one JSON object with unambiguous keys
//     (rejectAmbiguousKeys): a key repeated at any depth, two top-level keys
//     encoding/json folds together, or anything after the object.
//  1. Cut the trailing signature member. A body without one — unsigned, a
//     null or non-string signature, a signature that is not the last member,
//     trailing whitespace — is refused (strict mode, CONTRACT.md §8 rule 3),
//     never repaired.
//  2. Accept iff HMAC-SHA256(signingKey, canonical) equals the signature,
//     compared with hmac.Equal (constant time).
//  3. Require the verified bytes to be one of the known signed layouts — the
//     exact top-level member sequence of AuthzRequest or AuditEventMessage
//     (signedLayoutOf) — and decode the replay-protection fields from those
//     same bytes.
//
// Returns (false, zero-value, nil) on every failure, never panics. On
// success the replayMeta feeds the NEW-4 checks the caller runs next.
func verifyHMAC(signingKey []byte, body []byte) (bool, replayMeta, []byte) {
	if rejectAmbiguousKeys(body) {
		return false, replayMeta{}, nil
	}
	canonical, sigHex, ok := cutTrailingSignature(body)
	if !ok {
		return false, replayMeta{}, nil
	}
	expected, err := hex.DecodeString(sigHex)
	if err != nil {
		return false, replayMeta{}, nil
	}
	mac := hmac.New(sha256.New, signingKey)
	mac.Write(canonical)
	if !hmac.Equal(mac.Sum(nil), expected) {
		return false, replayMeta{}, nil
	}
	meta, ok := signedLayoutOf(canonical)
	if !ok {
		return false, replayMeta{}, nil
	}
	return true, meta, canonical
}

// The top-level member sequences of the two signed message types, in the
// server's declaration order (crates/axiam-amqp/src/messages.rs). A member
// marked optional may be absent (serde skip_serializing_if); every other
// member is always written.
var (
	authzRequestLayout = []layoutMember{
		{"correlation_id", false}, {"tenant_id", false}, {"subject_id", false},
		{"action", false}, {"resource_id", false}, {"scope", true},
		{"key_version", false}, {"nonce", false}, {"issued_at", false},
	}
	auditEventLayout = []layoutMember{
		{"tenant_id", false}, {"actor_id", false}, {"actor_type", false},
		{"action", false}, {"resource_id", true}, {"outcome", false},
		{"ip_address", true}, {"metadata", true},
		{"key_version", false}, {"nonce", false}, {"issued_at", false},
	}
)

type layoutMember struct {
	name     string
	optional bool
}

// signedLayoutOf reports whether canonical's top-level members are exactly
// one known signed layout, in order, and decodes the replay-protection fields
// from canonical through that layout's struct (which also checks each
// member's JSON type). The member names are compared exactly, so the struct
// decode cannot fold a differently spelled key onto a field.
func signedLayoutOf(canonical []byte) (replayMeta, bool) {
	keys, ok := topLevelKeys(canonical)
	if !ok {
		return replayMeta{}, false
	}
	switch {
	case matchesLayout(keys, authzRequestLayout):
		var m authzRequestCanonical
		if json.Unmarshal(canonical, &m) != nil {
			return replayMeta{}, false
		}
		return replayMeta{KeyVersion: m.KeyVersion, Nonce: m.Nonce, IssuedAt: m.IssuedAt}, true
	case matchesLayout(keys, auditEventLayout):
		var m auditEventCanonical
		if json.Unmarshal(canonical, &m) != nil {
			return replayMeta{}, false
		}
		return replayMeta{KeyVersion: m.KeyVersion, Nonce: m.Nonce, IssuedAt: m.IssuedAt}, true
	}
	return replayMeta{}, false
}

func matchesLayout(keys []string, layout []layoutMember) bool {
	i := 0
	for _, m := range layout {
		if i < len(keys) && keys[i] == m.name {
			i++
			continue
		}
		if !m.optional {
			return false
		}
	}
	return i == len(keys)
}

// topLevelKeys returns the member names of the JSON object in body, in order.
func topLevelKeys(body []byte) ([]string, bool) {
	dec := json.NewDecoder(bytes.NewReader(body))
	tok, err := dec.Token()
	if err != nil {
		return nil, false
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, false
	}
	var keys []string
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, false
		}
		key, ok := keyTok.(string)
		if !ok {
			return nil, false
		}
		keys = append(keys, key)
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return nil, false
		}
	}
	return keys, true
}

// rejectAmbiguousKeys reports whether body is not a JSON object whose keys
// are unambiguous: an object with the same key twice at any depth, or two
// top-level keys that encoding/json's struct decode matches to one field
// (it folds keys with Unicode simple folding — see foldName — so "ACTION",
// "action", and "ſubject_id"/"subject_id" each name one field to the struct
// decode and two to a map decode). It also reports true for
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
			f := foldName(key)
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
// bytes. buildAuthzRequest encodes the requester's request through it;
// verifyHMAC only decodes verified bytes through it and never re-encodes them.
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
// `hmac_signature` is excluded from the signed bytes. verifyHMAC only decodes
// verified bytes through it and never re-encodes them.
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
// issued_at) decoded from the verified bytes through their layout, so the caller (verifyAndDispatch) can enforce the key_version
// gate, the issued_at freshness window, and nonce dedup AFTER the
// cryptographic check succeeds.
type replayMeta struct {
	KeyVersion uint8
	Nonce      string
	IssuedAt   string
}

// foldName folds a key exactly as encoding/json does when it matches an
// object key to a struct field (encoding/json/fold.go, appendFoldedName):
// ASCII letters to upper case, every other rune to the smallest rune of its
// unicode.SimpleFold orbit. So U+017F (ſ) folds with s and S, and U+212A
// (the Kelvin sign) with k and K — which strings.ToLower does not do for ſ.
// Two keys with the same foldName are one field to the struct decode.
func foldName(key string) string {
	out := make([]rune, 0, len(key))
	for _, r := range key {
		if r < utf8.RuneSelf {
			if 'a' <= r && r <= 'z' {
				r -= 'a' - 'A'
			}
			out = append(out, r)
			continue
		}
		out = append(out, foldRune(r))
	}
	return string(out)
}

// foldRune returns the smallest rune of r's simple-fold orbit (encoding/json's
// foldRune).
func foldRune(r rune) rune {
	for {
		r2 := unicode.SimpleFold(r)
		if r2 <= r {
			return r2
		}
		r = r2
	}
}
