// Package amqp implements the AXIAM AMQP event consumer: a closure-handler
// Consume loop, typed to the one message type it consumes, that
// HMAC-SHA256-verifies every delivery BEFORE the caller's handler ever runs
// (CONTRACT.md §8, D-07, SC#4).
package amqp

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

// MessageType is the one signed type an event consumer consumes (CONTRACT.md
// §8 protocol step 2c, "Typed: one configured type", contract 1.69, D-9).
//
// AuthzRequest, AuditEventMessage and AuthzResponse are signed with the same
// scheme under the same tenant subkey, so a genuine signed message of one type
// replayed onto a queue that carries another passes the signature check; only
// its layout tells it apart. A consumer is therefore configured with exactly
// one type and refuses every other layout before the HMAC is computed and
// before anything is decoded. An application that consumes both types runs two
// consumers. The zero value is not a type: Consume refuses it.
type MessageType int

const (
	// AuthzRequestMessage is the server's AuthzRequest
	// (crates/axiam-amqp/src/messages.rs).
	AuthzRequestMessage MessageType = iota + 1
	// AuditEventMessage is the server's AuditEventMessage
	// (crates/axiam-amqp/src/messages.rs).
	AuditEventMessage
)

// String names the type as the server's struct does.
func (t MessageType) String() string {
	switch t {
	case AuthzRequestMessage:
		return "AuthzRequest"
	case AuditEventMessage:
		return "AuditEventMessage"
	}
	return fmt.Sprintf("MessageType(%d)", int(t))
}

// layout is the type's exact top-level member sequence; ok is false for a
// value that names no type.
func (t MessageType) layout() (layout []layoutMember, ok bool) {
	switch t {
	case AuthzRequestMessage:
		return authzRequestLayout, true
	case AuditEventMessage:
		return auditEventLayout, true
	}
	return nil, false
}

// The event consumer's discard reasons beyond the three it shares with the
// requester (CONTRACT.md §8 protocol rule 4, contract 1.69, D-8).
const (
	discardKeyVersion = "key_version"
	discardStale      = "stale"
	discardReplay     = "replay"
)

// verifyEvent applies §8 protocol steps 2a-2f to body for a consumer of the
// one type t, over the RECEIVED BYTES (server #882, D-5), and returns the
// bytes it verified — the only bytes a caller may build the handler's view
// from (C2) — with the replay-protection members decoded from them, or the
// discard reason.
//
// The server writes every signed message as a typed serde_json struct:
// compact, in field-declaration order, with hmac_signature serialized LAST.
// So the bytes the HMAC covers are the received body with its trailing
// `,"hmac_signature":"<64 hex>"` member cut out of the closing brace. They
// are never rebuilt by decoding and re-encoding: encoding/json escapes <, >,
// &, U+2028 and U+2029 and rewrites \u escapes of printable characters, so a
// re-serialization fails to verify a genuine message whenever a value
// contains one of them, and lets the handler be given a parse that differs
// from what was verified.
//
// The reason is the first that applies, in the normative order of CONTRACT
// 1.69 §8 protocol rule 4 (positions (6)-(8), the v2 gates, are the caller's):
//
//	(1) the body is not one JSON object — its first byte is not `{` (a
//	    byte-order mark, whitespace or any other prefix is refused, never
//	    stripped), it is not valid UTF-8 JSON, or a second value follows
//	    its closing `}`                                             -> malformed
//	(2) it has no top-level hmac_signature member                    -> unsigned
//	(3) a member name repeated at any depth or two top-level names
//	    encoding/json folds together, hmac_signature not a trailing
//	    64-hex string, or canonical bytes whose top-level members are
//	    not exactly t's layout (the typed check: another signed type's
//	    layout is refused here, before the HMAC)                     -> malformed
//	(4) HMAC-SHA256(signingKey, canonical) differs from the signature,
//	    compared with hmac.Equal (constant time)                     -> signature
//	(5) the verified bytes do not decode into t: a member of the wrong
//	    JSON type, an issued_at that is not RFC 3339, a nonce that is
//	    not a UUID                                                   -> malformed
//
// It never panics, whatever the bytes.
func verifyEvent(signingKey []byte, body []byte, t MessageType) ([]byte, replayMeta, string) {
	layout, ok := t.layout()
	if !ok {
		return nil, replayMeta{}, discardMalformed
	}
	// (1) One JSON object whose first byte is `{`. json.Valid also bounds the
	// nesting depth before anything below recurses into it. Whitespace after
	// the object is not refused here: a signed body is refused for it at (3),
	// where cutTrailingSignature finds no trailing signature member.
	if len(body) == 0 || body[0] != '{' || !utf8.Valid(body) || !json.Valid(body) {
		return nil, replayMeta{}, discardMalformed
	}
	// (2) No signature member at all, whatever else the body lacks.
	keys, ok := topLevelKeys(body)
	if !ok {
		return nil, replayMeta{}, discardMalformed
	}
	if !slices.Contains(keys, "hmac_signature") {
		return nil, replayMeta{}, discardUnsigned
	}
	// (3) Unambiguous names, a trailing signature member, the typed layout.
	if rejectAmbiguousKeys(body) {
		return nil, replayMeta{}, discardMalformed
	}
	canonical, sigHex, ok := cutTrailingSignature(body)
	if !ok {
		return nil, replayMeta{}, discardMalformed
	}
	canonicalKeys, ok := topLevelKeys(canonical)
	if !ok || !matchesLayout(canonicalKeys, layout) {
		return nil, replayMeta{}, discardMalformed
	}
	// (4) The HMAC over the canonical bytes as received.
	expected, err := hex.DecodeString(sigHex)
	if err != nil {
		return nil, replayMeta{}, discardMalformed
	}
	mac := hmac.New(sha256.New, signingKey)
	mac.Write(canonical)
	if !hmac.Equal(mac.Sum(nil), expected) {
		return nil, replayMeta{}, discardSignature
	}
	// (5) Decode the verified bytes into t.
	meta, ok := decodeReplayMeta(canonical, t)
	if !ok {
		return nil, replayMeta{}, discardMalformed
	}
	return canonical, meta, ""
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

// decodeReplayMeta decodes canonical — whose top-level members verifyEvent has
// already matched, exactly, against t's layout — through t's struct (which
// checks each member's JSON type) and checks the replay members' formats: a
// nonce that is a UUID and an issued_at that is an RFC 3339 timestamp.
func decodeReplayMeta(canonical []byte, t MessageType) (replayMeta, bool) {
	var meta replayMeta
	switch t {
	case AuthzRequestMessage:
		var m authzRequestCanonical
		if json.Unmarshal(canonical, &m) != nil {
			return replayMeta{}, false
		}
		meta = replayMeta{KeyVersion: m.KeyVersion, Nonce: m.Nonce, IssuedAt: m.IssuedAt}
	case AuditEventMessage:
		var m auditEventCanonical
		if json.Unmarshal(canonical, &m) != nil {
			return replayMeta{}, false
		}
		meta = replayMeta{KeyVersion: m.KeyVersion, Nonce: m.Nonce, IssuedAt: m.IssuedAt}
	default:
		return replayMeta{}, false
	}
	if _, err := uuid.Parse(meta.Nonce); err != nil {
		return replayMeta{}, false
	}
	if _, err := time.Parse(time.RFC3339, meta.IssuedAt); err != nil {
		return replayMeta{}, false
	}
	return meta, true
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
// verifyEvent only decodes verified bytes through it and never re-encodes them.
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
// `hmac_signature` is excluded from the signed bytes. verifyEvent only decodes
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
