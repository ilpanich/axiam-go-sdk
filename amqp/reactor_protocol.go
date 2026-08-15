// Reactor wire protocol — CONTRACT.md §22.2, §22.3, §22.4.
//
// Both directions are signed with the same §8 v2 primitives and the same
// tenant subkey: the server signs the event, the reactor signs the reply. A
// reply is an instruction to change a token or refuse a login, so an unsigned
// reply is not a weak reply — it is not a reply at all, and the server
// discards it as though the reactor had never answered.
//
// THE ONE CANONICALIZATION DIFFERENCE FROM §8. On a reactor event and a
// reactor reply, `hmac_signature` is serialized as JSON **null** inside the
// signed bytes. It is NOT omitted, which is what §8's own two message types
// (AuthzRequest, AuditEventMessage — see hmac.go) do. Getting this wrong
// produces a MAC that never verifies in either direction, so the §22.13
// vectors carry `canonical_signed_json` for every message and
// reactor_vectors_test.go asserts against them byte-for-byte rather than
// against anyone's memory of this paragraph.
//
// Field order is the server's struct declaration order (serde_json emits
// declaration order, not alphabetical), reproduced here by Go structs whose
// json-tagged fields are declared in that same order — the same technique
// hmac.go already uses for §8.

package amqp

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// reactorChainPatchKey is the payload key under which the server inserts the
// patch accumulated by earlier reactors in the chain (§22.3), so a later
// reactor decides against the state that will actually be committed. It is
// READ-ONLY context: echoing it back inside one's own patch is not how a
// field is preserved — the server merges (§22.6).
const reactorChainPatchKey = "_reactor_patch"

// Reply decisions (§22.4). Lowercase, closed set.
const (
	reactorDecisionAllow  = "allow"
	reactorDecisionDeny   = "deny"
	reactorDecisionMutate = "mutate"
)

// reactorDefaultDenyReason is what the server substitutes when a deny
// carries no reason. Stated here so a caller reading a deny answer back sees
// the same string the audit record will.
const reactorDefaultDenyReason = "denied by reactor"

// Protocol errors surfaced by the reactor runtime. Every one of them results
// in NO REPLY being published, which hands the decision to the
// registration's failure_policy (§22.8) — never to a synthesized allow.
var (
	// ErrReactorKeyVersionTooOld reports an event whose key_version is below
	// the replay-protected floor of 2. Checked before the signature is even
	// computed (§22.3).
	ErrReactorKeyVersionTooOld = errors.New("axiam: reactor event key_version is below the accepted floor")
	// ErrReactorBadSignature reports a missing or wrong MAC.
	ErrReactorBadSignature = errors.New("axiam: reactor event signature is missing or invalid")
	// ErrReactorStale reports an issued_at outside the ±300 s freshness
	// window, in either direction — a future timestamp is not "extra fresh",
	// it is the shape of a captured message held for later.
	ErrReactorStale = errors.New("axiam: reactor event issued_at is outside the freshness window")
	// ErrReactorReplay reports a nonce already seen inside the freshness
	// window.
	ErrReactorReplay = errors.New("axiam: reactor event nonce has already been seen (replay)")
	// ErrReactorTenantMismatch reports an event addressed to another tenant.
	ErrReactorTenantMismatch = errors.New("axiam: reactor event names a different tenant")
	// ErrReactorUnknownEvent reports an event name outside the §22.5
	// registry. The server dispatches no such event, so a delivery carrying
	// one is not something to guess about.
	ErrReactorUnknownEvent = errors.New("axiam: reactor event name is not in the §22.5 registry")
	// ErrReactorMalformed reports a body that is not a decodable reactor
	// event.
	ErrReactorMalformed = errors.New("axiam: reactor event body is malformed")
	// ErrReactorRequireMFAUnsupported reports a handler answer carrying
	// require_mfa on any event other than login.post_auth (§22.4 rule 3).
	// Refused client-side rather than sent; the server would refuse it too,
	// before even looking at the decision.
	ErrReactorRequireMFAUnsupported = errors.New("axiam: require_mfa is only valid on login.post_auth")
	// ErrReactorEmptyPatch reports a mutate answer with no patch entries.
	// The server rejects it as malformed_mutation; there is nothing to gain
	// by putting it on the wire.
	ErrReactorEmptyPatch = errors.New("axiam: a mutate answer requires a non-empty patch")
)

// ---------------------------------------------------------------------------
// Canonical layouts
// ---------------------------------------------------------------------------

// reactorEventCanonical mirrors ReactorEventMessage in
// crates/axiam-amqp/src/reactor/protocol.rs in EXACT field-declaration order:
//
//	tenant_id, event, correlation_id, payload, timeout_ms, key_version,
//	nonce, issued_at, hmac_signature
//
// `payload` is held as json.RawMessage and echoed VERBATIM — never re-parsed
// and re-encoded — so the server's own key order inside it survives into the
// bytes this SDK verifies. `nonce` and `issued_at` are plain strings for the
// same reason: reformatting a timestamp is how a body that was signed stops
// verifying.
//
// `hmac_signature` is a *string with NO omitempty: while signing it is nil
// and therefore serialized as `null`, which is exactly what §22.2 requires
// and exactly what §8's two message types do NOT do.
type reactorEventCanonical struct {
	TenantID      string          `json:"tenant_id"`
	Event         string          `json:"event"`
	CorrelationID string          `json:"correlation_id"`
	Payload       json.RawMessage `json:"payload"`
	TimeoutMS     uint32          `json:"timeout_ms"`
	KeyVersion    uint8           `json:"key_version"`
	Nonce         string          `json:"nonce"`
	IssuedAt      string          `json:"issued_at"`
	HMACSignature *string         `json:"hmac_signature"`
}

// reactorReplyCanonical mirrors ReactorReply in
// crates/axiam-amqp/src/reactor/protocol.rs in EXACT field-declaration order:
//
//	correlation_id, tenant_id, event, decision, reason (omitted when absent),
//	patch (omitted when absent), require_mfa (omitted when false),
//	key_version, nonce, issued_at, hmac_signature
//
// The three conditional omissions are load-bearing. A reply that serializes
// `"require_mfa": false` rather than omitting it produces different canonical
// bytes and therefore a different MAC — the omission rule must be reproduced,
// not merely the values.
//
// `patch` is a map[string]string: Go marshals map keys in sorted order, which
// is what the server's BTreeMap produces, so the two agree without a helper.
type reactorReplyCanonical struct {
	CorrelationID string            `json:"correlation_id"`
	TenantID      string            `json:"tenant_id"`
	Event         string            `json:"event"`
	Decision      string            `json:"decision"`
	Reason        *string           `json:"reason,omitempty"`
	Patch         map[string]string `json:"patch,omitempty"`
	RequireMFA    bool              `json:"require_mfa,omitempty"`
	KeyVersion    uint8             `json:"key_version"`
	Nonce         string            `json:"nonce"`
	IssuedAt      string            `json:"issued_at"`
	HMACSignature *string           `json:"hmac_signature"`
}

// marshalReactorCanonical serializes v the way serde_json does: compact, and
// WITHOUT Go's default HTML escaping.
//
// encoding/json escapes the three HTML-significant characters into \u
// sequences unless told not to; serde_json escapes none of them. A deny
// reason containing an ampersand would therefore produce bytes the server
// never reconstructs, and a MAC it rejects — for a message that was
// otherwise perfectly well formed. json.Encoder is the only encoding/json
// entry point that exposes the switch, and it appends a newline that has to
// come back off.
func marshalReactorCanonical(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// signReactorBytes returns the hex-encoded HMAC-SHA256 of canonical under
// key — the tenant's HKDF-derived AMQP subkey (§8, §22.2). There is no second
// key and no asymmetric variant in v1.
func signReactorBytes(key, canonical []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(canonical)
	return hex.EncodeToString(mac.Sum(nil))
}

// verifyReactorMAC compares in constant time. hmac.Equal, never == on the
// hex strings.
func verifyReactorMAC(key, canonical []byte, signatureHex string) bool {
	expected, err := hex.DecodeString(signatureHex)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(canonical)
	return hmac.Equal(mac.Sum(nil), expected)
}

// ---------------------------------------------------------------------------
// ReactorEvent — the verified event handed to a handler
// ---------------------------------------------------------------------------

// ReactorEvent is one hook firing, delivered to a reactor and already
// verified: by the time a ReactorHandler sees one, its key_version, MAC,
// freshness and nonce have all been checked (§22.3). A runtime that hands an
// unverified payload to user code has already lost — the handler will act on
// it, and "we checked afterwards" is not a check.
type ReactorEvent struct {
	// TenantID is the tenant this event belongs to.
	TenantID string
	// Event is the registry name, e.g. ReactorEventTokenPreIssue.
	Event string
	// CorrelationID is the single-use handle for this dispatch. The runtime
	// copies it into the reply body; nothing else binds one reply to one
	// event.
	CorrelationID string
	// Payload is the event-specific body, verbatim. It never carries a
	// credential, a token or a signing key — a reactor is told what is being
	// decided, not handed the means to act on it elsewhere.
	//
	// It is tenant business data: readable by design (§22.12), but not
	// something to log at info level.
	Payload json.RawMessage
	// Timeout is how long the server will wait for THIS dispatch. It is
	// inside the signed body, so it cannot be widened in transit.
	Timeout time.Duration
	// Nonce and IssuedAt are the §8 v2 replay fields, kept for correlation.
	// Neither is a secret.
	Nonce    string
	IssuedAt time.Time
	// Deadline is when the runtime stops waiting on the handler: the moment
	// this delivery was received plus Timeout.
	//
	// Measured from RECEIPT rather than from IssuedAt on purpose. The
	// freshness window is ±300 s while a timeout is typically 500 ms, so a
	// clock a couple of seconds behind the server would compute a window
	// that has already closed for every event and answer nothing at all.
	Deadline time.Time
}

// Spec returns the event's registry entry (§22.5). The second return is
// false only for a name outside the registry, which the runtime refuses
// before a handler is ever called.
func (e ReactorEvent) Spec() (ReactorEventSpec, bool) {
	return ReactorEventSpecFor(e.Event)
}

// DecodePayload unmarshals the event payload into v.
func (e ReactorEvent) DecodePayload(v any) error {
	if err := json.Unmarshal(e.Payload, v); err != nil {
		return fmt.Errorf("axiam: failed to decode reactor event payload: %w", err)
	}
	return nil
}

// ChainPatch returns the patch accumulated by earlier reactors in the chain
// (§22.3's `_reactor_patch`), and whether one was present.
//
// It is READ-ONLY context, provided so a later reactor decides against the
// state that will actually be committed. Echoing it back inside this
// reactor's own patch is not how a field is preserved: the server merges the
// chain itself, as a union with last-write-wins per key (§22.6).
func (e ReactorEvent) ChainPatch() (map[string]string, bool) {
	var envelope struct {
		Patch map[string]string `json:"_reactor_patch"`
	}
	if err := json.Unmarshal(e.Payload, &envelope); err != nil {
		return nil, false
	}
	if envelope.Patch == nil {
		return nil, false
	}
	return envelope.Patch, true
}

// decodeReactorEvent parses and fully verifies one delivery body, in the
// order §22.3 fixes: reject key_version < 2, verify the MAC, check
// freshness, check the nonce. Only then is the payload decoded and handed
// on.
//
// tenantID is this reactor's configured tenant; an event naming another one
// is refused outright rather than dispatched. guard may be nil (the nonce
// check is then skipped, which is what the sign-direction tests want).
func decodeReactorEvent(key []byte, body []byte, tenantID string, now time.Time, skew time.Duration, guard *replayGuard) (ReactorEvent, error) {
	var raw reactorEventCanonical
	if err := json.Unmarshal(body, &raw); err != nil {
		return ReactorEvent{}, fmt.Errorf("%w: %v", ErrReactorMalformed, err)
	}
	if raw.HMACSignature == nil {
		return ReactorEvent{}, ErrReactorBadSignature
	}
	if len(raw.Payload) == 0 {
		return ReactorEvent{}, fmt.Errorf("%w: no payload", ErrReactorMalformed)
	}

	// 1. key_version, before anything else about the body is considered.
	if raw.KeyVersion < minKeyVersion {
		return ReactorEvent{}, ErrReactorKeyVersionTooOld
	}

	// 2. The MAC, over the body with hmac_signature set to null.
	signature := *raw.HMACSignature
	unsigned := raw
	unsigned.HMACSignature = nil
	canonical, err := marshalReactorCanonical(&unsigned)
	if err != nil {
		return ReactorEvent{}, fmt.Errorf("%w: %v", ErrReactorMalformed, err)
	}
	if !verifyReactorMAC(key, canonical, signature) {
		return ReactorEvent{}, ErrReactorBadSignature
	}

	// 3. Freshness, in both directions.
	issuedAt, err := time.Parse(time.RFC3339, raw.IssuedAt)
	if err != nil {
		return ReactorEvent{}, fmt.Errorf("%w: issued_at %q is not RFC3339", ErrReactorMalformed, raw.IssuedAt)
	}
	if age := now.Sub(issuedAt); age > skew || age < -skew {
		return ReactorEvent{}, ErrReactorStale
	}

	// 4. The nonce, against the seen-set.
	if guard != nil && !guard.claimReactorNonce(raw.Nonce, now) {
		return ReactorEvent{}, ErrReactorReplay
	}

	// Identity and registry membership. Neither is cryptography, so both
	// come after the MAC: spending them on unauthenticated bytes tells an
	// unauthenticated party what this reactor accepts.
	if tenantID != "" && raw.TenantID != tenantID {
		return ReactorEvent{}, ErrReactorTenantMismatch
	}
	if _, known := ReactorEventSpecFor(raw.Event); !known {
		return ReactorEvent{}, fmt.Errorf("%w: %q", ErrReactorUnknownEvent, raw.Event)
	}

	timeout := time.Duration(raw.TimeoutMS) * time.Millisecond
	return ReactorEvent{
		TenantID:      raw.TenantID,
		Event:         raw.Event,
		CorrelationID: raw.CorrelationID,
		Payload:       raw.Payload,
		Timeout:       timeout,
		Nonce:         raw.Nonce,
		IssuedAt:      issuedAt,
		Deadline:      now.Add(timeout),
	}, nil
}

// ---------------------------------------------------------------------------
// ReactorAnswer — what a handler decided
// ---------------------------------------------------------------------------

// ReactorAnswer is one of the three answers a handler may give — allow, deny
// or mutate — with require_mfa available on login.post_auth as a flag on the
// allow answer (§22.10).
//
// Its fields are unexported and it is built only through the four
// constructors below, which is what makes §22.4's rules structural rather
// than documented: there is no way to spell `allow` + `patch`, because the
// allow constructors take no patch.
type ReactorAnswer struct {
	decision   string
	reason     string
	patch      map[string]string
	requireMFA bool
}

// ReactorAllow proceeds unchanged.
func ReactorAllow() ReactorAnswer {
	return ReactorAnswer{decision: reactorDecisionAllow}
}

// ReactorAllowWithStepUp proceeds only after step-up authentication —
// `allow` + `require_mfa: true`.
//
// It is NOT a separate decision value, and it is valid on login.post_auth
// ONLY. The runtime refuses it on any other event rather than putting a
// reply on the wire the server will reject as require_mfa_not_supported.
//
// On the federated sign-in paths (SAML ACS, OIDC callback) there is no
// step-up branch to take, so a require_mfa answer FAILS the sign-in rather
// than being silently dropped. A reactor that needs step-up there should
// answer ReactorDeny and drive enrolment out of band (§22.5).
func ReactorAllowWithStepUp() ReactorAnswer {
	return ReactorAnswer{decision: reactorDecisionAllow, requireMFA: true}
}

// ReactorDeny refuses the operation. The reason is audited; a deny with no
// reason still denies, and the server substitutes "denied by reactor".
//
// A deny short-circuits the chain: no later reactor is consulted (§22.6).
func ReactorDeny(reason string) ReactorAnswer {
	return ReactorAnswer{decision: reactorDecisionDeny, reason: reason}
}

// ReactorMutate proceeds, applying patch — a flat map of string to string,
// valid on a mutable event only.
//
// The patch is sent UNFILTERED (§22.4 rule 1, §22.10 rule 3). One forbidden
// key rejects the whole patch server-side, including the fields that would
// have been fine, and this SDK does NOT quietly drop the offender to rescue
// the rest: doing so would leave the reactor author believing a field was
// set when it was dropped, which is the exact failure the server refuses to
// produce.
func ReactorMutate(patch map[string]string) ReactorAnswer {
	copied := make(map[string]string, len(patch))
	for k, v := range patch {
		copied[k] = v
	}
	return ReactorAnswer{decision: reactorDecisionMutate, patch: copied}
}

// Decision returns the wire decision string: "allow", "deny" or "mutate".
func (a ReactorAnswer) Decision() string { return a.decision }

// RequireMFA reports whether this answer demands step-up.
func (a ReactorAnswer) RequireMFA() bool { return a.requireMFA }

// buildReactorReply renders and signs the reply for one answer.
//
// The two client-side refusals here both produce an error rather than a
// reply, which hands the outcome to the registration's failure_policy —
// never to a synthesized allow:
//
//   - require_mfa on any event other than login.post_auth. §22.13 permits
//     rejecting this client-side or sending it and surfacing the server's
//     rejection; rejecting names the author's mistake at the place it was
//     made.
//   - a mutate answer with an empty patch, which the server rejects as
//     malformed_mutation.
//
// It does NOT refuse a patch key outside the event's allow-list. That is the
// one case where sending the wrong thing is required: the server names the
// offending key in its audit record, and filtering it out here would hide
// the mistake from everyone.
func buildReactorReply(key []byte, ev ReactorEvent, answer ReactorAnswer, nonce string, now time.Time) ([]byte, error) {
	if answer.requireMFA && ev.Event != ReactorEventLoginPostAuth {
		return nil, fmt.Errorf("%w (event %q)", ErrReactorRequireMFAUnsupported, ev.Event)
	}
	if answer.decision == reactorDecisionMutate && len(answer.patch) == 0 {
		return nil, ErrReactorEmptyPatch
	}

	reply := reactorReplyCanonical{
		CorrelationID: ev.CorrelationID,
		TenantID:      ev.TenantID,
		Event:         ev.Event,
		Decision:      answer.decision,
		Patch:         answer.patch,
		RequireMFA:    answer.requireMFA,
		KeyVersion:    reactorKeyVersion,
		// A FRESH nonce per reply. The server keeps no durable nonce-dedup
		// store for replies — its protection is the freshness window plus
		// the correlation_id binding — but the nonce is inside the signed
		// bytes, and a unique one is the only thing that keeps two replies
		// from being byte-identical. A constant nonce removes the sole
		// uniqueness the body carries beyond its timestamp.
		Nonce:    nonce,
		IssuedAt: now.UTC().Truncate(time.Second).Format(time.RFC3339),
	}
	if answer.decision == reactorDecisionDeny && answer.reason != "" {
		reason := answer.reason
		reply.Reason = &reason
	}

	canonical, err := marshalReactorCanonical(&reply)
	if err != nil {
		return nil, fmt.Errorf("axiam: failed to canonicalize reactor reply: %w", err)
	}
	signature := signReactorBytes(key, canonical)
	reply.HMACSignature = &signature
	body, err := marshalReactorCanonical(&reply)
	if err != nil {
		return nil, fmt.Errorf("axiam: failed to serialize reactor reply: %w", err)
	}
	return body, nil
}

// reactorKeyVersion is the §8 v2 key version both directions carry. A body
// below it is refused before anything else about it is considered.
const reactorKeyVersion uint8 = 2

// claimReactorNonce records nonce as seen at now and reports whether it was
// FRESH (true) or a replay (false).
//
// It reuses the §8 replayGuard's seen-set and TTL discipline but takes `now`
// as an argument rather than reading the guard's clock, because the reactor
// path has already parsed and range-checked issued_at against the same
// instant it uses for the delivery deadline — running two different clocks
// over one delivery is how a message ends up fresh for one check and stale
// for the next.
func (g *replayGuard) claimReactorNonce(nonce string, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.prune(now)
	if _, replayed := g.seen[nonce]; replayed {
		return false
	}
	g.seen[nonce] = now.Add(2 * g.skew)
	return true
}
