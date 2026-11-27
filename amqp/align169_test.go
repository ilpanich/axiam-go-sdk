package amqp

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Contract 1.69 §8 alignment (df06a8b): the `wire_json` reference vectors,
// the producer's wire form, the remaining consumer negatives, the normative
// discard reason order of the AuthzResponse requester and the after-Close
// rule.

// TestReferenceVectors_WireJSONCutsVerifiesAndDispatches feeds the fixture's
// `wire_json` exactly as delivered: it must cut to exactly
// `canonical_signed_json`, verify, pass the layout check and dispatch, with the
// handler given those canonical bytes.
func TestReferenceVectors_WireJSONCutsVerifiesAndDispatches(t *testing.T) {
	vectors := loadReferenceVectors(t)
	subkey, err := hex.DecodeString(vectors.HKDF.DerivedSubkeyHex)
	if err != nil || len(subkey) == 0 {
		t.Fatalf("fixture derived_subkey_hex unusable: %v", err)
	}
	for name, vec := range map[string]referenceVector{"authz_request": vectors.AuthzRequest, "audit_event": vectors.AuditEvent} {
		t.Run(name, func(t *testing.T) {
			if vec.WireJSON == "" {
				t.Fatal("fixture lacks wire_json")
			}
			wire := []byte(vec.WireJSON)
			canonical, sigHex, ok := cutTrailingSignature(wire)
			if !ok || string(canonical) != vec.CanonicalSignedJSON || sigHex != vec.HMACSignatureHex {
				t.Fatalf("wire_json must cut to canonical_signed_json and its signature (ok=%v)\n got  %s\n want %s", ok, canonical, vec.CanonicalSignedJSON)
			}
			if _, layoutOK := signedLayoutOf(canonical); !layoutOK {
				t.Fatal("canonical_signed_json must pass the layout check")
			}
			ok, _, signed := verifyHMAC(subkey, wire)
			if !ok || string(signed) != vec.CanonicalSignedJSON {
				t.Fatalf("verifyHMAC must accept wire_json and return the canonical bytes (ok=%v)", ok)
			}
			// The vectors' issued_at is fixed, so the replay gate (tested on
			// its own elsewhere) is left out here.
			var calls int32
			var seen Event
			d := newRecordingDelivery(wire)
			verifyAndDispatch(context.Background(), d, subkey, func(_ context.Context, e Event) error {
				atomic.AddInt32(&calls, 1)
				seen = e
				return nil
			}, &recordingLogger{}, nil)
			if calls != 1 {
				t.Fatalf("wire_json must dispatch exactly once, got %d", calls)
			}
			if acked, _, _ := d.counts(); acked != 1 {
				t.Fatal("wire_json must be acked")
			}
			if string(seen.Raw) != vec.CanonicalSignedJSON {
				t.Fatalf("Event.Raw must be the canonical bytes, got %s", seen.Raw)
			}
		})
	}
}

// TestBuildAuthzRequest_EmitsTheServerWireForm: for the vector inputs the
// producer emits byte for byte the fixture's `wire_json`.
func TestBuildAuthzRequest_EmitsTheServerWireForm(t *testing.T) {
	vectors := loadReferenceVectors(t)
	subkey, err := hex.DecodeString(vectors.HKDF.DerivedSubkeyHex)
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		CorrelationID string `json:"correlation_id"`
		TenantID      string `json:"tenant_id"`
		SubjectID     string `json:"subject_id"`
		Action        string `json:"action"`
		ResourceID    string `json:"resource_id"`
		Scope         string `json:"scope"`
		Nonce         string `json:"nonce"`
		IssuedAt      string `json:"issued_at"`
	}
	if err := json.Unmarshal(vectors.AuthzRequest.Message, &m); err != nil {
		t.Fatal(err)
	}
	issuedAt, err := time.Parse(time.RFC3339, m.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		at   time.Time
	}{
		{"UTC", issuedAt},
		{"a non-UTC clock is written as UTC", issuedAt.In(time.FixedZone("UTC+2", 2*3600))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := buildAuthzRequest(subkey, m.CorrelationID, m.TenantID, m.SubjectID, m.Action, m.ResourceID, []string{m.Scope}, m.Nonce, tc.at)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != vectors.AuthzRequest.WireJSON {
				t.Fatalf("producer output differs from wire_json\n got  %s\n want %s", got, vectors.AuthzRequest.WireJSON)
			}
		})
	}
	// Without the optional scope the member is omitted, never null.
	got, err := buildAuthzRequest(subkey, m.CorrelationID, m.TenantID, m.SubjectID, m.Action, m.ResourceID, nil, m.Nonce, issuedAt)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(vectors.AuthzRequest.CanonicalSignedJSON, `"scope":"confidential",`, ``, 1)
	if canonical, _, ok := cutTrailingSignature(got); !ok || string(canonical) != want {
		t.Fatalf("an absent scope must be omitted\n got  %s\n want %s", canonical, want)
	}
}

// alignAuditEvent is a server-order AuditEventMessage with a fresh nonce.
func alignAuditEvent(actionJSON, metadataJSON string) string {
	nonce, issuedAt := c2Fresh()
	return `{"tenant_id":"` + c2SignedTenant + `","actor_id":"` + c2SignedSubject + `","actor_type":"User","action":` + actionJSON +
		`,"outcome":"Success","metadata":` + metadataJSON + `,` + c2Tail(nonce, issuedAt) + `}`
}

// A genuine AuditEventMessage whose action and metadata contain < > &, a
// non-ASCII character and a \u escape of a printable character verifies, and
// the handler receives exactly those values.
func TestVerifyAndDispatch_169_GenuineAuditEventWithEscapesVerifies(t *testing.T) {
	key := []byte(fixtureSigningKey)
	canonical := alignAuditEvent(`"user.login <a&b> é A"`, `{"note":"<x>&éB","z":"1"}`)
	calls, seen, d := c2Run(t, key, oi16Sign(key, canonical))
	if calls != 1 {
		t.Fatalf("a genuine audit event must dispatch exactly once, got %d", calls)
	}
	if acked, _, _ := d.counts(); acked != 1 {
		t.Fatal("must be acked")
	}
	if string(seen.Raw) != canonical {
		t.Fatalf("Event.Raw must be the canonical bytes\n got  %s\n want %s", seen.Raw, canonical)
	}
	if got := c2Field(t, seen, "action"); got != "user.login <a&b> é A" {
		t.Fatalf("action = %q", got)
	}
	var meta map[string]string
	if err := json.Unmarshal(seen.Fields["metadata"], &meta); err != nil || meta["note"] != "<x>&éB" {
		t.Fatalf("metadata = %v (%v)", meta, err)
	}
}

// The consumer negatives of the 1.69 required-test list not already covered
// by TestVerifyAndDispatch_882_MalformedBodiesAreNackedBeforeTheHandler and
// TestVerifyHMAC_RefusesSignedBodiesOfAnotherLayout.
func TestVerifyAndDispatch_169_MoreRefusedBodies(t *testing.T) {
	key := []byte(fixtureSigningKey)
	audit := alignAuditEvent(`"user.login"`, `{"method":"password"}`)
	req := oi16AuthzRequest(`"documents:read"`)
	for _, tc := range []struct {
		name string
		body []byte
	}{
		{"hmac_signature null", []byte(strings.TrimSuffix(req, "}") + `,"hmac_signature":null}`)},
		{"hmac_signature a number", []byte(strings.TrimSuffix(req, "}") + `,"hmac_signature":1}`)},
		{"duplicate member nested in metadata, validly signed",
			oi16Sign(key, strings.Replace(audit, `{"method":"password"}`, `{"method":"mfa","method":"password"}`, 1))},
		{"duplicate top-level member in an audit event, validly signed",
			oi16Sign(key, strings.Replace(audit, `"outcome":"Success"`, `"outcome":"Failure","outcome":"Success"`, 1))},
		{"audit event with members reordered, validly signed",
			oi16Sign(key, strings.Replace(audit, `"actor_type":"User","action":"user.login"`, `"action":"user.login","actor_type":"User"`, 1))},
		{"a JSON array", []byte(`[` + string(oi16Sign(key, req)) + `]`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls, _, d := c2Run(t, key, tc.body)
			c2ExpectNacked(t, calls, d)
		})
	}
	// Control: the unmodified audit event dispatches.
	if calls, _, _ := c2Run(t, key, oi16Sign(key, audit)); calls != 1 {
		t.Fatal("control: the server-shaped audit event must dispatch")
	}
}

// TestAuthzRequester_169_NormativeReasonOrder pins the first-that-applies
// order of consumer obligation 4: malformed (not one object), unsigned (no
// hmac_signature member, whatever else is missing), malformed (bad signature
// member, or allowed/tenant_id/nonce/correlation_id missing or ill-typed),
// signature, tenant, unknown_request.
func TestAuthzRequester_169_NormativeReasonOrder(t *testing.T) {
	good := mustHex(t, vecSubkeyHex)
	other := subkeyFor(t, vecOtherTenant, 2)
	v1 := authzVectors[0].canonical
	drop := func(member string) string {
		// member is `"name":value,` as written in vector 1.
		return strings.Replace(v1, member, ``, 1)
	}
	for _, tc := range []struct {
		name   string
		body   []byte
		reason string
	}{
		{"(1) JSON null", []byte(`null`), "malformed"},
		{"(1) an array", []byte(`[]`), "malformed"},
		{"(1) a string", []byte(`"x"`), "malformed"},
		{"(1) two objects", append(append([]byte(nil), signWith(good, v1)...), []byte(`{}`)...), "malformed"},
		{"(2) the empty object", []byte(`{}`), "unsigned"},
		{"(2) neither hmac_signature nor allowed", []byte(drop(`"allowed":true,`)), "unsigned"},
		{"(2) allowed ill-typed, no hmac_signature", []byte(strings.Replace(v1, `"allowed":true`, `"allowed":"true"`, 1)), "unsigned"},
		{"(3) hmac_signature null, no allowed", []byte(`{"correlation_id":"` + vecCorrelation + `","hmac_signature":null}`), "malformed"},
		{"(3) no tenant_id, signed with another key", signWith(other, drop(`"tenant_id":"`+vecTenant+`",`)), "malformed"},
		{"(3) no correlation_id, signed with another key", signWith(other, drop(`"correlation_id":"`+vecCorrelation+`",`)), "malformed"},
		{"(3) no nonce, signed with another key", signWith(other, strings.Replace(v1, `,"nonce":"`+vecNonce+`"`, ``, 1)), "malformed"},
		{"(3) tenant_id a number, signed with another key", signWith(other, strings.Replace(v1, `"tenant_id":"`+vecTenant+`"`, `"tenant_id":1`, 1)), "malformed"},
		{"(3) nonce null, validly signed", signWith(good, strings.Replace(v1, `"nonce":"`+vecNonce+`"`, `"nonce":null`, 1)), "malformed"},
		{"(3) allowed ill-typed, signed with another key", signWith(other, strings.Replace(v1, `"allowed":true`, `"allowed":1`, 1)), "malformed"},
		{"(4) well-formed, another tenant's subkey", signWith(other, v1), "signature"},
		{"(5) validly signed for another tenant", signWith(good, strings.Replace(v1, vecTenant, vecOtherTenant, 1)), "tenant"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			log := &recordingLogger{}
			r, p := vectorRequester(t, WithAuthzSecurityLogger(log))
			dec, done, d := offer(r, p, tc.body)
			if done || dec.Allowed {
				t.Fatalf("must be discarded, never an allow (got %+v)", dec)
			}
			if _, _, nn := d.counts(); nn != 1 {
				t.Fatal("must be nacked without requeue")
			}
			oi16AssertDiscardEvent(t, log, r, tc.reason)
		})
	}
}

// After Close, an answer is not decoded or dispatched: it is nacked without
// requeue and no discard event is logged.
func TestAuthzRequester_169_AnswerAfterCloseIsNackedSilently(t *testing.T) {
	for _, tc := range []struct {
		name string
		body []byte
	}{
		{"the genuine answer", authzVectors[0].wire()},
		{"a malformed body", []byte(`not json`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			log := &recordingLogger{}
			r, p := vectorRequester(t, WithAuthzSecurityLogger(log))
			r.Close()
			_, done, d := offer(r, p, tc.body)
			if done {
				t.Fatal("an answer after Close must not be dispatched")
			}
			if acked, nr, nn := d.counts(); acked != 0 || nr != 0 || nn != 1 {
				t.Fatalf("want Nack(false) only, got acked=%d nackRequeue=%d nackNoRequeue=%d", acked, nr, nn)
			}
			if ev := log.events(); len(ev) != 0 {
				t.Fatalf("no discard event is logged after Close, got %+v", ev)
			}
		})
	}
}
