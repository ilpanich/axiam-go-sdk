package amqp

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	amqp091 "github.com/rabbitmq/amqp091-go"
)

// OI-16 regression tests: GO-R1-1 (key folding), GO-R1-4 (Close), server
// #882 (verify and dispatch the received bytes), #881 (no unsigned opt-out)
// and #883 (the requester's discard event, CONTRACT 1.69 §8 consumer
// obligation 4).

// ---------------------------------------------------------------------------
// GO-R1-1: keys are folded exactly as encoding/json folds them.
// ---------------------------------------------------------------------------

func TestRejectAmbiguousKeys_FoldsLikeEncodingJSON(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		// U+017F LATIN SMALL LETTER LONG S folds to s/S.
		{"long s", `{"subject_id":"x","ſubject_id":"y"}`},
		// U+212A KELVIN SIGN folds to k/K.
		{"Kelvin sign", `{"key_version":2,"Key_version":2}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The premise: encoding/json's struct decode resolves both keys to
			// ONE field, last key winning. Without it the case is not ambiguous.
			var probe struct {
				SubjectID  string `json:"subject_id"`
				KeyVersion int    `json:"key_version"`
			}
			if err := json.Unmarshal([]byte(strings.Replace(tc.body, `":2,`, `":1,`, 1)), &probe); err != nil {
				t.Fatal(err)
			}
			if probe.SubjectID != "y" && probe.KeyVersion != 2 {
				t.Fatalf("premise failed: encoding/json did not fold the second key onto the field (%+v)", probe)
			}
			if !rejectAmbiguousKeys([]byte(tc.body)) {
				t.Fatalf("rejectAmbiguousKeys(%s) = false: two keys encoding/json treats as one passed", tc.body)
			}
		})
	}
	// Keys that encoding/json keeps apart stay apart.
	if rejectAmbiguousKeys([]byte(`{"subject_id":"x","subject_ix":"y"}`)) {
		t.Fatal("distinct keys must not be refused")
	}
}

// The same check serves the requester: a validly signed response whose
// `reason` is repeated under a long-s spelling is discarded, not accepted.
func TestAuthzRequester_UnicodeFoldedDuplicateIsDiscarded(t *testing.T) {
	v2 := authzVectors[1]
	canonical := strings.Replace(v2.canonical, `"reason":`, `"reason":"forged","reaſon":`, 1)
	r, p := vectorRequester(t)
	dec, done, d := offer(r, p, signWith(mustHex(t, vecSubkeyHex), canonical))
	if done {
		t.Fatalf("a body with keys encoding/json folds together must be discarded, got %+v", dec)
	}
	if _, _, nn := d.counts(); nn != 1 {
		t.Fatal("must be nacked without requeue")
	}
}

// ---------------------------------------------------------------------------
// #882 (D-5): the event consumer verifies the received bytes and dispatches
// a value parsed from those same bytes.
// ---------------------------------------------------------------------------

// oi16AuthzRequest returns a server-shaped AuthzRequest canonical form whose
// action is the given JSON string literal (already escaped as on the wire).
func oi16AuthzRequest(actionJSON string) string {
	nonce, issuedAt := c2Fresh()
	return `{"correlation_id":"` + c2CorrelationID + `","tenant_id":"` + c2SignedTenant +
		`","subject_id":"` + c2SignedSubject + `","action":` + actionJSON +
		`,"resource_id":"` + c2ResourceID + `",` + c2Tail(nonce, issuedAt) + `}`
}

func oi16Sign(key []byte, canonical string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(canonical))
	return []byte(strings.TrimSuffix(canonical, "}") + `,"hmac_signature":"` + hex.EncodeToString(mac.Sum(nil)) + `"}`)
}

func TestVerifyAndDispatch_882_GenuineMessageWithCharactersEncodersDisagreeOnVerifies(t *testing.T) {
	key := []byte(fixtureSigningKey)
	for _, tc := range []struct {
		name       string
		actionJSON string
		want       string
	}{
		// serde_json's bytes: < > & / and non-ASCII raw, `"` as \", a control
		// character as \u00XX. encoding/json would write <, >, &.
		{"serde_json escaping", `"docs:a&b</\"c\">/é€\u0001"`, "docs:a&b</\"c\">/é€\x01"},
		// A producer whose encoder escapes non-ASCII (Python's json.dumps
		// default): encoding/json would re-encode é as raw é.
		{"a \\u escape for a non-ASCII character", `"café <b>"`, "café <b>"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			canonical := oi16AuthzRequest(tc.actionJSON)
			calls, seen, d := c2Run(t, key, oi16Sign(key, canonical))
			if calls != 1 {
				t.Fatalf("a genuine signed message must dispatch exactly once, got %d call(s)", calls)
			}
			if acked, _, _ := d.counts(); acked != 1 {
				t.Fatal("a genuine signed message must be acked")
			}
			if string(seen.Raw) != canonical {
				t.Fatalf("Event.Raw must be the received bytes the HMAC covered\n got  %s\n want %s", seen.Raw, canonical)
			}
			if got := c2Field(t, seen, "action"); got != tc.want {
				t.Fatalf("action = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestVerifyAndDispatch_882_MalformedBodiesAreNackedBeforeTheHandler(t *testing.T) {
	key := []byte(fixtureSigningKey)
	canonical := oi16AuthzRequest(`"documents:read"`)
	wire := oi16Sign(key, canonical)
	sig := string(wire[len(wire)-66 : len(wire)-2])

	for _, tc := range []struct {
		name string
		body []byte
	}{
		// A key repeated, signed over exactly these bytes.
		{"duplicate key, validly signed", oi16Sign(key, strings.Replace(canonical, `"action":"documents:read"`, `"action":"documents:delete","action":"documents:read"`, 1))},
		{"trailing content after the object", append(append([]byte(nil), wire...), []byte(` {"action":"x"}`)...)},
		{"trailing whitespace after the object", append(append([]byte(nil), wire...), '\n')},
		// The signature is a member, but not the trailing one: the bytes the
		// HMAC would cover cannot be cut out of what was received.
		{"signature not the trailing member", []byte(`{"hmac_signature":"` + sig + `",` + strings.TrimPrefix(canonical, "{"))},
		{"an unsigned extra member", []byte(strings.Replace(string(wire), `"resource_id"`, `"is_admin":true,"resource_id"`, 1))},
		{"no signature", []byte(canonical)},
		{"not JSON", []byte(`not json`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls, _, d := c2Run(t, key, tc.body)
			c2ExpectNacked(t, calls, d)
		})
	}
}

// ---------------------------------------------------------------------------
// #881 (Appendix A.1) and #883 (Appendix A.2).
// ---------------------------------------------------------------------------

// oi16DiscardEvents asserts that exactly one discard event was logged with
// the canonical members, the reply queue as routing key, the requester's own
// tenant and reason want, and that none of forbidden appears anywhere in it.
func oi16AssertDiscardEvent(t *testing.T, log *recordingLogger, r *AuthzRequester, want string, forbidden ...string) {
	t.Helper()
	events := log.events()
	if len(events) != 1 {
		t.Fatalf("want exactly one discard event, got %d: %+v", len(events), events)
	}
	e := events[0]
	keys := map[string]bool{}
	for i := 0; i < len(e.args); i += 2 {
		k, _ := e.args[i].(string)
		keys[k] = true
	}
	for _, k := range []string{"timestamp", "exchange", "routing_key", "tenant_id", "reason"} {
		if !keys[k] {
			t.Fatalf("discard event lacks member %q: %+v", k, e.args)
		}
	}
	if len(keys) != 5 || len(e.args) != 10 {
		t.Fatalf("discard event must carry exactly the five canonical members, got %+v", e.args)
	}
	if got := e.members["routing_key"]; got != r.ReplyTo() || got == "" {
		t.Fatalf("routing_key = %v, want the reply queue %q", got, r.ReplyTo())
	}
	if got := e.members["tenant_id"]; got != vecTenant {
		t.Fatalf("tenant_id = %v, want the requester's own tenant %q", got, vecTenant)
	}
	if got := e.members["exchange"]; got != "" {
		t.Fatalf("exchange = %v, want the default exchange \"\"", got)
	}
	if got := e.members["reason"]; got != want {
		t.Fatalf("reason = %v, want %q", got, want)
	}
	ts, ok := e.members["timestamp"].(string)
	if !ok {
		t.Fatalf("timestamp is not a string: %T", e.members["timestamp"])
	}
	if parsed, err := time.Parse(time.RFC3339Nano, ts); err != nil || !strings.HasSuffix(ts, "Z") || time.Since(parsed) > time.Minute {
		t.Fatalf("timestamp %q is not a current RFC 3339 UTC time (%v)", ts, err)
	}
	serialized := e.msg + " " + fmt.Sprint(e.args...)
	for _, f := range forbidden {
		if f != "" && strings.Contains(serialized, f) {
			t.Fatalf("the discard event carries a forbidden value %q: %s", f, serialized)
		}
	}
}

func computedSig(key []byte, canonical string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(canonical))
	return hex.EncodeToString(mac.Sum(nil))
}

func TestAuthzRequester_A2_DiscardEventPerReason(t *testing.T) {
	good := mustHex(t, vecSubkeyHex)
	other := subkeyFor(t, vecOtherTenant, 2)
	v1, v2 := authzVectors[0], authzVectors[1]
	otherTenantCanonical := strings.Replace(v1.canonical, vecTenant, vecOtherTenant, 1)
	unknownNonce := strings.Replace(v1.canonical, vecNonce, "66666666-6666-6666-6666-666666666666", 1)
	tampered := strings.Replace(string(v2.wire()), `"allowed":false`, `"allowed":true`, 1)

	for _, tc := range []struct {
		name      string
		body      []byte
		reason    string
		forbidden []string
	}{
		{"signature: another tenant's subkey", signWith(other, v1.canonical), "signature",
			[]string{computedSig(other, v1.canonical), computedSig(good, v1.canonical), vecNonce, vecCorrelation}},
		{"signature: a tampered decision", []byte(tampered), "signature",
			[]string{v2.sig, computedSig(good, strings.Replace(v2.canonical, `"allowed":false`, `"allowed":true`, 1)), vecNonce, vecCorrelation}},
		{"tenant: validly signed for another tenant", signWith(good, otherTenantCanonical), "tenant",
			[]string{computedSig(good, otherTenantCanonical), vecOtherTenant, vecNonce, vecCorrelation}},
		{"unknown_request: no outstanding nonce", signWith(good, unknownNonce), "unknown_request",
			[]string{computedSig(good, unknownNonce), "66666666-6666-6666-6666-666666666666", vecNonce, vecCorrelation}},
		{"unsigned: a well-formed 1.67-shaped response", []byte(`{"correlation_id":"` + vecCorrelation + `","allowed":true,"reason_code":"allowed"}`), "unsigned",
			[]string{vecCorrelation}},
		{"malformed: no allowed", signWith(good, strings.Replace(v1.canonical, `"allowed":true,`, ``, 1)), "malformed",
			[]string{vecNonce, vecCorrelation}},
		{"malformed: a null signature", []byte(`{"correlation_id":"` + vecCorrelation + `","allowed":true,"tenant_id":"` + vecTenant + `","nonce":"` + vecNonce + `","hmac_signature":null}`), "malformed",
			[]string{vecNonce, vecCorrelation}},
		{"malformed: not JSON", []byte(`not json`), "malformed", nil},
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
			oi16AssertDiscardEvent(t, log, r, tc.reason, tc.forbidden...)
		})
	}
}

// A second answer for a request the requester has already retired is
// unknown_request too.
func TestAuthzRequester_A2_SecondAnswerIsUnknownRequest(t *testing.T) {
	log := &recordingLogger{}
	r, p := vectorRequester(t, WithAuthzSecurityLogger(log))
	if _, done, _ := offer(r, p, authzVectors[0].wire()); !done {
		t.Fatal("the genuine answer must complete the request")
	}
	if _, done, _ := offer(r, p, authzVectors[0].wire()); done {
		t.Fatal("a second answer must be discarded")
	}
	oi16AssertDiscardEvent(t, log, r, "unknown_request", authzVectors[0].sig, vecNonce, vecCorrelation)
}

// Appendix A.1: there is no unsigned-response opt-out. A well-formed unsigned
// response for an outstanding correlation_id is discarded with reason
// `unsigned`, the check keeps waiting, and the genuine answer completes it.
func TestAuthzRequester_UnsignedResponseIsDiscardedAndTheCheckKeepsWaiting(t *testing.T) {
	ft := newFakeAuthzTransport()
	log := &recordingLogger{}
	r, err := NewAuthzRequesterWithTransport(context.Background(), ft, vecTenant, mustHex(t, vecSubkeyHex), WithAuthzSecurityLogger(log), WithAuthzTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	type result struct {
		d   AuthzDecision
		err error
	}
	ch := make(chan result, 1)
	go func() {
		d, err := r.Check(context.Background(), "33333333-3333-3333-3333-333333333333", "documents:read", "44444444-4444-4444-4444-444444444444")
		ch <- result{d, err}
	}()
	pub := ft.lastPublished(t)
	var req map[string]any
	if err := json.Unmarshal(pub.body, &req); err != nil {
		t.Fatal(err)
	}
	nonce, _ := req["nonce"].(string)

	unsigned := newRecordingDelivery([]byte(`{"correlation_id":"` + pub.correlationID + `","allowed":true,"reason_code":"allowed"}`))
	ft.deliveries <- unsigned
	select {
	case res := <-ch:
		t.Fatalf("an unsigned response completed the Check: %+v", res)
	case <-time.After(100 * time.Millisecond):
	}
	if _, _, nn := unsigned.counts(); nn != 1 {
		t.Fatal("the unsigned response must be nacked without requeue")
	}
	oi16AssertDiscardEvent(t, log, r, "unsigned", pub.correlationID, nonce)

	canonical := `{"correlation_id":"` + pub.correlationID + `","allowed":false,"reason_code":"no_grant","tenant_id":"` + vecTenant + `","nonce":"` + nonce + `"}`
	ft.deliveries <- newRecordingDelivery(signWith(mustHex(t, vecSubkeyHex), canonical))
	select {
	case res := <-ch:
		if res.err != nil || res.d.Allowed || res.d.ReasonCode != "no_grant" {
			t.Fatalf("got %+v", res)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the genuine response did not complete the Check")
	}
}

// ---------------------------------------------------------------------------
// GO-R1-4: Close cancels the broker consumer and the adapter goroutine exits.
// ---------------------------------------------------------------------------

func TestAuthzRequester_CloseCancelsTheConsumerAndLeaksNoGoroutine(t *testing.T) {
	before := settleGoroutines(-1)

	for i := 0; i < 4; i++ {
		fc := &fakeAuthzChannel{}
		if i%2 == 1 {
			// A cancel that fails (a channel already gone, say) leaves the
			// delivery channel open: the adapter must still exit.
			fc.cancelErr = errors.New("channel closed")
		}
		r, err := NewAuthzRequesterWithTransport(context.Background(), &amqp091AuthzTransport{ch: fc}, vecTenant, mustHex(t, vecSubkeyHex))
		if err != nil {
			t.Fatal(err)
		}
		r.Close()
		r.Close() // idempotent

		if fc.consumerTag == "" {
			t.Fatal("the reply-queue consumer must be started with a known consumer tag")
		}
		if got := atomic.LoadInt32(&fc.cancels); got != 1 || fc.cancelledTag != fc.consumerTag {
			t.Fatalf("Close must cancel the broker consumer once by its tag: cancels=%d tag=%q, consumed with %q", got, fc.cancelledTag, fc.consumerTag)
		}
	}
	if after := settleGoroutines(before); after > before {
		t.Fatalf("goroutine leak: %d goroutines before, %d after four requesters were closed", before, after)
	}
}

// ---------------------------------------------------------------------------
// Review round 1, item 1: the signed-layout check is load-bearing. A body
// validly signed under the tenant subkey over exactly its received bytes is
// still refused unless it is an AuthzRequest or AuditEventMessage in the
// server's member order.
// ---------------------------------------------------------------------------

func TestVerifyHMAC_RefusesSignedBodiesOfAnotherLayout(t *testing.T) {
	key := []byte(fixtureSigningKey)
	nonce, issuedAt := c2Fresh()
	ids := `"correlation_id":"` + c2CorrelationID + `","tenant_id":"` + c2SignedTenant + `","subject_id":"` + c2SignedSubject + `"`
	rest := `"action":"documents:read","resource_id":"` + c2ResourceID + `"`
	for _, tc := range []struct {
		name      string
		canonical string
		// dispatch: also run it through verifyAndDispatch (the body carries
		// key_version, nonce and issued_at, so only the layout check stops it).
		dispatch bool
	}{
		{"a signed AuthzResponse (contract vector 1, vector subkey)", authzVectors[0].canonical, false},
		{"an AuthzRequest with its members reordered", `{"tenant_id":"` + c2SignedTenant + `","correlation_id":"` + c2CorrelationID +
			`","subject_id":"` + c2SignedSubject + `",` + rest + `,` + c2Tail(nonce, issuedAt) + `}`, true},
		{"an AuthzRequest with an extra member, signed over those bytes", `{` + ids + `,` + rest + `,"is_admin":true,` + c2Tail(nonce, issuedAt) + `}`, true},
		{"a CacheInvalidationMessage", `{"origin_id":"` + c2CorrelationID + `","tenant_id":"` + c2SignedTenant +
			`","subject_id":"` + c2SignedSubject + `",` + c2Tail(nonce, issuedAt) + `}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			signKey := key
			if !tc.dispatch {
				signKey = mustHex(t, vecSubkeyHex)
			}
			body := oi16Sign(signKey, tc.canonical)
			if ok, _, _ := verifyHMAC(signKey, body); ok {
				t.Fatalf("verifyHMAC accepted a validly signed body that is not a known signed layout: %s", body)
			}
			if tc.dispatch {
				calls, _, d := c2Run(t, signKey, body)
				c2ExpectNacked(t, calls, d)
			}
		})
	}
	// Control: the same signer and the server's own layout verify.
	if ok, _, _ := verifyHMAC(key, oi16Sign(key, `{`+ids+`,`+rest+`,`+c2Tail(nonce, issuedAt)+`}`)); !ok {
		t.Fatal("control: a server-shaped AuthzRequest must verify")
	}
}

// ---------------------------------------------------------------------------
// Review round 1, item 2: what the broker still holds when Close runs is
// nacked without requeue — the delivery the forwarder had in hand and those
// still buffered — and the forwarder exits.
// ---------------------------------------------------------------------------

// recordingAcknowledger records Nack calls of amqp091 deliveries.
type recordingAcknowledger struct {
	nacks    atomic.Int32
	badNacks atomic.Int32 // multiple or requeue set
	others   atomic.Int32
}

func (a *recordingAcknowledger) Ack(uint64, bool) error { a.others.Add(1); return nil }
func (a *recordingAcknowledger) Reject(uint64, bool) error {
	a.others.Add(1)
	return nil
}
func (a *recordingAcknowledger) Nack(_ uint64, multiple, requeue bool) error {
	a.nacks.Add(1)
	if multiple || requeue {
		a.badNacks.Add(1)
	}
	return nil
}

func TestAmqp091AuthzTransport_CloseNacksInFlightAndBufferedDeliveries(t *testing.T) {
	before := settleGoroutines(-1)
	ack := &recordingAcknowledger{}
	fc := &fakeAuthzChannel{rawCap: 4}
	// The broker still delivers two answers between the cancel and its
	// confirmation; amqp091 closes the delivery channel once they are read.
	fc.onCancel = func() {
		fc.raw <- amqp091.Delivery{Acknowledger: ack, DeliveryTag: 2}
		fc.raw <- amqp091.Delivery{Acknowledger: ack, DeliveryTag: 3}
	}
	tr := &amqp091AuthzTransport{ch: fc}
	_, out, err := tr.DeclareReplyQueue(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// One delivery the forwarder takes and holds: nobody reads out.
	fc.raw <- amqp091.Delivery{Acknowledger: ack, DeliveryTag: 1}
	deadline := time.Now().Add(2 * time.Second)
	for len(fc.raw) > 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(fc.raw) != 0 {
		t.Fatal("the forwarder did not take the first delivery")
	}

	if err := tr.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case _, open := <-out:
		if open {
			t.Fatal("no delivery may be forwarded after Close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the forwarder did not exit after Close")
	}
	if n, bad, other := ack.nacks.Load(), ack.badNacks.Load(), ack.others.Load(); n != 3 || bad != 0 || other != 0 {
		t.Fatalf("want the in-flight and both buffered deliveries Nack(false,false): nacks=%d bad=%d acks/rejects=%d", n, bad, other)
	}
	if after := settleGoroutines(before); after > before {
		t.Fatalf("goroutine leak: %d before, %d after", before, after)
	}
}

// settleGoroutines waits (up to 2 s) for the goroutine count to fall to
// limit and returns it. With limit < 0 it takes a baseline after a short
// fixed pause, so goroutines of earlier tests can finish without stalling.
func settleGoroutines(limit int) int {
	if limit < 0 {
		time.Sleep(20 * time.Millisecond)
		return runtime.NumGoroutine()
	}
	deadline := time.Now().Add(2 * time.Second)
	n := runtime.NumGoroutine()
	for n > limit && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
		n = runtime.NumGoroutine()
	}
	return n
}
