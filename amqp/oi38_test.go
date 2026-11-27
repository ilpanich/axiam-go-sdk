package amqp

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	amqp091 "github.com/rabbitmq/amqp091-go"
)

// OI-38 — contract 1.69 §8, owner decisions D-8, D-9 and D-10 (axiam#883):
// the event consumer is typed (one configured type, the other layout refused
// as `malformed` before the HMAC), logs the five-member discard event with its
// own configured tenant in the normative reason order, and refuses a
// byte-order mark or any other prefix as `malformed` without stopping.

// oi38Tenant is the consumer's own configured tenant. It differs from every
// tenant_id the test bodies carry, so an event that read the body's tenant is
// caught.
const oi38Tenant = "77777777-7777-7777-7777-777777777777"

// oi38Queue is the queue the test consumer reads.
const oi38Queue = "axiam.audit.events"

// oi38Dispatch runs one delivery through an event consumer configured for typ
// and oi38Tenant.
func oi38Dispatch(d AckableDelivery, typ MessageType, key []byte, h Handler, log securityLogger, g *replayGuard) {
	verifyAndDispatch(context.Background(), d, eventConsumerSpec{msgType: typ, tenantID: oi38Tenant, queue: oi38Queue, now: time.Now}, key, h, log, g)
}

// oi38Run dispatches body to a consumer of typ and reports the handler's call
// count, the delivery and the recorded events.
func oi38Run(t *testing.T, typ MessageType, key, body []byte, g *replayGuard) (int32, *recordingDelivery, *recordingLogger) {
	t.Helper()
	var calls int32
	d := newRecordingDelivery(body)
	log := &recordingLogger{}
	oi38Dispatch(d, typ, key, func(context.Context, Event) error {
		atomic.AddInt32(&calls, 1)
		return nil
	}, log, g)
	return calls, d, log
}

// oi38AssertEvent checks the one rule 4 event: exactly timestamp, exchange,
// routing_key, tenant_id (the configured tenant) and reason, and none of the
// forbidden values anywhere in it.
func oi38AssertEvent(t *testing.T, log *recordingLogger, reason, exchange, routingKey string, forbidden ...string) {
	t.Helper()
	events := log.events()
	if len(events) != 1 {
		t.Fatalf("want exactly one discard event, got %d: %+v", len(events), events)
	}
	e := events[0]
	if len(e.args) != 10 || len(e.members) != 5 {
		t.Fatalf("the discard event must carry exactly the five canonical members, got %+v", e.args)
	}
	for _, k := range []string{"timestamp", "exchange", "routing_key", "tenant_id", "reason"} {
		if _, ok := e.members[k]; !ok {
			t.Fatalf("discard event lacks member %q: %+v", k, e.args)
		}
	}
	if got := e.members["reason"]; got != reason {
		t.Fatalf("reason = %v, want %q", got, reason)
	}
	if got := e.members["tenant_id"]; got != oi38Tenant {
		t.Fatalf("tenant_id = %v, want the consumer's configured tenant %q", got, oi38Tenant)
	}
	if got := e.members["exchange"]; got != exchange {
		t.Fatalf("exchange = %v, want %q", got, exchange)
	}
	if got := e.members["routing_key"]; got != routingKey {
		t.Fatalf("routing_key = %v, want %q", got, routingKey)
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
			t.Fatalf("the discard event leaks %q: %s", f, serialized)
		}
	}
}

func oi38ExpectRefused(t *testing.T, calls int32, d *recordingDelivery) {
	t.Helper()
	if calls != 0 {
		t.Fatalf("the handler must never run, got %d call(s)", calls)
	}
	if acked, nr, nn := d.counts(); acked != 0 || nr != 0 || nn != 1 {
		t.Fatalf("want Nack(false) only, got acked=%d nackRequeue=%d nackNoRequeue=%d", acked, nr, nn)
	}
}

// flipLastSigHex changes one hex digit of a wire body's trailing signature.
func flipLastSigHex(wire string) string {
	i := len(wire) - 3 // the last hex digit, before `"}`
	c := byte('0')
	if wire[i] == '0' {
		c = '1'
	}
	return wire[:i] + string(c) + wire[i+1:]
}

// D-9: each fixture vector's wire_json — genuine, signed under the same
// tenant subkey — delivered to the consumer of the OTHER type is refused as
// `malformed`, and still `malformed` (not `signature`) with one hex digit of
// its signature changed: the typed check precedes the HMAC. The handler never
// runs, and the event carries no signature or nonce.
func TestTypedConsume_D9_OtherTypesVectorIsMalformedBeforeTheHMAC(t *testing.T) {
	vectors := loadReferenceVectors(t)
	subkey, err := hex.DecodeString(vectors.HKDF.DerivedSubkeyHex)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		vec      referenceVector
		consumer MessageType
	}{
		{"audit_event to the AuthzRequest consumer", vectors.AuditEvent, AuthzRequestMessage},
		{"authz_request to the AuditEventMessage consumer", vectors.AuthzRequest, AuditEventMessage},
	} {
		var nonce struct{ Nonce string }
		_ = json.Unmarshal([]byte(tc.vec.CanonicalSignedJSON), &nonce)
		for _, body := range []struct{ name, wire string }{
			{"genuine", tc.vec.WireJSON},
			{"one signature hex digit changed", flipLastSigHex(tc.vec.WireJSON)},
		} {
			t.Run(tc.name+"/"+body.name, func(t *testing.T) {
				calls, d, log := oi38Run(t, tc.consumer, subkey, []byte(body.wire), nil)
				oi38ExpectRefused(t, calls, d)
				oi38AssertEvent(t, log, "malformed", "", oi38Queue, tc.vec.HMACSignatureHex, nonce.Nonce)
			})
		}
		// Control: the same vector is accepted by the consumer of its own type.
		own := AuditEventMessage
		if tc.consumer == AuditEventMessage {
			own = AuthzRequestMessage
		}
		if calls, _, _ := oi38Run(t, own, subkey, []byte(tc.vec.WireJSON), nil); calls != 1 {
			t.Fatalf("control: %s must dispatch on the consumer of its own type", tc.name)
		}
	}
}

// D-8: the event of the malformed, unsigned and signature paths carries the
// delivery's exchange and routing key as the broker reported them, the
// consumer's configured tenant (never the body's), and no signature or nonce.
func TestConsumer_D8_DiscardEventCarriesDeliveryAndConfiguredTenant(t *testing.T) {
	key := []byte(fixtureSigningKey)
	nonce, issuedAt := c2Fresh()
	canonical := `{"correlation_id":"` + c2CorrelationID + `","tenant_id":"` + c2SignedTenant +
		`","subject_id":"` + c2SignedSubject + `","action":"documents:read","resource_id":"` + c2ResourceID +
		`",` + c2Tail(nonce, issuedAt) + `}`
	signed := string(oi16Sign(key, canonical))
	sig := signed[len(signed)-2-64 : len(signed)-2]
	wrongKey := string(oi16Sign([]byte("another-tenant-subkey"), canonical))
	wrongSig := wrongKey[len(wrongKey)-2-64 : len(wrongKey)-2]
	for _, tc := range []struct {
		name, body, reason string
	}{
		{"malformed (a byte-order mark)", "\xEF\xBB\xBF" + signed, "malformed"},
		{"unsigned", canonical, "unsigned"},
		{"signature", flipLastSigHex(signed), "signature"},
		{"signature (another key)", wrongKey, "signature"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ack := &recordingAcknowledger{}
			d := deliveryAdapter{d: amqp091.Delivery{
				Acknowledger: ack, Exchange: "axiam.events", RoutingKey: "authz.request.t1", Body: []byte(tc.body),
			}}
			log := &recordingLogger{}
			var calls int32
			oi38Dispatch(d, AuthzRequestMessage, key, func(context.Context, Event) error {
				atomic.AddInt32(&calls, 1)
				return nil
			}, log, newReplayGuard(defaultSkew))
			if calls != 0 || ack.nacks.Load() != 1 || ack.badNacks.Load() != 0 || ack.others.Load() != 0 {
				t.Fatalf("want one Nack(false) and no handler call, got calls=%d nacks=%d bad=%d others=%d",
					calls, ack.nacks.Load(), ack.badNacks.Load(), ack.others.Load())
			}
			oi38AssertEvent(t, log, tc.reason, "axiam.events", "authz.request.t1", sig, wrongSig, nonce, c2SignedTenant)
		})
	}
}

// oi38Request is a server-order AuthzRequest with the given replay members.
func oi38Request(keyVersion, nonce, issuedAt string) string {
	return `{"correlation_id":"` + c2CorrelationID + `","tenant_id":"` + c2SignedTenant +
		`","subject_id":"` + c2SignedSubject + `","action":"documents:read","resource_id":"` + c2ResourceID +
		`","key_version":` + keyVersion + `,"nonce":"` + nonce + `","issued_at":"` + issuedAt + `"}`
}

// D-8 / D-9 / D-10: the reason is the first that applies, in the normative
// order (1)-(8) of §8 protocol rule 4.
func TestConsumer_D8_NormativeReasonOrder(t *testing.T) {
	key := []byte(fixtureSigningKey)
	other := []byte("another-tenant-subkey")
	now := time.Now().UTC()
	fresh := now.Format(time.RFC3339)
	stale := now.Add(-time.Hour).Format(time.RFC3339)
	req := func(kv, issued string) string { return oi38Request(kv, uuid.NewString(), issued) }
	audit := alignAuditEvent(`"user.login"`, `{"method":"password"}`)
	for _, tc := range []struct {
		name   string
		body   []byte
		reason string
	}{
		{"(1) a byte-order mark before a valid signed body", append([]byte("\xEF\xBB\xBF"), oi16Sign(key, req("2", fresh))...), "malformed"},
		{"(1) whitespace before a body signed with it", oi16Sign(key, " "+req("2", fresh)), "malformed"},
		{"(1) a newline before a body signed with it", oi16Sign(key, "\n"+req("2", fresh)), "malformed"},
		{"(1) empty", []byte{}, "malformed"},
		{"(1) not JSON", []byte(`not json`), "malformed"},
		{"(1) not UTF-8", []byte("{\xff\xfe}"), "malformed"},
		{"(1) truncated", oi16Sign(key, req("2", fresh))[:40], "malformed"},
		{"(1) deeply nested", []byte(`{"a":` + strings.Repeat(`[`, 100000) + strings.Repeat(`]`, 100000) + `}`), "malformed"},
		{"(1) trailing content after the object", append(oi16Sign(key, req("2", fresh)), []byte(`{}`)...), "malformed"},
		{"(1) a trailing newline", append(oi16Sign(key, req("2", fresh)), '\n'), "malformed"},
		{"(2) the empty object", []byte(`{}`), "unsigned"},
		{"(2) an unsigned request", []byte(req("2", fresh)), "unsigned"},
		{"(2) another type, unsigned", []byte(`{"correlation_id":"x","allowed":true}`), "unsigned"},
		{"(3) hmac_signature null", []byte(strings.TrimSuffix(req("2", fresh), "}") + `,"hmac_signature":null}`), "malformed"},
		{"(3) a folded duplicate, validly signed", oi16Sign(key, strings.Replace(req("2", fresh), `"action"`, `"ACTION":"x","action"`, 1)), "malformed"},
		{"(3) another type, signed with another key", oi16Sign(other, audit), "malformed"},
		{"(3) an AuthzResponse, validly signed", oi16Sign(key, authzVectors[0].canonical), "malformed"},
		{"(4) the right layout, another key", oi16Sign(other, req("2", fresh)), "signature"},
		{"(5) issued_at not RFC 3339, validly signed", oi16Sign(key, req("2", "yesterday")), "malformed"},
		{"(5) nonce not a UUID, validly signed", oi16Sign(key, oi38Request("2", "not-a-uuid", fresh)), "malformed"},
		{"(5) key_version a string, validly signed", oi16Sign(key, req(`"2"`, fresh)), "malformed"},
		{"(5) before (6): key_version 1 and issued_at not RFC 3339", oi16Sign(key, req("1", "yesterday")), "malformed"},
		{"(6) key_version 1", oi16Sign(key, req("1", fresh)), "key_version"},
		{"(6) before (7): key_version 1 and stale", oi16Sign(key, req("1", stale)), "key_version"},
		{"(7) stale", oi16Sign(key, req("2", stale)), "stale"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls, d, log := oi38Run(t, AuthzRequestMessage, key, tc.body, newReplayGuard(defaultSkew))
			oi38ExpectRefused(t, calls, d)
			oi38AssertEvent(t, log, tc.reason, "", oi38Queue)
		})
	}

	t.Run("(8) replay, and a nonce refused at (4)-(7) is never recorded", func(t *testing.T) {
		g := newReplayGuard(defaultSkew)
		n := uuid.NewString()
		// Refused at (4) and (7) with nonce n: neither records it.
		if calls, d, log := oi38Run(t, AuthzRequestMessage, key, oi16Sign(other, oi38Request("2", n, fresh)), g); calls != 0 {
			t.Fatal("a wrong-key body must not dispatch")
		} else {
			oi38ExpectRefused(t, calls, d)
			oi38AssertEvent(t, log, "signature", "", oi38Queue, n)
		}
		if calls, _, log := oi38Run(t, AuthzRequestMessage, key, oi16Sign(key, oi38Request("2", n, stale)), g); calls != 0 {
			t.Fatal("a stale body must not dispatch")
		} else {
			oi38AssertEvent(t, log, "stale", "", oi38Queue, n)
		}
		body := oi16Sign(key, oi38Request("2", n, fresh))
		if calls, _, log := oi38Run(t, AuthzRequestMessage, key, body, g); calls != 1 || len(log.events()) != 0 {
			t.Fatalf("the first genuine delivery of n must dispatch (calls=%d events=%d)", calls, len(log.events()))
		}
		calls, d, log := oi38Run(t, AuthzRequestMessage, key, body, g)
		oi38ExpectRefused(t, calls, d)
		oi38AssertEvent(t, log, "replay", "", oi38Queue, n)
	})
}

// D-10, requester side: a byte-order mark, whitespace or any other byte before
// the `{` is `malformed` — never stripped, and not `signature` for a body
// whose signature covers the prefix.
func TestAuthzRequester_D10_PrefixIsMalformed(t *testing.T) {
	good := mustHex(t, vecSubkeyHex)
	v1 := authzVectors[0].canonical
	for _, tc := range []struct {
		name string
		body []byte
	}{
		{"a byte-order mark before the genuine answer", append([]byte("\xEF\xBB\xBF"), authzVectors[0].wire()...)},
		{"a space, signed with it", signWith(good, " "+v1)},
		{"a tab, signed with it", signWith(good, "\t"+v1)},
		{"a byte-order mark, signed with it", signWith(good, "\xEF\xBB\xBF"+v1)},
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
			oi16AssertDiscardEvent(t, log, r, "malformed", authzVectors[0].sig, vecNonce)
		})
	}
}

// D-10, requester side: a byte-order-mark body is refused and the delivery
// loop goes on to the next delivery, which completes the check.
func TestAuthzRequester_D10_BOMThenNextDeliveryIsProcessed(t *testing.T) {
	log := &recordingLogger{}
	tr := newFakeAuthzTransport()
	r, err := NewAuthzRequesterWithTransport(context.Background(), tr, vecTenant, mustHex(t, vecSubkeyHex), WithAuthzSecurityLogger(log))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	p := &pendingAuthz{nonce: vecNonce, result: make(chan AuthzDecision, 1)}
	r.mu.Lock()
	r.pending[vecCorrelation] = p
	r.mu.Unlock()

	bom := newRecordingDelivery(append([]byte("\xEF\xBB\xBF"), authzVectors[0].wire()...))
	next := newRecordingDelivery(authzVectors[0].wire())
	tr.deliveries <- bom
	tr.deliveries <- next
	select {
	case dec := <-p.result:
		if !dec.Allowed {
			t.Fatalf("the genuine answer after the BOM body must complete the check, got %+v", dec)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the delivery after the BOM body was not processed")
	}
	if _, _, nn := bom.counts(); nn != 1 {
		t.Fatal("the BOM body must be nacked without requeue")
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if acked, _, _ := next.counts(); acked == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the genuine answer was not acked")
		}
		time.Sleep(5 * time.Millisecond)
	}
	oi16AssertDiscardEvent(t, log, r, "malformed")
}

// Test consumers of each type, configured with oi38Tenant.
var (
	testAuthzSpec = eventConsumerSpec{msgType: AuthzRequestMessage, tenantID: oi38Tenant, queue: oi38Queue, now: time.Now}
	testAuditSpec = eventConsumerSpec{msgType: AuditEventMessage, tenantID: oi38Tenant, queue: oi38Queue, now: time.Now}
)

// verifyAs runs verifyEvent for a consumer of typ and reports it as (accepted,
// replay members, canonical bytes).
func verifyAs(typ MessageType, key, body []byte) (bool, replayMeta, []byte) {
	canonical, meta, reason := verifyEvent(key, body, typ)
	return reason == "", meta, canonical
}

// D-10, event consumer: through the real delivery loop, a byte-order-mark body
// is nacked without requeue with one `malformed` event (exchange and routing
// key as the broker reported them) and the loop goes on to the next delivery,
// which dispatches.
func TestConsume_D10_BOMThenNextDeliveryIsProcessed(t *testing.T) {
	key := []byte(fixtureSigningKey)
	good := oi16Sign(key, alignAuditEvent(`"user.login"`, `{"method":"password"}`))
	ack := &recordingAcknowledger{}
	deliveries := make(chan amqp091.Delivery, 2)
	deliveries <- amqp091.Delivery{Acknowledger: ack, Exchange: "", RoutingKey: "axiam.audit.events", Body: append([]byte("\xEF\xBB\xBF"), good...)}
	deliveries <- amqp091.Delivery{Acknowledger: ack, Exchange: "", RoutingKey: "axiam.audit.events", Body: good}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log := &recordingLogger{}
	handled := make(chan Event, 1)
	replay := newReplayGuard(defaultSkew)
	done := make(chan error, 1)
	go func() {
		done <- consumeLoop(ctx, deliveries, make(chan *amqp091.Error), func(d AckableDelivery) {
			verifyAndDispatch(ctx, d, testAuditSpec, key, func(_ context.Context, e Event) error {
				handled <- e
				return nil
			}, log, replay)
		})
	}()
	select {
	case <-handled:
	case <-time.After(2 * time.Second):
		t.Fatal("the delivery after the BOM body was not processed")
	}
	cancel()
	if err := <-done; err != context.Canceled {
		t.Fatalf("the loop must run until its context ends, got %v", err)
	}
	if ack.nacks.Load() != 1 || ack.badNacks.Load() != 0 || ack.others.Load() != 1 {
		t.Fatalf("want one Nack(false) (the BOM body) and one Ack, got nacks=%d bad=%d others=%d", ack.nacks.Load(), ack.badNacks.Load(), ack.others.Load())
	}
	oi38AssertEvent(t, log, "malformed", "", "axiam.audit.events")
}

// D-10, requester side: a deeply nested or non-UTF-8 body is refused as
// malformed without crashing the requester.
func TestAuthzRequester_D10_HostileBodiesAreMalformed(t *testing.T) {
	for _, tc := range []struct {
		name string
		body []byte
	}{
		{"deeply nested", []byte(`{"a":` + strings.Repeat(`[`, 100000) + strings.Repeat(`]`, 100000) + `}`)},
		{"deeply nested objects", []byte(strings.Repeat(`{"a":`, 100000) + `1` + strings.Repeat(`}`, 100000))},
		{"not UTF-8", []byte("{\xff\xfe}")},
		{"empty", []byte{}},
		{"truncated", authzVectors[0].wire()[:40]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			log := &recordingLogger{}
			r, p := vectorRequester(t, WithAuthzSecurityLogger(log))
			if _, done, d := offer(r, p, tc.body); done {
				t.Fatal("must be discarded")
			} else if _, _, nn := d.counts(); nn != 1 {
				t.Fatal("must be nacked without requeue")
			}
			oi16AssertDiscardEvent(t, log, r, "malformed")
		})
	}
}

// Consume needs its type and its own tenant: a consumer that would accept
// either type, or one with no tenant to report, is refused before it touches
// the channel.
func TestConsume_RefusesMissingTypeOrTenant(t *testing.T) {
	h := func(context.Context, Event) error { return nil }
	key := []byte(fixtureSigningKey)
	if err := Consume(context.Background(), nil, "q", MessageType(0), oi38Tenant, key, h); err == nil {
		t.Fatal("a Consume without a message type must be refused")
	}
	if err := Consume(context.Background(), nil, "q", MessageType(3), oi38Tenant, key, h); err == nil {
		t.Fatal("an unknown message type must be refused")
	}
	for _, tenant := range []string{"", "not-a-uuid"} {
		if err := Consume(context.Background(), nil, "q", AuthzRequestMessage, tenant, key, h); err == nil {
			t.Fatalf("tenant %q must be refused", tenant)
		}
	}
	if AuthzRequestMessage.String() != "AuthzRequest" || AuditEventMessage.String() != "AuditEventMessage" || MessageType(0).String() != "MessageType(0)" {
		t.Fatal("MessageType.String")
	}
}
