package amqp

import (
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	amqp091 "github.com/rabbitmq/amqp091-go"
)

// Contract 1.68 §8 test vectors ("Signed authorization responses").
const (
	vecMasterKeyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	vecSubkeyHex    = "919e125ec83799c1e113a27707cac5008a2608d0557e00dfe1b3a316abed4b89"
	vecTenant       = "11111111-1111-1111-1111-111111111111"
	vecOtherTenant  = "99999999-9999-9999-9999-999999999999"
	vecCorrelation  = "22222222-2222-2222-2222-222222222222"
	vecNonce        = "55555555-5555-5555-5555-555555555555"
)

type authzVector struct {
	name      string
	canonical string
	sig       string
	allowed   bool
	reason    string
	code      string
}

var authzVectors = []authzVector{
	{"1 allow",
		`{"correlation_id":"22222222-2222-2222-2222-222222222222","allowed":true,"reason_code":"allowed","tenant_id":"11111111-1111-1111-1111-111111111111","nonce":"55555555-5555-5555-5555-555555555555"}`,
		"8d81f0437df6c6fffafd13f4265bd41d3cfd6fcbf7c251b3bb79e0846578574a", true, "", "allowed"},
	{"2 deny no_grant",
		`{"correlation_id":"22222222-2222-2222-2222-222222222222","allowed":false,"reason":"no permission grants action 'documents:read'","reason_code":"no_grant","tenant_id":"11111111-1111-1111-1111-111111111111","nonce":"55555555-5555-5555-5555-555555555555"}`,
		"f3105ee678acd79da6ffd28c02b86311e16bb8d8dfd3fd0addbacdf73bd5a400", false, "no permission grants action 'documents:read'", "no_grant"},
	{"3 deny denied_by_rule",
		`{"correlation_id":"22222222-2222-2222-2222-222222222222","allowed":false,"reason":"an explicit deny rule refuses action 'documents:read'","reason_code":"denied_by_rule","tenant_id":"11111111-1111-1111-1111-111111111111","nonce":"55555555-5555-5555-5555-555555555555"}`,
		"4bfc2ce9a035bd4a028ee2a5cb75a08832915c60cd2b176c8d4bf28910a61adc", false, "an explicit deny rule refuses action 'documents:read'", "denied_by_rule"},
	{"4 escapes encoders disagree on",
		`{"correlation_id":"22222222-2222-2222-2222-222222222222","allowed":false,"reason":"no permission grants action 'docs:a&b</\"c\">/é€'","reason_code":"no_grant","tenant_id":"11111111-1111-1111-1111-111111111111","nonce":"55555555-5555-5555-5555-555555555555"}`,
		"5194142df4bf66b07e9e8d516caf6be099af025219ab12deb26fea39e93490ff", false, `no permission grants action 'docs:a&b</"c">/é€'`, "no_grant"},
}

func (v authzVector) wire() []byte {
	return []byte(strings.TrimSuffix(v.canonical, "}") + `,"hmac_signature":"` + v.sig + `"}`)
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// subkeyFor derives HKDF-SHA256(salt, ikm=master, info="axiam-amqp-v1" ||
// key_version || tenant_id raw 16 bytes), the contract's derivation.
func subkeyFor(t *testing.T, tenant string, keyVersion byte) []byte {
	t.Helper()
	raw := mustHex(t, strings.ReplaceAll(tenant, "-", ""))
	info := append([]byte("axiam-amqp-v1"), keyVersion)
	info = append(info, raw...)
	k, err := hkdf.Key(sha256.New, mustHex(t, vecMasterKeyHex), []byte("axiam-amqp-hkdf-salt-v1"), string(info), 32)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func signWith(key []byte, canonical string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(canonical))
	return []byte(strings.TrimSuffix(canonical, "}") + `,"hmac_signature":"` + hex.EncodeToString(mac.Sum(nil)) + `"}`)
}

// fakeAuthzTransport is a broker-free AuthzTransport.
type fakeAuthzTransport struct {
	queue      string
	deliveries chan AckableDelivery

	mu        sync.Mutex
	published []publishedAuthz
	declared  int
	closed    int
}

type publishedAuthz struct {
	queue, replyTo, correlationID string
	body                          []byte
}

func newFakeAuthzTransport() *fakeAuthzTransport {
	return &fakeAuthzTransport{queue: "amq.gen-Xk3p", deliveries: make(chan AckableDelivery, 8)}
}

func (f *fakeAuthzTransport) DeclareReplyQueue(context.Context) (string, <-chan AckableDelivery, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.declared++
	return f.queue, f.deliveries, nil
}

func (f *fakeAuthzTransport) PublishRequest(_ context.Context, queue, replyTo, correlationID string, body []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.published = append(f.published, publishedAuthz{queue, replyTo, correlationID, body})
	return nil
}

func (f *fakeAuthzTransport) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed++
	return nil
}

func (f *fakeAuthzTransport) lastPublished(t *testing.T) publishedAuthz {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		f.mu.Lock()
		n := len(f.published)
		var p publishedAuthz
		if n > 0 {
			p = f.published[n-1]
		}
		f.mu.Unlock()
		if n > 0 {
			return p
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("no request was published")
	return publishedAuthz{}
}

// vectorRequester returns a requester for the vectors' tenant with one
// outstanding request (the vectors' correlation_id and nonce).
func vectorRequester(t *testing.T, opts ...AuthzRequesterOption) (*AuthzRequester, *pendingAuthz) {
	t.Helper()
	r, err := NewAuthzRequesterWithTransport(context.Background(), newFakeAuthzTransport(), vecTenant, mustHex(t, vecSubkeyHex), opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	p := &pendingAuthz{nonce: vecNonce, result: make(chan AuthzDecision, 1)}
	r.mu.Lock()
	r.pending[vecCorrelation] = p
	r.mu.Unlock()
	return r, p
}

// offer feeds body to the requester and reports whether it completed the
// outstanding request, plus the delivery's ack/nack counts.
func offer(r *AuthzRequester, p *pendingAuthz, body []byte) (AuthzDecision, bool, *recordingDelivery) {
	d := newRecordingDelivery(body)
	r.handle(d)
	select {
	case dec := <-p.result:
		return dec, true, d
	default:
		return AuthzDecision{}, false, d
	}
}

func TestVectorSubkeyDerivation(t *testing.T) {
	if got := hex.EncodeToString(subkeyFor(t, vecTenant, 2)); got != vecSubkeyHex {
		t.Fatalf("test HKDF derivation %s does not match the contract's subkey %s", got, vecSubkeyHex)
	}
}

func TestAuthzRequester_ContractVectorsVerify(t *testing.T) {
	for _, v := range authzVectors {
		t.Run(v.name, func(t *testing.T) {
			r, p := vectorRequester(t)
			dec, done, d := offer(r, p, v.wire())
			if !done {
				t.Fatal("the contract vector must verify and complete the request")
			}
			if dec.Allowed != v.allowed || dec.Reason != v.reason || dec.ReasonCode != v.code {
				t.Fatalf("decision = %+v", dec)
			}
			if acked, _, _ := d.counts(); acked != 1 {
				t.Fatal("an accepted response must be acked")
			}
			// Retired on acceptance: the same response again is dropped.
			if _, again, d2 := offer(r, p, v.wire()); again {
				t.Fatal("a second response for a retired request must be dropped")
			} else if _, _, nn := d2.counts(); nn != 1 {
				t.Fatal("the duplicate must be nacked without requeue")
			}
		})
	}
}

func TestAuthzRequester_DiscardsAndNeverAllows(t *testing.T) {
	v1, v2 := authzVectors[0], authzVectors[1]
	flip := func(v authzVector, from, to string) []byte {
		return []byte(strings.Replace(string(v.wire()), from, to, 1))
	}
	reSign := func(key []byte, canonical string) []byte { return signWith(key, canonical) }
	good := mustHex(t, vecSubkeyHex)

	cases := []struct {
		name string
		body []byte
	}{
		{"vector 1 under another tenant's subkey", reSign(subkeyFor(t, vecOtherTenant, 2), v1.canonical)},
		{"vector 1 under key_version 3", reSign(subkeyFor(t, vecTenant, 3), v1.canonical)},
		{"tampered decision: allowed flipped to false, signature kept", flip(v1, `"allowed":true`, `"allowed":false`)},
		{"tampered decision: vector 2 flipped to true, signature kept", flip(v2, `"allowed":false`, `"allowed":true`)},
		{"tampered reason_code", flip(v2, `no_grant`, `allowed`)},
		{"response for another nonce", reSign(good, strings.Replace(v1.canonical, vecNonce, "66666666-6666-6666-6666-666666666666", 1))},
		{"response for another correlation_id", reSign(good, strings.Replace(v1.canonical, vecCorrelation, "77777777-7777-7777-7777-777777777777", 1))},
		{"response for another tenant (validly signed with our key)", reSign(good, strings.Replace(v1.canonical, vecTenant, vecOtherTenant, 1))},
		{"no allowed: a signed AuthzRequest on the response queue", reSign(good, `{"correlation_id":"`+vecCorrelation+`","tenant_id":"`+vecTenant+`","subject_id":"33333333-3333-3333-3333-333333333333","action":"documents:read","resource_id":"44444444-4444-4444-4444-444444444444","key_version":2,"nonce":"`+vecNonce+`","issued_at":"2026-07-10T12:00:00Z"}`)},
		{"allowed not a boolean", reSign(good, strings.Replace(v1.canonical, `"allowed":true`, `"allowed":"true"`, 1))},
		{"no tenant_id", reSign(good, strings.Replace(v1.canonical, `"tenant_id":"`+vecTenant+`",`, ``, 1))},
		{"no nonce", reSign(good, strings.Replace(v1.canonical, `,"nonce":"`+vecNonce+`"`, ``, 1))},
		{"signature not the trailing member", []byte(strings.Replace(string(v1.wire()), `"allowed":true`, `"allowed":true,"x":1`, 1))},
		{"duplicate allowed keys, validly signed", reSign(good, strings.Replace(v1.canonical, `"allowed":true`, `"allowed":false,"allowed":true`, 1))},
		{"case-variant allowed key, validly signed", reSign(good, strings.Replace(v1.canonical, `"reason_code"`, `"ALLOWED":false,"reason_code"`, 1))},
		{"trailing whitespace after the closing brace", append(v1.wire(), '\n')},
		{"non-hex signature", []byte(strings.Replace(string(v1.wire()), v1.sig, strings.Repeat("z", 64), 1))},
		{"short signature", []byte(strings.Replace(string(v1.wire()), v1.sig, v1.sig[:62], 1))},
		{"not JSON", []byte("not json")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, p := vectorRequester(t)
			dec, done, d := offer(r, p, tc.body)
			if done || dec.Allowed {
				t.Fatalf("must be discarded, never completed and never an allow (got %+v)", dec)
			}
			if a, nr, nn := d.counts(); a != 0 || nr != 0 || nn != 1 {
				t.Fatalf("must be nacked without requeue, got acked=%d nackRequeue=%d nackNoRequeue=%d", a, nr, nn)
			}
			// The request is still outstanding: the genuine answer completes it.
			if _, done, _ := offer(r, p, v1.wire()); !done {
				t.Fatal("a discarded response must leave the request waiting for the genuine answer")
			}
		})
	}
}

// CONTRACT 1.69 §8 (Appendix A.1 of the fix plan): there is no opt-out that
// accepts an unsigned response. One with no hmac_signature member, or with a
// null one, is discarded and is never an allow.
func TestAuthzRequester_UnsignedResponses(t *testing.T) {
	for _, body := range []string{
		`{"correlation_id":"` + vecCorrelation + `","allowed":true,"reason_code":"allowed"}`,
		`{"correlation_id":"` + vecCorrelation + `","allowed":true,"reason_code":"allowed","tenant_id":"` + vecTenant + `","nonce":"` + vecNonce + `"}`,
		`{"correlation_id":"` + vecCorrelation + `","allowed":true,"hmac_signature":null}`,
	} {
		r, p := vectorRequester(t)
		if dec, done, d := offer(r, p, []byte(body)); done || dec.Allowed {
			t.Fatalf("an unsigned response must be discarded (got %+v): %s", dec, body)
		} else if _, _, nn := d.counts(); nn != 1 {
			t.Fatalf("must be nacked without requeue: %s", body)
		}
		if _, done, _ := offer(r, p, authzVectors[0].wire()); !done {
			t.Fatal("the request must still be waiting for the genuine answer")
		}
	}
}

func TestAuthzRequester_CheckEndToEnd(t *testing.T) {
	ft := newFakeAuthzTransport()
	key := mustHex(t, vecSubkeyHex)
	r, err := NewAuthzRequesterWithTransport(context.Background(), ft, vecTenant, key, WithAuthzTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	if r.ReplyTo() != "amq.gen-Xk3p" {
		t.Fatalf("ReplyTo = %q", r.ReplyTo())
	}

	type result struct {
		d   AuthzDecision
		err error
	}
	run := func(action string) (chan result, publishedAuthz) {
		ch := make(chan result, 1)
		before := func() int { ft.mu.Lock(); defer ft.mu.Unlock(); return len(ft.published) }()
		go func() {
			d, err := r.Check(context.Background(), "33333333-3333-3333-3333-333333333333", action, "44444444-4444-4444-4444-444444444444", "confidential")
			ch <- result{d, err}
		}()
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			ft.mu.Lock()
			if len(ft.published) > before {
				p := ft.published[len(ft.published)-1]
				ft.mu.Unlock()
				return ch, p
			}
			ft.mu.Unlock()
			time.Sleep(time.Millisecond)
		}
		t.Fatal("no request published")
		return nil, publishedAuthz{}
	}

	ch, pub := run("docs:a&b</\"c\">")

	// The request: default-exchange routing to the request queue, a private
	// reply_to, a correlation_id property equal to the body's.
	if pub.queue != AuthzRequestQueue || pub.replyTo != ft.queue || pub.correlationID == "" {
		t.Fatalf("published %+v", pub)
	}
	var req map[string]any
	if err := json.Unmarshal(pub.body, &req); err != nil {
		t.Fatal(err)
	}
	if req["correlation_id"] != pub.correlationID || req["tenant_id"] != vecTenant || req["key_version"] != float64(2) {
		t.Fatalf("request body %s", pub.body)
	}
	// The request verifies under the subkey over its canonical form, and
	// carries the action's characters raw, as serde_json writes them.
	if !strings.Contains(string(pub.body), `"action":"docs:a&b</\"c\">"`) {
		t.Fatalf("action was HTML-escaped: %s", pub.body)
	}
	// (Checked over the received bytes with the signature member cut out, as the
	// server would; Consume's verifyHMAC re-marshals through encoding/json,
	// which HTML-escapes < > & and so cannot verify this action.)
	canon, sigHex, ok := cutTrailingSignature(pub.body)
	if !ok {
		t.Fatalf("request does not end in the signature member: %s", pub.body)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(canon)
	if hex.EncodeToString(mac.Sum(nil)) != sigHex {
		t.Fatal("the published request must verify under the tenant subkey over its canonical bytes")
	}

	// A forgery with the right ids and a wrong key is discarded; the genuine
	// answer then completes the Check.
	nonce, _ := req["nonce"].(string)
	canonical := `{"correlation_id":"` + pub.correlationID + `","allowed":true,"reason_code":"allowed","tenant_id":"` + vecTenant + `","nonce":"` + nonce + `"}`
	ft.deliveries <- newRecordingDelivery(signWith(subkeyFor(t, vecOtherTenant, 2), canonical))
	select {
	case res := <-ch:
		t.Fatalf("a forged response completed the Check: %+v", res)
	case <-time.After(100 * time.Millisecond):
	}
	ft.deliveries <- newRecordingDelivery(signWith(key, canonical))
	select {
	case res := <-ch:
		if res.err != nil || !res.d.Allowed || res.d.ReasonCode != "allowed" {
			t.Fatalf("got %+v", res)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the genuine response did not complete the Check")
	}

	// Fresh, distinct, unpredictable ids per request.
	ch2, pub2 := run("documents:read")
	if pub2.correlationID == pub.correlationID {
		t.Fatal("correlation_id must be fresh per request")
	}
	var req2 map[string]any
	_ = json.Unmarshal(pub2.body, &req2)
	if req2["nonce"] == req["nonce"] || req2["nonce"] == pub2.correlationID {
		t.Fatal("nonce must be fresh per request and independent of the correlation_id")
	}
	r.Close()
	if res := <-ch2; !errors.Is(res.err, ErrAuthzRequesterClosed) {
		t.Fatalf("Close must release outstanding Checks, got %+v", res)
	}
}

func TestAuthzRequester_CheckTimesOutWithoutAnAnswer(t *testing.T) {
	r, err := NewAuthzRequesterWithTransport(context.Background(), newFakeAuthzTransport(), vecTenant, mustHex(t, vecSubkeyHex), WithAuthzTimeout(30*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	_, err = r.Check(context.Background(), "33333333-3333-3333-3333-333333333333", "a", "44444444-4444-4444-4444-444444444444")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.pending) != 0 {
		t.Fatal("a timed-out request must leave no outstanding entry")
	}
}

func TestNewAuthzRequester_RefusesNonPrivateReplyQueue(t *testing.T) {
	for _, q := range []string{"", "axiam.authz.response", "axiam.mail.outbound"} {
		ft := newFakeAuthzTransport()
		ft.queue = q
		if _, err := NewAuthzRequesterWithTransport(context.Background(), ft, vecTenant, []byte("k")); err == nil {
			t.Fatalf("reply queue %q must be refused", q)
		}
	}
	if _, err := NewAuthzRequesterWithTransport(context.Background(), newFakeAuthzTransport(), "not-a-uuid", []byte("k")); err == nil {
		t.Fatal("a non-UUID tenant must be refused")
	}
	if _, err := NewAuthzRequesterWithTransport(context.Background(), newFakeAuthzTransport(), vecTenant, nil); err == nil {
		t.Fatal("a missing signing key must be refused")
	}
}

func TestBuildAuthzRequest_RejectsUnsignableInput(t *testing.T) {
	k := []byte("k")
	ok := "33333333-3333-3333-3333-333333333333"
	for name, args := range map[string][]string{
		"subject not a UUID":   {"x", "a", ok},
		"resource not a UUID":  {ok, "a", "x"},
		"U+2028 in action":     {ok, "a b", ok},
		"invalid UTF-8 action": {ok, "a\xffb", ok},
	} {
		if _, err := buildAuthzRequest(k, "c", vecTenant, args[0], args[1], args[2], nil, "n", time.Now()); err == nil {
			t.Fatalf("%s must be refused", name)
		}
	}
	if _, err := buildAuthzRequest(k, "c", vecTenant, ok, "a", ok, []string{"s1", "s2"}, "n", time.Now()); err == nil {
		t.Fatal("more than one scope must be refused")
	}
}

// fakeAuthzChannel records how the amqp091 adapter declares and publishes.
type fakeAuthzChannel struct {
	declare  []bool // durable, autoDelete, exclusive
	declName string
	consumeX bool
	consumeA bool
	pub      amqp091.Publishing
	pubEx    string
	pubKey   string
	raw      chan amqp091.Delivery

	consumerTag  string
	cancelledTag string
	cancels      int32
	cancelErr    error
	rawCap       int    // capacity of the delivery channel (0: unbuffered)
	onCancel     func() // runs on a successful cancel, before raw is closed
}

func (f *fakeAuthzChannel) QueueDeclare(name string, durable, autoDelete, exclusive, _ bool, _ amqp091.Table) (amqp091.Queue, error) {
	f.declName = name
	f.declare = []bool{durable, autoDelete, exclusive}
	return amqp091.Queue{Name: "amq.gen-abc"}, nil
}
func (f *fakeAuthzChannel) Consume(_, consumer string, autoAck, exclusive, _, _ bool, _ amqp091.Table) (<-chan amqp091.Delivery, error) {
	f.consumeA, f.consumeX = autoAck, exclusive
	f.consumerTag = consumer
	f.raw = make(chan amqp091.Delivery, f.rawCap)
	return f.raw, nil
}

// Cancel mirrors amqp091: a confirmed cancel closes the consumer's delivery
// channel; a failed one (cancelErr) leaves it open.
func (f *fakeAuthzChannel) Cancel(consumer string, _ bool) error {
	atomic.AddInt32(&f.cancels, 1)
	f.cancelledTag = consumer
	if f.cancelErr != nil {
		return f.cancelErr
	}
	if f.onCancel != nil {
		f.onCancel()
	}
	close(f.raw)
	return nil
}
func (f *fakeAuthzChannel) PublishWithContext(_ context.Context, ex, key string, _, _ bool, msg amqp091.Publishing) error {
	f.pubEx, f.pubKey, f.pub = ex, key, msg
	return nil
}

func TestAmqp091AuthzTransport_PrivateExclusiveReplyQueue(t *testing.T) {
	fc := &fakeAuthzChannel{}
	tr := &amqp091AuthzTransport{ch: fc}
	q, deliveries, err := tr.DeclareReplyQueue(context.Background())
	if err != nil || q != "amq.gen-abc" || deliveries == nil {
		t.Fatalf("q=%q err=%v", q, err)
	}
	// Broker-named (empty name), not durable, auto-delete, EXCLUSIVE; consumed
	// exclusively with manual acknowledgement.
	if fc.declName != "" || fc.declare[0] || !fc.declare[1] || !fc.declare[2] {
		t.Fatalf("declare name=%q durable/autoDelete/exclusive=%v", fc.declName, fc.declare)
	}
	if !fc.consumeX || fc.consumeA {
		t.Fatalf("consume exclusive=%v autoAck=%v", fc.consumeX, fc.consumeA)
	}
	if err := tr.PublishRequest(context.Background(), AuthzRequestQueue, q, "cid", []byte("{}")); err != nil {
		t.Fatal(err)
	}
	if fc.pubEx != "" || fc.pubKey != AuthzRequestQueue || fc.pub.ReplyTo != q || fc.pub.CorrelationId != "cid" {
		t.Fatalf("publish exchange=%q key=%q %+v", fc.pubEx, fc.pubKey, fc.pub)
	}
	close(fc.raw)
	if _, open := <-deliveries; open {
		t.Fatal("the deliveries channel must close with the broker's")
	}
}
