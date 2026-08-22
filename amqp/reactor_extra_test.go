package amqp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	amqp091 "github.com/rabbitmq/amqp091-go"
)

// TestReactorOptions_ApplyAndRejectNonsense covers every ReactorOption, and
// the rule each of them shares: a non-positive duration is IGNORED rather
// than accepted, so a caller who passes a zero value gets the documented
// default instead of a runtime with no freshness window and no drain.
func TestReactorOptions_ApplyAndRejectNonsense(t *testing.T) {
	base := reactorConfig{skew: defaultSkew, logger: noopLogger{}, drainGrace: reactorDefaultDrainGrace}

	cfg := base
	logger := &reactorRecordingLogger{}
	for _, opt := range []ReactorOption{
		WithReactorSkew(90 * time.Second),
		WithReactorSecurityLogger(logger),
		WithReactorDrainGrace(2 * time.Second),
		WithReactorTelemetryHook(func(ReactorTelemetryEvent) {}),
	} {
		opt(&cfg)
	}
	if cfg.skew != 90*time.Second {
		t.Fatalf("skew = %s", cfg.skew)
	}
	if cfg.drainGrace != 2*time.Second {
		t.Fatalf("drainGrace = %s", cfg.drainGrace)
	}
	if cfg.logger != securityLogger(logger) {
		t.Fatal("the security logger was not installed")
	}
	if cfg.telemetry == nil {
		t.Fatal("the telemetry hook was not installed")
	}

	// Non-positive and nil arguments must leave the defaults standing.
	ignored := base
	for _, opt := range []ReactorOption{
		WithReactorSkew(0),
		WithReactorSkew(-time.Second),
		WithReactorDrainGrace(0),
		WithReactorSecurityLogger(nil),
		WithReactorTelemetryHook(nil),
	} {
		opt(&ignored)
	}
	if ignored.skew != defaultSkew || ignored.drainGrace != reactorDefaultDrainGrace {
		t.Fatalf("a nonsense option must not overwrite a default: %+v", ignored)
	}
	if ignored.telemetry != nil {
		t.Fatal("a nil telemetry hook must not be installed")
	}
	if ignored.logger != securityLogger(noopLogger{}) {
		t.Fatal("a nil security logger must not replace the no-op")
	}
	// The no-op logger has to actually be callable — it is the default, and
	// the dispatch path calls it on every refusal.
	noopLogger{}.SecurityWarn("ignored", "args")
}

// TestAMQPSDialerOptions_Apply covers the dialer's own options, including
// their non-positive guards.
func TestAMQPSDialerOptions_Apply(t *testing.T) {
	cfg := amqpsDialerConfig{heartbeat: 10 * time.Second, prefetch: 10}
	WithReactorHeartbeat(30 * time.Second)(&cfg)
	WithReactorPrefetch(64)(&cfg)
	if cfg.heartbeat != 30*time.Second || cfg.prefetch != 64 {
		t.Fatalf("options did not apply: %+v", cfg)
	}
	WithReactorHeartbeat(0)(&cfg)
	WithReactorPrefetch(-1)(&cfg)
	if cfg.heartbeat != 30*time.Second || cfg.prefetch != 64 {
		t.Fatalf("a non-positive value must be ignored: %+v", cfg)
	}
}

// TestAMQPSDialer_AcceptsAPEMBundleAndSurfacesDialFailure walks the dialer
// past its CA-bundle parse and into the connection attempt.
//
// The dial is expected to FAIL — there is no broker — and that is the point:
// the failure must be a plain transport error naming neither the URL's
// credentials nor anything else a reconnect diagnostic should not carry.
func TestAMQPSDialer_AcceptsAPEMBundleAndSurfacesDialFailure(t *testing.T) {
	caPEM := selfSignedCAPEM(t)

	_, err := AMQPSDialer(
		"amqps://reactor:hunter2@127.0.0.1:1",
		WithReactorCABundle(caPEM),
		WithReactorHeartbeat(5*time.Second),
		WithReactorPrefetch(4),
	)(context.Background())
	if err == nil {
		t.Fatal("dialing a closed port must fail")
	}
	if errors.Is(err, ErrReactorInsecureURL) {
		t.Fatal("an amqps:// URL must get past the scheme check")
	}
	// The runtime never renders this error into telemetry — it renders a
	// category instead, precisely because an AMQP URL carries credentials.
	if got := reactorRedactedReason(err); got != "transport_error" {
		t.Fatalf("reconnect reason = %q, want a redacted category", got)
	}
	if strings.Contains(reactorRedactedReason(err), "hunter2") {
		t.Fatal("the redacted reason must not carry the URL's password")
	}

	// An uppercase scheme is still amqps.
	if _, err := AMQPSDialer("AMQPS://127.0.0.1:1")(context.Background()); errors.Is(err, ErrReactorInsecureURL) {
		t.Fatal("the scheme check must be case-insensitive")
	}
}

// selfSignedCAPEM mints a throwaway CA certificate so the dialer's bundle
// parse has something valid to accept.
func selfSignedCAPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate a test key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "axiam-reactor-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create a test certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// TestAMQP091Transport_ShimBehaviour covers the thin rabbitmq/amqp091-go
// adapter without a broker.
//
// Everything here is a boundary the adapter owns rather than delegates: the
// delivery accessors, the ack/nack calls on an unattached delivery (which
// amqp091 answers with an error rather than a panic, and which this adapter
// deliberately swallows — once the loop has decided the outcome there is no
// further recovery available), the empty-reply_to refusal, and an idempotent
// Close over nothing.
func TestAMQP091Transport_ShimBehaviour(t *testing.T) {
	d := amqp091ReactorDelivery{}
	d.d.Body = []byte(`{"hello":"world"}`)
	d.d.ReplyTo = "reply-q"
	d.d.CorrelationId = "corr-1"

	if string(d.Body()) != `{"hello":"world"}` {
		t.Fatalf("Body() = %s", d.Body())
	}
	if d.ReplyTo() != "reply-q" || d.CorrelationID() != "corr-1" {
		t.Fatalf("ReplyTo/CorrelationID = %q/%q", d.ReplyTo(), d.CorrelationID())
	}
	// Neither may panic on a delivery with no acknowledger attached.
	d.Ack()
	d.Nack()

	transport := &amqp091Transport{}
	// §22.1's reply addressing: with no reply_to there is nowhere to answer,
	// and inventing a queue name would be the one thing a reactor must not do.
	if err := transport.PublishReply(context.Background(), "", "corr", []byte("{}")); err == nil {
		t.Fatal("publishing with no reply_to queue must fail")
	}
	// Close over nothing is a no-op, twice (§18.1 rule 2).
	if err := transport.Close(); err != nil {
		t.Fatalf("Close over an empty transport: %v", err)
	}
	if err := transport.Close(); err != nil {
		t.Fatalf("Close must be idempotent: %v", err)
	}
}

// TestReactorTelemetryEvents_AreAClosedSet calls each variant's marker so the
// closed-interface guarantee is exercised rather than merely declared, and
// asserts every variant satisfies the interface.
func TestReactorTelemetryEvents_AreAClosedSet(t *testing.T) {
	ReactorReceivedEvent{}.isReactorTelemetryEvent()
	ReactorRejectedEvent{}.isReactorTelemetryEvent()
	ReactorRepliedEvent{}.isReactorTelemetryEvent()
	ReactorNoReplyEvent{}.isReactorTelemetryEvent()
	ReactorReconnectEvent{}.isReactorTelemetryEvent()

	all := []ReactorTelemetryEvent{
		ReactorReceivedEvent{Event: "token.pre_issue", CorrelationID: "c"},
		ReactorRejectedEvent{Event: "", Reason: "bad_signature"},
		ReactorRepliedEvent{Event: "token.pre_issue", CorrelationID: "c", Decision: "mutate", Duration: time.Millisecond},
		ReactorNoReplyEvent{Event: "login.post_auth", CorrelationID: "c", Reason: "handler_error"},
		ReactorReconnectEvent{Attempt: 1, Delay: time.Second, Reason: "session_closed"},
	}
	if len(all) != 5 {
		t.Fatalf("expected five variants, got %d", len(all))
	}
	// Encodable, because that is what a metrics exporter does with them, and
	// the point of the closed set is that no field can carry a secret.
	if _, err := json.Marshal(all); err != nil {
		t.Fatalf("telemetry events must serialize: %v", err)
	}
}

// TestReactorEvent_Accessors covers the handler-facing helpers.
func TestReactorEvent_Accessors(t *testing.T) {
	ev := ReactorEvent{
		Event:   ReactorEventTokenPreIssue,
		Payload: json.RawMessage(`{"sub":"alice","client_id":"portal"}`),
	}

	spec, ok := ev.Spec()
	if !ok || spec.Name != ReactorEventTokenPreIssue || !spec.Mutable {
		t.Fatalf("Spec() = %+v, %v", spec, ok)
	}
	if _, ok := (ReactorEvent{Event: "nope.not_an_event"}).Spec(); ok {
		t.Fatal("an unregistered name must report no spec")
	}

	var payload struct {
		Sub      string `json:"sub"`
		ClientID string `json:"client_id"`
	}
	if err := ev.DecodePayload(&payload); err != nil {
		t.Fatalf("DecodePayload: %v", err)
	}
	if payload.Sub != "alice" || payload.ClientID != "portal" {
		t.Fatalf("decoded payload = %+v", payload)
	}
	// A decode failure names itself rather than surfacing a bare json error.
	if err := ev.DecodePayload(&struct {
		Sub int `json:"sub"`
	}{}); err == nil || !strings.Contains(err.Error(), "reactor event payload") {
		t.Fatalf("expected a named decode error, got %v", err)
	}

	// A payload that is not an object cannot carry a chain patch.
	if _, ok := (ReactorEvent{Payload: json.RawMessage(`"scalar"`)}).ChainPatch(); ok {
		t.Fatal("a non-object payload must report no chain patch")
	}
}

// TestReactorAnswer_Accessors covers the two readers on an answer.
func TestReactorAnswer_Accessors(t *testing.T) {
	if got := ReactorAllow(); got.Decision() != "allow" || got.RequireMFA() {
		t.Fatalf("allow = %+v", got)
	}
	if got := ReactorAllowWithStepUp(); got.Decision() != "allow" || !got.RequireMFA() {
		t.Fatalf("allow+step-up = %+v", got)
	}
	if got := ReactorDeny("nope"); got.Decision() != "deny" || got.RequireMFA() {
		t.Fatalf("deny = %+v", got)
	}
	// ReactorMutate copies its argument: a handler that keeps mutating the
	// map it handed over must not change what goes on the wire.
	original := map[string]string{"ext.a": "1"}
	answer := ReactorMutate(original)
	original["ext.a"] = "2"
	original["ext.b"] = "3"
	if answer.patch["ext.a"] != "1" || len(answer.patch) != 1 {
		t.Fatalf("ReactorMutate must snapshot its patch, got %v", answer.patch)
	}
}

// TestReactorRejectionReason_CoversEveryCategory pins the telemetry
// vocabulary to §22.4's rejection table, including the default.
func TestReactorRejectionReason_CoversEveryCategory(t *testing.T) {
	cases := map[string]error{
		"key_version_too_old": ErrReactorKeyVersionTooOld,
		"bad_signature":       ErrReactorBadSignature,
		"stale":               ErrReactorStale,
		"replay":              ErrReactorReplay,
		"tenant_mismatch":     ErrReactorTenantMismatch,
		"unknown_event":       fmt.Errorf("%w: %q", ErrReactorUnknownEvent, "nope"),
		"malformed":           ErrReactorMalformed,
	}
	for want, err := range cases {
		if got := reactorRejectionReason(err); got != want {
			t.Errorf("reactorRejectionReason(%v) = %q, want %q", err, got, want)
		}
	}
	if got := reactorRejectionReason(errors.New("something else")); got != "malformed" {
		t.Errorf("an unrecognised error must fall back to malformed, got %q", got)
	}
}

// TestReactorRedactedReason_CoversEveryCategory does the same for the
// session-loss vocabulary. The categories exist because an AMQP dial error
// embeds the URL, and an AMQP URL carries credentials.
func TestReactorRedactedReason_CoversEveryCategory(t *testing.T) {
	if got := reactorRedactedReason(nil); got != "session_closed" {
		t.Errorf("nil = %q", got)
	}
	if got := reactorRedactedReason(ErrReactorInsecureURL); got != "insecure_url" {
		t.Errorf("insecure url = %q", got)
	}
	if got := reactorRedactedReason(errors.New("dial tcp 10.0.0.1:5671: connection refused")); got != "transport_error" {
		t.Errorf("transport = %q", got)
	}
}

// TestReactorReconnectDelay_GuardsItsInputs covers the clamps around the
// backoff arithmetic.
func TestReactorReconnectDelay_GuardsItsInputs(t *testing.T) {
	if got := reactorReconnectDelay(0, 1); got != reactorReconnectBaseDelay {
		t.Fatalf("attempt 0 must be treated as attempt 1, got %s", got)
	}
	if got := reactorReconnectDelay(-5, 1); got != reactorReconnectBaseDelay {
		t.Fatalf("a negative attempt must be treated as attempt 1, got %s", got)
	}
	if got := reactorReconnectDelay(1, 2); got != reactorReconnectBaseDelay {
		t.Fatalf("a jitter fraction above 1 must clamp, got %s", got)
	}
	if got := reactorReconnectDelay(1, -1); got != 0 {
		t.Fatalf("a jitter fraction below 0 must clamp, got %s", got)
	}
	if got := reactorReconnectDelay(1000, 1); got != reactorReconnectMaxDelay {
		t.Fatalf("an attempt beyond the shift guard must clamp to the cap, got %s", got)
	}
}

// TestDecodeReactorEvent_MalformedBodies covers the decode failures that are
// not signature failures. Each one produces no reply, which hands the
// outcome to the registration's failure_policy.
func TestDecodeReactorEvent_MalformedBodies(t *testing.T) {
	v, subkey := loadReactorVectors(t)
	now := vectorsNow(t, v)

	for _, tc := range []struct {
		name string
		body string
		want error
	}{
		{"not JSON at all", `<html>`, ErrReactorMalformed},
		{"no signature field", `{"tenant_id":"t","event":"login.post_auth"}`, ErrReactorBadSignature},
		{"signature present, no payload", `{"tenant_id":"t","event":"login.post_auth","hmac_signature":"ab"}`, ErrReactorMalformed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decodeReactorEvent(subkey, []byte(tc.body), v.TenantID, now, defaultSkew, nil)
			if !errors.Is(err, tc.want) {
				t.Fatalf("expected %v, got %v", tc.want, err)
			}
		})
	}
}

// TestDecodeReactorEvent_UnknownEventNameRefused covers the registry check.
// The server dispatches no event outside the registry, so a delivery
// carrying one is not something to guess about — and this is the same check
// that makes §22.7's hot-path exclusion structural rather than advisory.
func TestDecodeReactorEvent_UnknownEventNameRefused(t *testing.T) {
	v, subkey := loadReactorVectors(t)
	now := time.Now()

	body := freshReactorEventNamed(t, subkey, v.TenantID, "nope.not_an_event", v.ExpectedCorrelationID)
	_, err := decodeReactorEvent(subkey, body, v.TenantID, now, defaultSkew, nil)
	if !errors.Is(err, ErrReactorUnknownEvent) {
		t.Fatalf("expected ErrReactorUnknownEvent, got %v", err)
	}

	// A malformed issued_at is caught after the MAC, because the MAC is over
	// the string exactly as it arrived.
	bad := freshReactorEventWithIssuedAt(t, subkey, v.TenantID, ReactorEventLoginPostAuth, v.ExpectedCorrelationID, "not-a-timestamp")
	if _, err := decodeReactorEvent(subkey, bad, v.TenantID, now, defaultSkew, nil); !errors.Is(err, ErrReactorMalformed) {
		t.Fatalf("expected a malformed-timestamp refusal, got %v", err)
	}
}

// freshReactorEventNamed signs a current-clock event for an arbitrary name.
func freshReactorEventNamed(t *testing.T, subkey []byte, tenantID, event, correlationID string) []byte {
	t.Helper()
	return signTestReactorEvent(t, subkey, tenantID, event, correlationID,
		time.Now().UTC().Truncate(time.Second).Format(time.RFC3339))
}

// freshReactorEventWithIssuedAt signs an event carrying an arbitrary
// issued_at string, so the timestamp parse can be exercised on a body whose
// MAC is nonetheless valid.
func freshReactorEventWithIssuedAt(t *testing.T, subkey []byte, tenantID, event, correlationID, issuedAt string) []byte {
	t.Helper()
	return signTestReactorEvent(t, subkey, tenantID, event, correlationID, issuedAt)
}

func signTestReactorEvent(t *testing.T, subkey []byte, tenantID, event, correlationID, issuedAt string) []byte {
	t.Helper()
	msg := reactorEventCanonical{
		TenantID:      tenantID,
		Event:         event,
		CorrelationID: correlationID,
		Payload:       json.RawMessage(`{"sub":"alice"}`),
		TimeoutMS:     500,
		KeyVersion:    reactorKeyVersion,
		Nonce:         defaultReactorNonce()(),
		IssuedAt:      issuedAt,
	}
	canonical, err := marshalReactorCanonical(&msg)
	if err != nil {
		t.Fatalf("failed to canonicalize: %v", err)
	}
	sig := signReactorBytes(subkey, canonical)
	msg.HMACSignature = &sig
	body, err := marshalReactorCanonical(&msg)
	if err != nil {
		t.Fatalf("failed to serialize: %v", err)
	}
	return body
}

// TestVerifyReactorMAC_RejectsNonHex covers the decode guard on a signature
// that is not hex at all — rejected rather than compared, and never a panic.
func TestVerifyReactorMAC_RejectsNonHex(t *testing.T) {
	if verifyReactorMAC([]byte("key"), []byte("body"), "zzzz") {
		t.Fatal("a non-hex signature must not verify")
	}
	if verifyReactorMAC([]byte("key"), []byte("body"), "") {
		t.Fatal("an empty signature must not verify")
	}
}

// TestMarshalReactorCanonical_DoesNotHTMLEscape is the PHP/Go-shared trap in
// its Go form: encoding/json escapes the HTML-significant characters by
// default and serde_json escapes none of them, so a deny reason containing
// an ampersand would otherwise produce bytes the server never reconstructs.
func TestMarshalReactorCanonical_DoesNotHTMLEscape(t *testing.T) {
	v, subkey := loadReactorVectors(t)
	reason := `R&D <team> "west"`

	body, err := buildReactorReply(subkey, ReactorEvent{
		TenantID:      v.TenantID,
		Event:         ReactorEventLoginPostAuth,
		CorrelationID: v.ExpectedCorrelationID,
	}, ReactorDeny(reason), "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", vectorsNow(t, v))
	if err != nil {
		t.Fatalf("building the reply failed: %v", err)
	}
	for _, escaped := range []string{`\u0026`, `\u003c`, `\u003e`} {
		if strings.Contains(string(body), escaped) {
			t.Fatalf("the canonical encoder must not HTML-escape (%s): %s", escaped, body)
		}
	}
	if !strings.Contains(string(body), `R&D <team>`) {
		t.Fatalf("the reason must survive verbatim: %s", body)
	}

	// A value the encoder genuinely cannot render fails the build rather
	// than producing half a reply.
	if _, err := marshalReactorCanonical(map[string]any{"bad": make(chan int)}); err == nil {
		t.Fatal("an unencodable value must produce an error")
	}
}

// TestReactorServe_ReturnsImmediatelyOnACancelledContext covers the loop's
// entry guard: a context that is already done never dials.
func TestReactorServe_ReturnsImmediatelyOnACancelledContext(t *testing.T) {
	v, subkey := loadReactorVectors(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	dialed := false
	err := ReactorServe(ctx,
		func(context.Context) (ReactorTransport, error) {
			dialed = true
			return newFakeReactorTransport(), nil
		},
		ReactorConfig{TenantID: v.TenantID, ReactorID: v.ReactorID, SigningKey: subkey},
		func(context.Context, ReactorEvent) (ReactorAnswer, error) { return ReactorAllow(), nil },
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if dialed {
		t.Fatal("a cancelled context must not dial")
	}
}

// TestReactorServe_DialFailureIsAReconnectNotAFatal covers the other half of
// the loop: a dialer that cannot connect produces a reconnect, because a
// long-lived daemon that gave up on the first refused connection would go
// deaf for the rest of the process's life.
func TestReactorServe_DialFailureIsAReconnectNotAFatal(t *testing.T) {
	v, subkey := loadReactorVectors(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reconnects := make(chan ReactorReconnectEvent, 2)
	go func() {
		_ = ReactorServe(ctx,
			func(context.Context) (ReactorTransport, error) {
				return nil, errors.New("broker unreachable")
			},
			ReactorConfig{TenantID: v.TenantID, ReactorID: v.ReactorID, SigningKey: subkey},
			func(context.Context, ReactorEvent) (ReactorAnswer, error) { return ReactorAllow(), nil },
			WithReactorTelemetryHook(func(e ReactorTelemetryEvent) {
				if ev, ok := e.(ReactorReconnectEvent); ok {
					select {
					case reconnects <- ev:
					default:
					}
				}
			}),
		)
	}()

	select {
	case ev := <-reconnects:
		if ev.Reason != "transport_error" {
			t.Fatalf("reconnect reason = %q", ev.Reason)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a dial failure must produce a reconnect event")
	}
}

// TestReactorDispatch_PublishFailureIsNotAnAllow covers the last no-reply
// path: the reply was built and signed, and the broker would not take it.
// Like every other failure here it resolves to the operator's policy.
func TestReactorDispatch_PublishFailureIsNotAnAllow(t *testing.T) {
	rig := newReactorTestRig(t)
	rig.transport.publishFn = func(string, string, []byte) error {
		return errors.New("channel closed")
	}
	d := rig.delivery(t, "login_post_auth")

	rig.dispatch(d, func(context.Context, ReactorEvent) (ReactorAnswer, error) {
		return ReactorAllow(), nil
	})

	if replies := rig.transport.replies(); len(replies) != 0 {
		t.Fatalf("a failed publish must record no reply, got %d", len(replies))
	}
	found := false
	for _, e := range rig.telemetry() {
		if ev, ok := e.(ReactorNoReplyEvent); ok && ev.Reason == "publish_failed" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a publish_failed ReactorNoReplyEvent, got %+v", rig.telemetry())
	}
}

// TestRunReactorSession_ConsumeFailureEndsTheSession covers the Consume error
// path, which the reconnect loop treats exactly like a dropped session.
func TestRunReactorSession_ConsumeFailureEndsTheSession(t *testing.T) {
	v, subkey := loadReactorVectors(t)
	transport := &failingConsumeTransport{}

	err := runReactorSession(context.Background(),
		func(context.Context) (ReactorTransport, error) { return transport, nil },
		"axiam.reactor.q.x.y",
		ReactorConfig{TenantID: v.TenantID, ReactorID: v.ReactorID, SigningKey: subkey},
		func(context.Context, ReactorEvent) (ReactorAnswer, error) { return ReactorAllow(), nil },
		reactorConfig{skew: defaultSkew, logger: noopLogger{}, drainGrace: time.Millisecond, now: time.Now},
		newReplayGuard(defaultSkew),
	)
	if err == nil {
		t.Fatal("a Consume failure must end the session")
	}
	if !transport.closed {
		t.Fatal("the transport must be closed even when Consume failed")
	}
}

type failingConsumeTransport struct {
	closed bool
}

func (t *failingConsumeTransport) Consume(context.Context, string) (<-chan ReactorDelivery, error) {
	return nil, errors.New("no such queue")
}

func (t *failingConsumeTransport) PublishReply(context.Context, string, string, []byte) error {
	return nil
}

func (t *failingConsumeTransport) Close() error {
	t.closed = true
	return nil
}

// ---------------------------------------------------------------------------
// The amqp091 adapter, against a fake channel
// ---------------------------------------------------------------------------

// fakeAMQP091Channel implements the narrow slice of *amqp091.Channel the
// adapter uses. Note what it CANNOT be asked to do: there is no declare or
// bind method on the interface, so this fake could not record one even if
// the adapter tried (§22.1).
type fakeAMQP091Channel struct {
	deliveries chan amqp091.Delivery
	consumeErr error
	publishErr error

	mu        sync.Mutex
	published []amqp091.Publishing
	exchanges []string
	keys      []string
	closed    int
	consumed  []string
}

func (c *fakeAMQP091Channel) Consume(queue, _ string, _, _, _, _ bool, _ amqp091.Table) (<-chan amqp091.Delivery, error) {
	c.mu.Lock()
	c.consumed = append(c.consumed, queue)
	c.mu.Unlock()
	if c.consumeErr != nil {
		return nil, c.consumeErr
	}
	return c.deliveries, nil
}

func (c *fakeAMQP091Channel) PublishWithContext(_ context.Context, exchange, key string, _, _ bool, msg amqp091.Publishing) error {
	if c.publishErr != nil {
		return c.publishErr
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.exchanges = append(c.exchanges, exchange)
	c.keys = append(c.keys, key)
	c.published = append(c.published, msg)
	return nil
}

func (c *fakeAMQP091Channel) Qos(int, int, bool) error { return nil }

func (c *fakeAMQP091Channel) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed++
	return nil
}

type fakeAMQP091Conn struct {
	err    error
	closed int
}

func (c *fakeAMQP091Conn) Close() error {
	c.closed++
	return c.err
}

// TestAMQP091Transport_ConsumeForwardsAndEndsWithTheSession covers the
// adapter's delivery forwarding, including the close that ReactorServe reads
// as "this session ended, reconnect".
func TestAMQP091Transport_ConsumeForwardsAndEndsWithTheSession(t *testing.T) {
	ch := &fakeAMQP091Channel{deliveries: make(chan amqp091.Delivery, 2)}
	transport := &amqp091Transport{conn: &fakeAMQP091Conn{}, ch: ch}

	out, err := transport.Consume(context.Background(), "axiam.reactor.q.t.r")
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if len(ch.consumed) != 1 || ch.consumed[0] != "axiam.reactor.q.t.r" {
		t.Fatalf("the adapter must consume exactly the queue it was given: %v", ch.consumed)
	}

	ch.deliveries <- amqp091.Delivery{Body: []byte("one"), ReplyTo: "rq", CorrelationId: "c1"}
	got := <-out
	if string(got.Body()) != "one" || got.ReplyTo() != "rq" || got.CorrelationID() != "c1" {
		t.Fatalf("forwarded delivery = %s/%s/%s", got.Body(), got.ReplyTo(), got.CorrelationID())
	}

	close(ch.deliveries)
	if _, open := <-out; open {
		t.Fatal("the forwarded channel must close when the broker's does")
	}
}

// TestAMQP091Transport_ConsumeFailureIsWrapped covers the error path, which
// the reconnect loop treats as a session that never started.
func TestAMQP091Transport_ConsumeFailureIsWrapped(t *testing.T) {
	ch := &fakeAMQP091Channel{consumeErr: errors.New("NOT_FOUND - no queue")}
	transport := &amqp091Transport{conn: &fakeAMQP091Conn{}, ch: ch}

	_, err := transport.Consume(context.Background(), "missing")
	if err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("expected a wrapped, queue-naming error, got %v", err)
	}
}

// TestAMQP091Transport_PublishReplyUsesTheDefaultExchange pins the one
// publication a reactor makes: default exchange, routing key = the queue the
// delivery's reply_to named, correlation echoed onto the property.
//
// The exchange being empty is the assertion that matters — publishing to
// `axiam.reactor.events` would be a reactor injecting events rather than
// answering one.
func TestAMQP091Transport_PublishReplyUsesTheDefaultExchange(t *testing.T) {
	ch := &fakeAMQP091Channel{}
	transport := &amqp091Transport{conn: &fakeAMQP091Conn{}, ch: ch}

	if err := transport.PublishReply(context.Background(), "reply-q", "corr-9", []byte(`{"decision":"allow"}`)); err != nil {
		t.Fatalf("PublishReply: %v", err)
	}
	if len(ch.published) != 1 {
		t.Fatalf("expected one publication, got %d", len(ch.published))
	}
	if ch.exchanges[0] != "" {
		t.Fatalf("a reply goes to the DEFAULT exchange, not %q", ch.exchanges[0])
	}
	if ch.keys[0] != "reply-q" {
		t.Fatalf("routing key = %q, want the delivery's reply_to", ch.keys[0])
	}
	if ch.published[0].CorrelationId != "corr-9" || ch.published[0].ContentType != "application/json" {
		t.Fatalf("publishing properties = %+v", ch.published[0])
	}

	ch.publishErr = errors.New("channel/connection is not open")
	err := transport.PublishReply(context.Background(), "reply-q", "corr-9", []byte("{}"))
	if err == nil || !strings.Contains(err.Error(), "publish a reply") {
		t.Fatalf("expected a wrapped publish failure, got %v", err)
	}
}

// TestAMQP091Transport_CloseReleasesBothAndIsIdempotent covers §18.1 rules 2
// and 3 on the adapter: channel and connection both released, and a second
// close raises nothing.
func TestAMQP091Transport_CloseReleasesBothAndIsIdempotent(t *testing.T) {
	ch := &fakeAMQP091Channel{}
	conn := &fakeAMQP091Conn{}
	transport := &amqp091Transport{conn: conn, ch: ch}

	if err := transport.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if ch.closed != 1 || conn.closed != 1 {
		t.Fatalf("Close must release both: channel=%d conn=%d", ch.closed, conn.closed)
	}
	if err := transport.Close(); err != nil {
		t.Fatalf("Close must be idempotent: %v", err)
	}

	// amqp091 answers a second connection close with ErrClosed, which is a
	// cleanup-path non-event rather than a failure worth surfacing.
	quiet := &amqp091Transport{conn: &fakeAMQP091Conn{err: amqp091.ErrClosed}, ch: &fakeAMQP091Channel{}}
	if err := quiet.Close(); err != nil {
		t.Fatalf("ErrClosed on close must be swallowed, got %v", err)
	}

	// Any other connection-close failure IS surfaced: it means a socket was
	// not released, which is exactly what §18.1 rule 3 is about.
	loud := &amqp091Transport{conn: &fakeAMQP091Conn{err: errors.New("write: broken pipe")}, ch: &fakeAMQP091Channel{}}
	if err := loud.Close(); err == nil {
		t.Fatal("a real close failure must be surfaced")
	}
}

// fakeConnWithChannel drives newAMQP091Transport's two failure paths.
type fakeConnWithChannel struct {
	ch      *fakeAMQP091Channel
	chanErr error
	closed  int
}

func (c *fakeConnWithChannel) Close() error { c.closed++; return nil }

func (c *fakeConnWithChannel) reactorChannel() (amqp091Channel, error) {
	if c.chanErr != nil {
		return nil, c.chanErr
	}
	return c.ch, nil
}

// qosFailingChannel fails its QoS so the leak-on-failure ordering can be
// asserted.
type qosFailingChannel struct {
	fakeAMQP091Channel
}

func (c *qosFailingChannel) Qos(int, int, bool) error { return errors.New("PRECONDITION_FAILED") }

// TestNewAMQP091Transport_ReleasesEverythingOnFailure covers the session
// construction, and specifically that a partially-built session leaks
// nothing: a channel that opened and then failed its QoS is closed along
// with the connection, because a socket the caller never learned about is a
// socket the caller cannot release.
func TestNewAMQP091Transport_ReleasesEverythingOnFailure(t *testing.T) {
	// Success.
	ok := &fakeConnWithChannel{ch: &fakeAMQP091Channel{}}
	transport, err := newAMQP091Transport(ok, 10)
	if err != nil {
		t.Fatalf("newAMQP091Transport: %v", err)
	}
	if transport == nil || ok.closed != 0 {
		t.Fatal("a successful construction must not close the connection")
	}

	// Channel open fails: the connection is released.
	noChannel := &fakeConnWithChannel{chanErr: errors.New("CHANNEL_ERROR")}
	if _, err := newAMQP091Transport(noChannel, 10); err == nil {
		t.Fatal("a channel-open failure must be surfaced")
	}
	if noChannel.closed != 1 {
		t.Fatalf("the connection must be closed when the channel will not open, closed=%d", noChannel.closed)
	}

	// QoS fails: BOTH are released.
	badQos := &qosFailingChannel{}
	conn := &fakeConnWithChannel{ch: &badQos.fakeAMQP091Channel}
	conn.chanErr = nil
	_, err = newAMQP091Transport(&qosConn{conn: conn, ch: badQos}, 10)
	if err == nil {
		t.Fatal("a QoS failure must be surfaced")
	}
	if badQos.closed != 1 || conn.closed != 1 {
		t.Fatalf("a QoS failure must release both: channel=%d conn=%d", badQos.closed, conn.closed)
	}
}

// qosConn hands out the QoS-failing channel.
type qosConn struct {
	conn *fakeConnWithChannel
	ch   amqp091Channel
}

func (c *qosConn) Close() error { return c.conn.Close() }

func (c *qosConn) reactorChannel() (amqp091Channel, error) { return c.ch, nil }

// §19.2: the five reactor telemetry events form a CLOSED set — the interface's
// marker method is unexported, so a caller cannot add a sixth and a type
// switch over them cannot go stale. This asserts the membership, which is the
// only thing the markers exist to state.
func TestEveryReactorTelemetryEventSatisfiesTheClosedInterface(t *testing.T) {
	events := []ReactorTelemetryEvent{
		ReactorReceivedEvent{},
		ReactorRejectedEvent{},
		ReactorRepliedEvent{},
		ReactorNoReplyEvent{},
		ReactorReconnectEvent{},
	}
	for _, event := range events {
		event.isReactorTelemetryEvent()
	}
	if len(events) != 5 {
		t.Fatalf("the closed set is five events, got %d", len(events))
	}

	// CF-02: with no logger configured the security sink discards, rather
	// than writing tenant data to stderr on a caller's behalf.
	noopLogger{}.SecurityWarn("dropped", "reason", "no logger configured")
}
