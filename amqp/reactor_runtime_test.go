package amqp

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

// fakeReactorDelivery records the ack/nack decision so the runtime's
// never-requeue contract is provable without a broker. Note it has no
// requeue parameter — neither does the interface (§22.1's comment on why).
type fakeReactorDelivery struct {
	body          []byte
	replyTo       string
	correlationID string

	mu     sync.Mutex
	acked  int
	nacked int
}

func (d *fakeReactorDelivery) Body() []byte          { return d.body }
func (d *fakeReactorDelivery) ReplyTo() string       { return d.replyTo }
func (d *fakeReactorDelivery) CorrelationID() string { return d.correlationID }
func (d *fakeReactorDelivery) Ack()                  { d.mu.Lock(); d.acked++; d.mu.Unlock() }
func (d *fakeReactorDelivery) Nack()                 { d.mu.Lock(); d.nacked++; d.mu.Unlock() }

func (d *fakeReactorDelivery) counts() (int, int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.acked, d.nacked
}

// fakeReactorTransport records every publication. Zero published messages is
// the assertion §22.13 asks for on the handler-throws path.
type fakeReactorTransport struct {
	deliveries chan ReactorDelivery

	mu        sync.Mutex
	published []publishedReply
	closes    int
	publishFn func(replyQueue, correlationID string, body []byte) error
}

type publishedReply struct {
	queue         string
	correlationID string
	body          []byte
}

func newFakeReactorTransport() *fakeReactorTransport {
	return &fakeReactorTransport{deliveries: make(chan ReactorDelivery, 8)}
}

func (t *fakeReactorTransport) Consume(context.Context, string) (<-chan ReactorDelivery, error) {
	return t.deliveries, nil
}

func (t *fakeReactorTransport) PublishReply(_ context.Context, replyQueue, correlationID string, body []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.publishFn != nil {
		if err := t.publishFn(replyQueue, correlationID, body); err != nil {
			return err
		}
	}
	t.published = append(t.published, publishedReply{queue: replyQueue, correlationID: correlationID, body: append([]byte(nil), body...)})
	return nil
}

func (t *fakeReactorTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closes++
	return nil
}

func (t *fakeReactorTransport) closeCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.closes
}

func (t *fakeReactorTransport) replies() []publishedReply {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]publishedReply(nil), t.published...)
}

// reactorRecordingLogger captures security events so a test can prove the
// signing key never reaches one. (consumer_test.go's recordingLogger keeps
// only the message; this one also renders the args, which is where a leak
// would actually hide.)
type reactorRecordingLogger struct {
	mu    sync.Mutex
	lines []string
}

func (l *reactorRecordingLogger) SecurityWarn(msg string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprint(append([]any{msg}, args...)...))
}

func (l *reactorRecordingLogger) joined() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

// reactorTestRig builds a dispatch harness around the committed vectors.
type reactorTestRig struct {
	vectors   reactorVectors
	subkey    []byte
	now       time.Time
	transport *fakeReactorTransport
	logger    *reactorRecordingLogger
	events    []ReactorTelemetryEvent
	eventsMu  sync.Mutex
	cfg       reactorConfig
	reactor   ReactorConfig
}

func newReactorTestRig(t *testing.T) *reactorTestRig {
	t.Helper()
	v, subkey := loadReactorVectors(t)
	now := vectorsNow(t, v)
	rig := &reactorTestRig{
		vectors:   v,
		subkey:    subkey,
		now:       now,
		transport: newFakeReactorTransport(),
		logger:    &reactorRecordingLogger{},
	}
	rig.reactor = ReactorConfig{
		TenantID:   v.TenantID,
		ReactorID:  v.ReactorID,
		SigningKey: subkey,
	}
	rig.cfg = reactorConfig{
		skew:       defaultSkew,
		logger:     rig.logger,
		drainGrace: reactorDefaultDrainGrace,
		now:        func() time.Time { return rig.now },
		newNonce:   func() string { return "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb" },
		jitter:     func() float64 { return 0 },
		telemetry: func(e ReactorTelemetryEvent) {
			rig.eventsMu.Lock()
			defer rig.eventsMu.Unlock()
			rig.events = append(rig.events, e)
		},
	}
	return rig
}

func (r *reactorTestRig) delivery(t *testing.T, vectorName string) *fakeReactorDelivery {
	t.Helper()
	vec, ok := r.vectors.ServerToReactor[vectorName]
	if !ok {
		t.Fatalf("fixture carries no server_to_reactor.%s vector", vectorName)
	}
	return &fakeReactorDelivery{
		body:          wireBody(t, vec),
		replyTo:       "amq.rabbitmq.reply-to.axiam",
		correlationID: r.vectors.ExpectedCorrelationID,
	}
}

func (r *reactorTestRig) dispatch(d ReactorDelivery, handler ReactorHandler) {
	dispatchReactorDelivery(context.Background(), d, r.transport, r.reactor, handler, r.cfg, nil)
}

// freshReactorEvent signs an event AT THE CURRENT WALL CLOCK, for the tests
// that exercise ReactorServe end to end rather than dispatchReactorDelivery
// with an injected clock. The committed vectors are dated, so a runtime
// running on the real clock correctly refuses them as stale — which is the
// freshness rule working, not a test to defeat.
//
// It signs through the same canonical layout and the same signer the runtime
// verifies with, so a divergence between the two would fail here as well.
func freshReactorEvent(t *testing.T, subkey []byte, tenantID, event, correlationID string, timeoutMS uint32) []byte {
	t.Helper()
	msg := reactorEventCanonical{
		TenantID:      tenantID,
		Event:         event,
		CorrelationID: correlationID,
		Payload:       json.RawMessage(`{"sub":"alice"}`),
		TimeoutMS:     timeoutMS,
		KeyVersion:    reactorKeyVersion,
		Nonce:         defaultReactorNonce()(),
		IssuedAt:      time.Now().UTC().Truncate(time.Second).Format(time.RFC3339),
	}
	canonical, err := marshalReactorCanonical(&msg)
	if err != nil {
		t.Fatalf("failed to canonicalize a test event: %v", err)
	}
	sig := signReactorBytes(subkey, canonical)
	msg.HMACSignature = &sig
	body, err := marshalReactorCanonical(&msg)
	if err != nil {
		t.Fatalf("failed to serialize a test event: %v", err)
	}
	return body
}

func (r *reactorTestRig) telemetry() []ReactorTelemetryEvent {
	r.eventsMu.Lock()
	defer r.eventsMu.Unlock()
	return append([]ReactorTelemetryEvent(nil), r.events...)
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

// TestReactorDispatch_AllowPublishesASignedReply is the happy path end to
// end: a verified event reaches the handler, and the answer comes back as a
// signed reply on the queue the delivery named.
func TestReactorDispatch_AllowPublishesASignedReply(t *testing.T) {
	rig := newReactorTestRig(t)
	d := rig.delivery(t, "login_post_auth")

	var seen ReactorEvent
	rig.dispatch(d, func(_ context.Context, ev ReactorEvent) (ReactorAnswer, error) {
		seen = ev
		return ReactorAllow(), nil
	})

	if seen.Event != ReactorEventLoginPostAuth {
		t.Fatalf("handler saw event %q", seen.Event)
	}
	replies := rig.transport.replies()
	if len(replies) != 1 {
		t.Fatalf("expected exactly one reply, got %d", len(replies))
	}
	if replies[0].queue != d.replyTo {
		t.Fatalf("reply went to %q, want the delivery's reply_to %q", replies[0].queue, d.replyTo)
	}
	// The correlation the SERVER authenticates is the one inside the signed
	// body; the property is echoed as well because that is the RPC
	// convention.
	if replies[0].correlationID != rig.vectors.ExpectedCorrelationID {
		t.Fatalf("reply property correlation_id = %q", replies[0].correlationID)
	}
	if !strings.Contains(string(replies[0].body), `"correlation_id":"`+rig.vectors.ExpectedCorrelationID+`"`) {
		t.Fatalf("the SIGNED BODY must carry correlation_id: %s", replies[0].body)
	}
	if want := rig.vectors.ReactorToServer["allow"].HMACSignatureHex; !strings.Contains(string(replies[0].body), want) {
		t.Fatalf("published reply does not carry the fixture's MAC\n got: %s\nwant: %s", replies[0].body, want)
	}
	if acked, nacked := d.counts(); acked != 1 || nacked != 0 {
		t.Fatalf("a handled delivery must be acked exactly once: acked=%d nacked=%d", acked, nacked)
	}
}

// TestReactorDispatch_HandlerErrorPublishesNothing is §22.10 rule 2 and
// §22.13's "assert zero published messages, not an allow".
//
// An SDK that answered allow on behalf of a handler that failed would have
// overridden the operator's fail_closed setting from inside the library.
func TestReactorDispatch_HandlerErrorPublishesNothing(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handler ReactorHandler
		reason  string
	}{
		{
			name: "returns an error",
			handler: func(context.Context, ReactorEvent) (ReactorAnswer, error) {
				return ReactorAnswer{}, errors.New("fraud service unreachable")
			},
			reason: "handler_error",
		},
		{
			name: "panics",
			handler: func(context.Context, ReactorEvent) (ReactorAnswer, error) {
				panic("handler bug carrying secret-token-value")
			},
			reason: "handler_panic",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rig := newReactorTestRig(t)
			d := rig.delivery(t, "login_post_auth")

			rig.dispatch(d, tc.handler)

			if replies := rig.transport.replies(); len(replies) != 0 {
				t.Fatalf("expected ZERO published messages, got %d: %s", len(replies), replies[0].body)
			}
			found := false
			for _, e := range rig.telemetry() {
				if ev, ok := e.(ReactorNoReplyEvent); ok && ev.Reason == tc.reason {
					found = true
				}
			}
			if !found {
				t.Fatalf("expected a ReactorNoReplyEvent with reason %q", tc.reason)
			}
		})
	}
}

// TestReactorDispatch_PanicValueIsNotLeaked asserts a panicking handler's
// value never reaches telemetry or the security log. A handler that panicked
// while holding a token would otherwise put it there.
func TestReactorDispatch_PanicValueIsNotLeaked(t *testing.T) {
	rig := newReactorTestRig(t)
	d := rig.delivery(t, "login_post_auth")

	rig.dispatch(d, func(context.Context, ReactorEvent) (ReactorAnswer, error) {
		panic("secret-token-value")
	})

	rendered := fmt.Sprintf("%+v", rig.telemetry()) + rig.logger.joined()
	if strings.Contains(rendered, "secret-token-value") {
		t.Fatalf("a panic value must not reach any observable surface: %s", rendered)
	}
}

// TestReactorDispatch_RefusedEventNeverReachesTheHandler covers the §22.3
// pre-handler gate. A runtime that hands an unverified payload to user code
// has already lost: the handler will act on it, and "we checked afterwards"
// is not a check.
func TestReactorDispatch_RefusedEventNeverReachesTheHandler(t *testing.T) {
	rig := newReactorTestRig(t)
	base := string(rig.delivery(t, "login_post_auth").body)

	for _, tc := range []struct {
		name   string
		body   string
		reason string
	}{
		{"bad signature", strings.Replace(base, `"hmac_signature":"cd`, `"hmac_signature":"ce`, 1), "bad_signature"},
		{"key_version 1", strings.Replace(base, `"key_version":2`, `"key_version":1`, 1), "key_version_too_old"},
		{"not JSON", "{not json", "malformed"},
		{"unsigned", strings.Replace(base, `"hmac_signature":"cd1c0ecc40489a4b73ec5a1303ba1eacc2807c9e4a34cb3b2cae5ffe6790ddd1"`, `"hmac_signature":null`, 1), "bad_signature"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rig := newReactorTestRig(t)
			d := &fakeReactorDelivery{body: []byte(tc.body), replyTo: "reply-q"}
			called := false

			rig.dispatch(d, func(context.Context, ReactorEvent) (ReactorAnswer, error) {
				called = true
				return ReactorAllow(), nil
			})

			if called {
				t.Fatal("the handler MUST NOT be invoked for an unverified delivery")
			}
			if replies := rig.transport.replies(); len(replies) != 0 {
				t.Fatalf("a refused delivery must publish nothing, got %d", len(replies))
			}
			if acked, nacked := d.counts(); acked != 0 || nacked != 1 {
				t.Fatalf("a refused delivery must be nacked without requeue: acked=%d nacked=%d", acked, nacked)
			}
			found := false
			for _, e := range rig.telemetry() {
				if ev, ok := e.(ReactorRejectedEvent); ok && ev.Reason == tc.reason {
					found = true
				}
			}
			if !found {
				t.Fatalf("expected a ReactorRejectedEvent with reason %q, got %+v", tc.reason, rig.telemetry())
			}
		})
	}
	_ = base
}

// TestReactorDispatch_MutationIsSentUnfiltered is §22.4 rule 1 and §22.10
// rule 3: one forbidden key rejects the WHOLE patch server-side, and this
// SDK does not quietly drop `sub` to rescue the rest.
//
// Filtering would leave the reactor author believing a field was set when it
// was dropped, which is the exact failure the server refuses to produce.
func TestReactorDispatch_MutationIsSentUnfiltered(t *testing.T) {
	rig := newReactorTestRig(t)
	d := rig.delivery(t, "token_pre_issue")

	rig.dispatch(d, func(context.Context, ReactorEvent) (ReactorAnswer, error) {
		return ReactorMutate(map[string]string{"ext.department": "eng", "sub": "root"}), nil
	})

	replies := rig.transport.replies()
	if len(replies) != 1 {
		t.Fatalf("expected one reply, got %d", len(replies))
	}
	body := string(replies[0].body)
	if !strings.Contains(body, `"sub":"root"`) {
		t.Fatalf("the forbidden key MUST be sent unfiltered: %s", body)
	}
	if !strings.Contains(body, `"ext.department":"eng"`) {
		t.Fatalf("the allowed key must be present too: %s", body)
	}
	if !strings.Contains(body, `"decision":"mutate"`) {
		t.Fatalf("a mutation must be decision mutate: %s", body)
	}
	// The bytes must match the fixture's own forbidden_patch_field vector,
	// which the server rejects as forbidden_patch_field:sub.
	want := rig.vectors.RejectedReplies["forbidden_patch_field"].HMACSignatureHex
	if !strings.Contains(body, want) {
		t.Fatalf("unfiltered patch bytes do not match the fixture\n got: %s\nwant MAC: %s", body, want)
	}
}

// TestReactorDispatch_RequireMFAOffLoginIsRefusedClientSide covers §22.4
// rule 3 / §22.13's third reply-construction case. §22.13 permits rejecting
// client-side or sending and surfacing the server's rejection; rejecting
// names the author's mistake where it was made, and the outcome is the same
// either way — no usable reply, so the failure policy decides.
func TestReactorDispatch_RequireMFAOffLoginIsRefusedClientSide(t *testing.T) {
	rig := newReactorTestRig(t)
	d := rig.delivery(t, "token_pre_issue")

	rig.dispatch(d, func(context.Context, ReactorEvent) (ReactorAnswer, error) {
		return ReactorAllowWithStepUp(), nil
	})

	if replies := rig.transport.replies(); len(replies) != 0 {
		t.Fatalf("require_mfa off login.post_auth must not be published: %s", replies[0].body)
	}

	// And directly on the builder, so the error is nameable.
	_, err := buildReactorReply(rig.subkey, ReactorEvent{
		TenantID:      rig.vectors.TenantID,
		Event:         ReactorEventTokenPreIssue,
		CorrelationID: rig.vectors.ExpectedCorrelationID,
	}, ReactorAllowWithStepUp(), "n", rig.now)
	if !errors.Is(err, ErrReactorRequireMFAUnsupported) {
		t.Fatalf("expected ErrReactorRequireMFAUnsupported, got %v", err)
	}

	// It IS valid on login.post_auth.
	if _, err := buildReactorReply(rig.subkey, ReactorEvent{
		TenantID:      rig.vectors.TenantID,
		Event:         ReactorEventLoginPostAuth,
		CorrelationID: rig.vectors.ExpectedCorrelationID,
	}, ReactorAllowWithStepUp(), "n", rig.now); err != nil {
		t.Fatalf("require_mfa on login.post_auth must be accepted: %v", err)
	}
}

// TestReactorAnswer_AllowCannotCarryAPatch asserts §22.4 rule 2
// STRUCTURALLY: there is no constructor that produces allow + patch, so the
// ambiguity the server refuses cannot be spelled in this SDK at all.
func TestReactorAnswer_AllowCannotCarryAPatch(t *testing.T) {
	if got := ReactorAllow(); got.patch != nil {
		t.Fatal("ReactorAllow must not carry a patch")
	}
	if got := ReactorAllowWithStepUp(); got.patch != nil {
		t.Fatal("ReactorAllowWithStepUp must not carry a patch")
	}
	if got := ReactorMutate(map[string]string{"ext.a": "b"}); got.Decision() != "mutate" {
		t.Fatalf("a mutation must be decision mutate, got %q", got.Decision())
	}
	// A mutate with nothing in it is malformed_mutation server-side; there
	// is nothing to gain by putting it on the wire.
	v, subkey := loadReactorVectors(t)
	_, err := buildReactorReply(subkey, ReactorEvent{TenantID: v.TenantID, Event: ReactorEventTokenPreIssue, CorrelationID: v.ExpectedCorrelationID}, ReactorMutate(nil), "n", vectorsNow(t, v))
	if !errors.Is(err, ErrReactorEmptyPatch) {
		t.Fatalf("expected ErrReactorEmptyPatch, got %v", err)
	}
}

// TestReactorDispatch_LatereplyIsSkipped covers §22.3's SHOULD: a reply
// arriving after the window has closed is discarded by the server, so the
// runtime does not spend the CPU producing it.
func TestReactorDispatch_LatereplyIsSkipped(t *testing.T) {
	rig := newReactorTestRig(t)
	d := rig.delivery(t, "token_pre_issue") // timeout_ms 500

	// The clock advances past the deadline while the handler is deciding.
	base := rig.now
	first := true
	rig.cfg.now = func() time.Time {
		if first {
			first = false
			return base
		}
		return base.Add(2 * time.Second)
	}

	rig.dispatch(d, func(context.Context, ReactorEvent) (ReactorAnswer, error) {
		return ReactorAllow(), nil
	})

	if replies := rig.transport.replies(); len(replies) != 0 {
		t.Fatalf("a reply into a closed window must be skipped, got %s", replies[0].body)
	}
	found := false
	for _, e := range rig.telemetry() {
		if ev, ok := e.(ReactorNoReplyEvent); ok && ev.Reason == "deadline_passed" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected a deadline_passed ReactorNoReplyEvent")
	}
}

// TestReactorDispatch_HandlerGetsTheDispatchDeadline asserts timeout_ms
// reaches the handler both as a value and as a context deadline, so an actor
// can shed load rather than answer into a closed window.
func TestReactorDispatch_HandlerGetsTheDispatchDeadline(t *testing.T) {
	rig := newReactorTestRig(t)
	d := rig.delivery(t, "token_pre_issue")

	rig.dispatch(d, func(ctx context.Context, ev ReactorEvent) (ReactorAnswer, error) {
		if ev.Timeout != 500*time.Millisecond {
			t.Errorf("timeout = %s, want 500ms", ev.Timeout)
		}
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Error("the handler context must carry the dispatch deadline")
		} else if !deadline.Equal(ev.Deadline) {
			t.Errorf("context deadline %s != event deadline %s", deadline, ev.Deadline)
		}
		return ReactorAllow(), nil
	})
}

// TestReactorDispatch_ListenModePublishesNothing covers §22.5: a listener
// cannot affect any outcome, so it never publishes a reply.
func TestReactorDispatch_ListenModePublishesNothing(t *testing.T) {
	rig := newReactorTestRig(t)
	rig.reactor.Mode = ReactorModeListen
	d := rig.delivery(t, "login_post_auth")

	called := false
	rig.dispatch(d, func(context.Context, ReactorEvent) (ReactorAnswer, error) {
		called = true
		return ReactorDeny("a listener cannot veto"), nil
	})

	if !called {
		t.Fatal("a listener handler must still observe the event")
	}
	if replies := rig.transport.replies(); len(replies) != 0 {
		t.Fatalf("a listener MUST NOT publish a reply, got %s", replies[0].body)
	}
	if acked, _ := d.counts(); acked != 1 {
		t.Fatal("a listener delivery must still be acked")
	}
}

// TestReactorDispatch_ChainPatchIsReadableContext covers §22.3's
// `_reactor_patch`: a later reactor decides against the state that will
// actually be committed.
func TestReactorDispatch_ChainPatchIsReadableContext(t *testing.T) {
	v, subkey := loadReactorVectors(t)
	_ = subkey
	ev := ReactorEvent{
		TenantID: v.TenantID,
		Event:    ReactorEventTokenPreIssue,
		Payload:  json.RawMessage(`{"sub":"alice","_reactor_patch":{"ext.department":"eng"}}`),
	}
	patch, ok := ev.ChainPatch()
	if !ok || patch["ext.department"] != "eng" {
		t.Fatalf("ChainPatch() = %v, %v", patch, ok)
	}

	bare := ReactorEvent{Payload: json.RawMessage(`{"sub":"alice"}`)}
	if _, ok := bare.ChainPatch(); ok {
		t.Fatal("an event with no accumulated patch must report none")
	}
}

// ---------------------------------------------------------------------------
// Serve loop, shutdown and configuration
// ---------------------------------------------------------------------------

// TestReactorServe_DrainsInFlightOnShutdown is §18: cancellation stops
// intake and waits for the handler that is already deciding, rather than
// abandoning it mid-flight.
func TestReactorServe_DrainsInFlightOnShutdown(t *testing.T) {
	rig := newReactorTestRig(t)
	transport := rig.transport
	d := &fakeReactorDelivery{
		body:          freshReactorEvent(t, rig.subkey, rig.vectors.TenantID, ReactorEventLoginPostAuth, rig.vectors.ExpectedCorrelationID, 5000),
		replyTo:       "reply-q",
		correlationID: rig.vectors.ExpectedCorrelationID,
	}
	transport.deliveries <- d

	ctx, cancel := context.WithCancel(context.Background())
	entered := make(chan struct{})
	release := make(chan struct{})
	finished := make(chan struct{})

	done := make(chan error, 1)
	go func() {
		done <- ReactorServe(ctx,
			func(context.Context) (ReactorTransport, error) { return transport, nil },
			rig.reactor,
			func(context.Context, ReactorEvent) (ReactorAnswer, error) {
				close(entered)
				<-release
				close(finished)
				return ReactorAllow(), nil
			},
			WithReactorTelemetryHook(func(ReactorTelemetryEvent) {}),
		)
	}()

	<-entered
	cancel()
	// Give the loop a moment to notice the cancellation while the handler is
	// still in flight; the drain must not have returned yet.
	select {
	case err := <-done:
		t.Fatalf("ReactorServe returned before the in-flight handler finished: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	<-finished

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ReactorServe did not return after the drain")
	}
	if transport.closeCount() == 0 {
		t.Fatal("the transport must be closed on shutdown (§18.1 rule 3)")
	}
}

// TestReactorServe_ReconnectsWithJitteredBackoff asserts a dropped session is
// a reconnect, not a fatal error, and that the wait is announced.
func TestReactorServe_ReconnectsWithJitteredBackoff(t *testing.T) {
	rig := newReactorTestRig(t)

	var mu sync.Mutex
	dials := 0
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reconnects := make(chan ReactorReconnectEvent, 4)
	go func() {
		_ = ReactorServe(ctx,
			func(context.Context) (ReactorTransport, error) {
				mu.Lock()
				dials++
				n := dials
				mu.Unlock()
				tr := newFakeReactorTransport()
				// Drop the session immediately, twice.
				if n <= 2 {
					close(tr.deliveries)
				}
				return tr, nil
			},
			rig.reactor,
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

	for i := 1; i <= 2; i++ {
		select {
		case ev := <-reconnects:
			if ev.Attempt != i {
				t.Fatalf("reconnect attempt = %d, want %d", ev.Attempt, i)
			}
			if ev.Delay > reactorReconnectMaxDelay {
				t.Fatalf("reconnect delay %s exceeds the §16.1 cap", ev.Delay)
			}
			if ev.Reason != "session_closed" && ev.Reason != "transport_error" {
				t.Fatalf("reconnect reason %q is not a redacted category", ev.Reason)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("expected reconnect attempt %d", i)
		}
	}
}

// TestReactorReconnectDelay_IsCappedAndJittered pins the backoff shape.
func TestReactorReconnectDelay_IsCappedAndJittered(t *testing.T) {
	if got := reactorReconnectDelay(1, 1); got != reactorReconnectBaseDelay {
		t.Fatalf("attempt 1 full jitter = %s, want %s", got, reactorReconnectBaseDelay)
	}
	if got := reactorReconnectDelay(2, 1); got != 2*reactorReconnectBaseDelay {
		t.Fatalf("attempt 2 full jitter = %s, want %s", got, 2*reactorReconnectBaseDelay)
	}
	if got := reactorReconnectDelay(50, 1); got != reactorReconnectMaxDelay {
		t.Fatalf("a far attempt must clamp to the cap, got %s", got)
	}
	if got := reactorReconnectDelay(3, 0); got != 0 {
		t.Fatalf("full jitter over [0, backoff] must be able to draw 0, got %s", got)
	}
}

// TestReactorServe_RejectsUnusableConfiguration covers the construction
// errors, including the §8.1 requirement that a signing key be supplied
// rather than defaulted.
func TestReactorServe_RejectsUnusableConfiguration(t *testing.T) {
	dial := func(context.Context) (ReactorTransport, error) { return newFakeReactorTransport(), nil }
	handler := func(context.Context, ReactorEvent) (ReactorAnswer, error) { return ReactorAllow(), nil }
	ctx := context.Background()

	for _, tc := range []struct {
		name string
		cfg  ReactorConfig
	}{
		{"no tenant", ReactorConfig{ReactorID: "r", SigningKey: []byte("k")}},
		{"no queue and no reactor id", ReactorConfig{TenantID: "t", SigningKey: []byte("k")}},
		{"no signing key", ReactorConfig{TenantID: "t", ReactorID: "r"}},
		{"bad mode", ReactorConfig{TenantID: "t", ReactorID: "r", SigningKey: []byte("k"), Mode: "observe"}},
	} {
		if err := ReactorServe(ctx, dial, tc.cfg, handler); err == nil {
			t.Errorf("%s: expected a configuration error", tc.name)
		}
	}
	if err := ReactorServe(ctx, nil, ReactorConfig{TenantID: "t", ReactorID: "r", SigningKey: []byte("k")}, handler); err == nil {
		t.Error("a nil dialer must be rejected")
	}
	if err := ReactorServe(ctx, dial, ReactorConfig{TenantID: "t", ReactorID: "r", SigningKey: []byte("k")}, nil); err == nil {
		t.Error("a nil handler must be rejected")
	}
}

// TestReactorConfig_QueueIsTheServerDeclaredOne asserts the derived name
// matches §22.1's format and that an explicit override wins.
func TestReactorConfig_QueueIsTheServerDeclaredOne(t *testing.T) {
	v, _ := loadReactorVectors(t)
	cfg := ReactorConfig{TenantID: v.TenantID, ReactorID: v.ReactorID}
	if got := cfg.queueName(); got != v.Topology.Queue {
		t.Fatalf("derived queue = %q, fixture = %q", got, v.Topology.Queue)
	}
	cfg.Queue = "explicit"
	if got := cfg.queueName(); got != "explicit" {
		t.Fatalf("explicit queue = %q", got)
	}
}

// ---------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------

// TestReactorRuntime_SigningKeyNeverAppearsInObservableOutput is §22.12 and
// §22.13's last runtime requirement: scan the serialized output for the
// fixture key value, the same discipline §12/§14/§15/§20 use.
func TestReactorRuntime_SigningKeyNeverAppearsInObservableOutput(t *testing.T) {
	rig := newReactorTestRig(t)
	keyHex := hex.EncodeToString(rig.subkey)

	// A refused delivery (security log), a handled one (telemetry), and a
	// configuration error (error string) — the three surfaces that render
	// anything at all.
	bad := &fakeReactorDelivery{body: []byte(`{"nope":true}`), replyTo: "q"}
	rig.dispatch(bad, func(context.Context, ReactorEvent) (ReactorAnswer, error) { return ReactorAllow(), nil })
	good := rig.delivery(t, "login_post_auth")
	rig.dispatch(good, func(context.Context, ReactorEvent) (ReactorAnswer, error) { return ReactorDeny("nope"), nil })

	cfgErr := ReactorServe(context.Background(), nil, rig.reactor, nil)

	rendered := strings.Join([]string{
		rig.logger.joined(),
		fmt.Sprintf("%+v", rig.telemetry()),
		fmt.Sprintf("%#v", rig.telemetry()),
		fmt.Sprint(cfgErr),
		fmt.Sprintf("%+v", rig.reactor.queueName()),
	}, "\n")

	if strings.Contains(rendered, keyHex) {
		t.Fatalf("the signing key must never appear in observable output: %s", rendered)
	}
	if strings.Contains(rendered, string(rig.subkey)) {
		t.Fatal("the raw signing key bytes must never appear in observable output")
	}
	// The telemetry surface has no field that could carry one: assert the
	// JSON encoding of every event too, since that is what a metrics
	// exporter ships.
	encoded, err := json.Marshal(rig.telemetry())
	if err != nil {
		t.Fatalf("failed to encode telemetry: %v", err)
	}
	if strings.Contains(string(encoded), keyHex) {
		t.Fatalf("serialized telemetry must not carry the signing key: %s", encoded)
	}
}

// TestReactorTelemetry_HookPanicCannotFailADecision is §19.2 rule 2. In Go an
// unrecovered panic in a hook would take the process down, not just the
// decision.
func TestReactorTelemetry_HookPanicCannotFailADecision(t *testing.T) {
	rig := newReactorTestRig(t)
	rig.cfg.telemetry = func(ReactorTelemetryEvent) { panic("metrics backend is on fire") }
	d := rig.delivery(t, "login_post_auth")

	rig.dispatch(d, func(context.Context, ReactorEvent) (ReactorAnswer, error) {
		return ReactorAllow(), nil
	})

	if replies := rig.transport.replies(); len(replies) != 1 {
		t.Fatalf("a panicking telemetry hook must not stop the reply, got %d", len(replies))
	}
}

// TestReactorTelemetry_OffUnlessInstalled is §19.2 rule 1.
func TestReactorTelemetry_OffUnlessInstalled(t *testing.T) {
	rig := newReactorTestRig(t)
	rig.cfg.telemetry = nil
	d := rig.delivery(t, "login_post_auth")

	rig.dispatch(d, func(context.Context, ReactorEvent) (ReactorAnswer, error) {
		return ReactorAllow(), nil
	})

	if replies := rig.transport.replies(); len(replies) != 1 {
		t.Fatalf("a reactor with no telemetry hook must behave identically, got %d replies", len(replies))
	}
}

// TestAMQPSDialer_RefusesPlaintext covers §8b: no plaintext fallback, and no
// verification-skip switch anywhere in the surface.
func TestAMQPSDialer_RefusesPlaintext(t *testing.T) {
	_, err := AMQPSDialer("amqp://guest:guest@localhost:5672")(context.Background())
	if !errors.Is(err, ErrReactorInsecureURL) {
		t.Fatalf("a plaintext AMQP URL must be refused, got %v", err)
	}
	if strings.Contains(fmt.Sprint(err), "guest:guest") {
		t.Fatalf("the refusal must not echo the URL's credentials: %v", err)
	}

	_, err = AMQPSDialer("amqps://broker.invalid:5671", WithReactorCABundle([]byte("not pem")))(context.Background())
	if err == nil {
		t.Fatal("a CA bundle with no valid certificate must be refused")
	}
}
