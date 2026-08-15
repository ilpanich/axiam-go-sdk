// Reactor runtime — CONTRACT.md §22.10 (`reactor_serve`, spelled
// ReactorServe in Go by §22.10's per-language table).
//
// A Reactor is an external process that subscribes to named hook events on
// the AMQP bus and answers back — allow, deny, or a field-allow-listed
// mutation — inside a timeout the server declared. It is AXIAM's answer to
// Zitadel Actions and Keycloak SPIs, and the difference is the whole design:
// those load third-party code INTO the authorization server, and this keeps
// it outside, reachable only through a signed reply schema the server
// validates before it believes a word of it.
//
// The four rules §22.10 puts on this helper, and where each one lives:
//
//  1. It MUST NOT declare topology (§22.1) — enforced by the shape of
//     ReactorTransport, which has no declare or bind method at all
//     (reactor_transport.go).
//  2. It MUST fail closed on its own errors. A handler that panics, an
//     answer this SDK refuses to send, a reply that will not serialize —
//     every one of them results in NO REPLY, letting the operator's
//     failure_policy decide. An SDK that answered `allow` on behalf of a
//     handler that crashed would have overridden a `fail_closed` setting
//     from inside the library.
//  3. It MUST NOT filter a patch to the allowed subset (§22.4 rule 1) —
//     see ReactorMutate.
//  4. It SHOULD honour timeout_ms by abandoning work whose window has
//     closed rather than replying late (§22.3) — see the deadline handling
//     in dispatchReactorDelivery.

package amqp

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Reconnect backoff. The shape is §16.1's — 200 ms base, doubling, capped at
// 5 s, FULL jitter over [0, backoff] — because an outage that drops every
// reactor at once is exactly the herd §16's jitter exists to break up.
//
// What is deliberately NOT borrowed is §16.1's three-attempt cap: that bounds
// one caller's wait for one request, and a long-lived daemon that stopped
// reconnecting after three tries would go quietly deaf for the rest of the
// process's life. The loop instead runs until the caller's context is done.
const (
	reactorReconnectBaseDelay = 200 * time.Millisecond
	reactorReconnectMaxDelay  = 5 * time.Second
)

// reactorDefaultDrainGrace bounds how long ReactorServe waits for in-flight
// handlers after the context is cancelled (§18.1 rule 3 — background work
// joined, not abandoned). The default is §22.8's chain wall-clock ceiling:
// past that, no in-flight dispatch can still have a server waiting on it.
const reactorDefaultDrainGrace = time.Duration(ReactorChainCeilingMS) * time.Millisecond

// ReactorHandler decides one event.
//
// Return one of ReactorAllow, ReactorAllowWithStepUp, ReactorDeny or
// ReactorMutate. Returning a non-nil error means "I could not decide": NO
// REPLY is published and the registration's failure_policy applies — which
// is the honest outcome, and the one an operator configured. A panic is
// recovered and treated identically.
//
// ctx carries the dispatch deadline (§22.3), so a handler that respects it
// stops work rather than answering into a closed window.
//
// In ReactorModeListen the return value is IGNORED and no reply is ever
// published (§22.5): a listener cannot affect any outcome. Write a listener
// handler IDEMPOTENTLY — a redelivery after a broker hiccup is normal, and a
// listener that double-counts is one that assumed an exactly-once delivery
// it was never promised.
type ReactorHandler func(ctx context.Context, event ReactorEvent) (ReactorAnswer, error)

// ReactorConfig identifies this reactor to the runtime.
type ReactorConfig struct {
	// TenantID is the tenant whose events this reactor serves. An event
	// naming any other tenant is refused before the handler sees it.
	TenantID string
	// ReactorID is this reactor's registration id. The queue name is derived
	// from it when Queue is empty.
	ReactorID string
	// Queue overrides the derived queue name. It is only ever the queue the
	// SERVER declared for THIS reactor (§22.1) — a reactor never consumes,
	// and never derives a name for, another reactor's queue.
	Queue string
	// SigningKey is the tenant's HKDF-derived AMQP subkey (§8.1) — the same
	// key that verifies the event and signs the reply. It MUST be fetched
	// from the AXIAM management API; hardcoding one is prohibited.
	//
	// It is a credential (§22.12): it is never logged at any level, never
	// appears in a reconnect diagnostic, and no telemetry event has a field
	// it could be put in.
	SigningKey []byte
	// Mode is ReactorModeIntercept (the default) or ReactorModeListen.
	Mode string
}

func (c ReactorConfig) queueName() string {
	if c.Queue != "" {
		return c.Queue
	}
	return ReactorQueueName(c.TenantID, c.ReactorID)
}

func (c ReactorConfig) validate() error {
	if c.TenantID == "" {
		return errors.New("axiam: ReactorConfig.TenantID is required")
	}
	if c.Queue == "" && c.ReactorID == "" {
		return errors.New("axiam: ReactorConfig needs either ReactorID (to derive the server-declared queue) or an explicit Queue")
	}
	if len(c.SigningKey) == 0 {
		return errors.New("axiam: ReactorConfig.SigningKey is required — fetch the tenant AMQP subkey from the management API (§8.1)")
	}
	switch c.Mode {
	case "", ReactorModeIntercept, ReactorModeListen:
	default:
		return fmt.Errorf("axiam: ReactorConfig.Mode must be %q or %q", ReactorModeIntercept, ReactorModeListen)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Telemetry (§19)
// ---------------------------------------------------------------------------

// ReactorTelemetryEvent is a reactor-runtime telemetry event.
//
// The interface is CLOSED — its marker method is unexported — so no package
// outside this one can add a variant. That is what makes §19.2 rule 3's "no
// secrets, ever" checkable rather than aspirational: every field of every
// variant below is a name, an id, a fixed category string or a duration.
// There is nowhere to put the signing key, the payload or the patch.
type ReactorTelemetryEvent interface {
	isReactorTelemetryEvent()
}

// ReactorReceivedEvent fires when a delivery has passed every §22.3 check
// and is about to reach the handler.
type ReactorReceivedEvent struct {
	Event         string
	CorrelationID string
}

// ReactorRejectedEvent fires when a delivery is refused BEFORE the handler
// runs. Reason is one of a fixed vocabulary — "bad_signature", "stale",
// "replay", "key_version_too_old", "tenant_mismatch", "unknown_event",
// "malformed" — never the received or expected MAC.
type ReactorRejectedEvent struct {
	Event  string
	Reason string
}

// ReactorRepliedEvent fires after a signed reply is published. Decision is
// the wire value; §22.12 makes it non-sensitive by design, because a handler
// that cannot be observed deciding cannot be operated.
type ReactorRepliedEvent struct {
	Event         string
	CorrelationID string
	Decision      string
	Duration      time.Duration
}

// ReactorNoReplyEvent fires when a delivery reached the handler but no reply
// was published. Reason is one of "handler_error", "handler_panic",
// "deadline_passed", "unsendable_answer", "publish_failed" or
// "listen_mode" — the first five all hand the outcome to the registration's
// failure_policy.
//
// This event is why §22.8's last paragraph matters to an SDK: a fail_open
// timeout produces `allow` AND an audit record, and the pair is the whole
// difference between "no reactor was configured" and "the reactor never
// answered". Health MUST NOT be inferred from the outcome alone.
type ReactorNoReplyEvent struct {
	Event         string
	CorrelationID string
	Reason        string
}

// ReactorReconnectEvent fires before each reconnect wait. Reason is a
// redacted description of the session loss; it never carries the URL's
// credentials or the signing key.
type ReactorReconnectEvent struct {
	Attempt int
	Delay   time.Duration
	Reason  string
}

func (ReactorReceivedEvent) isReactorTelemetryEvent()  {}
func (ReactorRejectedEvent) isReactorTelemetryEvent()  {}
func (ReactorRepliedEvent) isReactorTelemetryEvent()   {}
func (ReactorNoReplyEvent) isReactorTelemetryEvent()   {}
func (ReactorReconnectEvent) isReactorTelemetryEvent() {}

// ReactorTelemetryHook is a caller-supplied sink (§19). It is invoked on the
// dispatch path, so it MUST NOT block — §19.2 rule 4 makes buffering the
// caller's job so they can pick the policy. A hook that panics is recovered
// and swallowed: telemetry is not permitted to fail an authorization
// decision, and in Go an unrecovered panic would take the process down.
type ReactorTelemetryHook func(ReactorTelemetryEvent)

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

// ReactorOption configures ReactorServe.
type ReactorOption func(*reactorConfig)

type reactorConfig struct {
	skew       time.Duration
	logger     securityLogger
	telemetry  ReactorTelemetryHook
	drainGrace time.Duration
	now        func() time.Time
	newNonce   func() string
	jitter     func() float64
}

// WithReactorSkew overrides the ±5-minute freshness window applied to an
// event's issued_at (§8 v2, §22.2). It also sets the TTL (2×skew) of the
// in-memory nonce seen-set. A non-positive value is ignored.
func WithReactorSkew(skew time.Duration) ReactorOption {
	return func(c *reactorConfig) {
		if skew > 0 {
			c.skew = skew
		}
	}
}

// WithReactorSecurityLogger supplies a logger invoked when a delivery is
// refused. The event names the failure category only — never the received or
// expected MAC, and never the signing key.
func WithReactorSecurityLogger(l securityLogger) ReactorOption {
	return func(c *reactorConfig) {
		if l != nil {
			c.logger = l
		}
	}
}

// WithReactorTelemetryHook installs a §19 telemetry sink. Off unless
// installed: with no hook the runtime pays one nil check per event.
func WithReactorTelemetryHook(h ReactorTelemetryHook) ReactorOption {
	return func(c *reactorConfig) {
		if h != nil {
			c.telemetry = h
		}
	}
}

// WithReactorDrainGrace overrides how long ReactorServe waits for in-flight
// handlers once the context is cancelled (§18.1 rule 3). The default is
// §22.8's 5 s chain ceiling, past which no server is still waiting.
func WithReactorDrainGrace(d time.Duration) ReactorOption {
	return func(c *reactorConfig) {
		if d > 0 {
			c.drainGrace = d
		}
	}
}

// ---------------------------------------------------------------------------
// ReactorServe
// ---------------------------------------------------------------------------

// ReactorServe runs a reactor until ctx is cancelled (§22.10's
// `reactor_serve`).
//
// It dials, consumes the server-declared queue, and for each delivery: checks
// key_version, verifies the MAC, checks freshness, checks the nonce, decodes
// the event, dispatches to handler, then signs and publishes the reply. It
// reconnects with jittered backoff when a session drops, and on cancellation
// it stops taking deliveries and drains the in-flight ones before returning
// (§18).
//
// It never declares an exchange, a queue or a binding (§22.1).
//
// It returns ctx.Err() on a clean shutdown, or a configuration error
// immediately. A transport failure is never fatal — it is a reconnect.
//
//	err := amqp.ReactorServe(ctx,
//	    amqp.AMQPSDialer("amqps://broker.example:5671", amqp.WithReactorCABundle(caPEM)),
//	    amqp.ReactorConfig{TenantID: tenantID, ReactorID: reactorID, SigningKey: subkey},
//	    func(ctx context.Context, ev amqp.ReactorEvent) (amqp.ReactorAnswer, error) {
//	        return amqp.ReactorMutate(map[string]string{"ext.department": "eng"}), nil
//	    },
//	)
func ReactorServe(ctx context.Context, dial ReactorDialer, cfg ReactorConfig, handler ReactorHandler, opts ...ReactorOption) error {
	if dial == nil {
		return errors.New("axiam: ReactorServe requires a dialer")
	}
	if handler == nil {
		return errors.New("axiam: ReactorServe requires a handler")
	}
	if err := cfg.validate(); err != nil {
		return err
	}

	rc := reactorConfig{
		skew:       defaultSkew,
		logger:     noopLogger{},
		drainGrace: reactorDefaultDrainGrace,
		now:        time.Now,
		newNonce:   defaultReactorNonce(),
		jitter:     rand.Float64, //nolint:gosec // jitter spreads retries; it is not a secret.
	}
	for _, opt := range opts {
		opt(&rc)
	}

	guard := newReplayGuard(rc.skew)
	queue := cfg.queueName()

	attempt := 0
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		err := runReactorSession(ctx, dial, queue, cfg, handler, rc, guard)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		attempt++
		delay := reactorReconnectDelay(attempt, rc.jitter())
		emitReactorTelemetry(rc.telemetry, ReactorReconnectEvent{
			Attempt: attempt,
			Delay:   delay,
			Reason:  reactorRedactedReason(err),
		})
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
	}
}

// runReactorSession serves one connection, returning when it ends. In-flight
// handlers are drained before it returns, on every path — a lost session and
// a cancelled context alike.
func runReactorSession(ctx context.Context, dial ReactorDialer, queue string, cfg ReactorConfig, handler ReactorHandler, rc reactorConfig, guard *replayGuard) error {
	transport, err := dial(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = transport.Close() }()

	deliveries, err := transport.Consume(ctx, queue)
	if err != nil {
		return err
	}

	// Each dispatch runs on its own goroutine so one slow handler cannot
	// spend another event's 500 ms budget. The WaitGroup is the drain
	// (§18.1 rule 3): a session never returns while a handler is still
	// deciding, up to the grace bound.
	var inFlight sync.WaitGroup
	drain := func() {
		done := make(chan struct{})
		go func() {
			inFlight.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(rc.drainGrace):
		}
	}
	defer drain()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case delivery, ok := <-deliveries:
			if !ok {
				return errors.New("axiam: reactor delivery channel closed")
			}
			inFlight.Add(1)
			go func(d ReactorDelivery) {
				defer inFlight.Done()
				dispatchReactorDelivery(ctx, d, transport, cfg, handler, rc, guard)
			}(delivery)
		}
	}
}

// dispatchReactorDelivery is the load-bearing, separately-testable unit: one
// delivery, from verification through to a published reply.
//
// The order is §22.3's and is not negotiable — key_version, MAC, freshness,
// nonce, THEN decode and dispatch. A runtime that hands an unverified
// payload to user code has already lost.
func dispatchReactorDelivery(ctx context.Context, d ReactorDelivery, transport ReactorTransport, cfg ReactorConfig, handler ReactorHandler, rc reactorConfig, guard *replayGuard) {
	started := rc.now()

	event, err := decodeReactorEvent(cfg.SigningKey, d.Body(), cfg.TenantID, started, rc.skew, guard)
	if err != nil {
		reason := reactorRejectionReason(err)
		rc.logger.SecurityWarn("axiam_sdk_security: reactor event refused (" + reason + "); nacking without requeue")
		emitReactorTelemetry(rc.telemetry, ReactorRejectedEvent{Event: "", Reason: reason})
		d.Nack()
		return
	}
	emitReactorTelemetry(rc.telemetry, ReactorReceivedEvent{Event: event.Event, CorrelationID: event.CorrelationID})

	// The handler gets the dispatch window as its deadline, so a handler
	// that respects ctx sheds load instead of answering into a closed one.
	handlerCtx, cancel := context.WithDeadline(ctx, event.Deadline)
	defer cancel()

	answer, herr := invokeReactorHandler(handlerCtx, handler, event)

	// A listener never publishes (§22.5): the server does not read a reply
	// on this path, so producing one would be a message nobody consumes.
	if cfg.Mode == ReactorModeListen {
		emitReactorTelemetry(rc.telemetry, ReactorNoReplyEvent{Event: event.Event, CorrelationID: event.CorrelationID, Reason: "listen_mode"})
		d.Ack()
		return
	}

	if herr != nil {
		// §22.10 rule 2: fail closed on our own errors. No synthesized
		// allow — the operator's failure_policy decides.
		reason := "handler_error"
		if errors.Is(herr, errReactorHandlerPanicked) {
			reason = "handler_panic"
		}
		emitReactorTelemetry(rc.telemetry, ReactorNoReplyEvent{Event: event.Event, CorrelationID: event.CorrelationID, Reason: reason})
		d.Ack()
		return
	}

	// §22.3: a late reply is discarded, and the CPU spent producing it was
	// spent for nothing. Check before signing, not after publishing.
	if !rc.now().Before(event.Deadline) {
		emitReactorTelemetry(rc.telemetry, ReactorNoReplyEvent{Event: event.Event, CorrelationID: event.CorrelationID, Reason: "deadline_passed"})
		d.Ack()
		return
	}

	body, err := buildReactorReply(cfg.SigningKey, event, answer, rc.newNonce(), rc.now())
	if err != nil {
		emitReactorTelemetry(rc.telemetry, ReactorNoReplyEvent{Event: event.Event, CorrelationID: event.CorrelationID, Reason: "unsendable_answer"})
		d.Ack()
		return
	}

	if err := transport.PublishReply(ctx, d.ReplyTo(), d.CorrelationID(), body); err != nil {
		emitReactorTelemetry(rc.telemetry, ReactorNoReplyEvent{Event: event.Event, CorrelationID: event.CorrelationID, Reason: "publish_failed"})
		d.Ack()
		return
	}

	emitReactorTelemetry(rc.telemetry, ReactorRepliedEvent{
		Event:         event.Event,
		CorrelationID: event.CorrelationID,
		Decision:      answer.Decision(),
		Duration:      rc.now().Sub(started),
	})
	d.Ack()
}

// defaultReactorNonce returns the reply-nonce generator: a fresh UUIDv4 per
// reply (§22.2).
//
// It is a constructor rather than a bare function so the property that
// matters — successive calls never repeat — is directly assertable, and so a
// test can substitute a fixed nonce to reproduce a committed vector without
// the production path ever having a way to be pinned.
func defaultReactorNonce() func() string {
	return func() string { return uuid.NewString() }
}

// errReactorHandlerPanicked marks a handler that panicked, so the telemetry
// can distinguish "decided it could not decide" from "crashed". Both produce
// no reply.
var errReactorHandlerPanicked = errors.New("axiam: reactor handler panicked")

// invokeReactorHandler calls handler, converting a panic into an error. A
// panicking handler must not take the process down, and must not become an
// allow either.
func invokeReactorHandler(ctx context.Context, handler ReactorHandler, event ReactorEvent) (answer ReactorAnswer, err error) {
	defer func() {
		if r := recover(); r != nil {
			answer = ReactorAnswer{}
			// The panic value is NOT interpolated: a handler that panicked
			// while holding a token would otherwise put it in this error.
			err = errReactorHandlerPanicked
		}
	}()
	return handler(ctx, event)
}

// reactorRejectionReason maps a verification failure to the fixed telemetry
// vocabulary. The categories mirror §22.4's rejection table so a reactor's
// metrics line up with the server's audit records.
func reactorRejectionReason(err error) string {
	switch {
	case errors.Is(err, ErrReactorKeyVersionTooOld):
		return "key_version_too_old"
	case errors.Is(err, ErrReactorBadSignature):
		return "bad_signature"
	case errors.Is(err, ErrReactorStale):
		return "stale"
	case errors.Is(err, ErrReactorReplay):
		return "replay"
	case errors.Is(err, ErrReactorTenantMismatch):
		return "tenant_mismatch"
	case errors.Is(err, ErrReactorUnknownEvent):
		return "unknown_event"
	default:
		return "malformed"
	}
}

// reactorRedactedReason renders a session-loss cause for telemetry. It is a
// category, not the error text, because an AMQP dial error embeds the URL —
// and an AMQP URL carries credentials.
func reactorRedactedReason(err error) string {
	if err == nil {
		return "session_closed"
	}
	if errors.Is(err, ErrReactorInsecureURL) {
		return "insecure_url"
	}
	return "transport_error"
}

// reactorReconnectDelay is min(5s, 200ms * 2^(n-1)) with full jitter over
// [0, that] — §16.1's shape, unbounded in attempts (see the constants above).
func reactorReconnectDelay(attempt int, fraction float64) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	backoff := reactorReconnectMaxDelay
	if attempt < 32 {
		if d := reactorReconnectBaseDelay << (attempt - 1); d > 0 && d < reactorReconnectMaxDelay {
			backoff = d
		}
	}
	if fraction < 0 {
		fraction = 0
	} else if fraction > 1 {
		fraction = 1
	}
	return time.Duration(float64(backoff) * fraction)
}

// emitReactorTelemetry delivers event, recovering from a panicking hook
// (§19.2 rule 2).
func emitReactorTelemetry(hook ReactorTelemetryHook, event ReactorTelemetryEvent) {
	if hook == nil {
		return
	}
	defer func() {
		_ = recover() // Deliberately swallowed: telemetry cannot fail a decision.
	}()
	hook(event)
}
