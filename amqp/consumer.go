package amqp

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	amqp091 "github.com/rabbitmq/amqp091-go"
)

// defaultPrefetch is the default QoS prefetch count applied unless
// overridden via WithPrefetch (CF-03).
const defaultPrefetch = 10

// consumerTag identifies this SDK's consumer to the broker.
const consumerTag = "axiam-sdk-consumer"

// securityLogger is the minimal logging seam Consume uses to emit the §8
// rule 4 security event for every discarded delivery. It is intentionally narrow
// (one method) so callers can adapt any structured logger (e.g. slog) with a
// one-line closure, and so tests can supply a recording fake without pulling
// in a logging dependency. A nil securityLogger is valid — the security
// event is simply dropped (never a reason to fail closed on ack/nack).
type securityLogger interface {
	SecurityWarn(msg string, args ...any)
}

// noopLogger discards all security events. Used when no logger is
// configured (CF-02: observability is opt-in, off by default).
type noopLogger struct{}

func (noopLogger) SecurityWarn(string, ...any) {}

// AckableDelivery is the minimal seam over AMQP delivery acknowledgement
// this package needs. *amqp091.Delivery values satisfy it directly (see
// deliveryAdapter below); a recordingDelivery test fake also satisfies it,
// so verifyAndDispatch's nack-without-requeue security contract can be
// proven hermetically without a live broker.
type AckableDelivery interface {
	// Data returns the raw message payload bytes.
	Data() []byte
	// Ack acknowledges the delivery (message processed successfully).
	Ack()
	// Nack negatively acknowledges the delivery. requeue MUST be false on
	// every failure path this package drives (verification failure, parse
	// failure, ErrDrop) so poison/unverifiable messages do not loop the
	// queue; requeue is true only for a plain (non-ErrDrop) handler error.
	Nack(requeue bool)
}

// deliveryAdapter wraps *amqp091.Delivery to satisfy AckableDelivery. Ack/
// Nack failures are intentionally swallowed here (matching the Rust
// reference's `let _ = ...`): once the consumer loop has decided the
// outcome, there is no further recovery action available, and surfacing the
// ack/nack transport error would require either panicking or silently
// dropping it anyway.
type deliveryAdapter struct {
	d amqp091.Delivery
}

func (a deliveryAdapter) Data() []byte { return a.d.Body }

// exchangeAndRoutingKey reports the exchange and routing key the broker
// delivered the message with (the authz requester's discard event).
func (a deliveryAdapter) exchangeAndRoutingKey() (string, string) {
	return a.d.Exchange, a.d.RoutingKey
}

func (a deliveryAdapter) Ack() {
	_ = a.d.Ack(false)
}

func (a deliveryAdapter) Nack(requeue bool) {
	_ = a.d.Nack(false, requeue)
}

// Handler is the caller-supplied callback invoked only after a delivery's
// HMAC signature has been verified. Its return value drives the D-07 ack/
// nack matrix:
//
//	nil            -> Ack
//	ErrDrop        -> Nack WITHOUT requeue (poison message)
//	any other error -> Nack WITH requeue (transient/retryable)
type Handler func(ctx context.Context, e Event) error

// ConsumeOption configures Consume's behavior beyond its required
// parameters.
type ConsumeOption func(*consumeConfig)

type consumeConfig struct {
	prefetch int
	logger   securityLogger
	skew     time.Duration
}

// WithPrefetch overrides the default QoS prefetch count (CF-03).
func WithPrefetch(n int) ConsumeOption {
	return func(c *consumeConfig) {
		c.prefetch = n
	}
}

// WithSkew overrides the default ±5-minute freshness window (NEW-4) applied
// to a delivery's issued_at field: a message whose issued_at falls outside
// ±skew of the consumer's current clock is rejected (nacked without
// requeue, handler never invoked) even though its HMAC signature verifies.
// skew also sets the TTL (2×skew) of the in-memory nonce dedup set used for
// replay detection. skew <= 0 is ignored (the default is kept).
func WithSkew(skew time.Duration) ConsumeOption {
	return func(c *consumeConfig) {
		if skew > 0 {
			c.skew = skew
		}
	}
}

// WithSecurityLogger supplies the logger for discarded deliveries (CONTRACT
// 1.69 §8 protocol rule 4, D-8). Every discard emits one warning,
// "axiam_sdk_security: AMQP message discarded", with exactly these key/value
// members: timestamp (RFC 3339 UTC), exchange and routing_key (as the broker
// delivered the message), tenant_id (the tenant Consume was configured with,
// never one read from the message) and reason (malformed, unsigned,
// signature, key_version, stale or replay). It never includes a signature
// value, a nonce, the key or the body. Optional; defaults to a no-op logger
// (CF-02: observability off by default).
func WithSecurityLogger(l securityLogger) ConsumeOption {
	return func(c *consumeConfig) {
		if l != nil {
			c.logger = l
		}
	}
}

// eventConsumerSpec is what an event consumer is configured with besides its
// key: the one type it consumes (§8 step 2c, D-9), its own tenant and the
// queue it reads (both for the rule 4 discard event, D-8), and the clock the
// event's timestamp reads.
type eventConsumerSpec struct {
	msgType  MessageType
	tenantID string
	queue    string
	now      func() time.Time
}

// discard nacks d without requeue and logs the one rule 4 event (CONTRACT
// 1.69 §8 protocol rule 4, "Every SDK consumer, field by field"; D-8). Its
// members are fixed: timestamp, exchange, routing_key, tenant_id and reason.
// tenant_id is this consumer's own configured tenant, never read from the
// body; nothing in the event is read from the body, which is unauthenticated,
// and it never carries a signature value, a nonce or the key. Where the
// delivery cannot report its exchange and routing key, the values this
// consumer reads from ("" and its queue) are used.
func (s eventConsumerSpec) discard(d AckableDelivery, reason string, logger securityLogger) {
	exchange, routingKey := "", s.queue
	if rd, ok := d.(routedDelivery); ok {
		exchange, routingKey = rd.exchangeAndRoutingKey()
	}
	now := s.now
	if now == nil {
		now = time.Now
	}
	logger.SecurityWarn("axiam_sdk_security: AMQP message discarded",
		"timestamp", now().UTC().Format(time.RFC3339Nano),
		"exchange", exchange,
		"routing_key", routingKey,
		"tenant_id", s.tenantID,
		"reason", reason,
	)
	d.Nack(false)
}

// verifyAndDispatch verifies a single delivery BEFORE invoking handler (§8,
// D-07's core security invariant), then applies the NEW-4 replay-protection
// gate, then maps the outcome to the ack/nack matrix:
//
//   - The body is refused (verifyEvent: not one JSON object or a byte-order
//     mark or other prefix, unsigned, ambiguous member names, a signature
//     that is not the trailing member, a layout that is not spec.msgType's,
//     a signature that does not verify, verified bytes that do not decode),
//     or the replay gate refuses it (key_version < 2, stale issued_at, a
//     replayed nonce; skipped when replay is nil, for tests that only
//     exercise the ack/nack matrix) -> Nack(false) and one rule 4 discard
//     event naming the first reason that applies; handler is NEVER invoked.
//   - handler(ctx, event) returns nil -> Ack.
//   - handler returns ErrDrop -> Nack(false) (poison message).
//   - handler returns any other error -> Nack(true) (transient, requeue).
//
// This is the load-bearing, separately-testable unit backing Consume's
// per-delivery loop — generic over AckableDelivery so it is exercised
// against recordingDelivery in tests without a live broker.
func verifyAndDispatch(ctx context.Context, delivery AckableDelivery, spec eventConsumerSpec, signingKey []byte, handler Handler, logger securityLogger, replay *replayGuard) {
	if logger == nil {
		logger = noopLogger{}
	}

	// signed is the received body minus its trailing signature member: the
	// exact bytes the HMAC covered (server #882). Everything the handler later
	// sees is parsed from it (C2); nothing is re-serialized.
	signed, meta, reason := verifyEvent(signingKey, delivery.Data(), spec.msgType)
	var event Event
	if reason == "" {
		// Still position (5): the verified bytes decode, before the v2 gates.
		ev, err := parseEvent(signed)
		if err != nil {
			reason = discardMalformed
		}
		event = ev
	}
	if reason == "" && replay != nil {
		if err := replay.check(meta); err != nil {
			reason = discardMalformed
			var ge *gateError
			if errors.As(err, &ge) {
				reason = ge.reason
			}
		}
	}
	if reason != "" {
		spec.discard(delivery, reason, logger)
		return
	}

	if err := handler(ctx, event); err != nil {
		if errors.Is(err, ErrDrop) {
			delivery.Nack(false)
			return
		}
		delivery.Nack(true)
		return
	}

	delivery.Ack()
}

// Consume connects the SDK's ack/nack loop to ch for the ONE message type
// msgType (AuthzRequestMessage or AuditEventMessage), verifying every
// delivery's HMAC-SHA256 signature (CONTRACT.md §8) BEFORE invoking handler.
// The handler never sees an unverified message, nor one of another type: a
// body with another signed type's layout — a genuine AuditEventMessage
// replayed onto a queue of authorization requests, which the shared tenant
// subkey signs alike — is refused before the HMAC and before decoding
// (contract 1.69, D-9). An application that consumes both types runs two
// Consume loops. Every refusal is nacked without requeue and logged as one
// security event (see WithSecurityLogger). Consume sets a configurable QoS
// prefetch (default 10, CF-03, overridable via WithPrefetch) and blocks until
// ctx is cancelled or the delivery channel closes; no delivery, whatever its
// bytes, ends the loop.
//
// NEW-4 replay protection: after HMAC verification succeeds, Consume also
// rejects (nacks without requeue, handler never invoked, security event
// logged) any delivery whose key_version is below 2, whose issued_at falls
// outside a ±5-minute freshness window of the consumer's clock (overridable
// via WithSkew), or whose nonce has already been seen within that window
// (replay). The nonce dedup set is in-memory only and is bounded by a TTL of
// 2×skew, so it resets on process restart — this is a defense-in-depth
// client-side check; the server maintains the durable nonce store.
//
// tenantID is this consumer's own tenant (a UUID): the tenant whose subkey
// signingKey is. It is what the security event reports, never a tenant_id
// read from a message (contract 1.69, D-8). signingKey MUST be obtained from
// the AXIAM management API for that tenant (§8.1) — hardcoding a signing key
// is prohibited.
func Consume(ctx context.Context, ch *amqp091.Channel, queue string, msgType MessageType, tenantID string, signingKey []byte, handler Handler, opts ...ConsumeOption) error {
	if _, ok := msgType.layout(); !ok {
		return fmt.Errorf("axiam: Consume needs the message type it consumes (AuthzRequestMessage or AuditEventMessage), got %v", msgType)
	}
	tid, err := uuid.Parse(tenantID)
	if err != nil {
		return fmt.Errorf("axiam: Consume tenant_id is not a UUID: %w", err)
	}
	cfg := consumeConfig{prefetch: defaultPrefetch, logger: noopLogger{}, skew: defaultSkew}
	for _, opt := range opts {
		opt(&cfg)
	}
	spec := eventConsumerSpec{msgType: msgType, tenantID: tid.String(), queue: queue, now: time.Now}

	replay := newReplayGuard(cfg.skew)

	if err := ch.Qos(cfg.prefetch, 0, false); err != nil {
		return fmt.Errorf("axiam: failed to set AMQP QoS: %w", err)
	}

	// Buffered with capacity >= 1 (Pitfall 4): amqp091-go sends on
	// NotifyClose synchronously then closes the channel — an unbuffered
	// receiver risks the connection goroutine deadlocking if nothing is
	// actively selecting on it at the moment of closure.
	closeNotify := ch.NotifyClose(make(chan *amqp091.Error, 1))

	deliveries, err := ch.Consume(queue, consumerTag, false, false, false, false, nil)
	if err != nil {
		return fmt.Errorf("axiam: failed to start AMQP consumer: %w", err)
	}

	return consumeLoop(ctx, deliveries, closeNotify, func(d AckableDelivery) {
		verifyAndDispatch(ctx, d, spec, signingKey, handler, cfg.logger, replay)
	})
}

// consumeLoop feeds each delivery to dispatch until ctx is cancelled or the
// channel closes. A refused delivery is settled by dispatch and the loop goes
// on to the next one.
func consumeLoop(ctx context.Context, deliveries <-chan amqp091.Delivery, closeNotify <-chan *amqp091.Error, dispatch func(AckableDelivery)) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case closeErr, ok := <-closeNotify:
			if !ok {
				return fmt.Errorf("axiam: AMQP channel closed")
			}
			return fmt.Errorf("axiam: AMQP channel closed: %w", closeErr)
		case d, ok := <-deliveries:
			if !ok {
				return fmt.Errorf("axiam: AMQP delivery channel closed")
			}
			dispatch(deliveryAdapter{d: d})
		}
	}
}
