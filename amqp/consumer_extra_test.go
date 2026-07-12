package amqp

import (
	"context"
	"errors"
	"testing"
	"time"

	amqp091 "github.com/rabbitmq/amqp091-go"
)

// TestConsumeOptions_ApplyToConfig proves the functional options mutate the
// consumeConfig as documented (CF-03 prefetch, NEW-4 skew, §8.4 logger), and
// that the guard clauses (skew<=0, nil logger) leave the defaults intact.
func TestConsumeOptions_ApplyToConfig(t *testing.T) {
	cfg := consumeConfig{prefetch: defaultPrefetch, logger: noopLogger{}, skew: defaultSkew}

	WithPrefetch(42)(&cfg)
	if cfg.prefetch != 42 {
		t.Fatalf("WithPrefetch did not apply: %d", cfg.prefetch)
	}

	WithSkew(90 * time.Second)(&cfg)
	if cfg.skew != 90*time.Second {
		t.Fatalf("WithSkew did not apply: %s", cfg.skew)
	}
	// A non-positive skew is ignored — the previous value is kept.
	WithSkew(0)(&cfg)
	WithSkew(-5 * time.Second)(&cfg)
	if cfg.skew != 90*time.Second {
		t.Fatalf("WithSkew(<=0) must be ignored, got %s", cfg.skew)
	}

	rec := &recordingLogger{}
	WithSecurityLogger(rec)(&cfg)
	if cfg.logger != rec {
		t.Fatal("WithSecurityLogger did not apply")
	}
	// A nil logger is ignored — the previous logger is kept.
	WithSecurityLogger(nil)(&cfg)
	if cfg.logger != rec {
		t.Fatal("WithSecurityLogger(nil) must be ignored")
	}
}

// TestDeliveryAdapter_WrapsAMQPDelivery proves the adapter exposes the raw body
// and that Ack/Nack are safe to call — a transport error (here: an
// uninitialized Acknowledger) is intentionally swallowed, never panics.
func TestDeliveryAdapter_WrapsAMQPDelivery(t *testing.T) {
	adapter := deliveryAdapter{d: amqp091.Delivery{Body: []byte("payload")}}
	if string(adapter.Data()) != "payload" {
		t.Fatalf("Data() = %q", adapter.Data())
	}
	// These must not panic even though the delivery has no live Acknowledger.
	adapter.Ack()
	adapter.Nack(true)
	adapter.Nack(false)
}

func TestNoopLogger_SecurityWarnIsSilent(t *testing.T) {
	// The no-op logger must accept the call and discard it (never panic).
	noopLogger{}.SecurityWarn("dropped", "k", "v")
}

// TestVerifyAndDispatch_NilLoggerDefaultsToNoop proves the nil-logger branch:
// verifyAndDispatch tolerates a nil securityLogger by substituting the no-op,
// so a verification failure still nacks-without-requeue rather than panicking.
func TestVerifyAndDispatch_NilLoggerDefaultsToNoop(t *testing.T) {
	key := []byte(fixtureSigningKey)

	t.Run("verification failure with nil logger nacks without requeue", func(t *testing.T) {
		d := newRecordingDelivery([]byte(`{"no":"signature"}`))
		verifyAndDispatch(context.Background(), d, key, func(context.Context, Event) error { return nil }, nil, nil)
		acked, requeue, noRequeue := d.counts()
		if acked != 0 || requeue != 0 || noRequeue != 1 {
			t.Fatalf("expected exactly one nack-without-requeue, got ack=%d requeue=%d noRequeue=%d", acked, requeue, noRequeue)
		}
	})

	t.Run("valid message with nil logger + nil replay acks", func(t *testing.T) {
		d := newRecordingDelivery(signedTestBody(t, key, "read"))
		var invoked bool
		verifyAndDispatch(context.Background(), d, key, func(context.Context, Event) error { invoked = true; return nil }, nil, nil)
		acked, _, _ := d.counts()
		if !invoked || acked != 1 {
			t.Fatalf("expected the handler to run and the delivery to be acked, invoked=%v acked=%d", invoked, acked)
		}
	})

	t.Run("ErrDrop nacks without requeue; generic error requeues", func(t *testing.T) {
		drop := newRecordingDelivery(signedTestBody(t, key, "read"))
		verifyAndDispatch(context.Background(), drop, key, func(context.Context, Event) error { return ErrDrop }, nil, nil)
		if _, _, noRequeue := drop.counts(); noRequeue != 1 {
			t.Fatalf("ErrDrop must nack without requeue, got noRequeue=%d", noRequeue)
		}

		transient := newRecordingDelivery(signedTestBody(t, key, "read"))
		verifyAndDispatch(context.Background(), transient, key, func(context.Context, Event) error { return errors.New("db down") }, nil, nil)
		if _, requeue, _ := transient.counts(); requeue != 1 {
			t.Fatalf("a generic handler error must nack WITH requeue, got requeue=%d", requeue)
		}
	})
}
