// Reactor transport seam — CONTRACT.md §22.1, §8b.
//
// ACTORS CONSUME; THEY NEVER DECLARE TOPOLOGY. The server declares the
// exchange, the per-reactor queue and the bindings from the registration's
// `events`. That rule is enforced here by the shape of the interface rather
// than by a review comment: ReactorTransport has a Consume method and a
// PublishReply method and no declare/bind method at all, so there is nowhere
// in this package for an exchange, queue or binding declaration to live.
//
// This is not tidiness. A reactor that can bind is a reactor that can bind
// itself to `*.token.pre_issue` and read another tenant's issuance events.
// Refusing to hold that capability at all is cheaper than proving each actor
// does not misuse it.

package amqp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	amqp091 "github.com/rabbitmq/amqp091-go"
)

// ReactorDelivery is one message off the reactor's queue.
type ReactorDelivery interface {
	// Body returns the raw message bytes, exactly as received.
	Body() []byte
	// ReplyTo is the reply queue named in the delivery's AMQP `reply_to`
	// basic property — standard AMQP RPC. What the SERVER authenticates is
	// not this property but the correlation_id INSIDE the signed reply body
	// (§22.1); this only says where to put it.
	ReplyTo() string
	// CorrelationID is the delivery's AMQP `correlation_id` basic property,
	// echoed onto the reply publication. It is not the authenticated
	// binding either — the one in the signed body is.
	CorrelationID() string
	// Ack acknowledges the delivery.
	Ack()
	// Nack negatively acknowledges the delivery WITHOUT requeue.
	//
	// There is no requeue parameter on purpose. A reactor's dispatch window
	// is at most five seconds, so a redelivered event can only ever produce
	// a reply the server has already stopped reading — requeuing spends the
	// broker's effort to guarantee a late answer.
	Nack()
}

// ReactorTransport is one live session against the broker: a consumer on the
// reactor's own queue, and a way to publish a reply back to the queue the
// delivery named.
//
// Note the absence of any declare or bind method (§22.1).
type ReactorTransport interface {
	// Consume starts consuming queue and returns the delivery channel. The
	// channel is closed when the session ends, which is what tells
	// ReactorServe to reconnect.
	Consume(ctx context.Context, queue string) (<-chan ReactorDelivery, error)
	// PublishReply publishes body to replyQueue via the default exchange,
	// echoing correlationID onto the AMQP property.
	PublishReply(ctx context.Context, replyQueue, correlationID string, body []byte) error
	// Close releases the session. It must be idempotent (§18.1 rule 2).
	Close() error
}

// ReactorDialer opens one transport session. ReactorServe calls it again
// after a session ends, which is how reconnect works: the dialer, not the
// runtime, owns how a connection is made.
type ReactorDialer func(ctx context.Context) (ReactorTransport, error)

// ErrReactorInsecureURL reports an AMQP URL that is not `amqps://`.
//
// §8b: reactors connect across a trust boundary, so the transport is TLS,
// with a supplied CA bundle, no verification-skip switch and no plaintext
// fallback. HMAC does not substitute for TLS and TLS does not substitute for
// HMAC — the signed reply proves who wrote it, and only TLS keeps the
// payload off the wire in the clear.
var ErrReactorInsecureURL = errors.New("axiam: reactor AMQP URL must use amqps:// (CONTRACT.md §8b)")

// AMQPSDialerOption configures AMQPSDialer.
type AMQPSDialerOption func(*amqpsDialerConfig)

type amqpsDialerConfig struct {
	caPEM     []byte
	heartbeat time.Duration
	prefetch  int
	dialTO    time.Duration
}

// WithReactorCABundle supplies PEM-encoded CA certificates to verify the
// broker against (§8b). This is the only TLS-related knob: there is no
// option anywhere in this SDK that weakens or disables verification.
//
// Omitting it uses the host's trust store.
func WithReactorCABundle(pem []byte) AMQPSDialerOption {
	return func(c *amqpsDialerConfig) { c.caPEM = pem }
}

// WithReactorHeartbeat overrides the AMQP heartbeat interval (default 10 s).
// The heartbeat is how a half-open connection becomes a closed delivery
// channel, which is what makes ReactorServe's reconnect fire instead of the
// reactor sitting silently attached to a socket nobody is on the other end
// of.
func WithReactorHeartbeat(d time.Duration) AMQPSDialerOption {
	return func(c *amqpsDialerConfig) {
		if d > 0 {
			c.heartbeat = d
		}
	}
}

// WithReactorPrefetch overrides the QoS prefetch (default 10).
func WithReactorPrefetch(n int) AMQPSDialerOption {
	return func(c *amqpsDialerConfig) {
		if n > 0 {
			c.prefetch = n
		}
	}
}

// AMQPSDialer returns a ReactorDialer that connects to url over TLS
// (§8b) with rabbitmq/amqp091-go.
//
// url MUST be `amqps://`. A plaintext `amqp://` URL is refused at dial time
// rather than downgraded, because a fallback that works is a fallback that
// gets used.
func AMQPSDialer(url string, opts ...AMQPSDialerOption) ReactorDialer {
	cfg := amqpsDialerConfig{heartbeat: 10 * time.Second, prefetch: 10, dialTO: 30 * time.Second}
	for _, opt := range opts {
		opt(&cfg)
	}

	return func(ctx context.Context) (ReactorTransport, error) {
		if !strings.HasPrefix(strings.ToLower(url), "amqps://") {
			return nil, ErrReactorInsecureURL
		}

		// TLS 1.3 floor, matching the SDK's REST and gRPC transports. The
		// only configurable part is which roots to trust.
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13}
		if len(cfg.caPEM) > 0 {
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(cfg.caPEM) {
				return nil, errors.New("axiam: reactor CA bundle contains no valid PEM certificate")
			}
			tlsCfg.RootCAs = pool
		}

		conn, err := amqp091.DialConfig(url, amqp091.Config{
			Heartbeat:       cfg.heartbeat,
			TLSClientConfig: tlsCfg,
			Dial:            amqp091.DefaultDial(cfg.dialTO),
		})
		if err != nil {
			return nil, fmt.Errorf("axiam: reactor failed to connect to the AMQP broker: %w", err)
		}
		return newAMQP091Transport(amqp091Connection{Connection: conn}, cfg.prefetch)
	}
}

// newAMQP091Transport opens the session's channel and applies its QoS.
//
// Split out from AMQPSDialer because the failure ORDER matters and is worth
// asserting: a channel that opened and then failed its QoS must be closed
// along with the connection, or the dial has leaked a socket the caller
// never learned about and cannot release — the same leak §18.1 rule 3
// exists to rule out on the shutdown path.
func newAMQP091Transport(conn amqp091ConnWithChannel, prefetch int) (ReactorTransport, error) {
	ch, err := conn.reactorChannel()
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("axiam: reactor failed to open an AMQP channel: %w", err)
	}
	if err := ch.Qos(prefetch, 0, false); err != nil {
		_ = ch.Close()
		_ = conn.Close()
		return nil, fmt.Errorf("axiam: reactor failed to set AMQP QoS: %w", err)
	}
	return &amqp091Transport{conn: conn, ch: ch}, nil
}

// amqp091Channel is the NARROW slice of *amqp091.Channel this adapter uses:
// consume, publish, close. *amqp091.Channel satisfies it as it stands.
//
// It exists for two reasons, and the first is the load-bearing one. §22.1's
// "actors consume; they never declare topology" is enforced here by
// omission — this interface names no declare or bind method, so even the
// concrete adapter, the one place in the SDK holding a real channel, cannot
// reach one. The second reason is ordinary: it makes the adapter's own
// forwarding, publishing and shutdown behaviour testable without a broker.
type amqp091Channel interface {
	Consume(queue, consumer string, autoAck, exclusive, noLocal, noWait bool, args amqp091.Table) (<-chan amqp091.Delivery, error)
	PublishWithContext(ctx context.Context, exchange, key string, mandatory, immediate bool, msg amqp091.Publishing) error
	Qos(prefetchCount, prefetchSize int, global bool) error
	Close() error
}

// amqp091Conn is the equally narrow slice of *amqp091.Connection: the
// adapter closes it on shutdown.
type amqp091Conn interface {
	Close() error
}

// amqp091ConnWithChannel is a connection that can also open the session's
// channel. *amqp091.Connection's own Channel() returns a concrete
// *amqp091.Channel, which Go will not treat as returning the interface
// above, so amqp091Connection adapts it in the one line that costs.
type amqp091ConnWithChannel interface {
	amqp091Conn
	reactorChannel() (amqp091Channel, error)
}

// amqp091Connection adapts *amqp091.Connection to amqp091ConnWithChannel.
type amqp091Connection struct {
	*amqp091.Connection
}

func (c amqp091Connection) reactorChannel() (amqp091Channel, error) {
	return c.Connection.Channel()
}

// amqp091Transport is the rabbitmq/amqp091-go implementation of
// ReactorTransport. It declares nothing — Consume attaches to a queue the
// server already declared, and PublishReply publishes to the default
// exchange, which exists on every broker and needs no declaration.
type amqp091Transport struct {
	conn amqp091Conn
	ch   amqp091Channel
}

func (t *amqp091Transport) Consume(_ context.Context, queue string) (<-chan ReactorDelivery, error) {
	raw, err := t.ch.Consume(queue, "axiam-reactor", false, false, false, false, nil)
	if err != nil {
		return nil, fmt.Errorf("axiam: reactor failed to start consuming %q: %w", queue, err)
	}
	return forwardReactorDeliveries(raw), nil
}

// forwardReactorDeliveries adapts amqp091's delivery channel to the
// transport-neutral one the runtime consumes, and closes the output when the
// broker closes the input — which is the signal ReactorServe reads as "this
// session has ended, reconnect".
func forwardReactorDeliveries(raw <-chan amqp091.Delivery) <-chan ReactorDelivery {
	out := make(chan ReactorDelivery)
	go func() {
		defer close(out)
		for d := range raw {
			out <- amqp091ReactorDelivery{d: d}
		}
	}()
	return out
}

func (t *amqp091Transport) PublishReply(ctx context.Context, replyQueue, correlationID string, body []byte) error {
	if replyQueue == "" {
		return errors.New("axiam: reactor delivery carried no reply_to queue")
	}
	// Default exchange, routing key = the queue named by reply_to. Standard
	// AMQP RPC, and the one publication a reactor makes.
	err := t.ch.PublishWithContext(ctx, "", replyQueue, false, false, amqp091.Publishing{
		ContentType:   "application/json",
		CorrelationId: correlationID,
		Body:          body,
	})
	if err != nil {
		return fmt.Errorf("axiam: reactor failed to publish a reply: %w", err)
	}
	return nil
}

func (t *amqp091Transport) Close() error {
	// Idempotent (§18.1 rule 2): amqp091 returns ErrClosed on a second
	// close, which is not a failure worth surfacing from a cleanup path.
	if t.ch != nil {
		_ = t.ch.Close()
	}
	if t.conn != nil {
		if err := t.conn.Close(); err != nil && !errors.Is(err, amqp091.ErrClosed) {
			return err
		}
	}
	return nil
}

// amqp091ReactorDelivery adapts amqp091.Delivery to ReactorDelivery.
type amqp091ReactorDelivery struct {
	d amqp091.Delivery
}

func (a amqp091ReactorDelivery) Body() []byte          { return a.d.Body }
func (a amqp091ReactorDelivery) ReplyTo() string       { return a.d.ReplyTo }
func (a amqp091ReactorDelivery) CorrelationID() string { return a.d.CorrelationId }
func (a amqp091ReactorDelivery) Ack()                  { _ = a.d.Ack(false) }
func (a amqp091ReactorDelivery) Nack()                 { _ = a.d.Nack(false, false) }
