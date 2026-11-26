package amqp

// The AMQP authorization requester (CONTRACT.md §8, "Signed authorization
// responses", contract 1.68; N2, D-9). It publishes an AuthzRequest on
// axiam.authz.request with a private, exclusive, broker-named reply_to queue,
// and accepts an answer only when it verifies as the server's signed response
// to THAT request.
//
// The one rule that decides the design: verify the received bytes and deliver
// the same bytes (C2). The signature is checked over the delivery body with
// its trailing hmac_signature member cut out — never over a re-serialization —
// and the decision handed to the caller is decoded from those very canonical
// bytes.
//
// The requester requires an AXIAM server of 1.68 or later (contract 1.68). Such
// a server signs every authorization response with the tenant's AMQP subkey and
// answers on the requester's private reply_to queue. A server older than 1.68
// ignores reply_to and answers, unsigned, only on the shared
// axiam.authz.response queue, which this requester never reads: against it
// every check times out. There is no option to accept unsigned responses
// (CONTRACT 1.69 §8): no AXIAM server sends one to a reply queue, so an
// unsigned response can only have been published by someone else, and it is
// discarded and logged. During a rolling upgrade from a pre-1.68 server, use
// REST or gRPC authorization until every replica runs 1.68 or later.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	amqp091 "github.com/rabbitmq/amqp091-go"
)

const (
	// AuthzRequestQueue is the queue the server consumes AuthzRequest from.
	AuthzRequestQueue = "axiam.authz.request"

	// authzKeyVersion is the signing-key version this requester sends and
	// derives nothing from: the caller supplies the tenant subkey for it
	// (§8.1), and the response carries no key_version — the requester uses the
	// one it sent.
	authzKeyVersion = 2

	// defaultAuthzTimeout bounds one Check when the caller's context has no
	// earlier deadline.
	defaultAuthzTimeout = 10 * time.Second

	// serverQueuePrefix is the prefix of the server's own queues; the server
	// does not honour a reply_to that starts with it (§8 rule 5).
	serverQueuePrefix = "axiam."

	sigMember    = `,"hmac_signature":"`
	sigHexLength = 64
)

// ErrAuthzRequesterClosed is returned by Check once the requester's reply
// queue has gone away or Close was called.
var ErrAuthzRequesterClosed = errors.New("axiam: authz requester is closed")

// AuthzDecision is a verified answer to one AuthzRequest.
type AuthzDecision struct {
	// Allowed is the decision. It is true only for a response that verified
	// under the tenant subkey and is bound to this request.
	Allowed bool
	// Reason is the server's human-readable reason, "" when absent.
	Reason string
	// ReasonCode is the machine-readable code (`allowed`, `no_grant`,
	// `denied_by_rule`, `tenant_suspended`, ...), "" when absent. A code this
	// SDK does not know is surfaced verbatim.
	ReasonCode string
}

// AuthzTransport is the seam between the requester and a broker: it declares
// the private reply queue and publishes requests. The amqp091 implementation
// is NewAuthzRequester; tests supply a fake.
type AuthzTransport interface {
	// DeclareReplyQueue declares an EXCLUSIVE, auto-delete, broker-named queue
	// only this requester consumes (an `amq.gen-…` queue) and starts consuming
	// it with manual acknowledgement, returning its name and its deliveries.
	// The deliveries channel is closed when the queue or connection goes away.
	DeclareReplyQueue(ctx context.Context) (queue string, deliveries <-chan AckableDelivery, err error)
	// PublishRequest publishes body on the default exchange with routing key
	// queue, AMQP reply_to = replyTo, correlation_id = correlationID.
	PublishRequest(ctx context.Context, queue, replyTo, correlationID string, body []byte) error
	// Close stops consuming the reply queue: it cancels the broker consumer
	// DeclareReplyQueue started (by its consumer tag) and releases whatever
	// feeds the deliveries channel. AuthzRequester.Close calls it once.
	Close() error
}

// AuthzRequesterOption configures an AuthzRequester.
type AuthzRequesterOption func(*authzRequesterConfig)

type authzRequesterConfig struct {
	logger  securityLogger
	timeout time.Duration
	now     func() time.Time
}

// WithAuthzSecurityLogger supplies the logger for discarded responses
// (CONTRACT 1.69 §8 consumer obligation 4). Every discard emits one warning,
// "axiam_sdk_security: AMQP authz response discarded", with exactly these
// key/value members: timestamp (RFC 3339 UTC), exchange (as the broker
// reported it, "" for the default exchange), routing_key (this requester's
// reply queue), tenant_id (the requester's OWN tenant, never the one the
// response claims) and reason (malformed, unsigned, signature, tenant or
// unknown_request). It never carries a signature value, a nonce, the body or
// any member read from it. Defaults to a no-op logger.
func WithAuthzSecurityLogger(l securityLogger) AuthzRequesterOption {
	return func(c *authzRequesterConfig) {
		if l != nil {
			c.logger = l
		}
	}
}

// WithAuthzTimeout bounds each Check (default 10s) when the caller's context
// carries no earlier deadline. d <= 0 is ignored.
func WithAuthzTimeout(d time.Duration) AuthzRequesterOption {
	return func(c *authzRequesterConfig) {
		if d > 0 {
			c.timeout = d
		}
	}
}

// pendingAuthz is one outstanding request.
type pendingAuthz struct {
	nonce  string
	result chan AuthzDecision
}

// AuthzRequester publishes AuthzRequest messages and verifies their answers.
// It is safe for concurrent use; many Checks may be outstanding at once.
type AuthzRequester struct {
	transport  AuthzTransport
	tenantID   string
	signingKey []byte
	cfg        authzRequesterConfig
	replyTo    string

	mu      sync.Mutex
	pending map[string]*pendingAuthz // keyed by correlation_id
	closed  bool
	done    chan struct{}

	transportClose sync.Once
}

// NewAuthzRequester opens a private reply queue on ch and returns a requester
// for tenantID. signingKey is the tenant's AMQP subkey for key_version 2,
// obtained from the AXIAM management API (§8.1); tenantID is the requester's
// OWN tenant and is the only tenant a response is accepted for.
//
// It requires an AXIAM server of 1.68 or later: a pre-1.68 server answers,
// unsigned, only on the shared axiam.authz.response queue, which this
// requester never reads, so every Check against it times out. There is no
// option to accept unsigned responses (CONTRACT 1.69 §8); use REST or gRPC
// authorization until every replica runs 1.68 or later.
func NewAuthzRequester(ctx context.Context, ch *amqp091.Channel, tenantID string, signingKey []byte, opts ...AuthzRequesterOption) (*AuthzRequester, error) {
	return NewAuthzRequesterWithTransport(ctx, &amqp091AuthzTransport{ch: ch}, tenantID, signingKey, opts...)
}

// NewAuthzRequesterWithTransport is NewAuthzRequester over a caller-supplied
// transport.
func NewAuthzRequesterWithTransport(ctx context.Context, transport AuthzTransport, tenantID string, signingKey []byte, opts ...AuthzRequesterOption) (*AuthzRequester, error) {
	tid, err := uuid.Parse(tenantID)
	if err != nil {
		return nil, fmt.Errorf("axiam: authz requester tenant_id is not a UUID: %w", err)
	}
	if len(signingKey) == 0 {
		return nil, errors.New("axiam: authz requester needs the tenant signing key")
	}
	cfg := authzRequesterConfig{logger: noopLogger{}, timeout: defaultAuthzTimeout, now: time.Now}
	for _, o := range opts {
		o(&cfg)
	}

	queue, deliveries, err := transport.DeclareReplyQueue(ctx)
	if err != nil {
		return nil, fmt.Errorf("axiam: authz requester failed to declare its reply queue: %w", err)
	}
	if queue == "" || strings.HasPrefix(queue, serverQueuePrefix) {
		// The server answers a reply_to naming one of its own queues on the
		// shared axiam.authz.response instead (§8 rule 5), which would put
		// this requester back on the shared queue the contract forbids.
		_ = transport.Close()
		return nil, fmt.Errorf("axiam: authz reply queue %q is not a private queue", queue)
	}

	r := &AuthzRequester{
		transport:  transport,
		tenantID:   tid.String(),
		signingKey: append([]byte(nil), signingKey...),
		cfg:        cfg,
		replyTo:    queue,
		pending:    make(map[string]*pendingAuthz),
		done:       make(chan struct{}),
	}
	go r.consume(deliveries)
	return r, nil
}

// ReplyTo is the private reply queue requests name in their reply_to.
func (r *AuthzRequester) ReplyTo() string { return r.replyTo }

// Close stops accepting answers; outstanding and later Checks return
// ErrAuthzRequesterClosed. It cancels the broker consumer of the reply queue
// (AuthzTransport.Close) and stops the goroutines that read it; the queue is
// exclusive and auto-delete, so the broker deletes it once its consumer is
// cancelled, and an answer still in flight is dropped. The caller's channel is
// left open. Close is idempotent; a failure to cancel (for example on a
// channel that is already closed, which ends the consumer anyway) is not
// reported.
func (r *AuthzRequester) Close() {
	r.mu.Lock()
	if !r.closed {
		r.closed = true
		close(r.done)
	}
	r.mu.Unlock()
	r.transportClose.Do(func() { _ = r.transport.Close() })
}

// Check asks the server whether subjectID may perform action on resourceID
// (optionally narrowed by one scope) and waits for the verified answer. A
// response that fails verification or binding is discarded and Check keeps
// waiting for the genuine one until ctx or the timeout ends: a failed
// verification is never an allow and never completes the request.
func (r *AuthzRequester) Check(ctx context.Context, subjectID, action, resourceID string, scope ...string) (AuthzDecision, error) {
	correlationID := uuid.NewString() // crypto/rand, unpredictable
	nonce := uuid.NewString()
	body, err := buildAuthzRequest(r.signingKey, correlationID, r.tenantID, subjectID, action, resourceID, scope, nonce, r.cfg.now())
	if err != nil {
		return AuthzDecision{}, err
	}

	p := &pendingAuthz{nonce: nonce, result: make(chan AuthzDecision, 1)}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return AuthzDecision{}, ErrAuthzRequesterClosed
	}
	r.pending[correlationID] = p
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		delete(r.pending, correlationID)
		r.mu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(ctx, r.cfg.timeout)
	defer cancel()

	if err := r.transport.PublishRequest(ctx, AuthzRequestQueue, r.replyTo, correlationID, body); err != nil {
		return AuthzDecision{}, fmt.Errorf("axiam: failed to publish authz request: %w", err)
	}

	select {
	case d := <-p.result:
		return d, nil
	case <-r.done:
		return AuthzDecision{}, ErrAuthzRequesterClosed
	case <-ctx.Done():
		return AuthzDecision{}, ctx.Err()
	}
}

// consume reads the private reply queue until it closes.
func (r *AuthzRequester) consume(deliveries <-chan AckableDelivery) {
	for {
		select {
		case <-r.done:
			return
		case d, ok := <-deliveries:
			if !ok {
				r.Close()
				return
			}
			r.handle(d)
		}
	}
}

// Discard reasons (CONTRACT 1.69 §8 consumer obligation 4).
const (
	discardMalformed      = "malformed"
	discardUnsigned       = "unsigned"
	discardSignature      = "signature"
	discardTenant         = "tenant"
	discardUnknownRequest = "unknown_request"
)

// handle verifies one delivery and completes the matching request, or
// discards it (Nack without requeue plus the discard event).
func (r *AuthzRequester) handle(d AckableDelivery) {
	decision, correlationID, reason := r.verifyResponse(d.Data())
	if reason != "" {
		r.discard(d, reason)
		return
	}

	r.mu.Lock()
	p, ok := r.pending[correlationID]
	if ok {
		// Retire on acceptance: a second response for it is dropped.
		delete(r.pending, correlationID)
	}
	r.mu.Unlock()
	if !ok {
		r.discard(d, discardUnknownRequest)
		return
	}
	p.result <- decision
	d.Ack()
}

// routedDelivery is implemented by a delivery that knows the exchange and
// routing key the broker delivered it with (the amqp091 adapter does).
type routedDelivery interface {
	exchangeAndRoutingKey() (exchange, routingKey string)
}

// discard nacks d without requeue and logs the discard event. Its members are
// fixed by CONTRACT 1.69 §8 consumer obligation 4: nothing in it is read from
// the body, which is unauthenticated, and it never carries a signature value
// or a nonce. Where the delivery cannot report its exchange and routing key,
// the values this requester consumes from ("" and its reply queue) are used:
// they are the same for every delivery it can receive.
func (r *AuthzRequester) discard(d AckableDelivery, reason string) {
	exchange, routingKey := "", r.replyTo
	if rd, ok := d.(routedDelivery); ok {
		exchange, routingKey = rd.exchangeAndRoutingKey()
	}
	r.cfg.logger.SecurityWarn("axiam_sdk_security: AMQP authz response discarded",
		"timestamp", r.cfg.now().UTC().Format(time.RFC3339Nano),
		"exchange", exchange,
		"routing_key", routingKey,
		"tenant_id", r.tenantID,
		"reason", reason,
	)
	d.Nack(false)
}

// authzResponseWire is the response shape, decoded from the CANONICAL bytes
// (the received bytes with the signature member removed).
type authzResponseWire struct {
	CorrelationID string          `json:"correlation_id"`
	Allowed       json.RawMessage `json:"allowed"`
	Reason        *string         `json:"reason"`
	ReasonCode    *string         `json:"reason_code"`
	TenantID      string          `json:"tenant_id"`
	Nonce         string          `json:"nonce"`
}

// verifyResponse applies the §8 consumer obligations 1-3 to body and returns
// the decision and the correlation_id it answers, or the discard reason. It
// never re-serializes: the signature is checked over body minus its trailing
// signature member, and the decision is decoded from those same bytes.
func (r *AuthzRequester) verifyResponse(body []byte) (AuthzDecision, string, string) {
	if rejectAmbiguousKeys(body) {
		return AuthzDecision{}, "", discardMalformed
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(body, &members); err != nil {
		return AuthzDecision{}, "", discardMalformed
	}

	// Rule 1 (strict parse) for the members every response carries.
	if !isJSONBool(members["allowed"]) {
		return AuthzDecision{}, "", discardMalformed
	}
	if _, hasSig := members["hmac_signature"]; !hasSig {
		// An unsigned response is never accepted, whatever else it carries
		// (CONTRACT 1.69 §8, "Against a server older than 1.68").
		return AuthzDecision{}, "", discardUnsigned
	}

	// The canonical bytes: body with the final `,"hmac_signature":"<64 hex>"`
	// taken out of the closing brace. A body not ending in that member is
	// discarded (rule 1) — never repaired by re-serializing.
	canonical, sigHex, ok := cutTrailingSignature(body)
	if !ok {
		return AuthzDecision{}, "", discardMalformed
	}
	var embedded string
	if err := json.Unmarshal(members["hmac_signature"], &embedded); err != nil || embedded != sigHex {
		return AuthzDecision{}, "", discardMalformed
	}
	got, err := hex.DecodeString(sigHex)
	if err != nil {
		return AuthzDecision{}, "", discardMalformed
	}

	// Rule 2: HMAC-SHA256 under the requester's own tenant subkey.
	mac := hmac.New(sha256.New, r.signingKey)
	mac.Write(canonical)
	if !hmac.Equal(mac.Sum(nil), got) {
		return AuthzDecision{}, "", discardSignature
	}

	// Everything below reads the verified canonical bytes, not body (C2).
	var resp authzResponseWire
	if err := json.Unmarshal(canonical, &resp); err != nil {
		return AuthzDecision{}, "", discardMalformed
	}
	if resp.TenantID == "" || resp.Nonce == "" || resp.CorrelationID == "" {
		return AuthzDecision{}, "", discardMalformed
	}

	// Rule 3: binding to this requester's tenant and to one outstanding request.
	if resp.TenantID != r.tenantID {
		return AuthzDecision{}, "", discardTenant
	}
	r.mu.Lock()
	p, ok := r.pending[resp.CorrelationID]
	nonceOK := ok && p.nonce == resp.Nonce
	r.mu.Unlock()
	if !nonceOK {
		return AuthzDecision{}, "", discardUnknownRequest
	}
	return decisionFrom(resp), resp.CorrelationID, ""
}

func decisionFrom(resp authzResponseWire) AuthzDecision {
	d := AuthzDecision{Allowed: bytes.Equal(bytes.TrimSpace(resp.Allowed), []byte("true"))}
	if resp.Reason != nil {
		d.Reason = *resp.Reason
	}
	if resp.ReasonCode != nil {
		d.ReasonCode = *resp.ReasonCode
	}
	return d
}

func isJSONBool(raw json.RawMessage) bool {
	t := bytes.TrimSpace(raw)
	return bytes.Equal(t, []byte("true")) || bytes.Equal(t, []byte("false"))
}

// cutTrailingSignature removes the final `,"hmac_signature":"<64 hex>"` member
// from body, returning the canonical bytes (the rest, closed with `}`) and the
// signature hex. ok is false when body does not end in exactly that member.
func cutTrailingSignature(body []byte) (canonical []byte, sigHex string, ok bool) {
	const tail = `"}`
	suffixLen := len(sigMember) + sigHexLength + len(tail)
	if len(body) <= suffixLen || !bytes.HasSuffix(body, []byte(tail)) {
		return nil, "", false
	}
	start := len(body) - suffixLen
	if string(body[start:start+len(sigMember)]) != sigMember {
		return nil, "", false
	}
	sigHex = string(body[start+len(sigMember) : len(body)-len(tail)])
	if _, err := hex.DecodeString(sigHex); err != nil {
		return nil, "", false
	}
	canonical = make([]byte, 0, start+1)
	canonical = append(canonical, body[:start]...)
	canonical = append(canonical, '}')
	return canonical, sigHex, true
}

// buildAuthzRequest serializes and signs an AuthzRequest in the server's field
// order (see authzRequestCanonical), compact, with the signature appended as
// the trailing member. HTML escaping is OFF: serde_json writes <, > and & raw,
// and the server verifies the bytes it would itself produce.
func buildAuthzRequest(key []byte, correlationID, tenantID, subjectID, action, resourceID string, scope []string, nonce string, now time.Time) ([]byte, error) {
	sub, err := uuid.Parse(subjectID)
	if err != nil {
		return nil, fmt.Errorf("axiam: subject_id is not a UUID: %w", err)
	}
	res, err := uuid.Parse(resourceID)
	if err != nil {
		return nil, fmt.Errorf("axiam: resource_id is not a UUID: %w", err)
	}
	if len(scope) > 1 {
		return nil, errors.New("axiam: at most one scope may be passed")
	}
	req := authzRequestCanonical{
		CorrelationID: correlationID,
		TenantID:      tenantID,
		SubjectID:     sub.String(),
		Action:        action,
		ResourceID:    res.String(),
		KeyVersion:    authzKeyVersion,
		Nonce:         nonce,
		IssuedAt:      now.UTC().Format(time.RFC3339),
	}
	if len(scope) == 1 {
		req.Scope = &scope[0]
	}
	for _, s := range append([]string{action}, scope...) {
		// Go's encoder always escapes U+2028/U+2029 and replaces invalid UTF-8,
		// serde_json does neither, so the signed bytes would differ.
		if !utf8.ValidString(s) || strings.ContainsAny(s, "  ") {
			return nil, errors.New("axiam: action and scope must be valid UTF-8 without U+2028 or U+2029")
		}
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(&req); err != nil {
		return nil, fmt.Errorf("axiam: failed to encode authz request: %w", err)
	}
	canonical := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))

	mac := hmac.New(sha256.New, key)
	mac.Write(canonical)
	sig := hex.EncodeToString(mac.Sum(nil))

	wire := make([]byte, 0, len(canonical)+len(sigMember)+sigHexLength+2)
	wire = append(wire, canonical[:len(canonical)-1]...)
	wire = append(wire, sigMember...)
	wire = append(wire, sig...)
	wire = append(wire, '"', '}')
	return wire, nil
}

// amqp091AuthzChannel is the slice of *amqp091.Channel the requester uses.
type amqp091AuthzChannel interface {
	QueueDeclare(name string, durable, autoDelete, exclusive, noWait bool, args amqp091.Table) (amqp091.Queue, error)
	Consume(queue, consumer string, autoAck, exclusive, noLocal, noWait bool, args amqp091.Table) (<-chan amqp091.Delivery, error)
	Cancel(consumer string, noWait bool) error
	PublishWithContext(ctx context.Context, exchange, key string, mandatory, immediate bool, msg amqp091.Publishing) error
}

// authzConsumerTagPrefix prefixes the consumer tag of each requester's
// reply-queue consumer; a random suffix keeps tags unique on a shared channel.
const authzConsumerTagPrefix = "axiam-sdk-authz-"

type amqp091AuthzTransport struct {
	ch amqp091AuthzChannel

	consumerTag string
	stop        chan struct{}
	cancelled   bool // written before stop is closed: the broker consumer is gone
	closeOnce   sync.Once
}

func (t *amqp091AuthzTransport) DeclareReplyQueue(_ context.Context) (string, <-chan AckableDelivery, error) {
	// Empty name: the broker names it (`amq.gen-…`). Exclusive: only this
	// connection may consume it. Auto-delete: it goes with its consumer.
	q, err := t.ch.QueueDeclare("", false, true, true, false, nil)
	if err != nil {
		return "", nil, err
	}
	// A known tag, so Close can cancel exactly this consumer.
	t.consumerTag = authzConsumerTagPrefix + uuid.NewString()
	raw, err := t.ch.Consume(q.Name, t.consumerTag, false, true, false, false, nil)
	if err != nil {
		return "", nil, err
	}
	t.stop = make(chan struct{})
	out := make(chan AckableDelivery)
	go t.forward(raw, out)
	return q.Name, out, nil
}

// forward copies broker deliveries to out until the broker closes raw or
// Close is called.
func (t *amqp091AuthzTransport) forward(raw <-chan amqp091.Delivery, out chan<- AckableDelivery) {
	defer close(out)
	for {
		select {
		case <-t.stop:
			t.drain(raw)
			return
		case d, ok := <-raw:
			if !ok {
				return
			}
			select {
			case out <- deliveryAdapter{d: d}:
			case <-t.stop:
				_ = d.Nack(false, false)
				t.drain(raw)
				return
			}
		}
	}
}

// drain, after a successful cancel, nacks without requeue whatever amqp091
// still buffered for the cancelled consumer, so the library's own buffer
// goroutine can finish too: amqp091 closes raw once that buffer is empty.
// Without a confirmed cancel nothing guarantees raw closes, so it returns at
// once rather than wait on it.
func (t *amqp091AuthzTransport) drain(raw <-chan amqp091.Delivery) {
	if !t.cancelled {
		return
	}
	for d := range raw {
		_ = d.Nack(false, false)
	}
}

// Close cancels the reply-queue consumer by its tag (waiting for the broker's
// cancel-ok) and stops the forwarding goroutine.
func (t *amqp091AuthzTransport) Close() error {
	var err error
	t.closeOnce.Do(func() {
		if t.stop == nil {
			return
		}
		err = t.ch.Cancel(t.consumerTag, false)
		t.cancelled = err == nil
		close(t.stop)
	})
	return err
}

func (t *amqp091AuthzTransport) PublishRequest(ctx context.Context, queue, replyTo, correlationID string, body []byte) error {
	return t.ch.PublishWithContext(ctx, "", queue, false, false, amqp091.Publishing{
		ContentType:   "application/json",
		CorrelationId: correlationID,
		ReplyTo:       replyTo,
		Body:          body,
	})
}
