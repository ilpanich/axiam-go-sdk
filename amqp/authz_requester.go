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
	// under the tenant subkey (or, with AllowUnsignedResponses, for a response
	// that carried no signature at all — see Unsigned).
	Allowed bool
	// Reason is the server's human-readable reason, "" when absent.
	Reason string
	// ReasonCode is the machine-readable code (`allowed`, `no_grant`,
	// `denied_by_rule`, `tenant_suspended`, ...), "" when absent. A code this
	// SDK does not know is surfaced verbatim.
	ReasonCode string
	// Unsigned is true when the response carried no hmac_signature and was
	// accepted only because AllowUnsignedResponses is set.
	Unsigned bool
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
}

// AuthzRequesterOption configures an AuthzRequester.
type AuthzRequesterOption func(*authzRequesterConfig)

type authzRequesterConfig struct {
	allowUnsigned bool
	logger        securityLogger
	timeout       time.Duration
	now           func() time.Time
}

// AllowUnsignedResponses is the explicit, integrator-set opt-out for ONE
// rolling upgrade against a server older than contract 1.68, whose responses
// are unsigned (CONTRACT.md §8). Off by default. With it set, a response that
// carries NO hmac_signature member at all is accepted on its correlation_id
// alone (and logged as a security warning); a response that carries a
// signature is verified in full whatever this option says, and the opt-out
// never admits one that fails. Remove it once the server is upgraded.
func AllowUnsignedResponses() AuthzRequesterOption {
	return func(c *authzRequesterConfig) { c.allowUnsigned = true }
}

// WithAuthzSecurityLogger supplies the logger for discarded responses and for
// an unsigned response admitted by AllowUnsignedResponses. Messages never
// contain a signature value. Defaults to a no-op logger.
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
}

// NewAuthzRequester opens a private reply queue on ch and returns a requester
// for tenantID. signingKey is the tenant's AMQP subkey for key_version 2,
// obtained from the AXIAM management API (§8.1); tenantID is the requester's
// OWN tenant and is the only tenant a response is accepted for.
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
// ErrAuthzRequesterClosed. The reply queue is exclusive and auto-delete, so
// the broker removes it with the channel.
func (r *AuthzRequester) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.closed {
		r.closed = true
		close(r.done)
	}
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

// handle verifies one delivery and completes the matching request, or
// discards it (Nack without requeue plus a security event).
func (r *AuthzRequester) handle(d AckableDelivery) {
	decision, correlationID, err := r.verifyResponse(d.Data())
	if err != nil {
		// Fact of failure only — never a signature value (§8 protocol rule 4).
		r.cfg.logger.SecurityWarn("axiam_sdk_security: AMQP authz response discarded: " + err.Error())
		d.Nack(false)
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
		r.cfg.logger.SecurityWarn("axiam_sdk_security: AMQP authz response discarded: no outstanding request")
		d.Nack(false)
		return
	}
	p.result <- decision
	d.Ack()
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
// the decision and the correlation_id it answers. It does NOT consult the
// outstanding map beyond the nonce binding read below, and it never
// re-serializes: the signature is checked over body minus its trailing
// signature member, and the decision is decoded from those same bytes.
func (r *AuthzRequester) verifyResponse(body []byte) (AuthzDecision, string, error) {
	if rejectAmbiguousKeys(body) {
		return AuthzDecision{}, "", errors.New("body is not an object with unambiguous keys")
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(body, &members); err != nil {
		return AuthzDecision{}, "", errors.New("body is not a JSON object")
	}
	_, hasSig := members["hmac_signature"]

	// Rule 1 (strict parse) for the members every response carries.
	if !isJSONBool(members["allowed"]) {
		return AuthzDecision{}, "", errors.New("allowed is missing or not a boolean")
	}

	if !hasSig {
		return r.acceptUnsigned(body)
	}

	// The canonical bytes: body with the final `,"hmac_signature":"<64 hex>"`
	// taken out of the closing brace. A body not ending in that member is
	// discarded (rule 1) — never repaired by re-serializing.
	canonical, sigHex, ok := cutTrailingSignature(body)
	if !ok {
		return AuthzDecision{}, "", errors.New("body does not end in the hmac_signature member")
	}
	var embedded string
	if err := json.Unmarshal(members["hmac_signature"], &embedded); err != nil || embedded != sigHex {
		return AuthzDecision{}, "", errors.New("hmac_signature is not the trailing member")
	}
	got, err := hex.DecodeString(sigHex)
	if err != nil {
		return AuthzDecision{}, "", errors.New("hmac_signature is not hex")
	}

	// Rule 2: HMAC-SHA256 under the requester's own tenant subkey.
	mac := hmac.New(sha256.New, r.signingKey)
	mac.Write(canonical)
	if !hmac.Equal(mac.Sum(nil), got) {
		return AuthzDecision{}, "", errors.New("signature does not verify")
	}

	// Everything below reads the verified canonical bytes, not body (C2).
	var resp authzResponseWire
	if err := json.Unmarshal(canonical, &resp); err != nil {
		return AuthzDecision{}, "", errors.New("verified bytes do not decode")
	}
	if resp.TenantID == "" || resp.Nonce == "" || resp.CorrelationID == "" {
		return AuthzDecision{}, "", errors.New("tenant_id, nonce or correlation_id is missing")
	}

	// Rule 3: binding to this requester's tenant and to one outstanding request.
	if resp.TenantID != r.tenantID {
		return AuthzDecision{}, "", errors.New("tenant_id is not the requester's")
	}
	r.mu.Lock()
	p, ok := r.pending[resp.CorrelationID]
	nonceOK := ok && p.nonce == resp.Nonce
	r.mu.Unlock()
	if !nonceOK {
		return AuthzDecision{}, "", errors.New("correlation_id and nonce match no outstanding request")
	}
	return decisionFrom(resp, false), resp.CorrelationID, nil
}

// acceptUnsigned handles a response with no hmac_signature member: refused
// unless AllowUnsignedResponses is set, in which case it is accepted on its
// correlation_id alone (a pre-1.68 server answers with no tenant_id or nonce).
func (r *AuthzRequester) acceptUnsigned(body []byte) (AuthzDecision, string, error) {
	if !r.cfg.allowUnsigned {
		return AuthzDecision{}, "", errors.New("response is unsigned")
	}
	var resp authzResponseWire
	if err := json.Unmarshal(body, &resp); err != nil || resp.CorrelationID == "" {
		return AuthzDecision{}, "", errors.New("unsigned response has no correlation_id")
	}
	r.mu.Lock()
	_, ok := r.pending[resp.CorrelationID]
	r.mu.Unlock()
	if !ok {
		return AuthzDecision{}, "", errors.New("correlation_id matches no outstanding request")
	}
	r.cfg.logger.SecurityWarn("axiam_sdk_security: AMQP authz response accepted UNSIGNED because AllowUnsignedResponses is set")
	return decisionFrom(resp, true), resp.CorrelationID, nil
}

func decisionFrom(resp authzResponseWire, unsigned bool) AuthzDecision {
	d := AuthzDecision{Allowed: bytes.Equal(bytes.TrimSpace(resp.Allowed), []byte("true")), Unsigned: unsigned}
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
	PublishWithContext(ctx context.Context, exchange, key string, mandatory, immediate bool, msg amqp091.Publishing) error
}

type amqp091AuthzTransport struct {
	ch amqp091AuthzChannel
}

func (t *amqp091AuthzTransport) DeclareReplyQueue(_ context.Context) (string, <-chan AckableDelivery, error) {
	// Empty name: the broker names it (`amq.gen-…`). Exclusive: only this
	// connection may consume it. Auto-delete: it goes with its consumer.
	q, err := t.ch.QueueDeclare("", false, true, true, false, nil)
	if err != nil {
		return "", nil, err
	}
	raw, err := t.ch.Consume(q.Name, "", false, true, false, false, nil)
	if err != nil {
		return "", nil, err
	}
	out := make(chan AckableDelivery)
	go func() {
		defer close(out)
		for d := range raw {
			out <- deliveryAdapter{d: d}
		}
	}()
	return q.Name, out, nil
}

func (t *amqp091AuthzTransport) PublishRequest(ctx context.Context, queue, replyTo, correlationID string, body []byte) error {
	return t.ch.PublishWithContext(ctx, "", queue, false, false, amqp091.Publishing{
		ContentType:   "application/json",
		CorrelationId: correlationID,
		ReplyTo:       replyTo,
		Body:          body,
	})
}
