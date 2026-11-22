package amqp

import "encoding/json"

// Event is the server message shape a Consume handler receives, after HMAC
// verification has already succeeded (CONTRACT.md §8, D-07). Fields is the
// decoded JSON object so callers can read message-type-specific fields
// (AuthzRequest/AuditEventMessage, etc.) without this package needing to model
// every server message type.
//
// Both views are built from the verified canonical bytes — the exact bytes the
// HMAC covered — and never from the received body (C2). A key the signature
// does not cover therefore never appears in either.
type Event struct {
	// Raw is the verified canonical message bytes (compact JSON in the
	// server's field order, hmac_signature absent), for callers that need to
	// re-parse into a specific message type. It is not the delivery body: it
	// omits hmac_signature and any member the signature did not cover.
	Raw []byte
	// Fields is Raw decoded as a JSON object, member by member.
	Fields map[string]json.RawMessage
}

// parseEvent decodes verified canonical bytes into an Event. It is only ever
// called with the bytes verifyHMAC returned for the delivery (consumer.go),
// never with the received body, so a parse failure here indicates bytes that
// verified but are not a JSON object — treated as a failure by the caller
// (nack without requeue, handler never invoked).
func parseEvent(body []byte) (Event, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return Event{}, err
	}
	delete(fields, "hmac_signature")
	return Event{Raw: body, Fields: fields}, nil
}
