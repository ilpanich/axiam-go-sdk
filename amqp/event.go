package amqp

import "encoding/json"

// Event is the server message shape a Consume handler receives, after HMAC
// verification has already succeeded (CONTRACT.md §8, D-07). Fields is the
// decoded JSON object so callers can read message-type-specific fields
// (AuthzRequest/AuditEventMessage, etc.) without this package needing to model
// every server message type.
//
// Both views are built from the verified bytes — the received body with its
// trailing signature member removed, exactly what the HMAC covered — and are
// never re-serialized (C2, server #882). A key the signature
// does not cover therefore never appears in either.
type Event struct {
	// Raw is the bytes the HMAC covered: the delivery body exactly as
	// received, with its trailing hmac_signature member removed (server
	// #882). It is for callers that re-parse into a specific message type.
	Raw []byte
	// Fields is Raw decoded as a JSON object, member by member.
	Fields map[string]json.RawMessage
}

// parseEvent decodes verified canonical bytes into an Event. It is only ever
// called with the bytes verifyEvent returned for the delivery (consumer.go),
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
