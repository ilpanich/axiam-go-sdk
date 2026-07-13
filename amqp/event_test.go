package amqp

import (
	"encoding/json"
	"testing"
)

// TestParseEvent_ObjectStripsSignature proves parseEvent decodes a JSON object
// into Fields with hmac_signature removed and Raw preserved verbatim.
func TestParseEvent_ObjectStripsSignature(t *testing.T) {
	body := []byte(`{"action":"read","tenant_id":"t","hmac_signature":"deadbeef"}`)
	ev, err := parseEvent(body)
	if err != nil {
		t.Fatalf("parseEvent: %v", err)
	}
	if _, present := ev.Fields["hmac_signature"]; present {
		t.Fatal("hmac_signature must be stripped from Fields")
	}
	var action string
	if err := json.Unmarshal(ev.Fields["action"], &action); err != nil || action != "read" {
		t.Fatalf("action field not decoded: %q err=%v", action, err)
	}
	if string(ev.Raw) != string(body) {
		t.Fatal("Raw must preserve the original body bytes")
	}
}

// TestParseEvent_NonObjectIsError covers parseEvent's decode-error branch: a
// body that is valid JSON but not an object (here, an array) fails to unmarshal
// into the field map. This is the defensive path the consumer treats as a
// verified-but-unparseable message.
func TestParseEvent_NonObjectIsError(t *testing.T) {
	if _, err := parseEvent([]byte(`["not","an","object"]`)); err == nil {
		t.Fatal("expected parseEvent to reject a non-object JSON body")
	}
	if _, err := parseEvent([]byte(`not json at all`)); err == nil {
		t.Fatal("expected parseEvent to reject a non-JSON body")
	}
}
