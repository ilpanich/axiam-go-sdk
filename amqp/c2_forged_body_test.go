package amqp

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

// C2 (CONTRACT.md §8): only HMAC-covered values may reach the handler.
//
// verifyHMAC authenticates a canonical form rebuilt by decoding the body into
// a struct (case-insensitive key match, last key wins, unknown keys ignored)
// and re-marshalling it. A body carrying forged lower-case keys followed by
// the originally signed values under case-variant keys therefore verifies,
// while a case-sensitive map decode of the same body (the old parseEvent)
// hands the handler the forged values.

const (
	c2SignedSubject = "33333333-3333-3333-3333-333333333333"
	c2SignedTenant  = "22222222-2222-2222-2222-222222222222"
	c2ForgedSubject = "99999999-9999-9999-9999-999999999999"
	c2ForgedTenant  = "88888888-8888-8888-8888-888888888888"
	c2SignedAction  = "documents:read"
	c2ForgedAction  = "documents:delete"
	c2CorrelationID = "11111111-1111-1111-1111-111111111111"
	c2ResourceID    = "44444444-4444-4444-4444-444444444444"
)

// c2Fresh returns a fresh nonce and issued_at so the body passes the replay
// gate.
func c2Fresh() (nonce, issuedAt string) {
	return uuid.NewString(), time.Now().UTC().Format(time.RFC3339)
}

// c2Tail is the part of the body after the identity fields, shared by the
// signed canonical form and the forged variants.
func c2Tail(nonce, issuedAt string) string {
	return `"key_version":2,"nonce":"` + nonce + `","issued_at":"` + issuedAt + `"`
}

// c2Sign signs the server-order canonical form of the legitimate request.
func c2Sign(key []byte, nonce, issuedAt string) string {
	canonical := `{"correlation_id":"` + c2CorrelationID + `","tenant_id":"` + c2SignedTenant +
		`","subject_id":"` + c2SignedSubject + `","action":"` + c2SignedAction +
		`","resource_id":"` + c2ResourceID + `",` + c2Tail(nonce, issuedAt) + `}`
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(canonical))
	return hex.EncodeToString(mac.Sum(nil))
}

// c2Run dispatches body and reports the handler's call count, the Event it saw
// and the delivery's ack/nack counts.
func c2Run(t *testing.T, key, body []byte) (calls int32, seen Event, d *recordingDelivery) {
	t.Helper()
	d = newRecordingDelivery(body)
	handler := func(_ context.Context, e Event) error {
		atomic.AddInt32(&calls, 1)
		seen = e
		return nil
	}
	verifyAndDispatch(context.Background(), d, key, handler, &recordingLogger{}, newReplayGuard(defaultSkew))
	return calls, seen, d
}

func c2ExpectNacked(t *testing.T, calls int32, d *recordingDelivery) {
	t.Helper()
	if calls != 0 {
		t.Fatalf("handler must never be invoked, got %d call(s)", calls)
	}
	acked, nackRequeue, nackNoRequeue := d.counts()
	if acked != 0 || nackRequeue != 0 || nackNoRequeue != 1 {
		t.Fatalf("expected Nack(false) only, got acked=%d nackRequeue=%d nackNoRequeue=%d", acked, nackRequeue, nackNoRequeue)
	}
}

func c2Field(t *testing.T, e Event, name string) string {
	t.Helper()
	var s string
	if err := json.Unmarshal(e.Fields[name], &s); err != nil {
		t.Fatalf("field %q: %v (raw %s)", name, err, e.Fields[name])
	}
	return s
}

func TestVerifyAndDispatch_C2_ForgedCaseVariantBodyIsNackedAndHandlerNeverRuns(t *testing.T) {
	key := []byte(fixtureSigningKey)
	nonce, issuedAt := c2Fresh()
	sig := c2Sign(key, nonce, issuedAt)

	// Forged lower-case keys first, then the signed values under upper-case
	// keys: the struct decode (and so the HMAC) sees the signed values, a
	// case-sensitive map decode sees the forged ones.
	forged := []byte(`{"correlation_id":"` + c2CorrelationID + `",` +
		`"subject_id":"` + c2ForgedSubject + `","action":"` + c2ForgedAction + `","tenant_id":"` + c2ForgedTenant + `",` +
		`"SUBJECT_ID":"` + c2SignedSubject + `","ACTION":"` + c2SignedAction + `","TENANT_ID":"` + c2SignedTenant + `",` +
		`"resource_id":"` + c2ResourceID + `",` + c2Tail(nonce, issuedAt) + `,"hmac_signature":"` + sig + `"}`)

	calls, seen, d := c2Run(t, key, forged)
	if calls != 0 {
		t.Fatalf("forged body reached the handler: subject_id=%s action=%s tenant_id=%s",
			c2Field(t, seen, "subject_id"), c2Field(t, seen, "action"), c2Field(t, seen, "tenant_id"))
	}
	c2ExpectNacked(t, calls, d)
}

func TestVerifyAndDispatch_C2_ExactDuplicateKeysAreNacked(t *testing.T) {
	key := []byte(fixtureSigningKey)
	nonce, issuedAt := c2Fresh()
	sig := c2Sign(key, nonce, issuedAt)

	// The same key twice: the first (forged) value is what a first-wins
	// decoder sees, the second (signed) value is what the struct decode sees.
	dup := []byte(`{"correlation_id":"` + c2CorrelationID + `","tenant_id":"` + c2SignedTenant + `",` +
		`"subject_id":"` + c2ForgedSubject + `","subject_id":"` + c2SignedSubject + `",` +
		`"action":"` + c2SignedAction + `","resource_id":"` + c2ResourceID + `",` +
		c2Tail(nonce, issuedAt) + `,"hmac_signature":"` + sig + `"}`)

	calls, _, d := c2Run(t, key, dup)
	c2ExpectNacked(t, calls, d)
}

func TestVerifyAndDispatch_C2_PlainTamperControlStillNacks(t *testing.T) {
	key := []byte(fixtureSigningKey)
	nonce, issuedAt := c2Fresh()
	sig := c2Sign(key, nonce, issuedAt)

	tampered := []byte(`{"correlation_id":"` + c2CorrelationID + `","tenant_id":"` + c2SignedTenant + `",` +
		`"subject_id":"` + c2SignedSubject + `","action":"` + c2ForgedAction + `",` +
		`"resource_id":"` + c2ResourceID + `",` + c2Tail(nonce, issuedAt) + `,"hmac_signature":"` + sig + `"}`)

	calls, _, d := c2Run(t, key, tampered)
	c2ExpectNacked(t, calls, d)
}

func TestVerifyAndDispatch_C2_LegitimateMessageStillDispatchesSignedValues(t *testing.T) {
	key := []byte(fixtureSigningKey)
	nonce, issuedAt := c2Fresh()
	sig := c2Sign(key, nonce, issuedAt)

	legit := []byte(`{"correlation_id":"` + c2CorrelationID + `","tenant_id":"` + c2SignedTenant + `",` +
		`"subject_id":"` + c2SignedSubject + `","action":"` + c2SignedAction + `",` +
		`"resource_id":"` + c2ResourceID + `",` + c2Tail(nonce, issuedAt) + `,"hmac_signature":"` + sig + `"}`)

	calls, seen, d := c2Run(t, key, legit)
	if calls != 1 {
		t.Fatalf("a legitimate message must dispatch exactly once, got %d", calls)
	}
	if acked, nr, nn := d.counts(); acked != 1 || nr != 0 || nn != 0 {
		t.Fatalf("expected Ack, got acked=%d nackRequeue=%d nackNoRequeue=%d", acked, nr, nn)
	}
	if got := c2Field(t, seen, "subject_id"); got != c2SignedSubject {
		t.Fatalf("subject_id = %q", got)
	}
	if got := c2Field(t, seen, "action"); got != c2SignedAction {
		t.Fatalf("action = %q", got)
	}
	if got := c2Field(t, seen, "tenant_id"); got != c2SignedTenant {
		t.Fatalf("tenant_id = %q", got)
	}
	if _, present := seen.Fields["hmac_signature"]; present {
		t.Fatal("hmac_signature must not be in Fields")
	}
	if want := strings.TrimSuffix(string(legit), `,"hmac_signature":"`+sig+`"}`) + "}"; string(seen.Raw) != want {
		t.Fatalf("Event.Raw must be the received bytes minus the trailing signature\n got  %s\n want %s", seen.Raw, want)
	}
}

// A key the signature does not cover never reaches the handler. Since the
// HMAC is computed over the received bytes (server #882), such a body no
// longer verifies at all: it is nacked and the handler never runs. The test
// asserts that outcome unconditionally (GO-R1-7), so it cannot pass without
// running its assertions.
func TestVerifyAndDispatch_C2_UnsignedExtraKeyNeverReachesHandler(t *testing.T) {
	key := []byte(fixtureSigningKey)
	nonce, issuedAt := c2Fresh()
	sig := c2Sign(key, nonce, issuedAt)

	body := []byte(`{"correlation_id":"` + c2CorrelationID + `","tenant_id":"` + c2SignedTenant + `",` +
		`"subject_id":"` + c2SignedSubject + `","action":"` + c2SignedAction + `",` +
		`"resource_id":"` + c2ResourceID + `","is_admin":true,` + c2Tail(nonce, issuedAt) + `,"hmac_signature":"` + sig + `"}`)

	calls, seen, d := c2Run(t, key, body)
	if calls != 0 {
		t.Fatalf("a body carrying a member the signature does not cover reached the handler (is_admin present: %v)", seen.Fields["is_admin"] != nil)
	}
	c2ExpectNacked(t, calls, d)
}

func TestRejectAmbiguousKeys(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want bool
	}{
		{"plain object", `{"a":1,"b":{"x":1}}`, false},
		{"exact duplicate at top level", `{"a":1,"a":2}`, true},
		{"case-variant at top level", `{"action":"x","ACTION":"y"}`, true},
		{"duplicate in a nested object", `{"a":{"x":1,"x":2}}`, true},
		{"duplicate inside an array element", `{"a":[{"x":1,"x":2}]}`, true},
		{"case-variant keys in a nested object are data, not ambiguity", `{"metadata":{"User":1,"user":2}}`, false},
		{"trailing bytes after the object", `{"a":1} {"a":2}`, true},
		{"truncated", `{"a":1`, true},
		{"not an object is left to the caller", `["a"]`, false},
		{"long-s variant at top level (folds like encoding/json)", `{"subject_id":"x","ſubject_id":"y"}`, true},
		{"Kelvin-sign variant at top level (folds like encoding/json)", `{"key_version":2,"Key_version":2}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := rejectAmbiguousKeys([]byte(tc.body)); got != tc.want {
				t.Fatalf("rejectAmbiguousKeys(%s) = %v, want %v", tc.body, got, tc.want)
			}
		})
	}
}

// An AuditEventMessage whose `metadata` legitimately holds keys that differ
// only by case still verifies and dispatches, and the handler's Event is the
// canonical bytes.
func TestVerifyAndDispatch_C2_AuditMetadataCaseVariantKeysStillDispatch(t *testing.T) {
	key := []byte(fixtureSigningKey)
	nonce, issuedAt := c2Fresh()
	canonical := `{"tenant_id":"` + c2SignedTenant + `","actor_id":"` + c2SignedSubject + `","actor_type":"user",` +
		`"action":"login","outcome":"success","metadata":{"User":"a","user":"b"},` + c2Tail(nonce, issuedAt) + `}`
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(canonical))
	body := []byte(strings.TrimSuffix(canonical, "}") + `,"hmac_signature":"` + hex.EncodeToString(mac.Sum(nil)) + `"}`)

	calls, seen, _ := c2Run(t, key, body)
	if calls != 1 {
		t.Fatalf("a legitimate audit event must dispatch, got %d calls", calls)
	}
	if string(seen.Raw) != canonical {
		t.Fatalf("Event.Raw must be the canonical bytes\n got  %s\n want %s", seen.Raw, canonical)
	}
}
