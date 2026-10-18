package axiam

// Contract 1.62, items (e), (g) and (h) (CONTRACT.md §32.2, §32.8 test 7): the
// change-taking read-modify-write form for a stream, the response's own
// updated_at string, and the three meanings of events_requested at the
// UpdateStream call site.

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
)

// ── §32.8 test 7: the change-taking form ────────────────────────────────────

const (
	evA = SsfEventType("https://schemas.openid.net/secevent/caep/event-type/session-revoked")
	evB = SsfEventType("https://schemas.openid.net/secevent/caep/event-type/credential-change")
	evC = SsfEventType("https://schemas.openid.net/secevent/risc/event-type/account-disabled")
)

func readStream(t *testing.T, over map[string]any) SsfStream {
	t.Helper()
	body := ssfStreamBody(map[string]any{
		"events_allowed":   []string{string(evA), string(evB), string(evC)},
		"events_requested": []string{string(evA), string(evB)}, "events_delivered": []string{string(evA), string(evB)},
		// A spelling a re-render would change: +00:00 and nine fraction digits.
		"updated_at": "2026-10-04T08:15:30.123456789+00:00",
	})
	for k, v := range over {
		body[k] = v
	}
	var s SsfStream
	if err := json.Unmarshal([]byte(jsonOf(t, body)), &s); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSsfStreams_TheChangeTakingFormCutsEventsRequestedToALoweredCeiling(t *testing.T) {
	stream := readStream(t, nil)

	// Lowering events_allowed to one of the two requested: the requested list is
	// cut to what the new ceiling holds, in the read's order.
	body := stream.ToInputWith(SsfStreamChanges{EventsAllowed: []SsfEventType{evB}})
	if !reflect.DeepEqual(body.EventsAllowed, []SsfEventType{evB}) {
		t.Fatalf("events_allowed = %v", body.EventsAllowed)
	}
	if !reflect.DeepEqual(body.EventsRequested, []SsfEventType{evB}) {
		t.Fatalf("events_requested = %v, want only what is in the new ceiling", body.EventsRequested)
	}

	// A ceiling that holds none of the requested list: [] (the receiver's
	// "none"), never absent, which would reset the stream to every allowed event.
	body = stream.ToInputWith(SsfStreamChanges{EventsAllowed: []SsfEventType{evC}})
	if body.EventsRequested == nil || len(body.EventsRequested) != 0 {
		t.Fatalf("a cut to nothing is a non-nil empty list, got %#v", body.EventsRequested)
	}

	// Order is the read's, whatever order the ceiling is stated in.
	body = stream.ToInputWith(SsfStreamChanges{EventsAllowed: []SsfEventType{evC, evB, evA}})
	if !reflect.DeepEqual(body.EventsRequested, []SsfEventType{evA, evB}) {
		t.Fatalf("a ceiling that still holds both keeps them in the read's order, got %v", body.EventsRequested)
	}

	// An events_requested the caller names is sent as given: the server judges it.
	body = stream.ToInputWith(SsfStreamChanges{
		EventsAllowed: []SsfEventType{evB}, EventsRequested: []SsfEventType{evA, evC}})
	if !reflect.DeepEqual(body.EventsRequested, []SsfEventType{evA, evC}) {
		t.Fatalf("events_requested named in the changes is not cut: %v", body.EventsRequested)
	}
}

func TestSsfStreams_TheChangeTakingFormSendsEventsRequestedAndUpdatedAtAsRead(t *testing.T) {
	srv, c := managementServer(t)
	stream := readStream(t, nil)
	route := srv.mount(http.MethodPut, ssfStreamsPath()+"/"+stream.ID.String(), 200, mustJSON(t, ssfStreamBody(nil)))
	ctx := context.Background()

	// A change that is nothing about events: both go back as read, and
	// expected_updated_at comes back byte for byte.
	body := stream.ToInputWith(SsfStreamChanges{Description: ValueOf("renamed")})
	if _, err := c.Ssf().UpdateStream(ctx, stream.ID, body); err != nil {
		t.Fatal(err)
	}
	sent := route.last(t).jsonBody(t)
	if sent["expected_updated_at"] != "2026-10-04T08:15:30.123456789+00:00" {
		t.Fatalf("expected_updated_at = %v, want the response's own string", sent["expected_updated_at"])
	}
	if !reflect.DeepEqual(sent["events_requested"], []any{string(evA), string(evB)}) {
		t.Fatalf("events_requested = %v, want as read", sent["events_requested"])
	}
	if sent["description"] != "renamed" {
		t.Fatalf("the change is applied: %v", sent["description"])
	}
	if _, has := sent["authorization_header"]; has {
		t.Fatal("a read carries no header, so none is sent: absent keeps the stored one")
	}

	// A receiver's "none" goes back as [].
	none := readStream(t, map[string]any{"events_requested": []string{}, "events_delivered": []string{}})
	if _, err := c.Ssf().UpdateStream(ctx, stream.ID, none.ToInputWith(SsfStreamChanges{})); err != nil {
		t.Fatal(err)
	}
	if got, ok := route.last(t).jsonBody(t)["events_requested"].([]any); !ok || len(got) != 0 {
		t.Fatalf("an empty events_requested goes back as [], got %v", route.last(t).jsonBody(t)["events_requested"])
	}

	// An assigned null for expected_updated_at leaves the key out; null is never sent.
	nulled := stream.ToInputWith(SsfStreamChanges{ExpectedUpdatedAt: NullOf[string]()})
	if _, err := c.Ssf().UpdateStream(ctx, stream.ID, nulled); err != nil {
		t.Fatal(err)
	}
	raw := string(route.last(t).body)
	if strings.Contains(raw, "expected_updated_at") || strings.Contains(raw, "null") {
		t.Fatalf("a none expected_updated_at is omitted, never null: %s", raw)
	}

	// Cleared nullable members are left out too, and set ones replace.
	cleared := stream.ToInputWith(SsfStreamChanges{
		EndpointURL: NullOf[string](), StatusReason: ValueOf("maintenance"),
		Status: ptr(SsfStreamStatusPaused), ClearAuthorizationHeader: ptr(true)})
	if _, err := c.Ssf().UpdateStream(ctx, stream.ID, cleared); err != nil {
		t.Fatal(err)
	}
	sent = route.last(t).jsonBody(t)
	if _, has := sent["endpoint_url"]; has || sent["status_reason"] != "maintenance" ||
		sent["status"] != "paused" || sent["clear_authorization_header"] != true {
		t.Fatalf("changes applied: %v", sent)
	}
}

// The plain converter remains, it still sends the events_requested and the
// updated_at it read, and its documentation names the caller's duty.
func TestSsfStreams_ThePlainConverterRemainsAndItsDocNamesTheCallersDuty(t *testing.T) {
	stream := readStream(t, nil)
	body := stream.ToInput()
	if !reflect.DeepEqual(body.EventsRequested, []SsfEventType{evA, evB}) ||
		body.ExpectedUpdatedAt == nil || *body.ExpectedUpdatedAt != "2026-10-04T08:15:30.123456789+00:00" {
		t.Fatalf("ToInput: %+v", body)
	}
	src, err := os.ReadFile("management_checks.go")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(src)
	for _, want := range []string{"THE CALLER'S DUTY", "cut EventsRequested", "409", "resets the stream"} {
		if !strings.Contains(doc, want) {
			t.Fatalf("ToInput's documentation must name %q", want)
		}
	}
}

// §32.8 test 7, last sentence (a documentation check, not a mock): the
// UpdateStream documentation states the three meanings of events_requested.
func TestSsfStreams_TheUpdateStreamDocumentationStatesTheThreeMeanings(t *testing.T) {
	src, err := os.ReadFile("management_ssf.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	i := strings.Index(text, "// UpdateStream issues PUT")
	j := strings.Index(text, "func (a *SsfAPI) UpdateStream")
	if i < 0 || j < i {
		t.Fatal("UpdateStream's doc comment not found")
	}
	doc := strings.Join(strings.Fields(strings.ReplaceAll(text[i:j], "//", "")), " ")
	for _, want := range []string{
		"THE THREE MEANINGS OF EventsRequested",
		"RESETS the stream to every event of EventsAllowed",
		"sent as [] and is stored as the receiver's \"none\"",
		"refused (400) if any entry is outside EventsAllowed",
		"takes its default on every update",
		"left out of the PUT resets the stream",
	} {
		if !strings.Contains(doc, want) {
			t.Fatalf("UpdateStream's documentation lacks %q", want)
		}
	}
}

// (g): the stream's own updated_at string is what every converter sends.
func TestContract162_ExpectedUpdatedAtIsTheServersOwnStringNotARerenderedInstant(t *testing.T) {
	if f, _ := reflect.TypeOf(SsfStream{}).FieldByName("UpdatedAt"); f.Type.Kind() != reflect.String {
		t.Fatalf("SsfStream.UpdatedAt is %v: a typed date would force a re-render", f.Type)
	}
	if f, _ := reflect.TypeOf(SCIMTargetResponse{}).FieldByName("UpdatedAt"); f.Type.Kind() != reflect.String {
		t.Fatalf("SCIMTargetResponse.UpdatedAt is %v", f.Type)
	}
	const odd = "2026-10-04T08:15:30.100000000+00:00"
	if got := *readStream(t, map[string]any{"updated_at": odd}).ToInput().ExpectedUpdatedAt; got != odd {
		t.Fatalf("ToInput re-rendered the stamp: %q", got)
	}
}
