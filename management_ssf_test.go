package axiam

// The ssf management namespace — CONTRACT.md §32.8's six management tests.
// (The receiver helper's are in ssf_receiver_test.go.)

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func ssfStreamsPath() string { return "/api/v1/tenants/" + tenantID.String() + "/ssf/streams" }

func ssfStreamBody(extra map[string]any) map[string]any {
	revoked := string(SsfEventTypeSessionRevoked)
	body := map[string]any{
		"id": uuid.New(), "tenant_id": tenantID, "receiver_client_id": "rp-1",
		"audience": "https://rp.example", "description": nil, "delivery_method": "push",
		"endpoint_url": "https://rp.example/ssf", "authorization_header_set": true,
		"events_allowed": []string{revoked}, "events_requested": []string{revoked},
		"events_delivered": []string{revoked}, "subject_format": "iss_sub", "status": "enabled",
		"status_reason": nil, "status_actor": "admin", "last_verification_at": nil,
		"created_at": "2026-10-04T00:00:00Z", "updated_at": "2026-10-04T00:00:00Z",
		"transmitter_active": true,
	}
	for k, v := range extra {
		body[k] = v
	}
	return body
}

func ssfInput(header string) SsfStreamInput {
	body := NewSsfStreamInput("https://rp.example", SsfDeliveryMethodPush,
		[]SsfEventType{SsfEventTypeSessionRevoked}, "rp-1")
	body.Description = ptr("the RP")
	body.EndpointURL = ptr("https://rp.example/ssf")
	if header != "" {
		h := Sensitive(header)
		body.AuthorizationHeader = &h
	}
	return body
}

// ── 1. Replacement ──────────────────────────────────────────────────────────

func TestSsfStreams_UpdateStreamPutsEveryMemberItModels(t *testing.T) {
	srv, c := managementServer(t)
	id := uuid.New()
	route := srv.mount(http.MethodPut, ssfStreamsPath()+"/"+id.String(), 200, mustJSON(t, ssfStreamBody(nil)))
	body := ssfInput("")
	body.EventsRequested = []SsfEventType{SsfEventTypeSessionRevoked}
	body.SubjectFormat = ptr(SsfSubjectFormatIssSub)
	body.Status = ptr(SsfStreamStatusEnabled)
	body.StatusReason = ptr("ok")
	body.ClearAuthorizationHeader = ptr(false)
	stream, err := c.Ssf().UpdateStream(context.Background(), id, body)
	if err != nil {
		t.Fatalf("200: %v", err)
	}
	if !stream.TransmitterActive {
		t.Fatal("decoded")
	}
	sent := route.last(t).jsonBody(t)
	for _, member := range []string{"receiver_client_id", "audience", "delivery_method", "events_allowed",
		"description", "endpoint_url", "events_requested", "subject_format", "status", "status_reason",
		"clear_authorization_header"} {
		if _, ok := sent[member]; !ok {
			t.Fatalf("%s not sent", member)
		}
	}
	if !reflect.DeepEqual(sent["events_allowed"], []any{string(SsfEventTypeSessionRevoked)}) {
		t.Fatal("event types travel as their URIs")
	}
	if _, ok := sent["authorization_header"]; ok {
		t.Fatal("absent keeps the stored header, so it is not sent")
	}
	// The four required members are NewSsfStreamInput's arguments.
}

// ── 2. The header is Sensitive ──────────────────────────────────────────────

func TestSsfStreams_ThePushHeaderIsSentAndNeverRenderedOrDecoded(t *testing.T) {
	srv, c := managementServer(t)
	header := "Bearer " + randomSecret(t, "push-")
	body := ssfInput(header)
	assertNoFragmentIn(t, body, header, "SsfStreamInput")
	route := srv.mount(http.MethodPost, ssfStreamsPath(), 201,
		mustJSON(t, ssfStreamBody(map[string]any{"authorization_header": header})))
	created, err := c.Ssf().CreateStream(context.Background(), body)
	if err != nil {
		t.Fatalf("201: %v", err)
	}
	if route.last(t).jsonBody(t)["authorization_header"] != header {
		t.Fatal("the header must be on the wire")
	}
	assertNoFragmentIn(t, created, header, "SsfStream")
	if _, has := reflect.TypeOf(created).FieldByName("AuthorizationHeader"); has {
		t.Fatal("SsfStream must declare no header member")
	}
	if !created.AuthorizationHeaderSet {
		t.Fatal("authorization_header_set decodes")
	}
}

// ── 3. Open decoding ────────────────────────────────────────────────────────

func TestSsfStreams_UnknownValuesAndBothTransmitterStatesDecode(t *testing.T) {
	var odd SsfStream
	if err := json.Unmarshal([]byte(mustJSON(t, ssfStreamBody(map[string]any{
		"status": "quarantined", "delivery_method": "websocket", "subject_format": "opaque",
		"status_actor": "policy", "events_allowed": []string{"https://example.test/event-type/new"},
	}))), &odd); err != nil {
		t.Fatalf("decodes: %v", err)
	}
	if odd.Status != "quarantined" || odd.DeliveryMethod != "websocket" || odd.SubjectFormat != "opaque" ||
		odd.StatusActor != "policy" || odd.EventsAllowed[0] != "https://example.test/event-type/new" {
		t.Fatalf("unknown values decode verbatim: %+v", odd)
	}
	var inactive, active SsfStream
	_ = json.Unmarshal([]byte(mustJSON(t, ssfStreamBody(map[string]any{"transmitter_active": false,
		"transmitter_inactive_reason": "per-tenant issuers are off in a multi-tenant deployment"}))), &inactive)
	_ = json.Unmarshal([]byte(mustJSON(t, ssfStreamBody(nil))), &active)
	if inactive.TransmitterActive || inactive.TransmitterInactiveReason == nil || active.TransmitterInactiveReason != nil {
		t.Fatal("both transmitter states decode")
	}
}

// ── 4. Pagination ───────────────────────────────────────────────────────────

func TestSsfStreams_ListStreamsPagesAndTheWalkCarriesSearch(t *testing.T) {
	srv, c := managementServer(t)
	var queries []string
	srv.mountFunc(http.MethodGet, ssfStreamsPath(), func(w http.ResponseWriter, r *http.Request) {
		queries = append(queries, r.URL.RawQuery)
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		items := []any{}
		if offset < 2 {
			items = append(items, ssfStreamBody(nil))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, mustJSON(t, map[string]any{"items": items, "total": 2, "offset": offset, "limit": 1}))
	})
	ctx := context.Background()
	page, err := c.Ssf().ListStreams(ctx, Matching(1, "rp.example"))
	if err != nil || page.Total != 2 {
		t.Fatalf("page: %v", err)
	}
	all, err := c.Ssf().ListStreamsAll(ctx, Matching(1, "rp.example"))
	if err != nil || len(all) != 2 {
		t.Fatalf("walk: %v", err)
	}
	for _, q := range queries {
		if !strings.Contains(q, "search=rp.example") {
			t.Fatalf("every page carries search: %q", q)
		}
	}
}

// ── 5. No retry ─────────────────────────────────────────────────────────────

func TestSsfStreams_NoneOfTheThreeWritesIsRetriedOn503(t *testing.T) {
	srv, c := managementServer(t)
	id := uuid.New()
	routes := []*mountedRoute{
		srv.mount(http.MethodPost, ssfStreamsPath(), 503, ""),
		srv.mount(http.MethodPut, ssfStreamsPath()+"/"+id.String(), 503, ""),
		srv.mount(http.MethodDelete, ssfStreamsPath()+"/"+id.String(), 503, ""),
	}
	ctx := context.Background()
	_, e1 := c.Ssf().CreateStream(ctx, ssfInput("Bearer "+randomSecret(t, "push-")))
	_, e2 := c.Ssf().UpdateStream(ctx, id, ssfInput(""))
	e3 := c.Ssf().DeleteStream(ctx, id)
	for i, err := range []error{e1, e2, e3} {
		var netErr *NetworkError
		if !errors.As(err, &netErr) {
			t.Fatalf("write %d: want NetworkError, got %T", i, err)
		}
	}
	for i, r := range routes {
		if r.calls() != 1 {
			t.Fatalf("write %d: exactly one request, got %d", i, r.calls())
		}
	}
}

// ── 6. Errors ───────────────────────────────────────────────────────────────

func TestSsfStreams_StatusesMapPerSection2(t *testing.T) {
	srv, c := managementServer(t)
	id := uuid.New()
	srv.mount(http.MethodPut, ssfStreamsPath()+"/"+id.String(), 400, `{"error":"validation_error","message":"endpoint_url: must be https"}`)
	srv.mount(http.MethodPost, ssfStreamsPath(), 409, `{"error":"conflict","message":"audience"}`)
	srv.mount(http.MethodGet, ssfStreamsPath()+"/"+id.String(), 404, `{"error":"not_found","message":"no"}`)
	srv.mount(http.MethodDelete, ssfStreamsPath()+"/"+id.String(), 401, `{"error":"unauthorized","message":"human only"}`)
	ctx := context.Background()
	_, err := c.Ssf().UpdateStream(ctx, id, ssfInput(""))
	var verr *ValidationError
	if !errors.As(err, &verr) || !strings.Contains(verr.Message, "https") {
		t.Fatalf("400: %T", err)
	}
	if _, err := c.Ssf().CreateStream(ctx, ssfInput("")); !errors.Is(err, ErrConflict) {
		t.Fatalf("409: %T", err)
	}
	if _, err := c.Ssf().GetStream(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("404: %T", err)
	}
	var authErr *AuthError
	if err := c.Ssf().DeleteStream(ctx, id); !errors.As(err, &authErr) {
		t.Fatalf("401: %T", err)
	}
}

func TestSsfStreams_AReadConvertsIntoTheReplacementBodyWithoutTheHeader(t *testing.T) {
	var stream SsfStream
	if err := json.Unmarshal([]byte(mustJSON(t, ssfStreamBody(nil))), &stream); err != nil {
		t.Fatal(err)
	}
	body := stream.ToInput()
	if body.AuthorizationHeader != nil || body.ClearAuthorizationHeader != nil {
		t.Fatal("absent keeps the stored header")
	}
	if !reflect.DeepEqual(body.EventsRequested, stream.EventsRequested) || *body.Status != SsfStreamStatusEnabled ||
		*body.SubjectFormat != SsfSubjectFormatIssSub || body.ReceiverClientID != "rp-1" {
		t.Fatalf("every member carried over: %+v", body)
	}
}
