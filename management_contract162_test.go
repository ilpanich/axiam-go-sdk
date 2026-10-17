package axiam

// Contract 1.62 (CONTRACT.md §34.6): the `network` namespace's five required
// tests (§36.8), the change-taking SSF form (§32.8 test 7), the request
// user_id as an untyped string (§27.11 rule 5, item (i)), and the rows of
// item (f)/(g) that already held in this SDK and are pinned here so they stay
// held.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// ── fixtures ────────────────────────────────────────────────────────────────

var (
	segmentID  = uuid.MustParse("44444444-4444-4444-8444-444444444441")
	segmentID2 = uuid.MustParse("44444444-4444-4444-8444-444444444442")
	actorID    = uuid.MustParse("55555555-5555-4555-8555-555555555555")
)

func segmentBody(id uuid.UUID, over map[string]any) map[string]any {
	body := map[string]any{
		"id": id, "tenant_id": tenantID, "path": "/network/zones/default/iot", "name": "iot",
		"site_key": "default", "kind": "access", "vlan_id": 20, "filter_ids": []string{"iot-acl"},
		"rank": 10, "enabled": true, "version": 3, "created_by": actorID, "updated_by": actorID,
		"created_at": "2026-10-16T00:00:00Z", "updated_at": "2026-10-16T00:00:00Z",
	}
	for k, v := range over {
		if v == nil {
			delete(body, k)
		} else {
			body[k] = v
		}
	}
	return body
}

func profileBody(segment uuid.UUID, over map[string]any) map[string]any {
	body := map[string]any{
		"segment_id": segment, "tenant_id": tenantID, "dictionary": "axiam-radius-reply/1",
		"session_timeout_secs": 900, "session_timeout_clamped": false,
		"termination_action": "radius_request", "idle_timeout_secs": 600, "filter_id": "iot-acl",
		"service_type": "framed_user", "version": 2, "created_by": actorID, "updated_by": actorID,
		"created_at": "2026-10-16T00:00:00Z", "updated_at": "2026-10-16T00:00:00Z",
	}
	for k, v := range over {
		if v == nil {
			delete(body, k)
		} else {
			body[k] = v
		}
	}
	return body
}

func policyBody(maxSecs, version int) map[string]any {
	return map[string]any{
		"tenant_id": tenantID, "session_timeout_max_secs": maxSecs, "version": version,
	}
}

func pageOf(items ...any) string {
	b, _ := json.Marshal(map[string]any{"items": items, "total": len(items), "offset": 0, "limit": 200})
	return string(b)
}

func jsonOf(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func sortedKeysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ── §36.8 test 1: the surface ───────────────────────────────────────────────

// The twelve operations exist with the paths and methods of §36.1, and no
// method reaches POST /api/v1/network/decide.
func TestNetwork_TheTwelveOperationsAreOnTheHandleAndTheDecisionRouteIsNot(t *testing.T) {
	srv, c := managementServer(t)
	ctx := context.Background()
	seg, prof := segmentID.String(), segmentID.String()
	mounts := map[string]*mountedRoute{
		"list_segments":  srv.mount(http.MethodGet, "/api/v1/network/segments", 200, pageOf()),
		"create_segment": srv.mount(http.MethodPost, "/api/v1/network/segments", 201, jsonOf(t, segmentBody(segmentID, nil))),
		"get_segment":    srv.mount(http.MethodGet, "/api/v1/network/segments/"+seg, 200, jsonOf(t, segmentBody(segmentID, nil))),
		"replace_segment": srv.mount(http.MethodPut, "/api/v1/network/segments/"+seg, 200,
			jsonOf(t, segmentBody(segmentID, nil))),
		"delete_segment": srv.mount(http.MethodDelete, "/api/v1/network/segments/"+seg, 204, ""),
		"list_profiles":  srv.mount(http.MethodGet, "/api/v1/network/profiles", 200, pageOf()),
		"create_profile": srv.mount(http.MethodPost, "/api/v1/network/profiles", 201, jsonOf(t, profileBody(segmentID, nil))),
		"get_profile":    srv.mount(http.MethodGet, "/api/v1/network/profiles/"+prof, 200, jsonOf(t, profileBody(segmentID, nil))),
		"replace_profile": srv.mount(http.MethodPut, "/api/v1/network/profiles/"+prof, 200,
			jsonOf(t, profileBody(segmentID, nil))),
		"delete_profile": srv.mount(http.MethodDelete, "/api/v1/network/profiles/"+prof, 204, ""),
		"get_policy":     srv.mount(http.MethodGet, "/api/v1/network/policy", 200, jsonOf(t, policyBody(3600, 0))),
		"replace_policy": srv.mount(http.MethodPut, "/api/v1/network/policy", 200, jsonOf(t, policyBody(1800, 1))),
	}
	n := c.Network()
	profileInput := NetworkReplyProfileInput{SessionTimeoutSecs: 900}
	calls := map[string]func() error{
		"list_segments": func() error { _, err := n.ListSegments(ctx, "", Limited(10)); return err },
		"create_segment": func() error {
			_, err := n.CreateSegment(ctx, CreateNetworkSegmentRequest{
				Kind: NetworkSegmentKindAccess, SiteKey: "default", Name: "iot", VlanID: 20, Rank: ptr(10)})
			return err
		},
		"get_segment": func() error { _, err := n.GetSegment(ctx, segmentID); return err },
		"replace_segment": func() error {
			_, err := n.ReplaceSegment(ctx, segmentID, NewReplaceNetworkSegmentRequest(true, []string{}, 3, 20))
			return err
		},
		"delete_segment": func() error { return n.DeleteSegment(ctx, segmentID, 3) },
		"list_profiles":  func() error { _, err := n.ListProfiles(ctx, Limited(10)); return err },
		"create_profile": func() error {
			_, err := n.CreateProfile(ctx, CreateNetworkReplyProfileRequest{
				SegmentID: segmentID, SegmentVersion: 3, Profile: profileInput})
			return err
		},
		"get_profile": func() error { _, err := n.GetProfile(ctx, segmentID); return err },
		"replace_profile": func() error {
			_, err := n.ReplaceProfile(ctx, segmentID, NewReplaceNetworkReplyProfileRequest(profileInput, 3, 2))
			return err
		},
		"delete_profile": func() error { return n.DeleteProfile(ctx, segmentID, 2) },
		"get_policy":     func() error { _, err := n.GetPolicy(ctx); return err },
		"replace_policy": func() error { _, err := n.ReplacePolicy(ctx, NewReplaceNetworkPolicyRequest(1800, 0)); return err },
	}
	if len(calls) != 12 {
		t.Fatalf("want the twelve operations, have %d", len(calls))
	}
	for name, call := range calls {
		if err := call(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if mounts[name].calls() != 1 {
			t.Fatalf("%s: %d requests", name, mounts[name].calls())
		}
	}

	// The decision route is excluded by name; nothing on the handle reaches it,
	// and the generator would have to be edited to put it there.
	typ := reflect.TypeOf(n)
	for i := 0; i < typ.NumMethod(); i++ {
		if strings.Contains(strings.ToLower(typ.Method(i).Name), "decide") ||
			strings.Contains(strings.ToLower(typ.Method(i).Name), "decision") {
			t.Fatalf("NetworkAPI.%s reaches the decision route", typ.Method(i).Name)
		}
	}
	for _, op := range expectedSurface(t) {
		if strings.Contains(op, "decide") {
			t.Fatalf("the registry carries %s: the decision route is not SDK work (§36.11)", op)
		}
	}
	raw, err := os.ReadFile("management-registry.json")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "POST /api/v1/network/decide") {
		t.Fatal("the registry must exclude POST /api/v1/network/decide by name")
	}
	for _, f := range []string{"management_network.go"} {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(src), "network/decide") {
			t.Fatalf("%s reaches the decision route", f)
		}
	}
}

// ── §36.8 test 2: versions ──────────────────────────────────────────────────

func TestNetwork_EveryWriteSendsTheVersionItWasGivenExactlyAndAConflictIsOneRequest(t *testing.T) {
	srv, c := managementServer(t)
	ctx := context.Background()
	n := c.Network()
	seg := "/api/v1/network/segments/" + segmentID.String()
	prof := "/api/v1/network/profiles/" + segmentID.String()
	profileInput := NetworkReplyProfileInput{SessionTimeoutSecs: 900}

	ok := map[string]*mountedRoute{
		"replace_segment": srv.mount(http.MethodPut, seg, 200, jsonOf(t, segmentBody(segmentID, nil))),
		"delete_segment":  srv.mount(http.MethodDelete, seg, 204, ""),
		"create_profile":  srv.mount(http.MethodPost, "/api/v1/network/profiles", 201, jsonOf(t, profileBody(segmentID, nil))),
		"replace_profile": srv.mount(http.MethodPut, prof, 200, jsonOf(t, profileBody(segmentID, nil))),
		"delete_profile":  srv.mount(http.MethodDelete, prof, 204, ""),
		"replace_policy":  srv.mount(http.MethodPut, "/api/v1/network/policy", 200, jsonOf(t, policyBody(1800, 8))),
	}
	if _, err := n.ReplaceSegment(ctx, segmentID, NewReplaceNetworkSegmentRequest(true, []string{"a"}, 17, 20)); err != nil {
		t.Fatal(err)
	}
	if err := n.DeleteSegment(ctx, segmentID, 18); err != nil {
		t.Fatal(err)
	}
	if _, err := n.CreateProfile(ctx, CreateNetworkReplyProfileRequest{
		SegmentID: segmentID, SegmentVersion: 19, Profile: profileInput}); err != nil {
		t.Fatal(err)
	}
	if _, err := n.ReplaceProfile(ctx, segmentID, NewReplaceNetworkReplyProfileRequest(profileInput, 20, 21)); err != nil {
		t.Fatal(err)
	}
	if err := n.DeleteProfile(ctx, segmentID, 22); err != nil {
		t.Fatal(err)
	}
	if _, err := n.ReplacePolicy(ctx, NewReplaceNetworkPolicyRequest(1800, 0)); err != nil {
		t.Fatal(err)
	}

	if got := ok["replace_segment"].last(t).jsonBody(t)["version"]; got != float64(17) {
		t.Fatalf("replace_segment version = %v", got)
	}
	if got := ok["delete_segment"].last(t).query.Get("version"); got != "18" {
		t.Fatalf("delete_segment ?version= %q", got)
	}
	cp := ok["create_profile"].last(t).jsonBody(t)
	if cp["segment_version"] != float64(19) || cp["segment_id"] != segmentID.String() {
		t.Fatalf("create_profile body %v", cp)
	}
	rp := ok["replace_profile"].last(t).jsonBody(t)
	if rp["version"] != float64(21) || rp["segment_version"] != float64(20) {
		t.Fatalf("replace_profile body %v", rp)
	}
	if got := ok["delete_profile"].last(t).query.Get("version"); got != "22" {
		t.Fatalf("delete_profile ?version= %q", got)
	}
	// A tenant that has never written a policy sends version 0, and 0 is sent.
	if got, present := ok["replace_policy"].last(t).jsonBody(t)["version"]; !present || got != float64(0) {
		t.Fatalf("replace_policy version = %v (present %v)", got, present)
	}

	// Each write meets a 409 once: ConflictError after exactly one request,
	// exposing the body's reason_code.
	stale := `{"error":"conflict","message":"the row changed","reason_code":"stale_version"}`
	dup := `{"error":"already_exists","message":"vlan","reason_code":"duplicate_vlan"}`
	srv2, c2 := managementServer(t)
	conflicts := map[string]*mountedRoute{
		"replace_segment": srv2.mount(http.MethodPut, seg, 409, stale),
		"delete_segment":  srv2.mount(http.MethodDelete, seg, 409, stale),
		"create_profile":  srv2.mount(http.MethodPost, "/api/v1/network/profiles", 409, stale),
		"replace_profile": srv2.mount(http.MethodPut, prof, 409, stale),
		"delete_profile":  srv2.mount(http.MethodDelete, prof, 409, stale),
		"replace_policy":  srv2.mount(http.MethodPut, "/api/v1/network/policy", 409, stale),
		"create_segment":  srv2.mount(http.MethodPost, "/api/v1/network/segments", 409, dup),
	}
	n2 := c2.Network()
	errs := map[string]error{}
	_, errs["replace_segment"] = n2.ReplaceSegment(ctx, segmentID, NewReplaceNetworkSegmentRequest(true, []string{}, 1, 20))
	errs["delete_segment"] = n2.DeleteSegment(ctx, segmentID, 1)
	_, errs["create_profile"] = n2.CreateProfile(ctx, CreateNetworkReplyProfileRequest{SegmentID: segmentID, SegmentVersion: 1, Profile: profileInput})
	_, errs["replace_profile"] = n2.ReplaceProfile(ctx, segmentID, NewReplaceNetworkReplyProfileRequest(profileInput, 1, 1))
	errs["delete_profile"] = n2.DeleteProfile(ctx, segmentID, 1)
	_, errs["replace_policy"] = n2.ReplacePolicy(ctx, NewReplaceNetworkPolicyRequest(1800, 1))
	_, errs["create_segment"] = n2.CreateSegment(ctx, CreateNetworkSegmentRequest{
		Kind: NetworkSegmentKindAccess, SiteKey: "default", Name: "iot", VlanID: 20, Rank: ptr(1)})
	for name, err := range errs {
		var conflict *ConflictError
		if !errors.As(err, &conflict) || !errors.Is(err, ErrConflict) {
			t.Fatalf("%s: want ConflictError, got %T %v", name, err, err)
		}
		want := "stale_version"
		if name == "create_segment" {
			want = "duplicate_vlan"
		}
		if conflict.ReasonCode != want {
			t.Fatalf("%s: ReasonCode = %q, want %q", name, conflict.ReasonCode, want)
		}
		if conflicts[name].calls() != 1 {
			t.Fatalf("%s: a 409 is one request, got %d", name, conflicts[name].calls())
		}
	}

	// An unknown reason_code is surfaced verbatim (the vocabulary is open); a
	// 409 without one has none.
	srv3, c3 := managementServer(t)
	srv3.mount(http.MethodPut, "/api/v1/network/policy", 409, `{"error":"conflict","message":"x","reason_code":"brand_new"}`)
	_, err := c3.Network().ReplacePolicy(ctx, NewReplaceNetworkPolicyRequest(1800, 1))
	var conflict *ConflictError
	if !errors.As(err, &conflict) || conflict.ReasonCode != "brand_new" {
		t.Fatalf("open vocabulary: %v", err)
	}
	srv3.mount(http.MethodPut, "/api/v1/network/policy", 409, `{"error":"conflict","message":"x"}`)
	_, err = c3.Network().ReplacePolicy(ctx, NewReplaceNetworkPolicyRequest(1800, 1))
	if !errors.As(err, &conflict) || conflict.ReasonCode != "" {
		t.Fatalf("absent reason_code: %v", err)
	}
}

// ── §36.8 test 3: closed bodies ─────────────────────────────────────────────

func TestNetwork_RequestBodiesCarryExactlyTheKeysSection36Names(t *testing.T) {
	keysOf := func(v any) []string {
		t.Helper()
		var m map[string]any
		if err := json.Unmarshal([]byte(jsonOf(t, v)), &m); err != nil {
			t.Fatal(err)
		}
		return sortedKeysOf(m)
	}
	eq := func(name string, got []string, want ...string) {
		t.Helper()
		sort.Strings(want)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s keys = %v, want %v", name, got, want)
		}
	}

	// An unset rank, idle_timeout_secs, filter_id or service_type is absent, not null.
	eq("CreateNetworkSegmentRequest (quarantine)",
		keysOf(CreateNetworkSegmentRequest{Kind: NetworkSegmentKindQuarantine, SiteKey: "default", Name: "q", VlanID: 99}),
		"kind", "site_key", "name", "vlan_id")
	eq("CreateNetworkSegmentRequest (access, all set)",
		keysOf(CreateNetworkSegmentRequest{Kind: NetworkSegmentKindAccess, SiteKey: "default", Name: "a", VlanID: 20,
			FilterIDs: []string{"x"}, Rank: ptr(1), Enabled: ptr(false)}),
		"kind", "site_key", "name", "vlan_id", "filter_ids", "rank", "enabled")
	eq("ReplaceNetworkSegmentRequest",
		keysOf(NewReplaceNetworkSegmentRequest(true, []string{"x"}, 3, 20)),
		"version", "vlan_id", "filter_ids", "enabled")
	eq("CreateNetworkReplyProfileRequest",
		keysOf(CreateNetworkReplyProfileRequest{SegmentID: segmentID, SegmentVersion: 1,
			Profile: NetworkReplyProfileInput{SessionTimeoutSecs: 900}}),
		"segment_id", "segment_version", "profile")
	eq("ReplaceNetworkReplyProfileRequest",
		keysOf(NewReplaceNetworkReplyProfileRequest(NetworkReplyProfileInput{SessionTimeoutSecs: 900}, 1, 2)),
		"version", "segment_version", "profile")
	eq("ReplaceNetworkPolicyRequest", keysOf(NewReplaceNetworkPolicyRequest(1800, 0)),
		"session_timeout_max_secs", "version")

	// The profile input has no VLAN member, and an unset optional is absent.
	eq("NetworkReplyProfileInput (unset)", keysOf(NetworkReplyProfileInput{SessionTimeoutSecs: 900}),
		"session_timeout_secs")
	for _, forbidden := range []string{"vlan", "vlan_id"} {
		if _, has := reflect.TypeOf(NetworkReplyProfileInput{}).FieldByName(strings.ToUpper(forbidden[:1]) + forbidden[1:]); has {
			t.Fatalf("NetworkReplyProfileInput must have no %s member", forbidden)
		}
	}
	eq("NetworkReplyProfileInput (set)", keysOf(NetworkReplyProfileInput{
		SessionTimeoutSecs: 900, Dictionary: ptr("axiam-radius-reply/1"), TerminationAction: ptr(RadiusTerminationActionDefault),
		IdleTimeoutSecs: ptr(60), FilterID: ptr("x"), ServiceType: ptr(RadiusServiceTypeFramedUser)}),
		"session_timeout_secs", "dictionary", "termination_action", "idle_timeout_secs", "filter_id", "service_type")

	// The replace types cannot be built without their required members: a
	// constructor names every one as an argument (Go cannot make a keyed literal
	// refuse an omitted field, so the constructor is the guarantee).
	for name, fn := range map[string]any{
		"NewReplaceNetworkSegmentRequest":      NewReplaceNetworkSegmentRequest,
		"NewReplaceNetworkReplyProfileRequest": NewReplaceNetworkReplyProfileRequest,
		"NewReplaceNetworkPolicyRequest":       NewReplaceNetworkPolicyRequest,
	} {
		typ := reflect.TypeOf(fn)
		var want int
		switch name {
		case "NewReplaceNetworkSegmentRequest":
			want = 4 // enabled, filterIDs, version, vlanID
		case "NewReplaceNetworkReplyProfileRequest":
			want = 3 // profile, segmentVersion, version
		default:
			want = 2 // sessionTimeoutMaxSecs, version
		}
		if typ.NumIn() != want {
			t.Fatalf("%s takes %d arguments, want %d", name, typ.NumIn(), want)
		}
	}
}

// ── §36.8 test 4: open decoding and pagination ──────────────────────────────

func TestNetwork_UnknownEnumerationsDecodeAndTheListsPageWithSearchAndSite(t *testing.T) {
	var seg NetworkSegmentResponse
	if err := json.Unmarshal([]byte(jsonOf(t, segmentBody(segmentID, map[string]any{"kind": "overflow"}))), &seg); err != nil {
		t.Fatalf("unknown kind: %v", err)
	}
	if seg.Kind != "overflow" {
		t.Fatalf("kind decodes verbatim: %q", seg.Kind)
	}
	var prof NetworkReplyProfile
	if err := json.Unmarshal([]byte(jsonOf(t, profileBody(segmentID, map[string]any{
		"termination_action": "radius_new", "service_type": "administrative_user",
		"session_timeout_clamped": true, "session_timeout_secs": 3600}))), &prof); err != nil {
		t.Fatalf("unknown termination_action and service_type: %v", err)
	}
	if prof.TerminationAction != "radius_new" || prof.ServiceType == nil || *prof.ServiceType != "administrative_user" ||
		!prof.SessionTimeoutClamped || prof.SessionTimeoutSecs != 3600 {
		t.Fatalf("decoded %+v", prof)
	}

	srv, c := managementServer(t)
	var segQueries, profQueries []string
	srv.mountFunc(http.MethodGet, "/api/v1/network/segments", func(w http.ResponseWriter, r *http.Request) {
		segQueries = append(segQueries, r.URL.RawQuery)
		w.Header().Set("Content-Type", "application/json")
		offset := r.URL.Query().Get("offset")
		items := []any{}
		if offset == "" || offset == "0" {
			items = append(items, segmentBody(segmentID, nil))
		}
		_, _ = w.Write([]byte(jsonOf(t, map[string]any{"items": items, "total": 2, "offset": 0, "limit": 1})))
	})
	srv.mountFunc(http.MethodGet, "/api/v1/network/profiles", func(w http.ResponseWriter, r *http.Request) {
		profQueries = append(profQueries, r.URL.RawQuery)
		w.Header().Set("Content-Type", "application/json")
		offset := r.URL.Query().Get("offset")
		items := []any{}
		if offset == "" || offset == "0" {
			items = append(items, profileBody(segmentID, nil))
		}
		_, _ = w.Write([]byte(jsonOf(t, map[string]any{"items": items, "total": 2, "offset": 0, "limit": 1})))
	})
	ctx := context.Background()
	page, err := c.Network().ListSegments(ctx, "hq", Matching(1, "iot"))
	if err != nil || page.Total != 2 {
		t.Fatalf("segments page: %v %v", err, page.Total)
	}
	if _, err := c.Network().ListSegmentsAll(ctx, "hq", Matching(1, "iot")); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Network().ListProfilesAll(ctx, Matching(1, "acl")); err != nil {
		t.Fatal(err)
	}
	for _, q := range segQueries {
		if !strings.Contains(q, "search=iot") || !strings.Contains(q, "site=hq") {
			t.Fatalf("every segment request carries search and site: %q", q)
		}
	}
	for _, q := range profQueries {
		if !strings.Contains(q, "search=acl") {
			t.Fatalf("every profile request carries search: %q", q)
		}
	}
	if len(segQueries) < 2 || len(profQueries) < 1 {
		t.Fatalf("the walks issued %d and %d requests", len(segQueries), len(profQueries))
	}
}

// ── §36.8 test 5: errors ────────────────────────────────────────────────────

func TestNetwork_StatusesMapPerSection2AndTheWritesAreNotRetried(t *testing.T) {
	srv, c := managementServer(t)
	ctx := context.Background()
	n := c.Network()
	prof := "/api/v1/network/profiles/" + segmentID.String()
	srv.mount(http.MethodPut, "/api/v1/network/policy", 403,
		`{"error":"authorization_denied","message":"no","action":"network:grant","resource_id":"`+segmentID.String()+`"}`)
	srv.mount(http.MethodPost, "/api/v1/network/segments", 400, `{"error":"validation_error","message":"vlan_id: out of range"}`)
	srv.mount(http.MethodGet, prof, 404, `{"error":"not_found","message":"no"}`)
	srv.mount(http.MethodGet, "/api/v1/network/policy", 401, `{"error":"unauthorized","message":"human only"}`)

	_, err := n.ReplacePolicy(ctx, NewReplaceNetworkPolicyRequest(1800, 0))
	var authz *AuthzError
	if !errors.As(err, &authz) || authz.Action != "network:grant" || authz.ResourceID != segmentID.String() {
		t.Fatalf("403: %T %v", err, err)
	}
	_, err = n.CreateSegment(ctx, CreateNetworkSegmentRequest{Kind: NetworkSegmentKindAccess, SiteKey: "d", Name: "x", VlanID: 9999})
	var verr *ValidationError
	if !errors.As(err, &verr) || !strings.Contains(verr.Message, "out of range") {
		t.Fatalf("400: %T %v", err, err)
	}
	if _, err := n.GetProfile(ctx, segmentID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("404: %T %v", err, err)
	}
	var authErr *AuthError
	if _, err := n.GetPolicy(ctx); !errors.As(err, &authErr) {
		t.Fatalf("401: %T %v", err, err)
	}

	// 429 and 503 on each of the seven writes: NetworkError after one request.
	for _, status := range []int{429, 503} {
		srv2, c2 := managementServer(t)
		n2 := c2.Network()
		seg := "/api/v1/network/segments/" + segmentID.String()
		p := "/api/v1/network/profiles/" + segmentID.String()
		routes := []*mountedRoute{
			srv2.mount(http.MethodPost, "/api/v1/network/segments", status, ""),
			srv2.mount(http.MethodPut, seg, status, ""),
			srv2.mount(http.MethodDelete, seg, status, ""),
			srv2.mount(http.MethodPost, "/api/v1/network/profiles", status, ""),
			srv2.mount(http.MethodPut, p, status, ""),
			srv2.mount(http.MethodDelete, p, status, ""),
			srv2.mount(http.MethodPut, "/api/v1/network/policy", status, ""),
		}
		pi := NetworkReplyProfileInput{SessionTimeoutSecs: 900}
		_, e0 := n2.CreateSegment(ctx, CreateNetworkSegmentRequest{Kind: NetworkSegmentKindAccess, SiteKey: "d", Name: "x", VlanID: 9, Rank: ptr(1)})
		_, e1 := n2.ReplaceSegment(ctx, segmentID, NewReplaceNetworkSegmentRequest(true, []string{}, 1, 9))
		e2 := n2.DeleteSegment(ctx, segmentID, 1)
		_, e3 := n2.CreateProfile(ctx, CreateNetworkReplyProfileRequest{SegmentID: segmentID, SegmentVersion: 1, Profile: pi})
		_, e4 := n2.ReplaceProfile(ctx, segmentID, NewReplaceNetworkReplyProfileRequest(pi, 1, 1))
		e5 := n2.DeleteProfile(ctx, segmentID, 1)
		_, e6 := n2.ReplacePolicy(ctx, NewReplaceNetworkPolicyRequest(1800, 1))
		for i, e := range []error{e0, e1, e2, e3, e4, e5, e6} {
			var netErr *NetworkError
			if !errors.As(e, &netErr) {
				t.Fatalf("%d on write %d: want NetworkError, got %T %v", status, i, e, e)
			}
			if routes[i].calls() != 1 {
				t.Fatalf("%d on write %d: exactly one request, got %d", status, i, routes[i].calls())
			}
		}
	}
}

// ── item (i): the request user_id is an untyped string ──────────────────────

func TestContract162_AMalformedRequestUserIDReachesTheServerAndItsBadRequestIsSurfaced(t *testing.T) {
	srv, c := managementServer(t)
	ctx := context.Background()
	generate := srv.mount(http.MethodPost, "/api/v1/certificates", 400,
		`{"error":"validation_error","message":"user_id: not a user of this tenant"}`)
	sign := srv.mount(http.MethodPost, "/api/v1/certificates/sign-csr", 400,
		`{"error":"validation_error","message":"user_id: not a user of this tenant"}`)

	// Not a UUID, and not even close: a UUID-typed member could not spell it.
	const malformed = "  not-a-uuid\t"
	_, genErr := c.Certificates().Generate(ctx, generateRequest(ptr(malformed)))
	_, signErr := c.Certificates().SignCSR(ctx, signRequest(ptr(malformed)))
	for name, err := range map[string]error{"generate": genErr, "sign_csr": signErr} {
		var verr *ValidationError
		if !errors.As(err, &verr) || !strings.Contains(verr.Message, "user_id") {
			t.Fatalf("%s: the server's 400 must be surfaced, got %T %v", name, err, err)
		}
	}
	for name, route := range map[string]*mountedRoute{"generate": generate, "sign_csr": sign} {
		if route.calls() != 1 {
			t.Fatalf("%s: the malformed value is judged by the server, not here (%d requests)", name, route.calls())
		}
		if got := route.last(t).jsonBody(t)["user_id"]; got != malformed {
			t.Fatalf("%s: user_id = %#v, want it exactly as given", name, got)
		}
	}

	// The request member is a string; the RESPONSE member stays typed.
	for _, typ := range []reflect.Type{reflect.TypeOf(CreateCertificateRequest{}), reflect.TypeOf(SignCertificateCSRRequest{})} {
		f, _ := typ.FieldByName("UserID")
		if f.Type != reflect.TypeOf((*string)(nil)) {
			t.Fatalf("%s.UserID is %v, want *string", typ.Name(), f.Type)
		}
	}
	f, _ := reflect.TypeOf(Certificate{}).FieldByName("UserID")
	if f.Type != reflect.TypeOf((*uuid.UUID)(nil)) {
		t.Fatalf("Certificate.UserID is %v, want *uuid.UUID", f.Type)
	}
}

// ── item (f): an assigned null is "none" ────────────────────────────────────

// A Go request member that can be unset is a pointer with omitempty, so an
// "assigned null" is the nil pointer and the key is omitted: null is never
// sent for user_id (both requests) or expected_updated_at (both updates).
func TestContract162_ANilUserIDAndANilExpectedUpdatedAtAreOmittedNeverNull(t *testing.T) {
	for name, v := range map[string]any{
		"CreateCertificateRequest":  generateRequest(nil),
		"SignCertificateCSRRequest": signRequest(nil),
		"SsfStreamInput":            ssfInput("").toWire(),
		"SCIMTargetInput": NewSCIMTargetInput(SCIMTargetAuth{Type: "bearer"}, "https://idp.example/scim/v2",
			"t", SCIMTargetScope{Type: "all_users"}).toWire(),
	} {
		raw := jsonOf(t, v)
		if strings.Contains(raw, "null") || strings.Contains(raw, "user_id") || strings.Contains(raw, "expected_updated_at") {
			t.Fatalf("%s sent a none member: %s", name, raw)
		}
	}
}
