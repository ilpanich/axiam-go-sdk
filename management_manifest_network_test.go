package axiam

// The `network` namespace in a manifest — CONTRACT.md §27.6.2 and the "Manifest,
// `network`" list of §27.9 (contract 1.62, items (n), (u), (v), (w)).

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
)

// netFake is a small stateful network service: a policy, segments and profiles
// with the version rules of §36.3 rule 2, behind the management test server.
type netFake struct {
	t        *testing.T
	srv      *managementTestServer
	mu       sync.Mutex
	policy   map[string]any
	segments map[uuid.UUID]map[string]any
	order    []uuid.UUID
	profiles map[uuid.UUID]map[string]any
	nextID   int
	// gate lets a test refuse a write: it returns a status and body, or 0.
	gate func(method, path string, body map[string]any) (int, string)
	log  []string
}

func newNetFake(t *testing.T, srv *managementTestServer) *netFake {
	f := &netFake{
		t: t, srv: srv,
		policy:   policyBody(3600, 0),
		segments: map[uuid.UUID]map[string]any{},
		profiles: map[uuid.UUID]map[string]any{},
	}
	mountEmptyTenant(srv)
	srv.mountFunc(http.MethodGet, "/api/v1/network/policy", f.handler(func(w http.ResponseWriter, r *http.Request, _ map[string]any) {
		f.reply(w, 200, f.policy)
	}))
	srv.mountFunc(http.MethodPut, "/api/v1/network/policy", f.handler(func(w http.ResponseWriter, r *http.Request, body map[string]any) {
		if body["version"] != float64(f.policy["version"].(int)) {
			f.conflict(w, "stale_version")
			return
		}
		f.policy["session_timeout_max_secs"] = body["session_timeout_max_secs"]
		f.policy["version"] = f.policy["version"].(int) + 1
		f.reply(w, 200, f.policy)
	}))
	srv.mountFunc(http.MethodGet, "/api/v1/network/segments", f.handler(func(w http.ResponseWriter, r *http.Request, _ map[string]any) {
		items := []any{}
		for _, id := range f.order {
			items = append(items, f.segments[id])
		}
		f.page(w, items)
	}))
	srv.mountFunc(http.MethodGet, "/api/v1/network/profiles", f.handler(func(w http.ResponseWriter, r *http.Request, _ map[string]any) {
		items := []any{}
		for _, id := range f.order {
			if p, ok := f.profiles[id]; ok {
				items = append(items, p)
			}
		}
		f.page(w, items)
	}))
	srv.mountFunc(http.MethodPost, "/api/v1/network/segments", f.handler(func(w http.ResponseWriter, r *http.Request, body map[string]any) {
		f.nextID++
		id := uuid.MustParse(fmt.Sprintf("44444444-4444-4444-8444-%012d", f.nextID))
		seg := segmentBody(id, map[string]any{
			"name": body["name"], "site_key": body["site_key"], "kind": body["kind"], "vlan_id": body["vlan_id"],
			"filter_ids": orEmpty(body["filter_ids"]), "rank": body["rank"], "version": 1,
			"enabled": body["enabled"] == nil || body["enabled"] == true,
		})
		f.segments[id] = seg
		f.order = append(f.order, id)
		srv.mountFunc(http.MethodPut, "/api/v1/network/segments/"+id.String(), f.handler(f.replaceSegment(id)))
		srv.mountFunc(http.MethodPut, "/api/v1/network/profiles/"+id.String(), f.handler(f.replaceProfile(id)))
		f.reply(w, 201, seg)
	}))
	srv.mountFunc(http.MethodPost, "/api/v1/network/profiles", f.handler(func(w http.ResponseWriter, r *http.Request, body map[string]any) {
		id := uuid.MustParse(body["segment_id"].(string))
		seg, ok := f.segments[id]
		if !ok {
			f.reply(w, 404, map[string]any{"error": "not_found", "message": "no segment"})
			return
		}
		if body["segment_version"] != float64(seg["version"].(int)) {
			f.conflict(w, "stale_version")
			return
		}
		if _, exists := f.profiles[id]; exists {
			f.reply(w, 409, map[string]any{"error": "already_exists", "message": "x", "reason_code": "profile_exists"})
			return
		}
		f.profiles[id] = f.profileFrom(id, 1, body["profile"].(map[string]any))
		f.reply(w, 201, f.profiles[id])
	}))
	return f
}

func orEmpty(v any) any {
	if v == nil {
		return []any{}
	}
	return v
}

// seedSegment puts a segment on the server as if an administrator had made it.
func (f *netFake) seedSegment(over map[string]any) uuid.UUID {
	f.nextID++
	id := uuid.MustParse(fmt.Sprintf("44444444-4444-4444-8444-%012d", f.nextID))
	over["id"] = id
	f.segments[id] = segmentBody(id, over)
	f.order = append(f.order, id)
	f.srv.mountFunc(http.MethodPut, "/api/v1/network/segments/"+id.String(), f.handler(f.replaceSegment(id)))
	f.srv.mountFunc(http.MethodPut, "/api/v1/network/profiles/"+id.String(), f.handler(f.replaceProfile(id)))
	return id
}

func (f *netFake) seedProfile(id uuid.UUID, over map[string]any) {
	f.profiles[id] = profileBody(id, over)
}

func (f *netFake) profileFrom(id uuid.UUID, version int, in map[string]any) map[string]any {
	over := map[string]any{"version": version, "segment_id": id}
	for _, k := range []string{"session_timeout_secs", "termination_action", "idle_timeout_secs", "filter_id", "service_type", "dictionary"} {
		over[k] = in[k] // nil deletes the key
	}
	if over["termination_action"] == nil {
		over["termination_action"] = "radius_request"
	}
	if over["dictionary"] == nil {
		over["dictionary"] = "axiam-radius-reply/1"
	}
	return profileBody(id, over)
}

func (f *netFake) replaceSegment(id uuid.UUID) func(http.ResponseWriter, *http.Request, map[string]any) {
	return func(w http.ResponseWriter, r *http.Request, body map[string]any) {
		seg := f.segments[id]
		if body["version"] != float64(seg["version"].(int)) {
			f.conflict(w, "stale_version")
			return
		}
		seg["vlan_id"], seg["filter_ids"], seg["enabled"] = body["vlan_id"], body["filter_ids"], body["enabled"]
		if body["rank"] == nil {
			delete(seg, "rank")
		} else {
			seg["rank"] = body["rank"]
		}
		seg["version"] = seg["version"].(int) + 1
		f.reply(w, 200, seg)
	}
}

func (f *netFake) replaceProfile(id uuid.UUID) func(http.ResponseWriter, *http.Request, map[string]any) {
	return func(w http.ResponseWriter, r *http.Request, body map[string]any) {
		p, ok := f.profiles[id]
		if !ok {
			f.reply(w, 404, map[string]any{"error": "not_found", "message": "no profile"})
			return
		}
		if body["version"] != float64(p["version"].(int)) || body["segment_version"] != float64(f.segments[id]["version"].(int)) {
			f.conflict(w, "stale_version")
			return
		}
		f.profiles[id] = f.profileFrom(id, p["version"].(int)+1, body["profile"].(map[string]any))
		f.reply(w, 200, f.profiles[id])
	}
}

func (f *netFake) handler(h func(http.ResponseWriter, *http.Request, map[string]any)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		body := map[string]any{}
		if r.Method != http.MethodGet {
			// serve() has already drained the request body into the route's record.
			route := f.srv.routes[routeKey(r.Method, r.URL.Path)]
			_ = json.Unmarshal(route.requests[len(route.requests)-1].body, &body)
		}
		f.log = append(f.log, r.Method+" "+r.URL.Path)
		if f.gate != nil {
			if status, payload := f.gate(r.Method, r.URL.Path, body); status != 0 {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(status)
				_, _ = w.Write([]byte(payload))
				return
			}
		}
		h(w, r, body)
	}
}

func (f *netFake) reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (f *netFake) conflict(w http.ResponseWriter, reason string) {
	f.reply(w, 409, map[string]any{"error": "conflict", "message": "the row changed", "reason_code": reason})
}

func (f *netFake) page(w http.ResponseWriter, items []any) {
	f.reply(w, 200, map[string]any{"items": items, "total": len(items), "offset": 0, "limit": 200})
}

// writes lists the non-GET requests the fake saw, in order.
func (f *netFake) writes() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, l := range f.log {
		if !strings.HasPrefix(l, "GET ") {
			out = append(out, l)
		}
	}
	return out
}

func accessSegment(key, name string, vlan, rank int) NetworkSegmentSpec {
	return NetworkSegmentSpec{
		Key: key, Site: "default", Kind: NetworkSegmentKindAccess, Name: name, VlanID: vlan,
		Rank: ValueOf(rank), FilterIDs: []string{"iot-acl"},
	}
}

func networkManifest() ManagementManifest {
	return ManagementManifest{Network: NetworkSpec{
		Policy:   &NetworkPolicySpec{SessionTimeoutMaxSecs: 1800},
		Segments: []NetworkSegmentSpec{accessSegment("iot", "iot", 20, 10)},
		Profiles: []NetworkProfileSpec{{Segment: "iot", SessionTimeoutSecs: 900, FilterID: ValueOf("iot-acl")}},
	}}
}

func changeTargets(p ManagementPlan) []string {
	var out []string
	for _, a := range p.Actions {
		if a.Change != ChangeNone {
			out = append(out, string(a.Change)+" "+string(a.Target))
		}
	}
	return out
}

// plan issues GETs only (rule 1) and reads exactly get_policy, list_segments and
// list_profiles for the network section.
func TestManifestNetwork_PlanIssuesOnlyTheThreeGETsAndNoOtherMethod(t *testing.T) {
	srv, c := managementServer(t)
	f := newNetFake(t, srv)

	plan, err := c.Manifest().Plan(context.Background(), networkManifest())
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if got := changeTargets(plan); strings.Join(got, ",") != "update network-policy,create network-segment,create network-profile" {
		t.Fatalf("order must be policy, segments, profiles: %v", got)
	}
	if w := f.writes(); len(w) != 0 {
		t.Fatalf("plan wrote: %v", w)
	}
	seen := map[string]int{}
	for _, l := range f.log {
		seen[l]++
	}
	for _, want := range []string{"GET /api/v1/network/policy", "GET /api/v1/network/segments", "GET /api/v1/network/profiles"} {
		if seen[want] != 1 {
			t.Fatalf("%s issued %d times, want once (%v)", want, seen[want], f.log)
		}
	}
	if len(f.log) != 3 {
		t.Fatalf("plan made network requests beyond the three reads: %v", f.log)
	}
}

// A manifest without a network section makes no network request (rule 5:
// "appended last, so a manifest without a network section plans as before").
func TestManifestNetwork_AManifestWithoutANetworkSectionMakesNoNetworkRequest(t *testing.T) {
	srv, c := managementServer(t)
	f := newNetFake(t, srv)
	if _, err := c.Manifest().Plan(context.Background(), sampleManifest(t)); err != nil {
		t.Fatal(err)
	}
	if len(f.log) != 0 {
		t.Fatalf("network requests for a manifest with no network section: %v", f.log)
	}
}

// On an empty tenant, apply creates the segment and then the profile, the
// profile carries the new segment's id and the create response's version as
// segment_version, and a second plan is all NoChange (rule 6).
func TestManifestNetwork_ApplyCreatesTheSegmentThenTheProfileAndConverges(t *testing.T) {
	srv, c := managementServer(t)
	f := newNetFake(t, srv)
	ctx := context.Background()
	m := networkManifest()

	report, err := c.Manifest().Apply(ctx, m)
	if err != nil || !report.IsComplete() {
		t.Fatalf("apply: %v %+v", err, report)
	}
	want := []string{"PUT /api/v1/network/policy", "POST /api/v1/network/segments", "POST /api/v1/network/profiles"}
	if got := f.writes(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("writes = %v, want %v", got, want)
	}
	post := srv.routes[routeKey(http.MethodPost, "/api/v1/network/profiles")].last(t).jsonBody(t)
	segID := f.order[0]
	if post["segment_id"] != segID.String() || post["segment_version"] != float64(1) {
		t.Fatalf("create_profile body = %v, want the new segment's id and the create response's version", post)
	}
	if put := srv.routes[routeKey(http.MethodPut, "/api/v1/network/policy")].last(t).jsonBody(t); put["version"] != float64(0) {
		t.Fatalf("the first policy write names version 0: %v", put)
	}

	again, err := c.Manifest().Plan(ctx, m)
	if err != nil {
		t.Fatal(err)
	}
	if !again.IsConverged() {
		t.Fatalf("rule 6: apply then plan must be all NoChange, got %v", changeTargets(again))
	}
}

// A segment Update sends the FULL replacement body: version as read, the
// stated members, every unstated one carried from the read, and no kind,
// site_key or name (the exact key set). A stated null on an optional profile
// member leaves the key out.
func TestManifestNetwork_AnUpdateSendsTheFullBodyBuiltFromTheReadWithoutKindSiteOrName(t *testing.T) {
	srv, c := managementServer(t)
	f := newNetFake(t, srv)
	id := f.seedSegment(map[string]any{"name": "iot", "vlan_id": 20, "version": 5, "filter_ids": []string{"iot-acl", "cam-acl"}, "enabled": false})
	f.seedProfile(id, map[string]any{"version": 4, "session_timeout_secs": 900, "idle_timeout_secs": 600,
		"filter_id": "iot-acl", "service_type": "framed_user"})

	m := ManagementManifest{Network: NetworkSpec{
		Segments: []NetworkSegmentSpec{{Key: "iot", Site: "default", Kind: NetworkSegmentKindAccess, Name: "iot", VlanID: 21}},
		Profiles: []NetworkProfileSpec{{Segment: "iot", SessionTimeoutSecs: 900, IdleTimeoutSecs: NullOf[int](),
			TerminationAction: ptr(RadiusTerminationActionDefault)}},
	}}
	report, err := c.Manifest().Apply(context.Background(), m)
	if err != nil || !report.IsComplete() {
		t.Fatalf("apply: %v %+v", err, report)
	}

	seg := srv.routes[routeKey(http.MethodPut, "/api/v1/network/segments/"+id.String())].last(t).jsonBody(t)
	if got := sortedKeysOf(seg); strings.Join(got, ",") != "enabled,filter_ids,rank,version,vlan_id" {
		t.Fatalf("segment replacement keys = %v", got)
	}
	if seg["version"] != float64(5) || seg["vlan_id"] != float64(21) || seg["rank"] != float64(10) || seg["enabled"] != false ||
		fmt.Sprint(seg["filter_ids"]) != "[iot-acl cam-acl]" {
		t.Fatalf("stated members replace, unstated ones are carried from the read: %v", seg)
	}

	prof := srv.routes[routeKey(http.MethodPut, "/api/v1/network/profiles/"+id.String())].last(t).jsonBody(t)
	// The segment write moved the segment to version 6; the profile carries that.
	if prof["version"] != float64(4) || prof["segment_version"] != float64(6) {
		t.Fatalf("profile versions = %v, want 4 and the replace_segment response's 6", prof)
	}
	in := prof["profile"].(map[string]any)
	if _, has := in["idle_timeout_secs"]; has {
		t.Fatalf("a stated null is left out of the body: %v", in)
	}
	if got := sortedKeysOf(in); strings.Join(got, ",") != "dictionary,filter_id,service_type,session_timeout_secs,termination_action" {
		t.Fatalf("profile keys = %v", got)
	}
	if in["filter_id"] != "iot-acl" || in["service_type"] != "framed_user" || in["termination_action"] != "default" {
		t.Fatalf("unstated members are carried from the read: %v", in)
	}
}

// A manifest that changes a segment and its profile in one apply sends
// replace_segment and then replace_profile, and the profile's segment_version is
// the replace_segment response's version, not the one plan read.
func TestManifestNetwork_AProfileFollowsItsChangedSegmentWithTheNewSegmentVersion(t *testing.T) {
	srv, c := managementServer(t)
	f := newNetFake(t, srv)
	id := f.seedSegment(map[string]any{"name": "iot", "vlan_id": 20, "version": 7})
	f.seedProfile(id, map[string]any{"version": 2})

	m := ManagementManifest{Network: NetworkSpec{
		Segments: []NetworkSegmentSpec{{Key: "iot", Site: "default", Kind: NetworkSegmentKindAccess, Name: "iot", VlanID: 33}},
		Profiles: []NetworkProfileSpec{{Segment: "iot", SessionTimeoutSecs: 1200}},
	}}
	if report, err := c.Manifest().Apply(context.Background(), m); err != nil || !report.IsComplete() {
		t.Fatalf("apply: %v %+v", err, report)
	}
	want := []string{"PUT /api/v1/network/segments/" + id.String(), "PUT /api/v1/network/profiles/" + id.String()}
	if got := f.writes(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("writes = %v", got)
	}
	prof := srv.routes[routeKey(http.MethodPut, "/api/v1/network/profiles/"+id.String())].last(t).jsonBody(t)
	if prof["segment_version"] != float64(8) {
		t.Fatalf("segment_version = %v, want 8 (the replace_segment response), not the 7 plan read", prof["segment_version"])
	}
}

// A 409 on any network write makes exactly one request, stops the apply (later
// actions are not attempted), and the outcome exposes reason_code.
func TestManifestNetwork_AConflictIsOneRequestStopsTheApplyAndExposesReasonCode(t *testing.T) {
	for _, tc := range []struct {
		name, status, error, reason string
	}{
		{"stale_version", "409", "conflict", "stale_version"},
		{"duplicate_vlan", "409", "already_exists", "duplicate_vlan"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, c := managementServer(t)
			f := newNetFake(t, srv)
			f.gate = func(method, path string, _ map[string]any) (int, string) {
				if method == http.MethodPost && path == "/api/v1/network/segments" {
					return 409, `{"error":"` + tc.error + `","message":"refused","reason_code":"` + tc.reason + `"}`
				}
				return 0, ""
			}
			report, err := c.Manifest().Apply(context.Background(), networkManifest())
			if err != nil {
				t.Fatal(err)
			}
			failure, failed := report.Failure()
			if !failed || failure.Action.Target != TargetNetworkSegment || failure.ReasonCode != tc.reason {
				t.Fatalf("failure = %+v (failed %v)", failure, failed)
			}
			if report.IsComplete() {
				t.Fatal("a conflict fails the apply")
			}
			// Exactly one segment write; the profile after it is not attempted.
			segWrites, profWrites := 0, 0
			for _, w := range f.writes() {
				if strings.Contains(w, "/network/segments") {
					segWrites++
				}
				if strings.Contains(w, "/network/profiles") {
					profWrites++
				}
			}
			if segWrites != 1 || profWrites != 0 {
				t.Fatalf("segment writes %d, profile writes %d: %v", segWrites, profWrites, f.writes())
			}
			last := report.Steps[len(report.Steps)-1]
			if last.Action.Target != TargetNetworkProfile || last.Outcome.Status != StatusNotAttempted {
				t.Fatalf("the profile is not attempted: %+v", last)
			}
			// The outcome's message names the conflict as the error does.
			if report.Steps[1].Outcome.ReasonCode != tc.reason {
				t.Fatalf("the failed step exposes reason_code: %+v", report.Steps[1])
			}
		})
	}
}

// This SDK has no pruning for any namespace, so an apply never deletes: a
// segment and a profile the manifest does not state are left alone, and the
// policy is never deleted (§27.6.2 item 6's default).
func TestManifestNetwork_ApplyNeverDeletesWhatTheManifestDoesNotState(t *testing.T) {
	srv, c := managementServer(t)
	f := newNetFake(t, srv)
	other := f.seedSegment(map[string]any{"name": "other", "vlan_id": 30, "rank": 20})
	f.seedProfile(other, nil)
	f.seedSegment(map[string]any{"name": "iot", "vlan_id": 20})

	m := ManagementManifest{Network: NetworkSpec{
		Segments: []NetworkSegmentSpec{{Key: "iot", Site: "default", Kind: NetworkSegmentKindAccess, Name: "iot", VlanID: 20}},
	}}
	if _, err := c.Manifest().Apply(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	for _, w := range f.writes() {
		if strings.HasPrefix(w, "DELETE") {
			t.Fatalf("apply deleted: %v", f.writes())
		}
	}
}

// Two segments with one site, kind and name, and a profile whose segment names
// no segment spec, are each refused with zero wire calls — as is a profile
// declared twice for one segment, and a duplicate segment key.
func TestManifestNetwork_AmbiguousAndDanglingSpecsAreRefusedWithZeroWireCalls(t *testing.T) {
	cases := map[string]NetworkSpec{
		"one natural key twice": {Segments: []NetworkSegmentSpec{accessSegment("a", "iot", 20, 1), accessSegment("b", "iot", 21, 2)}},
		"dangling profile": {Segments: []NetworkSegmentSpec{accessSegment("a", "iot", 20, 1)},
			Profiles: []NetworkProfileSpec{{Segment: "nope", SessionTimeoutSecs: 900}}},
		"two profiles for one segment": {Segments: []NetworkSegmentSpec{accessSegment("a", "iot", 20, 1)},
			Profiles: []NetworkProfileSpec{{Segment: "a", SessionTimeoutSecs: 900}, {Segment: "a", SessionTimeoutSecs: 600}}},
		"one segment key twice": {Segments: []NetworkSegmentSpec{accessSegment("a", "iot", 20, 1), accessSegment("a", "cam", 21, 2)}},
	}
	for name, spec := range cases {
		t.Run(name, func(t *testing.T) {
			srv, c := managementServer(t)
			newNetFake(t, srv)
			before := srv.totalCalls()
			m := ManagementManifest{Network: spec}
			if _, err := c.Manifest().Plan(context.Background(), m); err == nil {
				t.Fatal("plan must refuse")
			}
			if _, err := c.Manifest().Apply(context.Background(), m); err == nil {
				t.Fatal("apply must refuse")
			}
			if srv.totalCalls() != before {
				t.Fatalf("a refusal makes zero wire calls, made %d", srv.totalCalls()-before)
			}
		})
	}
	// The same kind and name on another site, and another kind on the same
	// site, are different keys.
	ok := NetworkSpec{Segments: []NetworkSegmentSpec{
		accessSegment("a", "iot", 20, 1),
		{Key: "b", Site: "branch", Kind: NetworkSegmentKindAccess, Name: "iot", VlanID: 20, Rank: ValueOf(1)},
		{Key: "c", Site: "default", Kind: NetworkSegmentKindQuarantine, Name: "iot", VlanID: 99},
	}}
	if problems := validateNetwork(ok); len(problems) != 0 {
		t.Fatalf("distinct natural keys: %v", problems)
	}
}

// A segment's kind is the wire spelling: a segment stated as "access" is
// NoChange against a read that says "access", and its create_segment body
// carries "kind": "access"; the SDK has no zones value.
func TestManifestNetwork_KindIsTheWireSpellingInTheKeyAndInTheBody(t *testing.T) {
	srv, c := managementServer(t)
	f := newNetFake(t, srv)
	f.seedSegment(map[string]any{"name": "iot", "vlan_id": 20, "kind": "access", "rank": 10, "filter_ids": []string{"iot-acl"}})
	m := ManagementManifest{Network: NetworkSpec{Segments: []NetworkSegmentSpec{accessSegment("iot", "iot", 20, 10)}}}
	plan, err := c.Manifest().Plan(context.Background(), m)
	if err != nil || !plan.IsConverged() {
		t.Fatalf("a segment read as \"access\" and stated as \"access\" is NoChange: %v %v", err, changeTargets(plan))
	}

	// "zones" is a server-side path segment, not a kind: it names no segment.
	zones := m
	zones.Network.Segments = []NetworkSegmentSpec{{Key: "z", Site: "default", Kind: NetworkSegmentKind("zones"), Name: "iot", VlanID: 20}}
	plan, err = c.Manifest().Plan(context.Background(), zones)
	if err != nil || len(plan.Changes()) != 1 || plan.Changes()[0].Change != ChangeCreate {
		t.Fatalf("the SDK maps nothing to or from zones: %v %v", err, changeTargets(plan))
	}

	// A create body carries the string.
	srv2, c2 := managementServer(t)
	newNetFake(t, srv2)
	if _, err := c2.Manifest().Apply(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	if got := srv2.routes[routeKey(http.MethodPost, "/api/v1/network/segments")].last(t).jsonBody(t)["kind"]; got != "access" {
		t.Fatalf("create body kind = %v", got)
	}
}

// filter_ids is a SET: the read's names in another order are NoChange and apply
// writes nothing for it; an Update caused by another member sends the array in
// the order the manifest states; a Create does the same.
func TestManifestNetwork_FilterIDsCompareAsASetAndAreSentInTheStatedOrder(t *testing.T) {
	srv, c := managementServer(t)
	f := newNetFake(t, srv)
	id := f.seedSegment(map[string]any{"name": "iot", "vlan_id": 20, "filter_ids": []string{"a", "b", "c"}, "rank": 10})

	reordered := ManagementManifest{Network: NetworkSpec{Segments: []NetworkSegmentSpec{{
		Key: "iot", Site: "default", Kind: NetworkSegmentKindAccess, Name: "iot", VlanID: 20,
		Rank: ValueOf(10), FilterIDs: []string{"c", "a", "b"}}}}}
	report, err := c.Manifest().Apply(context.Background(), reordered)
	if err != nil || !report.IsComplete() || report.ChangedCount() != 0 || len(f.writes()) != 0 {
		t.Fatalf("a reorder alone is NoChange and writes nothing: %v %v %v", err, report.ChangedCount(), f.writes())
	}

	// Another member differs: the array goes out in the stated order.
	reordered.Network.Segments[0].VlanID = 21
	if _, err := c.Manifest().Apply(context.Background(), reordered); err != nil {
		t.Fatal(err)
	}
	body := srv.routes[routeKey(http.MethodPut, "/api/v1/network/segments/"+id.String())].last(t).jsonBody(t)
	if fmt.Sprint(body["filter_ids"]) != "[c a b]" {
		t.Fatalf("update filter_ids order = %v, want the manifest's [c a b]", body["filter_ids"])
	}

	// A member the manifest does not state carries the read's order.
	f2srv, c2 := managementServer(t)
	f2 := newNetFake(t, f2srv)
	id2 := f2.seedSegment(map[string]any{"name": "iot", "vlan_id": 20, "filter_ids": []string{"z", "y"}, "rank": 10})
	silent := ManagementManifest{Network: NetworkSpec{Segments: []NetworkSegmentSpec{{
		Key: "iot", Site: "default", Kind: NetworkSegmentKindAccess, Name: "iot", VlanID: 22}}}}
	if _, err := c2.Manifest().Apply(context.Background(), silent); err != nil {
		t.Fatal(err)
	}
	body = f2srv.routes[routeKey(http.MethodPut, "/api/v1/network/segments/"+id2.String())].last(t).jsonBody(t)
	if fmt.Sprint(body["filter_ids"]) != "[z y]" {
		t.Fatalf("unstated filter_ids carry the read's order: %v", body["filter_ids"])
	}

	// A create does the same as an update.
	srv3, c3 := managementServer(t)
	newNetFake(t, srv3)
	create := ManagementManifest{Network: NetworkSpec{Segments: []NetworkSegmentSpec{{
		Key: "n", Site: "default", Kind: NetworkSegmentKindAccess, Name: "n", VlanID: 40, Rank: ValueOf(3),
		FilterIDs: []string{"q", "p", "r"}}}}}
	if _, err := c3.Manifest().Apply(context.Background(), create); err != nil {
		t.Fatal(err)
	}
	if got := srv3.routes[routeKey(http.MethodPost, "/api/v1/network/segments")].last(t).jsonBody(t)["filter_ids"]; fmt.Sprint(got) != "[q p r]" {
		t.Fatalf("create filter_ids order = %v", got)
	}
}

// A segment that lists one Filter-Id twice is refused with zero wire calls, at
// plan and at apply.
func TestManifestNetwork_ADuplicateFilterIDIsRefusedAtPlanAndApplyWithZeroWireCalls(t *testing.T) {
	srv, c := managementServer(t)
	newNetFake(t, srv)
	before := srv.totalCalls()
	spec := accessSegment("iot", "iot", 20, 10)
	spec.FilterIDs = []string{"a", "b", "a"}
	m := ManagementManifest{Network: NetworkSpec{Segments: []NetworkSegmentSpec{spec}}}
	_, planErr := c.Manifest().Plan(context.Background(), m)
	_, applyErr := c.Manifest().Apply(context.Background(), m)
	if planErr == nil || applyErr == nil || !strings.Contains(planErr.Error(), "more than once") {
		t.Fatalf("both must refuse with the client-side error: %v / %v", planErr, applyErr)
	}
	var ne *NetworkError
	if !asNetworkError(planErr, &ne) {
		t.Fatalf("rule 2's client-side error: %T", planErr)
	}
	if srv.totalCalls() != before {
		t.Fatalf("zero wire calls, made %d", srv.totalCalls()-before)
	}
}

// A profile read with session_timeout_clamped: true and session_timeout_secs
// equal to the cap: a manifest stating that value is NoChange; a manifest
// stating a value above the cap is an Update in plan, and apply of it sends
// exactly one replace_profile, receives 403 authorization_denied, stops without
// a retry, later actions are not attempted, and the outcome carries the
// server's message.
func TestManifestNetwork_AClampedProfileIsJudgedOnTheReadAndTheCapRefusalIsTheActionsFailure(t *testing.T) {
	const capMsg = "session_timeout_secs is above the tenant's cap of 600"
	setup := func(t *testing.T) (*managementTestServer, *Client, *netFake, uuid.UUID) {
		srv, c := managementServer(t)
		f := newNetFake(t, srv)
		f.policy = policyBody(600, 4)
		id := f.seedSegment(map[string]any{"name": "iot", "vlan_id": 20, "rank": 10, "filter_ids": []string{"iot-acl"}})
		// Stored 900, lowered to the cap 600 at read.
		f.seedProfile(id, map[string]any{"session_timeout_secs": 600, "session_timeout_clamped": true,
			"idle_timeout_secs": 300, "filter_id": "iot-acl"})
		f.gate = func(method, path string, body map[string]any) (int, string) {
			if method == http.MethodPut && strings.Contains(path, "/network/profiles/") {
				if secs, _ := body["profile"].(map[string]any)["session_timeout_secs"].(float64); secs > 600 {
					return 403, `{"error":"authorization_denied","message":"` + capMsg + `"}`
				}
			}
			return 0, ""
		}
		return srv, c, f, id
	}
	manifest := func(secs int) ManagementManifest {
		return ManagementManifest{Network: NetworkSpec{
			Segments: []NetworkSegmentSpec{accessSegment("iot", "iot", 20, 10)},
			Profiles: []NetworkProfileSpec{{Segment: "iot", SessionTimeoutSecs: secs}},
			Policy:   &NetworkPolicySpec{SessionTimeoutMaxSecs: 600},
		}}
	}

	// Stating the cap is NoChange: the stored value is neither restored nor rewritten.
	_, c, f, _ := setup(t)
	report, err := c.Manifest().Apply(context.Background(), manifest(600))
	if err != nil || !report.IsComplete() || report.ChangedCount() != 0 || len(f.writes()) != 0 {
		t.Fatalf("the cap is NoChange: %v %v %v", err, report.ChangedCount(), f.writes())
	}

	// Stating a value above it differs from the read: plan shows an Update.
	srv, c, f, id := setup(t)
	plan, err := c.Manifest().Plan(context.Background(), manifest(900))
	if err != nil || strings.Join(changeTargets(plan), ",") != "update network-profile" {
		t.Fatalf("plan: %v %v", err, changeTargets(plan))
	}

	// Apply sends one replace_profile, the server refuses it, apply stops.
	later := manifest(900)
	// cam is a later segment with a later profile: the segment is written first
	// (segments precede profiles), and the profile after the failing one is not.
	later.Network.Segments = append(later.Network.Segments, accessSegment("cam", "cam", 21, 11))
	later.Network.Profiles = append(later.Network.Profiles, NetworkProfileSpec{Segment: "cam", SessionTimeoutSecs: 300})
	report, err = c.Manifest().Apply(context.Background(), later)
	if err != nil {
		t.Fatal(err)
	}
	failure, failed := report.Failure()
	if !failed || failure.Action.Target != TargetNetworkProfile || !strings.Contains(failure.Message, capMsg) {
		t.Fatalf("failure = %+v", failure)
	}
	profileWrites := 0
	for _, w := range f.writes() {
		if w == "PUT /api/v1/network/profiles/"+id.String() {
			profileWrites++
		}
		if w == "POST /api/v1/network/profiles" {
			t.Fatalf("a later action was attempted after the failure: %v", f.writes())
		}
	}
	if profileWrites != 1 {
		t.Fatalf("exactly one replace_profile, no retry; got %d (%v)", profileWrites, f.writes())
	}
	if sent := srv.routes[routeKey(http.MethodPut, "/api/v1/network/profiles/"+id.String())].last(t).jsonBody(t)["profile"].(map[string]any); sent["session_timeout_secs"] != float64(900) {
		t.Fatalf("the SDK sent %v: it must not lower the stated value to the cap", sent["session_timeout_secs"])
	}
}

// The policy is a singleton: it is never Create, a stated value equal to the
// read is NoChange, and an Update sends the policy's version exactly.
func TestManifestNetwork_ThePolicyIsNeverCreatedAndSendsItsVersionOnAnUpdate(t *testing.T) {
	srv, c := managementServer(t)
	f := newNetFake(t, srv)
	f.policy = policyBody(3600, 9)
	ctx := context.Background()

	same := ManagementManifest{Network: NetworkSpec{Policy: &NetworkPolicySpec{SessionTimeoutMaxSecs: 3600}}}
	plan, err := c.Manifest().Plan(ctx, same)
	if err != nil || !plan.IsConverged() || len(plan.Actions) != 1 || plan.Actions[0].Target != TargetNetworkPolicy {
		t.Fatalf("a stated value equal to the read is NoChange: %v %+v", err, plan)
	}
	lower := ManagementManifest{Network: NetworkSpec{Policy: &NetworkPolicySpec{SessionTimeoutMaxSecs: 1200}}}
	if _, err := c.Manifest().Apply(ctx, lower); err != nil {
		t.Fatal(err)
	}
	put := srv.routes[routeKey(http.MethodPut, "/api/v1/network/policy")].last(t).jsonBody(t)
	if put["version"] != float64(9) || put["session_timeout_max_secs"] != float64(1200) {
		t.Fatalf("replace_policy body = %v", put)
	}
	// Only the policy was read: no segment or profile list for a policy-only manifest.
	for _, l := range f.log {
		if strings.Contains(l, "/segments") || strings.Contains(l, "/profiles") {
			t.Fatalf("a policy-only manifest reads only the policy: %v", f.log)
		}
	}
}

// A 401 at the first network action (a service-account token) is the action's
// failure at plan time as an error, with nothing written.
func TestManifestNetwork_ANetworkReadRefusedWithAuth401FailsThePlanBeforeAnyWrite(t *testing.T) {
	srv, c := managementServer(t)
	f := newNetFake(t, srv)
	f.gate = func(method, path string, _ map[string]any) (int, string) {
		if strings.Contains(path, "/network/") {
			return 401, `{"error":"unauthorized","message":"human only"}`
		}
		return 0, ""
	}
	_, err := c.Manifest().Apply(context.Background(), networkManifest())
	var authErr *AuthError
	if !asAuthError(err, &authErr) {
		t.Fatalf("want AuthError, got %T %v", err, err)
	}
	if w := f.writes(); len(w) != 0 {
		t.Fatalf("wrote after a 401: %v", w)
	}
}

func asAuthError(err error, target **AuthError) bool {
	if e, ok := err.(*AuthError); ok {
		*target = e
		return true
	}
	return false
}
