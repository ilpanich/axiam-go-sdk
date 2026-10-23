package axiam

// Contract 1.63 — §6.1 rule 11 / §12.1 rule 3 (no session cookie and no
// X-CSRF-Token on /oauth2/*, §14.6) and the C162-07 refusal (§27.6.2 item 4).

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

func TestOAuth2RequestsCarryNeitherSessionCookieNorCSRFHeader(t *testing.T) {
	srv := newOidcTestServer(t)
	type seen struct{ path, cookie, csrf string }
	var got []seen
	record := func(w http.ResponseWriter, r *http.Request) {
		got = append(got, seen{r.URL.Path, r.Header.Get("Cookie"), r.Header.Get("X-CSRF-Token")})
		if r.URL.Path == "/oauth2/device_authorization" {
			writeStatusJSON(w, http.StatusOK, deviceAuthBody(nil))
			return
		}
		writeStatusJSON(w, http.StatusOK, map[string]any{
			"access_token": "t", "token_type": "Bearer", "expires_in": 900,
		})
	}
	srv.DeviceAuthHandler = record
	srv.TokenHandler = record

	client := newDeviceClient(t, srv)
	// A jar holding session cookies and a captured CSRF token, as after Login().
	base, _ := url.Parse(srv.URL)
	client.httpc.Jar.SetCookies(base, []*http.Cookie{
		{Name: "axiam_access", Value: "a", Path: "/"},
		{Name: "axiam_refresh", Value: "r", Path: "/"},
	})
	client.session.csrfToken = "csrf-value"

	ctx := context.Background()
	if _, err := client.DeviceAuthorize(ctx, DeviceAuthorizeParams{TenantID: testTenantUUID}); err != nil {
		t.Fatalf("DeviceAuthorize: %v", err)
	}
	if _, err := client.DevicePoll(ctx, DevicePollParams{DeviceCode: Sensitive(testDeviceCode), TenantID: testTenantUUID}); err != nil {
		t.Fatalf("DevicePoll: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("saw %d requests, want 2: %+v", len(got), got)
	}
	for _, s := range got {
		if s.cookie != "" || s.csrf != "" {
			t.Errorf("%s carried cookie %q / X-CSRF-Token %q", s.path, s.cookie, s.csrf)
		}
	}
	// The jar is untouched: a later REST request still sends the session.
	if len(client.httpc.Jar.Cookies(base)) != 2 {
		t.Error("the jar must still hold the session cookies")
	}
}

func TestManifestNetwork_PlanRefusesAnUnknownOpenEnumOnAnUnstatedMember(t *testing.T) {
	for name, over := range map[string]map[string]any{
		"termination_action": {"termination_action": "future"},
		"service_type":       {"service_type": "future"},
	} {
		t.Run(name, func(t *testing.T) {
			srv, c := managementServer(t)
			f := newNetFake(t, srv)
			id := f.seedSegment(map[string]any{"name": "iot", "vlan_id": 20, "rank": 10, "filter_ids": []string{"iot-acl"}})
			f.seedProfile(id, over)
			m := ManagementManifest{Network: NetworkSpec{
				Segments: []NetworkSegmentSpec{accessSegment("iot", "iot", 20, 10)},
				// states a DIFFERENT member (the Session-Timeout), so an update is planned
				Profiles: []NetworkProfileSpec{{Segment: "iot", SessionTimeoutSecs: 300, FilterID: ValueOf("iot-acl")}},
			}}
			_, err := c.Manifest().Plan(context.Background(), m)
			var ve *ValidationError
			if !errors.As(err, &ve) || !strings.Contains(ve.Message, name) || !strings.Contains(ve.Message, "future") {
				t.Fatalf("plan error = %v, want a ValidationError naming %s and the value", err, name)
			}
			if _, err := c.Manifest().Apply(context.Background(), m); err == nil {
				t.Fatal("apply must refuse too")
			}
			if w := f.writes(); len(w) != 0 {
				t.Fatalf("no write may be sent, got %v", w)
			}
		})
	}
}

// C163-08: the same assertion, against a client that really signed in. The
// sign-in mock sets axiam_access, axiam_csrf and X-CSRF-Token; the three
// /oauth2/* calls must carry neither Cookie nor X-CSRF-Token; the control, the
// next state-changing management request, carries both — so the assertions
// cannot pass for want of the session.
func TestOAuth2RequestsAfterLoginCarryNoSessionAndAManagementPostCarriesBoth(t *testing.T) {
	type seen struct{ method, path, cookie, csrf string }
	var (
		mu  sync.Mutex
		got []seen
	)
	mux := http.NewServeMux()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = append(got, seen{r.Method, r.URL.Path, r.Header.Get("Cookie"), r.Header.Get("X-CSRF-Token")})
		mu.Unlock()
		mux.ServeHTTP(w, r)
	}))
	defer srv.Close()
	mux.HandleFunc(loginPath, func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: accessCookie, Value: managementAccessToken(t), Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: refreshCookie, Value: "refresh-tok", Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: "axiam_csrf", Value: "csrf-from-login", Path: "/"})
		w.Header().Set("X-CSRF-Token", "csrf-from-login")
		writeStatusJSON(w, http.StatusOK, map[string]any{"session_id": "33333333-3333-3333-3333-333333333333", "expires_in": 900})
	})
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		writeStatusJSON(w, http.StatusOK, discoveryDoc(srv.URL))
	})
	mux.HandleFunc("/oauth2/device_authorization", func(w http.ResponseWriter, r *http.Request) {
		writeStatusJSON(w, http.StatusOK, deviceAuthBody(nil))
	})
	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		writeStatusJSON(w, http.StatusOK, map[string]any{"access_token": "t", "token_type": "Bearer", "expires_in": 900})
	})
	mux.HandleFunc("/api/v1/groups", func(w http.ResponseWriter, r *http.Request) {
		writeStatusJSON(w, http.StatusCreated, map[string]any{
			"id": "55555555-5555-5555-5555-555555555555", "tenant_id": tenantID, "name": "g", "description": "",
			"created_at": "2026-10-16T00:00:00Z", "updated_at": "2026-10-16T00:00:00Z",
		})
	})

	client, err := NewClient(srv.URL, "acme", WithOidcClientID("my-device"), WithOidcClientSecret("s3cret"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	ctx := context.Background()
	if _, err := client.Login(ctx, "admin@example.test", "hunter2hunter2"); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if _, err := client.DeviceAuthorize(ctx, DeviceAuthorizeParams{TenantID: testTenantUUID}); err != nil {
		t.Fatalf("DeviceAuthorize: %v", err)
	}
	if _, err := client.DevicePoll(ctx, DevicePollParams{DeviceCode: Sensitive(testDeviceCode), TenantID: testTenantUUID}); err != nil {
		t.Fatalf("DevicePoll: %v", err)
	}
	if _, err := client.LoginClientCredentials(ctx, LoginClientCredentialsParams{TenantID: testTenantUUID}); err != nil {
		t.Fatalf("LoginClientCredentials: %v", err)
	}
	if _, err := client.Groups().Create(ctx, CreateGroupRequest{Name: "g"}); err != nil {
		t.Fatalf("Groups().Create: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	oauth2 := 0
	var control *seen
	for i := range got {
		s := got[i]
		switch {
		case strings.HasPrefix(s.path, "/oauth2/"):
			oauth2++
			if s.cookie != "" || s.csrf != "" {
				t.Errorf("%s carried Cookie %q / X-CSRF-Token %q", s.path, s.cookie, s.csrf)
			}
		case s.path == "/api/v1/groups":
			control = &got[i]
		}
	}
	if oauth2 != 3 {
		t.Fatalf("saw %d /oauth2/* requests, want 3 (device_authorization, device poll, client credentials): %+v", oauth2, got)
	}
	if control == nil {
		t.Fatalf("the control request never arrived: %+v", got)
	}
	if !strings.Contains(control.cookie, accessCookie+"=") || control.csrf != "csrf-from-login" {
		t.Errorf("the management POST must carry the session and the CSRF token, got Cookie %q / X-CSRF-Token %q", control.cookie, control.csrf)
	}
}

// C163-09: for each open-enum member, the two cases around the refusal. A
// member the manifest states resolves the unknown read (one PUT carrying the
// stated value, and "future" is never re-sent); and when nothing differs the
// plan is converged and nothing is written — an unknown value on a member
// nobody changes is not a reason to refuse.
func TestManifestNetwork_AStatedOpenEnumMemberResolvesTheUnknownRead(t *testing.T) {
	cases := map[string]struct {
		member string
		stated NetworkProfileSpec
		want   string
	}{
		"termination_action": {"termination_action", NetworkProfileSpec{Segment: "iot", SessionTimeoutSecs: 900, TerminationAction: ptr(RadiusTerminationActionDefault)}, "default"},
		"service_type":       {"service_type", NetworkProfileSpec{Segment: "iot", SessionTimeoutSecs: 900, ServiceType: ValueOf(RadiusServiceTypeFramedUser)}, "framed_user"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			srv, c := managementServer(t)
			f := newNetFake(t, srv)
			id := f.seedSegment(map[string]any{"name": "iot", "vlan_id": 20, "rank": 10, "filter_ids": []string{"iot-acl"}})
			f.seedProfile(id, map[string]any{tc.member: "future"})
			m := ManagementManifest{Network: NetworkSpec{
				Segments: []NetworkSegmentSpec{accessSegment("iot", "iot", 20, 10)},
				Profiles: []NetworkProfileSpec{tc.stated},
			}}
			report, err := c.Manifest().Apply(context.Background(), m)
			if err != nil || !report.IsComplete() {
				t.Fatalf("apply: %v %+v", err, report)
			}
			if w := f.writes(); len(w) != 1 || !strings.HasPrefix(w[0], "PUT /api/v1/network/profiles/") {
				t.Fatalf("want exactly one PUT of the profile, got %v", w)
			}
			raw := srv.routes[routeKey(http.MethodPut, "/api/v1/network/profiles/"+id.String())].last(t).body
			var body struct {
				Profile map[string]any `json:"profile"`
			}
			if err := json.Unmarshal(raw, &body); err != nil {
				t.Fatalf("body: %v", err)
			}
			if body.Profile[tc.member] != tc.want {
				t.Errorf("%s = %v, want the stated %q", tc.member, body.Profile[tc.member], tc.want)
			}
			if strings.Contains(string(raw), "future") {
				t.Errorf("the unknown read value was re-sent: %s", raw)
			}
		})
	}
}

func TestManifestNetwork_NothingDifferingWithAnUnknownOpenEnumIsConvergedAndWritesNothing(t *testing.T) {
	for _, member := range []string{"termination_action", "service_type"} {
		t.Run(member, func(t *testing.T) {
			srv, c := managementServer(t)
			f := newNetFake(t, srv)
			id := f.seedSegment(map[string]any{"name": "iot", "vlan_id": 20, "rank": 10, "filter_ids": []string{"iot-acl"}})
			f.seedProfile(id, map[string]any{member: "future"})
			m := ManagementManifest{Network: NetworkSpec{
				Segments: []NetworkSegmentSpec{accessSegment("iot", "iot", 20, 10)},
				// states only what the read already has; the unknown member is not stated
				Profiles: []NetworkProfileSpec{{Segment: "iot", SessionTimeoutSecs: 900, FilterID: ValueOf("iot-acl")}},
			}}
			plan, err := c.Manifest().Plan(context.Background(), m)
			if err != nil || !plan.IsConverged() {
				t.Fatalf("plan: want converged, got %v %+v", err, plan)
			}
			if _, err := c.Manifest().Apply(context.Background(), m); err != nil {
				t.Fatalf("apply: %v", err)
			}
			if w := f.writes(); len(w) != 0 {
				t.Fatalf("no write may be sent, got %v", w)
			}
		})
	}
}

// C163-19: /oauth2/ is matched under the client's base path, not anywhere in
// the path — the federation routes under /api/v1/auth/federation/oauth2/ are
// management routes and take the session like any other.
func TestIsOAuth2PathIsAnchoredToTheBasePath(t *testing.T) {
	for base, paths := range map[string]map[string]bool{
		"https://axiam.example.test": {
			"/oauth2/token":                           true,
			"/oauth2/device_authorization":            true,
			"/api/v1/auth/federation/oauth2/callback": false,
			"/api/v1/groups":                          false,
			"/oauth2":                                 false,
			"/prefix/oauth2/token":                    false,
		},
		"https://axiam.example.test/prefix/": {
			"/prefix/oauth2/token": true,
			"/oauth2/token":        true, // a root /oauth2/* URL under a prefixed base (C164-24)
			"/prefix/api/v1/auth/federation/oauth2/callback": false,
		},
	} {
		client, err := NewClient(base, "acme")
		if err != nil {
			t.Fatalf("NewClient(%s): %v", base, err)
		}
		for path, want := range paths {
			req, _ := http.NewRequest(http.MethodPost, "https://axiam.example.test"+path, nil)
			if got := client.isOAuth2Path(req); got != want {
				t.Errorf("base %s, path %s: isOAuth2Path = %v, want %v", base, path, got, want)
			}
		}
	}
}
