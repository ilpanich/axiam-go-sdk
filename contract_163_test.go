package axiam

// Contract 1.63 — §6.1 rule 11 / §12.1 rule 3 (no session cookie and no
// X-CSRF-Token on /oauth2/*, §14.6) and the C162-07 refusal (§27.6.2 item 4).

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
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
