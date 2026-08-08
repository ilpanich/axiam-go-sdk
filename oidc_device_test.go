package axiam

// Device Authorization Grant — CONTRACT.md §14.
//
// The §14.6 required assertions split across two levels, deliberately:
//
//   - Interval ARITHMETIC — the interval comes from the response, slow_down
//     raises it permanently, polling stops at expires_in — is asserted against
//     pollSchedule directly. It is pure logic, so it is tested exactly and
//     instantly, including cases (a 30-minute grant, three cumulative
//     slow_downs) no wall-clock test could reach.
//
//   - WIRE behaviour lives in the integration tests: which answers loop, which
//     terminate, how many requests actually go out, and the §14.3 rule 2
//     ordering guarantee. Intervals in those fixtures are 1 s.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

const (
	testDeviceCode = "device-code-value"
	testUserCode   = "WDJB-MJHT"
	testTenantUUID = "11111111-1111-1111-1111-111111111111"
)

// ---------------------------------------------------------------------------
// §14.2 arithmetic — pollSchedule
// ---------------------------------------------------------------------------

func TestPollScheduleFallsBackToRFCDefaultOnlyWhenAbsent(t *testing.T) {
	if got := newPollSchedule(0, 10*time.Minute).interval; got != DefaultDevicePollInterval {
		t.Fatalf("zero interval: got %v, want %v", got, DefaultDevicePollInterval)
	}
	if got := newPollSchedule(7*time.Second, 10*time.Minute).interval; got != 7*time.Second {
		t.Fatalf("server interval: got %v, want 7s", got)
	}
}

func TestPollScheduleSlowDownIsCumulativeAndNeverResets(t *testing.T) {
	s := newPollSchedule(5*time.Second, 30*time.Minute)
	s.slowDown()
	if s.interval != 10*time.Second {
		t.Fatalf("after one slow_down: got %v, want 10s", s.interval)
	}
	s.slowDown()
	s.slowDown()
	if s.interval != 20*time.Second {
		t.Fatalf("after three slow_downs: got %v, want 20s", s.interval)
	}

	// Polling on must not undo the raise. This is the rule implementations get
	// wrong: backing off for one round and returning to the original interval
	// earns another slow_down, forever.
	s.tick()
	s.tick()
	if s.interval != 20*time.Second {
		t.Fatalf("interval reset by polling: got %v, want 20s", s.interval)
	}
}

func TestPollScheduleStopsAtTheDeadline(t *testing.T) {
	s := newPollSchedule(5*time.Second, 12*time.Second)
	if !s.tick() { // t=5
		t.Fatal("first tick should be allowed")
	}
	if !s.tick() { // t=10
		t.Fatal("second tick should be allowed")
	}
	if s.tick() { // t=15 is past 12
		t.Fatal("§14.2 rule 4: polling must stop at the deadline")
	}
}

func TestPollScheduleSlowedIntervalCanExhaustTheGrantEarly(t *testing.T) {
	s := newPollSchedule(5*time.Second, 20*time.Second)
	if !s.tick() {
		t.Fatal("first tick should be allowed")
	}
	s.slowDown()
	s.slowDown()
	if s.interval != 15*time.Second {
		t.Fatalf("interval: got %v, want 15s", s.interval)
	}
	if s.tick() {
		t.Fatal("a slowed interval past the remaining time must stop")
	}
}

func TestPollScheduleIntervalCoveringWholeGrantNeverPolls(t *testing.T) {
	if newPollSchedule(30*time.Second, 30*time.Second).tick() {
		t.Fatal("an interval equal to the grant leaves no room for a poll")
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func deviceAuthBody(overrides map[string]any) map[string]any {
	body := map[string]any{
		"device_code":               testDeviceCode,
		"user_code":                 testUserCode,
		"verification_uri":          "https://example.test/device",
		"verification_uri_complete": "https://example.test/device?user_code=" + testUserCode,
		"expires_in":                30,
		"interval":                  1,
	}
	for k, v := range overrides {
		if v == nil {
			delete(body, k)
			continue
		}
		body[k] = v
	}
	return body
}

// writeStatusJSON differs from the existing writeJSON(t, w, v) helper by
// taking an explicit status: these tests need 400s carrying an
// OAuth2ErrorResponse body, which is the whole §14.2 rule 5 surface.
func writeStatusJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func oauthErrorBody(code string) map[string]any {
	return map[string]any{"error": code, "error_description": code + " description"}
}

func deviceSuccessBody() map[string]any {
	return map[string]any{
		"access_token":  "device-access-token",
		"token_type":    "Bearer",
		"expires_in":    900,
		"refresh_token": "device-refresh-token",
	}
}

// scriptedTokenHandler replies with each response in order, repeating the
// last one once exhausted, and records the form bodies it saw.
func scriptedTokenHandler(t *testing.T, script []func(http.ResponseWriter)) (http.HandlerFunc, *[]string) {
	t.Helper()
	var forms []string
	i := 0
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm: %v", err)
		}
		forms = append(forms, r.PostForm.Encode())
		step := script[len(script)-1]
		if i < len(script) {
			step = script[i]
		}
		i++
		step(w)
	}, &forms
}

func newDeviceClient(t *testing.T, srv *oidcTestServer, opts ...Option) *Client {
	t.Helper()
	// Built WITHOUT a client secret: §14.1 says a device that cannot show a
	// browser cannot hold one, and the SDK must not refuse such a client.
	all := append([]Option{WithOidcClientID("my-device")}, opts...)
	client, err := NewClient(srv.URL, "acme", all...)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return client
}

// ---------------------------------------------------------------------------
// DeviceAuthorize
// ---------------------------------------------------------------------------

func TestDeviceAuthorizeIsUnauthenticatedAndFormEncoded(t *testing.T) {
	srv := newOidcTestServer(t)
	var form string
	var contentType string
	srv.DeviceAuthHandler = func(w http.ResponseWriter, r *http.Request) {
		contentType = r.Header.Get("Content-Type")
		_ = r.ParseForm()
		form = r.PostForm.Encode()
		if got := r.URL.Query().Get("tenant_id"); got != testTenantUUID {
			t.Errorf("tenant_id query: got %q, want %q", got, testTenantUUID)
		}
		writeStatusJSON(w, http.StatusOK, deviceAuthBody(nil))
	}

	client := newDeviceClient(t, srv)
	authorization, err := client.DeviceAuthorize(context.Background(), DeviceAuthorizeParams{
		Scope:    "openid profile",
		TenantID: testTenantUUID,
	})
	if err != nil {
		t.Fatalf("DeviceAuthorize: %v", err)
	}

	if !strings.HasPrefix(contentType, "application/x-www-form-urlencoded") {
		t.Errorf("Content-Type: got %q", contentType)
	}
	if strings.Contains(form, "client_secret") {
		t.Error("§14.1: device_authorize MUST NOT send client_secret")
	}
	if !strings.Contains(form, "scope=openid+profile") {
		t.Errorf("scope not sent: %q", form)
	}
	if strings.Contains(form, "tenant_id") {
		t.Error("§12.1 note 2: tenant_id is a query parameter, never a body field")
	}

	if authorization.UserCode != testUserCode {
		t.Errorf("UserCode: got %q", authorization.UserCode)
	}
	if authorization.Interval != 1 {
		t.Errorf("Interval: got %d, want 1 (from the response)", authorization.Interval)
	}
}

func TestDeviceAuthorizeDefaultsAbsentIntervalToFiveSeconds(t *testing.T) {
	srv := newOidcTestServer(t)
	srv.DeviceAuthHandler = func(w http.ResponseWriter, r *http.Request) {
		writeStatusJSON(w, http.StatusOK, deviceAuthBody(map[string]any{"interval": nil}))
	}

	authorization, err := newDeviceClient(t, srv).DeviceAuthorize(context.Background(), DeviceAuthorizeParams{TenantID: testTenantUUID})
	if err != nil {
		t.Fatalf("DeviceAuthorize: %v", err)
	}
	if authorization.Interval != 5 {
		t.Errorf("§14.2 rule 2: absent interval must default to 5 s, got %d", authorization.Interval)
	}
}

func TestDeviceAuthorizeErrorsWhenServerAdvertisesNoEndpoint(t *testing.T) {
	srv := newOidcTestServer(t)
	srv.DiscoveryDoc = discoveryDocWithoutOptionalEndpoints

	_, err := newDeviceClient(t, srv).DeviceAuthorize(context.Background(), DeviceAuthorizeParams{TenantID: testTenantUUID})
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("want *AuthError, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "device_authorization_endpoint") {
		t.Errorf("error should name the missing endpoint, got %q", err.Error())
	}
	if srv.DeviceAuthCalls() != 0 {
		t.Error("no URL should have been guessed and requested")
	}
}

func TestDeviceCodeIsRedactedAndUserCodeIsNot(t *testing.T) {
	srv := newOidcTestServer(t)
	srv.DeviceAuthHandler = func(w http.ResponseWriter, r *http.Request) {
		writeStatusJSON(w, http.StatusOK, deviceAuthBody(nil))
	}

	authorization, err := newDeviceClient(t, srv).DeviceAuthorize(context.Background(), DeviceAuthorizeParams{TenantID: testTenantUUID})
	if err != nil {
		t.Fatalf("DeviceAuthorize: %v", err)
	}

	rendered := fmt.Sprintf("%v %s", authorization.DeviceCode, authorization.DeviceCode.String())
	if strings.Contains(rendered, testDeviceCode) {
		t.Error("§14.5: device_code is a bearer credential and must never render")
	}
	if authorization.DeviceCode.expose() != testDeviceCode {
		t.Error("expose() must still return the value")
	}
	// §14.5: user_code is NOT wrapped — it exists to be read aloud, and
	// wrapping it would defeat the one thing it is for.
	if authorization.UserCode != testUserCode {
		t.Error("user_code must be a plain string")
	}
}

// ---------------------------------------------------------------------------
// §14.2 wire behaviour
// ---------------------------------------------------------------------------

func TestDeviceLoginLoopsOnAuthorizationPending(t *testing.T) {
	srv := newOidcTestServer(t)
	srv.DeviceAuthHandler = func(w http.ResponseWriter, r *http.Request) {
		writeStatusJSON(w, http.StatusOK, deviceAuthBody(nil))
	}
	handler, _ := scriptedTokenHandler(t, []func(http.ResponseWriter){
		func(w http.ResponseWriter) {
			writeStatusJSON(w, http.StatusBadRequest, oauthErrorBody("authorization_pending"))
		},
		func(w http.ResponseWriter) {
			writeStatusJSON(w, http.StatusBadRequest, oauthErrorBody("authorization_pending"))
		},
		func(w http.ResponseWriter) { writeStatusJSON(w, http.StatusOK, deviceSuccessBody()) },
	})
	srv.TokenHandler = handler

	tokens, err := newDeviceClient(t, srv).DeviceLogin(context.Background(), DeviceLoginParams{
		TenantID:   testTenantUUID,
		OnUserCode: func(DeviceAuthorization) error { return nil },
	})
	if err != nil {
		t.Fatalf("DeviceLogin: %v", err)
	}
	if srv.TokenCalls() != 3 {
		t.Errorf("token calls: got %d, want 3", srv.TokenCalls())
	}
	if tokens.AccessToken.expose() != "device-access-token" {
		t.Error("token set not returned")
	}
}

func TestDeviceLoginTreatsSlowDownAsNonTerminal(t *testing.T) {
	// The back-off arithmetic is asserted against pollSchedule; what matters
	// here is that slow_down is not mistaken for a terminal answer. An SDK
	// that let it fall through would abort a grant the user is still approving.
	srv := newOidcTestServer(t)
	srv.DeviceAuthHandler = func(w http.ResponseWriter, r *http.Request) {
		writeStatusJSON(w, http.StatusOK, deviceAuthBody(nil))
	}
	handler, _ := scriptedTokenHandler(t, []func(http.ResponseWriter){
		func(w http.ResponseWriter) { writeStatusJSON(w, http.StatusBadRequest, oauthErrorBody("slow_down")) },
		func(w http.ResponseWriter) { writeStatusJSON(w, http.StatusOK, deviceSuccessBody()) },
	})
	srv.TokenHandler = handler

	tokens, err := newDeviceClient(t, srv).DeviceLogin(context.Background(), DeviceLoginParams{
		TenantID:   testTenantUUID,
		OnUserCode: func(DeviceAuthorization) error { return nil },
	})
	if err != nil {
		t.Fatalf("DeviceLogin: %v", err)
	}
	if srv.TokenCalls() != 2 {
		t.Errorf("token calls: got %d, want 2", srv.TokenCalls())
	}
	if tokens.AccessToken.expose() != "device-access-token" {
		t.Error("token set not returned")
	}
}

func TestAccessDeniedAndExpiredTokenStayDistinct(t *testing.T) {
	// §14.2 rule 3: "a human said no" and "nobody answered" are the only two
	// pieces of information the device can act on.
	for _, code := range []string{"access_denied", "expired_token", "invalid_grant"} {
		t.Run(code, func(t *testing.T) {
			srv := newOidcTestServer(t)
			srv.DeviceAuthHandler = func(w http.ResponseWriter, r *http.Request) {
				writeStatusJSON(w, http.StatusOK, deviceAuthBody(nil))
			}
			srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
				writeStatusJSON(w, http.StatusBadRequest, oauthErrorBody(code))
			}

			_, err := newDeviceClient(t, srv).DeviceLogin(context.Background(), DeviceLoginParams{
				TenantID:   testTenantUUID,
				OnUserCode: func(DeviceAuthorization) error { return nil },
			})
			var protocolErr *OAuthProtocolError
			if !errors.As(err, &protocolErr) {
				t.Fatalf("want *OAuthProtocolError, got %T: %v", err, err)
			}
			if protocolErr.ErrorCode != code {
				t.Errorf("ErrorCode: got %q, want %q", protocolErr.ErrorCode, code)
			}
			if srv.TokenCalls() != 1 {
				t.Errorf("a terminal answer must stop the loop at once, got %d polls", srv.TokenCalls())
			}
		})
	}
}

func TestDeviceLoginStopsAtExpiresIn(t *testing.T) {
	srv := newOidcTestServer(t)
	// 2-second grant, 1-second interval: one poll at t=1, then the t=2 tick is
	// the deadline and must not be sent.
	srv.DeviceAuthHandler = func(w http.ResponseWriter, r *http.Request) {
		writeStatusJSON(w, http.StatusOK, deviceAuthBody(map[string]any{"expires_in": 2, "interval": 1}))
	}
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		writeStatusJSON(w, http.StatusBadRequest, oauthErrorBody("authorization_pending"))
	}

	_, err := newDeviceClient(t, srv).DeviceLogin(context.Background(), DeviceLoginParams{
		TenantID:   testTenantUUID,
		OnUserCode: func(DeviceAuthorization) error { return nil },
	})
	var protocolErr *OAuthProtocolError
	if !errors.As(err, &protocolErr) {
		t.Fatalf("want *OAuthProtocolError, got %T: %v", err, err)
	}
	if protocolErr.ErrorCode != "expired_token" {
		t.Errorf("§14.2 rule 4: got %q, want expired_token — the same code the server would have used", protocolErr.ErrorCode)
	}
	if srv.TokenCalls() != 1 {
		t.Errorf("no poll may be sent past the deadline, got %d", srv.TokenCalls())
	}
}

func TestServerErrorMidPollIsRetriedNotTerminal(t *testing.T) {
	srv := newOidcTestServer(t)
	srv.DeviceAuthHandler = func(w http.ResponseWriter, r *http.Request) {
		writeStatusJSON(w, http.StatusOK, deviceAuthBody(nil))
	}
	handler, _ := scriptedTokenHandler(t, []func(http.ResponseWriter){
		func(w http.ResponseWriter) {
			writeStatusJSON(w, http.StatusBadRequest, oauthErrorBody("authorization_pending"))
		},
		func(w http.ResponseWriter) { w.WriteHeader(http.StatusInternalServerError) },
		func(w http.ResponseWriter) { w.WriteHeader(http.StatusServiceUnavailable) },
		func(w http.ResponseWriter) { writeStatusJSON(w, http.StatusOK, deviceSuccessBody()) },
	})
	srv.TokenHandler = handler

	tokens, err := newDeviceClient(t, srv).DeviceLogin(context.Background(), DeviceLoginParams{
		TenantID:   testTenantUUID,
		OnUserCode: func(DeviceAuthorization) error { return nil },
	})
	if err != nil {
		t.Fatalf("§14.2 rule 6: a server restart must not lose an approved grant: %v", err)
	}
	if srv.TokenCalls() != 4 {
		t.Errorf("token calls: got %d, want 4", srv.TokenCalls())
	}
	if tokens.AccessToken.expose() != "device-access-token" {
		t.Error("token set not returned")
	}
}

// ---------------------------------------------------------------------------
// §14.3 DeviceLogin
// ---------------------------------------------------------------------------

func TestDeviceLoginSurfacesUserCodeBeforeFirstPoll(t *testing.T) {
	srv := newOidcTestServer(t)
	var order []string
	srv.DeviceAuthHandler = func(w http.ResponseWriter, r *http.Request) {
		writeStatusJSON(w, http.StatusOK, deviceAuthBody(nil))
	}
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		order = append(order, "poll")
		writeStatusJSON(w, http.StatusOK, deviceSuccessBody())
	}

	var seen string
	_, err := newDeviceClient(t, srv).DeviceLogin(context.Background(), DeviceLoginParams{
		TenantID: testTenantUUID,
		OnUserCode: func(a DeviceAuthorization) error {
			order = append(order, "user_code")
			seen = a.UserCode
			return nil
		},
	})
	if err != nil {
		t.Fatalf("DeviceLogin: %v", err)
	}

	// Ordering, not just presence (§14.6).
	if len(order) != 2 || order[0] != "user_code" || order[1] != "poll" {
		t.Errorf("§14.3 rule 2: got %v, want [user_code poll]", order)
	}
	if seen != testUserCode {
		t.Errorf("callback got %q", seen)
	}
}

func TestDeviceLoginAbortsWithoutPollingWhenTheCodeCannotBeDisplayed(t *testing.T) {
	srv := newOidcTestServer(t)
	srv.DeviceAuthHandler = func(w http.ResponseWriter, r *http.Request) {
		writeStatusJSON(w, http.StatusOK, deviceAuthBody(nil))
	}
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		t.Error("must not poll when the code was never displayed")
	}

	sentinel := errors.New("display is broken")
	_, err := newDeviceClient(t, srv).DeviceLogin(context.Background(), DeviceLoginParams{
		TenantID:   testTenantUUID,
		OnUserCode: func(DeviceAuthorization) error { return sentinel },
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("want the callback's own error wrapped, got %v", err)
	}
	if srv.TokenCalls() != 0 {
		t.Error("a device that cannot show the code has no approval to wait for")
	}
}

func TestDeviceLoginRequiresOnUserCode(t *testing.T) {
	srv := newOidcTestServer(t)
	_, err := newDeviceClient(t, srv).DeviceLogin(context.Background(), DeviceLoginParams{TenantID: testTenantUUID})
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("want *AuthError, got %T: %v", err, err)
	}
	if srv.DeviceAuthCalls() != 0 {
		t.Error("the grant must not be started when nothing can display the code")
	}
}

func TestDeviceLoginReturnsTheTokenSetAndAdoptsOnlyWhenAsked(t *testing.T) {
	// §14.6 as amended by the contract 1.7 errata: assert the RETURNED token
	// set, and — because this SDK's adoption is a flag — assert BOTH
	// directions of that flag.
	for _, adopt := range []bool{false, true} {
		t.Run(fmt.Sprintf("adopt=%v", adopt), func(t *testing.T) {
			srv := newOidcTestServer(t)
			srv.DeviceAuthHandler = func(w http.ResponseWriter, r *http.Request) {
				writeStatusJSON(w, http.StatusOK, deviceAuthBody(nil))
			}
			srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
				writeStatusJSON(w, http.StatusOK, deviceSuccessBody())
			}

			client := newDeviceClient(t, srv)
			tokens, err := client.DeviceLogin(context.Background(), DeviceLoginParams{
				TenantID:          testTenantUUID,
				OnUserCode:        func(DeviceAuthorization) error { return nil },
				AdoptAsCredential: adopt,
			})
			if err != nil {
				t.Fatalf("DeviceLogin: %v", err)
			}
			if tokens.AccessToken.expose() != "device-access-token" {
				t.Error("the token set must be returned regardless of adoption")
			}

			adopted := client.adoptedOidcCredential()
			if adopt && adopted.expose() != "device-access-token" {
				t.Error("AdoptAsCredential=true must adopt")
			}
			if !adopt && adopted != "" {
				t.Error("AdoptAsCredential=false must leave the client's credential untouched")
			}
		})
	}
}

func TestDeviceLoginHonoursContextCancellationBetweenPolls(t *testing.T) {
	srv := newOidcTestServer(t)
	srv.DeviceAuthHandler = func(w http.ResponseWriter, r *http.Request) {
		writeStatusJSON(w, http.StatusOK, deviceAuthBody(map[string]any{"interval": 30, "expires_in": 600}))
	}
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		t.Error("cancellation must be observed before the first poll")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// A device powering down should not have to wait out a 30-second interval.
	_, err := newDeviceClient(t, srv).DeviceLogin(ctx, DeviceLoginParams{
		TenantID:   testTenantUUID,
		OnUserCode: func(DeviceAuthorization) error { return nil },
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// DevicePoll standalone
// ---------------------------------------------------------------------------

func TestDevicePollSurfacesPendingForHandRolledLoops(t *testing.T) {
	srv := newOidcTestServer(t)
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		writeStatusJSON(w, http.StatusBadRequest, oauthErrorBody("authorization_pending"))
	}

	_, err := newDeviceClient(t, srv).DevicePoll(context.Background(), DevicePollParams{
		DeviceCode: Sensitive(testDeviceCode),
		TenantID:   testTenantUUID,
	})
	var protocolErr *OAuthProtocolError
	if !errors.As(err, &protocolErr) {
		t.Fatalf("want *OAuthProtocolError, got %T: %v", err, err)
	}
	if protocolErr.ErrorCode != "authorization_pending" {
		t.Errorf("a hand-rolled loop must see what DeviceLogin sees, got %q", protocolErr.ErrorCode)
	}
}

func TestDevicePollSendsTheDeviceCodeGrant(t *testing.T) {
	srv := newOidcTestServer(t)
	var form string
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		form = r.PostForm.Encode()
		writeStatusJSON(w, http.StatusOK, deviceSuccessBody())
	}

	_, err := newDeviceClient(t, srv).DevicePoll(context.Background(), DevicePollParams{
		DeviceCode: Sensitive(testDeviceCode),
		TenantID:   testTenantUUID,
	})
	if err != nil {
		t.Fatalf("DevicePoll: %v", err)
	}
	if !strings.Contains(form, "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code") {
		t.Errorf("grant_type not sent: %q", form)
	}
	if !strings.Contains(form, "device_code="+testDeviceCode) {
		t.Errorf("device_code not sent: %q", form)
	}
}
