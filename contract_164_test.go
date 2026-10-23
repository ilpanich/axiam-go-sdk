package axiam

// Contract 1.64 — §14.2 rule 9, last paragraph: a `429 rate_limit_exceeded` on
// a device-code poll is waited out, not raised (§14.6, #760 Q2). The 1.63
// §14.6 tests stay in oidc_device_test.go and contract_163_test.go unchanged.

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"sync"
	"testing"
	"time"
)

// recordedSleeps replaces the device loop's wait with a recorder, so the test
// asserts the wait it was asked for and never sleeps.
type recordedSleeps struct {
	mu sync.Mutex
	d  []time.Duration
}

func (r *recordedSleeps) sleep(_ context.Context, d time.Duration) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.d = append(r.d, d)
	return nil
}

func (r *recordedSleeps) got() []time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]time.Duration(nil), r.d...)
}

func rateLimited(retryAfter string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		if retryAfter != "" {
			w.Header().Set("Retry-After", retryAfter)
		}
		writeStatusJSON(w, http.StatusTooManyRequests, map[string]any{"error": "rate_limit_exceeded"})
	}
}

func TestDeviceLoginWaitsOutA429RetryAfterAndKeepsTheInterval(t *testing.T) {
	srv := newOidcTestServer(t)
	srv.DeviceAuthHandler = func(w http.ResponseWriter, r *http.Request) {
		writeStatusJSON(w, http.StatusOK, deviceAuthBody(nil)) // interval 1 s, expires_in 30 s
	}
	handler, _ := scriptedTokenHandler(t, []func(http.ResponseWriter){
		rateLimited("7"),
		func(w http.ResponseWriter) {
			writeStatusJSON(w, http.StatusBadRequest, oauthErrorBody("authorization_pending"))
		},
		func(w http.ResponseWriter) { writeStatusJSON(w, http.StatusOK, deviceSuccessBody()) },
	})
	srv.TokenHandler = handler
	client := newDeviceClient(t, srv)
	sleeps := &recordedSleeps{}
	client.pollSleep = sleeps.sleep

	tokens, err := client.DeviceLogin(context.Background(), DeviceLoginParams{
		TenantID:   testTenantUUID,
		OnUserCode: func(DeviceAuthorization) error { return nil },
	})
	if err != nil {
		t.Fatalf("DeviceLogin: a 429 must not be terminal: %v", err)
	}
	if tokens.AccessToken.expose() != "device-access-token" {
		t.Error("token set not returned")
	}
	if srv.TokenCalls() != 3 {
		t.Errorf("token calls: got %d, want 3 (429, pending, success)", srv.TokenCalls())
	}
	// 1 s before the poll that was answered 429; at least Retry-After (7 s)
	// before the next, which replaces that interval rather than adding to it;
	// then the unchanged 1 s — slow_down would have made it 6 s.
	want := []time.Duration{time.Second, 7 * time.Second, time.Second}
	got := sleeps.got()
	if len(got) != len(want) {
		t.Fatalf("waits: got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("wait %d: got %v, want %v (all: %v)", i, got[i], want[i], got)
		}
	}
}

func TestDeviceLoginBelowIntervalRetryAfterStillWaitsTheInterval(t *testing.T) {
	// A Retry-After is a minimum, and a 429 counts as one interval: a hint
	// shorter than the interval, or none at all, changes nothing.
	for name, retryAfter := range map[string]string{"absent": "", "shorter": "0"} {
		t.Run(name, func(t *testing.T) {
			srv := newOidcTestServer(t)
			srv.DeviceAuthHandler = func(w http.ResponseWriter, r *http.Request) {
				writeStatusJSON(w, http.StatusOK, deviceAuthBody(nil))
			}
			handler, _ := scriptedTokenHandler(t, []func(http.ResponseWriter){
				rateLimited(retryAfter),
				func(w http.ResponseWriter) { writeStatusJSON(w, http.StatusOK, deviceSuccessBody()) },
			})
			srv.TokenHandler = handler
			client := newDeviceClient(t, srv)
			sleeps := &recordedSleeps{}
			client.pollSleep = sleeps.sleep
			if _, err := client.DeviceLogin(context.Background(), DeviceLoginParams{
				TenantID:   testTenantUUID,
				OnUserCode: func(DeviceAuthorization) error { return nil },
			}); err != nil {
				t.Fatalf("DeviceLogin: %v", err)
			}
			for i, d := range sleeps.got() {
				if d != time.Second {
					t.Errorf("wait %d: got %v, want the 1 s interval", i, d)
				}
			}
		})
	}
}

func TestDeviceLoginCapsA429RetryAfterAtTheDeadline(t *testing.T) {
	srv := newOidcTestServer(t)
	srv.DeviceAuthHandler = func(w http.ResponseWriter, r *http.Request) {
		writeStatusJSON(w, http.StatusOK, deviceAuthBody(nil)) // expires_in 30 s
	}
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) { rateLimited("100")(w) }
	client := newDeviceClient(t, srv)
	sleeps := &recordedSleeps{}
	client.pollSleep = sleeps.sleep

	_, err := client.DeviceLogin(context.Background(), DeviceLoginParams{
		TenantID:   testTenantUUID,
		OnUserCode: func(DeviceAuthorization) error { return nil },
	})
	var protocolErr *OAuthProtocolError
	if !errors.As(err, &protocolErr) || protocolErr.ErrorCode != "expired_token" || !errors.Is(err, ErrExpiredToken) {
		t.Fatalf("want the typed expired_token outcome of rule 4, got %T: %v", err, err)
	}
	if srv.TokenCalls() != 1 {
		t.Errorf("nothing may be sent after the deadline: got %d token calls, want 1", srv.TokenCalls())
	}
	for _, d := range sleeps.got() {
		if d > 30*time.Second {
			t.Errorf("a wait of %v runs past the 30 s deadline", d)
		}
	}
}

func TestDevicePollRaisesTheTypedRateLimitErrorWithItsRetryAfter(t *testing.T) {
	// The single call is unchanged by 1.64: it raises (§14.2 rule 9, 1.63); only
	// the loop waits.
	srv := newOidcTestServer(t)
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) { rateLimited("7")(w) }
	_, err := newDeviceClient(t, srv).DevicePoll(context.Background(), DevicePollParams{
		DeviceCode: Sensitive(testDeviceCode), TenantID: testTenantUUID,
	})
	var protocolErr *OAuthProtocolError
	if !errors.As(err, &protocolErr) || protocolErr.ErrorCode != "rate_limit_exceeded" {
		t.Fatalf("want *OAuthProtocolError rate_limit_exceeded, got %T: %v", err, err)
	}
	if protocolErr.RetryAfter != 7*time.Second {
		t.Errorf("RetryAfter: got %v, want 7s", protocolErr.RetryAfter)
	}
}

// runDeviceLogin drives DeviceLogin against the scripted token answers with a
// recorded sleep, and returns the waits it asked for and the token calls.
func runDeviceLogin(t *testing.T, script []func(http.ResponseWriter), opts ...Option) ([]time.Duration, int, error) {
	t.Helper()
	srv := newOidcTestServer(t)
	srv.DeviceAuthHandler = func(w http.ResponseWriter, r *http.Request) {
		writeStatusJSON(w, http.StatusOK, deviceAuthBody(nil)) // interval 1 s, expires_in 30 s
	}
	handler, _ := scriptedTokenHandler(t, script)
	srv.TokenHandler = handler
	client := newDeviceClient(t, srv, opts...)
	sleeps := &recordedSleeps{}
	client.pollSleep = sleeps.sleep
	_, err := client.DeviceLogin(context.Background(), DeviceLoginParams{
		TenantID:   testTenantUUID,
		OnUserCode: func(DeviceAuthorization) error { return nil },
	})
	return sleeps.got(), int(srv.TokenCalls()), err
}

func ok200(w http.ResponseWriter) { writeStatusJSON(w, http.StatusOK, deviceSuccessBody()) }

// §14.2 rule 6 (1.64 as amended, C164-16): a 5xx on the poll is a transport
// failure whatever its body — the body the server really sends is
// 500 {"error":"server_error"}, and it must not end the flow.
func TestDeviceLoginA500ServerErrorBodyMidPollIsNotTerminal(t *testing.T) {
	serverError := func(w http.ResponseWriter) {
		writeStatusJSON(w, http.StatusInternalServerError, map[string]any{
			"error": "server_error", "error_description": "internal failure",
		})
	}
	pinned := withJitterSource(func() float64 { return 0 })
	// Two 500s are absorbed by the §16 retry inside the first poll...
	waits, calls, err := runDeviceLogin(t, []func(http.ResponseWriter){serverError, serverError, ok200}, pinned)
	if err != nil || calls != 3 || !reflect.DeepEqual(waits, []time.Duration{time.Second}) {
		t.Errorf("two 500s then tokens: waits %v, calls %d, err %v", waits, calls, err)
	}
	// ...and a budget the 500s exhaust (three attempts) is not terminal either:
	// the loop waits its next interval and polls again.
	waits, calls, err = runDeviceLogin(t, []func(http.ResponseWriter){serverError, serverError, serverError, ok200}, pinned)
	if err != nil {
		t.Fatalf("a 500 server_error must not be terminal: %v", err)
	}
	if calls != 4 || !reflect.DeepEqual(waits, []time.Duration{time.Second, time.Second}) {
		t.Errorf("three 500s then tokens: waits %v, calls %d", waits, calls)
	}
}

// §14.2 rule 9 (1.64 as amended, C164-04): the status decides. A 429 whose body
// names slow_down does not raise the interval; only the 400 does.
func TestDeviceLoginA429SlowDownBodyDoesNotRaiseTheInterval(t *testing.T) {
	for _, code := range []string{"slow_down", "authorization_pending", "invalid_grant"} {
		t.Run(code, func(t *testing.T) {
			throttled := func(w http.ResponseWriter) {
				writeStatusJSON(w, http.StatusTooManyRequests, map[string]any{"error": code})
			}
			waits, calls, err := runDeviceLogin(t, []func(http.ResponseWriter){throttled, ok200})
			if err != nil {
				t.Fatalf("a 429 is the wait, whatever its body names: %v", err)
			}
			if calls != 2 {
				t.Errorf("token calls: got %d, want 2", calls)
			}
			if want := []time.Duration{time.Second, time.Second}; !reflect.DeepEqual(waits, want) {
				t.Errorf("waits: got %v, want %v (the interval is not raised)", waits, want)
			}
		})
	}
	// Control: the 400 slow_down does raise it.
	waits, _, err := runDeviceLogin(t, []func(http.ResponseWriter){
		func(w http.ResponseWriter) { writeStatusJSON(w, http.StatusBadRequest, oauthErrorBody("slow_down")) }, ok200,
	})
	if err != nil || !reflect.DeepEqual(waits, []time.Duration{time.Second, 6 * time.Second}) {
		t.Errorf("the 400 slow_down adds 5 s: waits %v, err %v", waits, err)
	}
}

// C164-17: a bodiless 429 (a proxy's) is the same wait, with its Retry-After as
// a minimum.
func TestDeviceLoginABodilessA429HonoursRetryAfterAsAFloor(t *testing.T) {
	bodiless := func(w http.ResponseWriter) {
		w.Header().Set("Retry-After", "7")
		w.WriteHeader(http.StatusTooManyRequests)
	}
	waits, _, err := runDeviceLogin(t, []func(http.ResponseWriter){bodiless, ok200})
	if err != nil {
		t.Fatalf("DeviceLogin: %v", err)
	}
	if want := []time.Duration{time.Second, 7 * time.Second}; !reflect.DeepEqual(waits, want) {
		t.Errorf("waits: got %v, want %v", waits, want)
	}
}

// C164-05, §14.2 rule 4: the deadline is wall-clock. The time OnUserCode takes
// counts: here it eats 10 s of a 12 s grant at a 5 s interval, so no poll goes
// out.
func TestDeviceLoginDeadlineIsWallClockNotASumOfWaits(t *testing.T) {
	srv := newOidcTestServer(t)
	srv.DeviceAuthHandler = func(w http.ResponseWriter, r *http.Request) {
		writeStatusJSON(w, http.StatusOK, deviceAuthBody(map[string]any{"expires_in": 12, "interval": 5}))
	}
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) { ok200(w) }
	client := newDeviceClient(t, srv)
	now := time.Now()
	client.pollNow = func() time.Time { return now }
	client.pollSleep = func(_ context.Context, d time.Duration) error { now = now.Add(d); return nil }

	_, err := client.DeviceLogin(context.Background(), DeviceLoginParams{
		TenantID:   testTenantUUID,
		OnUserCode: func(DeviceAuthorization) error { now = now.Add(10 * time.Second); return nil },
	})
	var protocolErr *OAuthProtocolError
	if !errors.As(err, &protocolErr) || protocolErr.ErrorCode != "expired_token" {
		t.Fatalf("want the typed expired_token, got %T: %v", err, err)
	}
	if srv.TokenCalls() != 0 {
		t.Errorf("no poll may go out past the wall-clock deadline: got %d", srv.TokenCalls())
	}
}

// C164-25, §14.2 rule 6 and §16.2: the device poll is §16-retried inside the
// attempt on a 5xx or a transport failure — never on a 429 — so a 500 costs a
// retry, not a full interval.
func serverError500(w http.ResponseWriter) {
	writeStatusJSON(w, http.StatusInternalServerError, map[string]any{
		"error": "server_error", "error_description": "db",
	})
}

func TestDeviceLoginRetriesA5xxInsideThePollNotAFullInterval(t *testing.T) {
	pinned := withJitterSource(func() float64 { return 0 })
	waits, calls, err := runDeviceLogin(t, []func(http.ResponseWriter){serverError500, ok200}, pinned)
	if err != nil {
		t.Fatalf("DeviceLogin: %v", err)
	}
	if calls != 2 || !reflect.DeepEqual(waits, []time.Duration{time.Second}) {
		t.Errorf("one wait and two requests (the second is the §16 retry): waits %v, calls %d", waits, calls)
	}

	// A 429 is not retried inside the poll: it costs the loop's wait, once.
	throttled := func(w http.ResponseWriter) {
		writeStatusJSON(w, http.StatusTooManyRequests, map[string]any{"error": "rate_limit_exceeded"})
	}
	waits, calls, err = runDeviceLogin(t, []func(http.ResponseWriter){throttled, ok200}, pinned)
	if err != nil || calls != 2 || !reflect.DeepEqual(waits, []time.Duration{time.Second, time.Second}) {
		t.Errorf("a 429 is one request per wait: waits %v, calls %d, err %v", waits, calls, err)
	}

	// WithRetryDisabled: exactly one attempt per poll.
	waits, calls, err = runDeviceLogin(t, []func(http.ResponseWriter){serverError500, ok200}, pinned, WithRetryDisabled())
	if err != nil || calls != 2 || !reflect.DeepEqual(waits, []time.Duration{time.Second, time.Second}) {
		t.Errorf("with retry disabled a 500 costs the interval: waits %v, calls %d, err %v", waits, calls, err)
	}
}

func TestDevicePollRetriesA5xxUnderTheBudgetThenSurfaces(t *testing.T) {
	srv := newOidcTestServer(t)
	handler, _ := scriptedTokenHandler(t, []func(http.ResponseWriter){serverError500, serverError500, ok200})
	srv.TokenHandler = handler
	client := newDeviceClient(t, srv, withJitterSource(func() float64 { return 0 }))
	tokens, err := client.DevicePoll(context.Background(), DevicePollParams{DeviceCode: Sensitive(testDeviceCode), TenantID: testTenantUUID})
	if err != nil || tokens.AccessToken.expose() != "device-access-token" || srv.TokenCalls() != 3 {
		t.Fatalf("two 500s then 200 within the budget: err %v, calls %d", err, srv.TokenCalls())
	}

	srv2 := newOidcTestServer(t)
	srv2.TokenHandler = func(w http.ResponseWriter, r *http.Request) { serverError500(w) }
	_, err = newDeviceClient(t, srv2, withJitterSource(func() float64 { return 0 })).DevicePoll(
		context.Background(), DevicePollParams{DeviceCode: Sensitive(testDeviceCode), TenantID: testTenantUUID})
	var netErr *NetworkError
	if !errors.As(err, &netErr) || srv2.TokenCalls() != int32(MaxAttempts) {
		t.Fatalf("an exhausted budget surfaces *NetworkError after %d requests: %T %v, calls %d", MaxAttempts, err, err, srv2.TokenCalls())
	}
}

// The retry inside the poll waits on the loop's clock and never past the
// deadline: a 503 whose Retry-After is far past it ends in expired_token with
// no request after.
func TestDeviceLoginInPollRetryIsCappedAtTheDeadline(t *testing.T) {
	unavailable := func(w http.ResponseWriter) {
		w.Header().Set("Retry-After", "100")
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	_, calls, err := runDeviceLogin(t, []func(http.ResponseWriter){unavailable, ok200})
	if !errors.Is(err, ErrExpiredToken) || calls != 1 {
		t.Fatalf("want expired_token after 1 request, got %v after %d", err, calls)
	}
}
