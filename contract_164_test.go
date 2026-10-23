package axiam

// Contract 1.64 — §14.2 rule 9, last paragraph: a `429 rate_limit_exceeded` on
// a device-code poll is waited out, not raised (§14.6, #760 Q2). The 1.63
// §14.6 tests stay in oidc_device_test.go and contract_163_test.go unchanged.

import (
	"context"
	"errors"
	"net/http"
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
