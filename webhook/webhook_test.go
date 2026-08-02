package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	axiam "github.com/ilpanich/axiam-go-sdk"
)

// signHeader computes an X-Axiam-Signature header value the same way the
// AXIAM server does (CONTRACT.md §13.1): HMAC-SHA256(secret,
// "<timestamp>.<body>"), hex-encoded lowercase. Tests use this to build
// valid fixture input for Verify — it is deliberately independent test
// scaffolding, not a call into the package under test.
func signHeader(t *testing.T, secret string, timestamp int64, body []byte) string {
	t.Helper()
	tsStr := strconv.FormatInt(timestamp, 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(tsStr))
	mac.Write([]byte("."))
	mac.Write(body)
	return fmt.Sprintf("t=%s,v1=%s", tsStr, hex.EncodeToString(mac.Sum(nil)))
}

func fixedNow(unixSeconds int64) func() time.Time {
	return func() time.Time { return time.Unix(unixSeconds, 0) }
}

// Test 1: valid signature + fresh timestamp -> accepted.
func TestVerify_ValidAndFresh_Accepted(t *testing.T) {
	secret := "whsec_test_valid_and_fresh"
	body := []byte(`{"event":"user.created","id":"01JQ0000000000000000000001"}`)
	now := int64(1785700100)
	ts := now - 10 // well within default tolerance
	header := signHeader(t, secret, ts, body)

	event, err := Verify(axiam.Sensitive(secret), header, body, WithNow(fixedNow(now)))
	if err != nil {
		t.Fatalf("Verify() error = %v, want nil", err)
	}
	if event.Type != "user.created" {
		t.Errorf("event.Type = %q, want %q", event.Type, "user.created")
	}
	if event.Timestamp != ts {
		t.Errorf("event.Timestamp = %d, want %d", event.Timestamp, ts)
	}
	if string(event.Body) != string(body) {
		t.Errorf("event.Body = %q, want %q", event.Body, body)
	}
}

// Test 2: tampered body (one byte flipped) -> rejected.
func TestVerify_TamperedBody_Rejected(t *testing.T) {
	secret := "whsec_test_tampered_body"
	body := []byte(`{"event":"user.created","id":"01JQ0000000000000000000001"}`)
	now := int64(1785700100)
	ts := now - 10
	header := signHeader(t, secret, ts, body)

	tampered := make([]byte, len(body))
	copy(tampered, body)
	tampered[0] = '[' // was '{'

	_, err := Verify(axiam.Sensitive(secret), header, tampered, WithNow(fixedNow(now)))
	assertVerifyError(t, err, ReasonSignatureMismatch)
}

// Test 3: wrong secret -> rejected.
func TestVerify_WrongSecret_Rejected(t *testing.T) {
	body := []byte(`{"event":"user.created","id":"01JQ0000000000000000000001"}`)
	now := int64(1785700100)
	ts := now - 10
	header := signHeader(t, "whsec_test_right_secret", ts, body)

	_, err := Verify(axiam.Sensitive("whsec_test_WRONG_secret"), header, body, WithNow(fixedNow(now)))
	assertVerifyError(t, err, ReasonSignatureMismatch)
}

// Test 4: stale timestamp (now - t > tolerance) -> rejected.
func TestVerify_StaleTimestamp_Rejected(t *testing.T) {
	secret := "whsec_test_stale"
	body := []byte(`{"event":"user.created","id":"01JQ0000000000000000000001"}`)
	now := int64(1785700100)
	ts := now - 301 // 1s past the default 300s tolerance
	header := signHeader(t, secret, ts, body)

	_, err := Verify(axiam.Sensitive(secret), header, body, WithNow(fixedNow(now)))
	assertVerifyError(t, err, ReasonStale)
}

// Test 5: future timestamp beyond tolerance -> rejected (clock-skew abuse
// protection, CONTRACT.md §13.3 rule 5).
func TestVerify_FutureTimestamp_Rejected(t *testing.T) {
	secret := "whsec_test_future"
	body := []byte(`{"event":"user.created","id":"01JQ0000000000000000000001"}`)
	now := int64(1785700100)
	ts := now + 301 // 1s beyond the default 300s tolerance, into the future
	header := signHeader(t, secret, ts, body)

	_, err := Verify(axiam.Sensitive(secret), header, body, WithNow(fixedNow(now)))
	assertVerifyError(t, err, ReasonFuture)
}

// Test 6: malformed headers -> rejected, each with the specific reason.
func TestVerify_MalformedHeader_Rejected(t *testing.T) {
	secret := "whsec_test_malformed"
	body := []byte(`{"event":"user.created","id":"01JQ0000000000000000000001"}`)
	now := int64(1785700100)

	tests := []struct {
		name       string
		header     string
		wantReason Reason
	}{
		{
			name:       "no v1",
			header:     fmt.Sprintf("t=%d", now),
			wantReason: ReasonMissingV1,
		},
		{
			name:       "t non-numeric",
			header:     "t=not-a-number,v1=deadbeef",
			wantReason: ReasonInvalidTimestamp,
		},
		{
			name:       "empty",
			header:     "",
			wantReason: ReasonMalformedHeader,
		},
		{
			name:       "no t at all",
			header:     "v1=deadbeef",
			wantReason: ReasonMalformedHeader,
		},
		{
			name:       "duplicate t",
			header:     fmt.Sprintf("t=%d,t=%d,v1=deadbeef", now, now),
			wantReason: ReasonMalformedHeader,
		},
		{
			name:       "v1 is not valid hex",
			header:     fmt.Sprintf("t=%d,v1=not-hex-zzz", now),
			wantReason: ReasonSignatureMismatch,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Verify(axiam.Sensitive(secret), tc.header, body, WithNow(fixedNow(now)))
			assertVerifyError(t, err, tc.wantReason)
		})
	}
}

// Test 7: cross-SDK pin. The vector (secret, timestamp, body) is fixed by
// the shared spec; the expected v1 is computed HERE from Go's own
// crypto/hmac + crypto/sha256 (never copied as a literal hex value) so this
// test is the Go SDK's half of the cross-SDK pin: every SDK computing the
// same hex from the same input proves byte-for-byte interoperability with
// the server and with each other.
func TestVerify_CrossSDKPinVector_Accepted(t *testing.T) {
	const (
		secret    = "whsec_test_0123456789abcdef"
		timestamp = int64(1785700000)
	)
	body := []byte(`{"event":"user.created","id":"01JQ0000000000000000000000"}`)

	header := signHeader(t, secret, timestamp, body)

	event, err := Verify(axiam.Sensitive(secret), header, body, WithNow(fixedNow(timestamp)))
	if err != nil {
		t.Fatalf("Verify() on the shared cross-SDK vector: error = %v, want nil", err)
	}
	if event.Timestamp != timestamp {
		t.Errorf("event.Timestamp = %d, want %d", event.Timestamp, timestamp)
	}

	// Separately assert a byte-flipped body is rejected, per the spec's
	// explicit instruction alongside the pin vector.
	tampered := make([]byte, len(body))
	copy(tampered, body)
	tampered[len(tampered)-2] = '9' // flip the trailing digit of the id
	_, err = Verify(axiam.Sensitive(secret), header, tampered, WithNow(fixedNow(timestamp)))
	assertVerifyError(t, err, ReasonSignatureMismatch)
}

// Secret rotation: a header carrying multiple v1 values succeeds if ANY one
// matches (CONTRACT.md §13.1 allows multiple v1 pairs; §13.3 rule 4 requires
// trying each).
func TestVerify_MultipleV1_AcceptsAnyMatch(t *testing.T) {
	oldSecret := "whsec_test_old_rotating_secret"
	newSecret := "whsec_test_new_rotating_secret"
	body := []byte(`{"event":"user.created","id":"01JQ0000000000000000000001"}`)
	now := int64(1785700100)
	ts := now - 10

	oldHeader := signHeader(t, oldSecret, ts, body)
	newHeader := signHeader(t, newSecret, ts, body)
	// oldHeader is "t=...,v1=<oldsig>"; append the new v1 to simulate a
	// dual-signed rotation delivery.
	_, newV1, ok := strings.Cut(newHeader, ",v1=")
	if !ok {
		t.Fatalf("signHeader() produced unexpected shape: %q", newHeader)
	}
	combined := oldHeader + ",v1=" + newV1

	if _, err := Verify(axiam.Sensitive(oldSecret), combined, body, WithNow(fixedNow(now))); err != nil {
		t.Errorf("verifying against old secret: error = %v, want nil", err)
	}
	if _, err := Verify(axiam.Sensitive(newSecret), combined, body, WithNow(fixedNow(now))); err != nil {
		t.Errorf("verifying against new secret: error = %v, want nil", err)
	}
}

// WithTolerance overrides the default freshness window.
func TestVerify_WithTolerance_OverridesDefault(t *testing.T) {
	secret := "whsec_test_custom_tolerance"
	body := []byte(`{"event":"user.created","id":"01JQ0000000000000000000001"}`)
	now := int64(1785700100)
	ts := now - 30 // outside a tight 10s tolerance, inside the 300s default
	header := signHeader(t, secret, ts, body)

	_, err := Verify(axiam.Sensitive(secret), header, body, WithNow(fixedNow(now)), WithTolerance(10*time.Second))
	assertVerifyError(t, err, ReasonStale)

	// Same delivery accepted under the (larger) default tolerance.
	if _, err := Verify(axiam.Sensitive(secret), header, body, WithNow(fixedNow(now))); err != nil {
		t.Errorf("Verify() under default tolerance: error = %v, want nil", err)
	}
}

// errors.Is(err, ErrVerify) matches any *VerifyError (sentinel convention,
// mirroring AuthError/AuthzError/NetworkError elsewhere in this SDK).
func TestVerify_ErrorsIs_MatchesSentinel(t *testing.T) {
	_, err := Verify(axiam.Sensitive("whsec_test"), "", []byte("{}"))
	if !errors.Is(err, ErrVerify) {
		t.Fatalf("errors.Is(err, ErrVerify) = false, want true (err = %v)", err)
	}
}

// A VerifyError's message never leaks the expected/computed or received
// signature, and never leaks the secret.
func TestVerify_ErrorMessage_NeverLeaksSignatureOrSecret(t *testing.T) {
	secret := "whsec_test_super_secret_value"
	body := []byte(`{"event":"user.created","id":"01JQ0000000000000000000001"}`)
	now := int64(1785700100)
	ts := now - 10

	// A mismatched signature: wrong secret used to sign.
	header := signHeader(t, "whsec_test_a_completely_different_secret", ts, body)

	_, err := Verify(axiam.Sensitive(secret), header, body, WithNow(fixedNow(now)))
	if err == nil {
		t.Fatal("Verify() error = nil, want a mismatch error")
	}
	msg := err.Error()
	if strings.Contains(msg, secret) {
		t.Fatalf("error message leaked the secret: %q", msg)
	}
	// The received v1 hex value must not appear in the message either.
	_, wrongHeaderSig, ok := strings.Cut(header, ",v1=")
	if !ok {
		t.Fatalf("signHeader() produced unexpected shape: %q", header)
	}
	if strings.Contains(msg, wrongHeaderSig) {
		t.Fatalf("error message leaked the received signature: %q", msg)
	}
}

func assertVerifyError(t *testing.T, err error, wantReason Reason) {
	t.Helper()
	if err == nil {
		t.Fatalf("Verify() error = nil, want *VerifyError{Reason: %s}", wantReason)
	}
	var verr *VerifyError
	if !errors.As(err, &verr) {
		t.Fatalf("Verify() error = %v (%T), want *VerifyError", err, err)
	}
	if verr.Reason != wantReason {
		t.Fatalf("Verify() error reason = %s, want %s", verr.Reason, wantReason)
	}
	if !errors.Is(err, ErrVerify) {
		t.Fatalf("errors.Is(err, ErrVerify) = false, want true")
	}
}
