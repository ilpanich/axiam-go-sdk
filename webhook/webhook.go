// Package webhook implements the T-145 / CONTRACT.md §13 webhook-signature
// verifier: HMAC-SHA256 verification of an inbound AXIAM webhook delivery,
// with Stripe-style signed-timestamp freshness checking.
//
// Without this package every integrator hand-rolls the HMAC comparison (or
// skips it) — this is the gap §13 closes.
package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	axiam "github.com/ilpanich/axiam-go-sdk"
)

// defaultTolerance is the default two-sided freshness window applied to the
// signature header's t= timestamp (CONTRACT.md §13.2/§13.3 rule 5): a
// delivery is accepted only when abs(now - t) <= defaultTolerance, unless
// overridden via WithTolerance.
const defaultTolerance = 300 * time.Second

// Event is the verified webhook delivery returned by Verify on success.
type Event struct {
	// Type is the top-level "event" field decoded from Body, best-effort:
	// "" if Body is not a JSON object or has no string "event" field. This
	// is a convenience only — verification has already succeeded against
	// the raw bytes by the time Type is populated, so a decode miss here is
	// never a verification failure.
	Type string
	// Timestamp is the verified t= value from the signature header (unix
	// seconds). X-Axiam-Timestamp carries the same value redundantly
	// (CONTRACT.md §13.3 rule 2); Verify does not read that header at all,
	// so if a caller also received it and wants to enforce equality, compare
	// it to Timestamp themselves.
	Timestamp int64
	// Body is the exact raw bytes that were verified, unmodified.
	Body []byte
}

// Reason is a stable, machine-readable code identifying why Verify rejected
// a delivery. It never carries the expected/computed signature or the
// secret (CONTRACT.md §13.3 rule 6).
type Reason string

const (
	// ReasonMalformedHeader covers a signature header that fails to parse:
	// empty, no "t=" pair, or more than one "t=" pair.
	ReasonMalformedHeader Reason = "malformed_header"
	// ReasonMissingV1 covers a header with a valid "t=" but no "v1=" pair
	// at all — CONTRACT.md §13.3 rule 3: this is always a failure, never
	// treated as "nothing to verify".
	ReasonMissingV1 Reason = "missing_v1"
	// ReasonInvalidTimestamp covers a "t=" value that is not a base-10
	// integer.
	ReasonInvalidTimestamp Reason = "invalid_timestamp"
	// ReasonSignatureMismatch covers a syntactically well-formed header
	// whose signature(s) do not verify against secret and body — including
	// the case where every "v1=" value fails hex decoding, which fails
	// closed into a mismatch rather than falling back to any other
	// comparison.
	ReasonSignatureMismatch Reason = "signature_mismatch"
	// ReasonStale covers a signature that verified but whose t= is too far
	// in the past (now - t > tolerance).
	ReasonStale Reason = "timestamp_too_old"
	// ReasonFuture covers a signature that verified but whose t= is too far
	// in the future (t - now > tolerance) — clock-skew abuse protection
	// (CONTRACT.md §13.3 rule 5).
	ReasonFuture Reason = "timestamp_too_new"
)

// VerifyError is returned when webhook signature verification fails. It is
// deliberately narrow — the fact of failure plus a stable Reason code — and
// NEVER carries the expected/computed signature, the received signature, or
// the secret (CONTRACT.md §13.3 rule 6): logging or displaying a VerifyError
// is always safe.
type VerifyError struct {
	Reason Reason
}

func (e *VerifyError) Error() string {
	return fmt.Sprintf("axiam: webhook signature verification failed: %s", e.Reason)
}

// Is reports whether target is the ErrVerify sentinel, enabling
// errors.Is(err, ErrVerify) to match any *VerifyError, mirroring the root
// package's AuthError/AuthzError/NetworkError sentinel-matching convention.
func (e *VerifyError) Is(target error) bool {
	return target == ErrVerify
}

// ErrVerify is the sentinel error for errors.Is-based discrimination
// convenience. It is never returned directly — only *VerifyError values are,
// which implement Is(target) to match this sentinel.
var ErrVerify = fmt.Errorf("axiam: webhook signature verification failed")

// Option configures Verify's behavior beyond its required parameters.
type Option func(*config)

type config struct {
	tolerance time.Duration
	now       func() time.Time
}

// WithTolerance overrides the default ±300-second freshness window applied
// to the signature header's t= timestamp (CONTRACT.md §13.2). tolerance <= 0
// is ignored (the default is kept).
func WithTolerance(tolerance time.Duration) Option {
	return func(c *config) {
		if tolerance > 0 {
			c.tolerance = tolerance
		}
	}
}

// WithNow overrides the clock Verify uses to evaluate freshness. Intended
// for tests that need a fixed or synthetic "now" without sleeping past the
// tolerance window; defaults to time.Now. A nil now is ignored (the default
// is kept).
func WithNow(now func() time.Time) Option {
	return func(c *config) {
		if now != nil {
			c.now = now
		}
	}
}

// Verify checks an inbound AXIAM webhook delivery's X-Axiam-Signature header
// against body, keyed by secret, per CONTRACT.md §13. It returns the parsed
// Event on success, or a *VerifyError (matchable via errors.Is(err,
// ErrVerify)) on any failure — never a generic/untyped error, and never one
// whose message leaks the expected signature or the secret.
//
// body MUST be the exact raw bytes received off the wire. Never re-serialize
// parsed JSON before calling Verify: re-encoding changes key order and
// whitespace, which produces different bytes than the server signed and
// breaks the MAC (CONTRACT.md §13.3 rule 1).
//
// signatureHeader is the raw X-Axiam-Signature header value, of the form
// "t=<unix_seconds>,v1=<hex_lowercase>[,v1=<hex_lowercase>...]". Only the
// t= value actually covered by the MAC is trusted (CONTRACT.md §13.3 rule
// 2) — Verify does not read the separate, redundant X-Axiam-Timestamp
// header at all; a caller who also has that header and wants to enforce
// equality should compare it to the returned Event.Timestamp themselves.
// Unknown keys in the header are ignored for forward compatibility, but a
// header with no v1 pair is always a failure (CONTRACT.md §13.3 rule 3) —
// Verify never treats "nothing to check" as success.
//
// The verification algorithm, in order:
//  1. Parse signatureHeader into its "t" and "v1" pair(s). Malformed
//     structure (empty header, no t, more than one t) -> ReasonMalformedHeader.
//     No v1 pair at all -> ReasonMissingV1.
//  2. Parse t as a base-10 integer. Non-numeric -> ReasonInvalidTimestamp.
//  3. Recompute HMAC-SHA256(secret, "<t>.<body>") using the exact t bytes
//     from the header (never a re-formatted integer) and the raw body bytes.
//  4. Constant-time compare (hmac.Equal, over decoded bytes — never a hex
//     string ==) against every supplied v1. A v1 value that fails hex
//     decoding is treated as a non-match for that candidate (fail closed;
//     never a fallback comparison) rather than aborting immediately, so a
//     header carrying multiple v1 values (secret rotation) still succeeds if
//     any one decodes and matches. If none match -> ReasonSignatureMismatch.
//  5. Freshness: reject when abs(now - t) > tolerance (default 300s,
//     overridable via WithTolerance) — a future-dated t is rejected exactly
//     like a stale one (CONTRACT.md §13.3 rule 5) -> ReasonStale/ReasonFuture.
//  6. On success, return the parsed Event.
func Verify(secret axiam.Sensitive, signatureHeader string, body []byte, opts ...Option) (Event, error) {
	cfg := config{tolerance: defaultTolerance, now: time.Now}
	for _, opt := range opts {
		opt(&cfg)
	}

	tRaw, v1s, err := parseSignatureHeader(signatureHeader)
	if err != nil {
		return Event{}, err
	}

	tInt, err := strconv.ParseInt(tRaw, 10, 64)
	if err != nil {
		return Event{}, &VerifyError{Reason: ReasonInvalidTimestamp}
	}

	mac := hmac.New(sha256.New, []byte(string(secret)))
	mac.Write([]byte(tRaw))
	mac.Write([]byte("."))
	mac.Write(body)
	computed := mac.Sum(nil)

	matched := false
	for _, v1 := range v1s {
		decoded, decodeErr := hex.DecodeString(v1)
		if decodeErr != nil {
			// Fail closed for this candidate: never fall back to a raw hex
			// string comparison. Keep checking any remaining candidates.
			continue
		}
		if hmac.Equal(decoded, computed) {
			matched = true
			break
		}
	}
	if !matched {
		return Event{}, &VerifyError{Reason: ReasonSignatureMismatch}
	}

	now := cfg.now().Unix()
	age := now - tInt
	switch {
	case age > int64(cfg.tolerance.Seconds()):
		return Event{}, &VerifyError{Reason: ReasonStale}
	case age < -int64(cfg.tolerance.Seconds()):
		return Event{}, &VerifyError{Reason: ReasonFuture}
	}

	return Event{Type: bestEffortEventType(body), Timestamp: tInt, Body: body}, nil
}

// parseSignatureHeader splits header into comma-separated key=value pairs
// and extracts exactly one "t" and every "v1" (CONTRACT.md §13.3 rule 3).
// Unknown keys and malformed (non "key=value") pairs are ignored for forward
// compatibility. Returns *VerifyError{ReasonMalformedHeader} for an empty
// header, a missing t, or more than one t; *VerifyError{ReasonMissingV1} for
// a header with a valid t but no v1 at all.
func parseSignatureHeader(header string) (t string, v1s []string, err error) {
	haveT := false
	for _, part := range strings.Split(header, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		key, val := kv[0], kv[1]
		switch key {
		case "t":
			if haveT {
				// More than one t is ambiguous — fail closed rather than
				// picking one arbitrarily.
				return "", nil, &VerifyError{Reason: ReasonMalformedHeader}
			}
			t = val
			haveT = true
		case "v1":
			v1s = append(v1s, val)
		}
	}
	if !haveT {
		return "", nil, &VerifyError{Reason: ReasonMalformedHeader}
	}
	if len(v1s) == 0 {
		return "", nil, &VerifyError{Reason: ReasonMissingV1}
	}
	return t, v1s, nil
}

// bestEffortEventType decodes body's top-level "event" string field for
// caller convenience. Any failure (non-JSON body, non-object body, missing
// or non-string "event" field) yields "" rather than an error: by the time
// this runs, Verify has already accepted body's raw bytes against the MAC,
// so a body that fails this best-effort decode is still a verified delivery.
func bestEffortEventType(body []byte) string {
	var envelope struct {
		Event string `json:"event"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return ""
	}
	return envelope.Event
}
