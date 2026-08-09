// Bounded read-only retry policy — CONTRACT.md §16.
//
// This replaces the ad-hoc policy that used to live in authz.go's
// retryReadOnly: 100 ms base, `backoff *= 2` with NO cap and NO jitter, and no
// Retry-After handling. Both omissions matter.
//
// Uncapped, the wait is bounded by nothing but the attempt count — a fourth or
// fifth attempt, had anyone raised the cap, would sleep for seconds with no
// ceiling in sight. Unjittered, every client that saw the same outage retries
// at the same instant, which is the thundering herd the backoff is supposed to
// prevent rather than schedule.
//
// Go was one of five SDKs that had invented its own policy, and all five
// disagreed. §16 is the table they now share.

package axiam

import (
	"context"
	"math/rand"
	"time"
)

const (
	// MaxAttempts is the §16.1 attempt cap: 1 initial + 2 retries.
	MaxAttempts = 3
	// BaseDelay is the §16.1 first backoff step.
	BaseDelay = 200 * time.Millisecond
	// MaxDelay is the §16.1 ceiling on any single computed backoff.
	MaxDelay = 5 * time.Second
)

// backoffFor returns the un-jittered backoff for a 1-based attempt:
// min(MaxDelay, BaseDelay * 2^(n-1)). Attempt 1 → 200ms, attempt 2 → 400ms.
func backoffFor(attempt int) time.Duration {
	d := BaseDelay << (attempt - 1)
	if d > MaxDelay || d <= 0 { // d <= 0 guards the shift overflowing.
		return MaxDelay
	}
	return d
}

// delayFor is the actual wait: full jitter over [0, backoff], then raised to
// any server-supplied Retry-After (§16.1).
//
// Full jitter, not backoff ± 10%. Partial jitter still leaves every client's
// retries clustered around the same instant; only spreading uniformly across
// the whole window actually decorrelates them.
//
// Retry-After is a floor, never a ceiling: the server is stating when it will
// be ready, so retrying sooner is not permitted — and a Retry-After of zero
// cannot shorten the wait below what jitter chose.
//
// fraction is the jitter draw in [0, 1], injected so tests can pin it.
func delayFor(attempt int, retryAfter time.Duration, fraction float64) time.Duration {
	if fraction < 0 {
		fraction = 0
	} else if fraction > 1 {
		fraction = 1
	}
	jittered := time.Duration(float64(backoffFor(attempt)) * fraction)
	if retryAfter > jittered {
		return retryAfter
	}
	return jittered
}

// retryReadOnly runs op under the §16 policy.
//
// op receives the 1-based attempt number so it can label its §19 request pair.
// §19.2 rule 5 requires one pair per attempt so a caller can count real wire
// calls; passing 1 every time would make a retried call indistinguishable from
// a single slow one.
//
// op MUST be side-effect-free. This helper — like every retry helper — cannot
// tell the difference, so routing a mutation through it would silently
// duplicate a side effect, or replay a single-use credential (an authorization
// code, a device code at redemption, a rotating refresh token) into a hard
// invalid_grant.
//
// Only *NetworkError is retried. The §2 taxonomy folds 408/429/5xx/transport
// into that one type, so this implements the whole §16.3 table: AuthError and
// AuthzError are decisive answers from the server, not transport failures.
func (c *Client) retryReadOnly(ctx context.Context, operation string, op func(ctx context.Context, attempt int) error) error {
	attempts := MaxAttempts
	if !c.retryEnabled {
		attempts = 1
	}

	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		lastErr = op(ctx, attempt)
		if lastErr == nil {
			return nil
		}
		netErr, retryable := lastErr.(*NetworkError)
		if !retryable || attempt == attempts {
			return lastErr
		}

		wait := delayFor(attempt, netErr.RetryAfter, c.jitter())
		// §16.5 — without this event a retried-then-succeeded call is
		// invisible: a slow success with no signal that the server is failing.
		c.telemetry.emit(RetryEvent{
			Operation: operation,
			Attempt:   attempt,
			Delay:     wait,
			Reason:    lastErr.Error(),
		})

		select {
		case <-ctx.Done():
			// The caller's deadline outranks our backoff. Returning ctx.Err()
			// rather than lastErr is deliberate: a cancelled context is the
			// caller's decision, not the server's failure.
			return ctx.Err()
		case <-time.After(wait):
		}
	}
	return lastErr
}

// jitter returns the [0, 1) draw for the next backoff, using the injected
// source when a test supplied one.
func (c *Client) jitter() float64 {
	if c.rand != nil {
		return c.rand()
	}
	return rand.Float64() //nolint:gosec // Jitter spreads retries; not a security decision.
}
