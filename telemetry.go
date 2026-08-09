// Telemetry hooks — CONTRACT.md §19.
//
// An optional callback surface so callers can wire OpenTelemetry, Prometheus or
// a log line WITHOUT this module depending on any of them. No hook installed
// costs one nil check per request.
//
// Two rules from §19.2 are enforced here rather than left to documentation:
//
//   - A hook cannot break the SDK. dispatcher.emit recovers from a panicking
//     hook, so a broken sink cannot fail an authorization check.
//   - No secrets, ever. TelemetryEvent is a closed interface implemented only
//     by the four structs below, each with a fixed field set and no map. There
//     is no place to put a token in a payload bound for a metrics backend — the
//     type, not a review comment, is what keeps them out.

package axiam

import "time"

// Outcome reports why a request finished.
type Outcome string

const (
	// OutcomeSuccess indicates the call returned a usable response.
	OutcomeSuccess Outcome = "success"
	// OutcomeFailure indicates the call failed, at any layer.
	OutcomeFailure Outcome = "failure"
)

// RefreshRole reports whether this caller performed a §9 refresh or waited on
// another goroutine's.
type RefreshRole string

const (
	// RefreshLeader means this caller performed the refresh.
	RefreshLeader RefreshRole = "leader"
	// RefreshFollower means this caller waited on another's refresh.
	RefreshFollower RefreshRole = "follower"
)

// TelemetryEvent is a §19 event.
//
// The interface is closed — isTelemetryEvent is unexported, so no package
// outside this one can add a variant. That is what makes the "no field can
// carry a secret" guarantee checkable rather than aspirational.
type TelemetryEvent interface {
	isTelemetryEvent()
}

// RequestStartEvent is emitted before an outbound call leaves the SDK.
type RequestStartEvent struct {
	// Operation is the canonical name, e.g. "CheckAccess".
	Operation string
	// Method is the HTTP method.
	Method string
	// PathTemplate is the route constant — "/api/v1/authz/check", never a URL
	// with ids substituted in. A metric label carrying a UUID is a cardinality
	// bomb.
	PathTemplate string
	// Attempt is 1 for the first try, incrementing per §16 retry.
	Attempt int
}

func (RequestStartEvent) isTelemetryEvent() {}

// RequestEndEvent is emitted after a call completes, success or failure.
type RequestEndEvent struct {
	Operation    string
	Method       string
	PathTemplate string
	Attempt      int
	// Status is the HTTP status, or 0 when the call never got a response.
	Status int
	// Duration is the wall-clock time this attempt took.
	Duration time.Duration
	Outcome  Outcome
}

func (RequestEndEvent) isTelemetryEvent() {}

// RetryEvent is emitted before each §16 retry wait.
//
// §16.5 requires this: a retried-then-succeeded operation is otherwise
// invisible — the caller sees a slow success and no signal that the server is
// failing. That silence is the standing objection to automatic retry.
type RetryEvent struct {
	Operation string
	// Attempt is the attempt that just failed.
	Attempt int
	// Delay is the wait about to be taken, after jitter and any Retry-After.
	Delay time.Duration
	// Reason is a redacted failure description. Never carries a token, because
	// NetworkError.Error() is redacted at construction (D-04/CR-04).
	Reason string
}

func (RetryEvent) isTelemetryEvent() {}

// RefreshEvent is emitted around a §9 single-flight refresh.
type RefreshEvent struct {
	Role     RefreshRole
	Duration time.Duration
}

func (RefreshEvent) isTelemetryEvent() {}

// TelemetryHook is a caller-supplied sink.
//
// It is invoked on the calling goroutine, so it must not block: §19.2 rule 4
// makes buffering the caller's job so they can pick the policy. Every mature
// metrics library already buffers.
type TelemetryHook func(TelemetryEvent)

// dispatcher wraps an optional hook. The nil hook is the common case.
type dispatcher struct {
	hook TelemetryHook
}

func (d dispatcher) installed() bool { return d.hook != nil }

// emit delivers event, recovering from a panicking hook.
//
// §19.2 rule 2: telemetry is not permitted to fail an authorization check. A
// hook that panics is the caller's bug, and letting it unwind here would turn
// a metrics problem into an authorization failure — or, worse in Go, take the
// process down.
func (d dispatcher) emit(event TelemetryEvent) {
	if d.hook == nil {
		return
	}
	defer func() {
		_ = recover() // Deliberately swallowed; see above.
	}()
	d.hook(event)
}

// span carries the state needed to close a §19 request pair.
type span struct {
	d       dispatcher
	op      string
	method  string
	path    string
	attempt int
	started time.Time
}

// startRequest emits RequestStart and returns the span that emits its
// RequestEnd.
//
// One pair per ATTEMPT, not per logical call: §19.2 rule 5 requires a caller to
// be able to count real wire calls from the events, which one pair per
// operation would hide.
func (d dispatcher) startRequest(op, method, path string, attempt int) span {
	s := span{d: d, op: op, method: method, path: path, attempt: attempt}
	if d.installed() {
		d.emit(RequestStartEvent{
			Operation:    op,
			Method:       method,
			PathTemplate: path,
			Attempt:      attempt,
		})
		s.started = time.Now()
	}
	return s
}

// end closes the pair opened by startRequest.
func (s span) end(status int, outcome Outcome) {
	if !s.d.installed() {
		return
	}
	s.d.emit(RequestEndEvent{
		Operation:    s.op,
		Method:       s.method,
		PathTemplate: s.path,
		Attempt:      s.attempt,
		Status:       status,
		Duration:     time.Since(s.started),
		Outcome:      outcome,
	})
}
