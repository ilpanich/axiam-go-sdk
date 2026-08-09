// Telemetry hooks — CONTRACT.md §19.
//
// Wiring metrics to an AXIAM client WITHOUT this module depending on any
// metrics library. The sink below aggregates in-process so the example runs
// with no extra dependencies; the comment block at the bottom shows the exact
// mapping onto OpenTelemetry, which is a drop-in replacement for the body.
//
// Run: go run ./examples/telemetry-hook
package main

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	axiam "github.com/ilpanich/axiam-go-sdk"
)

// stat accumulates call count and total latency for one (operation, outcome).
type stat struct {
	count int
	total time.Duration
}

// sink is a §19 telemetry sink. It is mutex-guarded because hooks fire on
// whichever goroutine made the call, and a Go client is routinely shared.
type sink struct {
	mu       sync.Mutex
	requests map[string]*stat
	retries  map[string]int
}

func newSink() *sink {
	return &sink{requests: map[string]*stat{}, retries: map[string]int{}}
}

func (s *sink) record(event axiam.TelemetryEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch ev := event.(type) {
	// One pair per ATTEMPT, not per logical call (§19.2 rule 5), so counting
	// these gives the real number of wire calls — including the ones a retry
	// made on your behalf.
	case axiam.RequestEndEvent:
		key := fmt.Sprintf("%s/%s", ev.Operation, ev.Outcome)
		st, ok := s.requests[key]
		if !ok {
			st = &stat{}
			s.requests[key] = st
		}
		st.count++
		st.total += ev.Duration

	// §16.5 — the reason this event exists. A retried-then-succeeded operation
	// is otherwise invisible: the caller sees a slow success and no signal that
	// the server is failing. Alert on this rate, not on the error rate, or a
	// degrading server looks healthy right up until the retries stop being
	// enough.
	case axiam.RetryEvent:
		s.retries[ev.Operation]++
	}
}

func (s *sink) report() {
	s.mu.Lock()
	defer s.mu.Unlock()

	fmt.Println("--- requests (per attempt) ---")
	for key, st := range s.requests {
		fmt.Printf("  %-24s count=%d mean=%v\n", key, st.count, st.total/time.Duration(st.count))
	}
	fmt.Println("--- retries ---")
	if len(s.retries) == 0 {
		fmt.Println("  (none)")
	}
	for op, n := range s.retries {
		fmt.Printf("  %-24s %d\n", op, n)
	}
}

func main() {
	s := newSink()

	client, err := axiam.NewClient(
		"https://axiam.example.com", "acme",
		axiam.WithOrgSlug("acme"),
		axiam.WithTelemetryHook(s.record),
	)
	if err != nil {
		log.Fatalf("NewClient: %v", err)
	}
	// §18: release the client's local resources. Does not log out.
	defer func() { _ = client.Close() }()

	// This will fail — the host does not resolve — which is the point: a
	// failing call still emits a RequestEnd carrying the failure, and the §16
	// retries are visible as RetryEvents. Against a real server the same sink
	// reports the success path.
	allowed, reason, err := client.CheckAccess(
		context.Background(), "read", "00000000-0000-0000-0000-000000000000",
	)
	if err != nil {
		fmt.Printf("check failed as expected in this example: %v\n", err)
	} else {
		fmt.Printf("allowed=%v (%s)\n", allowed, reason)
	}

	s.report()
}

// ---------------------------------------------------------------------------
// The same sink, against OpenTelemetry
// ---------------------------------------------------------------------------
//
// This module deliberately requires no go.opentelemetry.io dependency — §19's
// whole point is that you choose your metrics stack. With the OTel API in YOUR
// go.mod, record becomes:
//
//	meter := otel.Meter("axiam-sdk")
//	duration, _ := meter.Float64Histogram("axiam.client.request.duration")
//	retries, _ := meter.Int64Counter("axiam.client.retries")
//
//	func record(event axiam.TelemetryEvent) {
//	    switch ev := event.(type) {
//	    case axiam.RequestEndEvent:
//	        duration.Record(ctx, ev.Duration.Seconds(), metric.WithAttributes(
//	            attribute.String("axiam.operation", ev.Operation),
//	            // The path TEMPLATE, never a substituted URL: a metric label
//	            // carrying a UUID is a cardinality bomb.
//	            attribute.String("http.route", ev.PathTemplate),
//	            attribute.Int("http.response.status_code", ev.Status),
//	            attribute.String("axiam.outcome", string(ev.Outcome)),
//	        ))
//	    case axiam.RetryEvent:
//	        retries.Add(ctx, 1, metric.WithAttributes(
//	            attribute.String("axiam.operation", ev.Operation),
//	            attribute.Int("axiam.attempt", ev.Attempt),
//	        ))
//	    }
//	}
//
// Two rules to keep in mind when writing any adapter:
//
//   - DO NOT BLOCK. Hooks run on the calling goroutine (§19.2 rule 4). Every
//     mature metrics library already buffers; if yours does not, buffer on your
//     side rather than doing I/O here.
//   - DO NOT ENRICH EVENTS FROM ELSEWHERE. TelemetryEvent is a closed interface
//     precisely so this surface cannot leak a token into a metrics backend
//     (§19.2 rule 3). Adding, say, the current Authorization header would
//     defeat that on your side of the boundary.
//
// A hook that panics is recovered by the SDK (§19.2 rule 2) — an authorization
// check is never failed by telemetry, and in Go an unrecovered panic would take
// the process down — but that is a backstop, not a licence to let a sink panic.
