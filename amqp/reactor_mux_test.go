package amqp

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func muxAllow(context.Context, ReactorEvent) (ReactorAnswer, error) {
	return ReactorAllow(), nil
}

func TestReactorMux_DispatchesByEvent(t *testing.T) {
	mux := NewReactorMux().
		On(ReactorEventTokenPreIssue, func(context.Context, ReactorEvent) (ReactorAnswer, error) {
			return ReactorMutate(map[string]string{"ext.department": "engineering"}), nil
		}).
		On(ReactorEventLoginPostAuth, func(context.Context, ReactorEvent) (ReactorAnswer, error) {
			return ReactorDeny("embargoed region"), nil
		})

	handler, err := mux.Handler()
	if err != nil {
		t.Fatalf("Handler() error = %v", err)
	}

	answer, err := handler(context.Background(), ReactorEvent{Event: ReactorEventTokenPreIssue})
	if err != nil {
		t.Fatalf("token.pre_issue error = %v", err)
	}
	if answer.Decision() != "mutate" {
		t.Fatalf("token.pre_issue decision = %q, want mutate", answer.Decision())
	}

	answer, err = handler(context.Background(), ReactorEvent{Event: ReactorEventLoginPostAuth})
	if err != nil {
		t.Fatalf("login.post_auth error = %v", err)
	}
	if answer.Decision() != "deny" {
		t.Fatalf("login.post_auth decision = %q, want deny", answer.Decision())
	}
}

// An unbound event ABSTAINS — no reply, failure_policy decides (§22.8). The
// value of the sugar is that this is not a `default: return ReactorAllow()`
// arm, which would answer on behalf of code that never ran and override an
// operator's fail_closed setting from inside the library (§22.10 rule 2).
func TestReactorMux_UnboundEventAbstains(t *testing.T) {
	handler, err := NewReactorMux().On(ReactorEventTokenPreIssue, muxAllow).Handler()
	if err != nil {
		t.Fatalf("Handler() error = %v", err)
	}

	answer, err := handler(context.Background(), ReactorEvent{Event: ReactorEventGrantPreAssign})
	if !errors.Is(err, ErrReactorNoHandler) {
		t.Fatalf("error = %v, want ErrReactorNoHandler", err)
	}
	if answer.Decision() == "allow" {
		t.Fatal("unbound event produced an allow answer; it must abstain")
	}
	if !strings.Contains(err.Error(), ReactorEventGrantPreAssign) {
		t.Fatalf("error %q does not name the unbound event", err)
	}
}

// A handler's own error reaches the runtime unchanged so it publishes nothing
// (§22.10 rule 2). The mux must not catch, translate or answer for it.
func TestReactorMux_HandlerErrorPropagates(t *testing.T) {
	sentinel := errors.New("fraud service unreachable")
	handler, err := NewReactorMux().
		On(ReactorEventLoginPostAuth, func(context.Context, ReactorEvent) (ReactorAnswer, error) {
			return ReactorAnswer{}, sentinel
		}).
		Handler()
	if err != nil {
		t.Fatalf("Handler() error = %v", err)
	}

	if _, err := handler(context.Background(), ReactorEvent{Event: ReactorEventLoginPostAuth}); !errors.Is(err, sentinel) {
		t.Fatalf("error = %v, want the handler's own error", err)
	}
}

// A handler panic must reach ReactorServe's recover, which turns it into "no
// reply". A recover() inside the mux would turn a crash into an answer.
func TestReactorMux_HandlerPanicPropagates(t *testing.T) {
	handler, err := NewReactorMux().
		On(ReactorEventUserPreCreate, func(context.Context, ReactorEvent) (ReactorAnswer, error) {
			panic("boom")
		}).
		Handler()
	if err != nil {
		t.Fatalf("Handler() error = %v", err)
	}

	defer func() {
		if recover() == nil {
			t.Fatal("mux swallowed a handler panic")
		}
	}()
	_, _ = handler(context.Background(), ReactorEvent{Event: ReactorEventUserPreCreate})
}

func TestReactorMux_RejectsUnknownEvent(t *testing.T) {
	_, err := NewReactorMux().On("token.pre_isue", muxAllow).Handler()
	if err == nil {
		t.Fatal("a typo'd event name was accepted")
	}
	if !strings.Contains(err.Error(), "token.pre_isue") {
		t.Fatalf("error %q does not name the rejected event", err)
	}
}

func TestReactorMux_RejectsDuplicateBinding(t *testing.T) {
	_, err := NewReactorMux().
		On(ReactorEventTokenPreIssue, muxAllow).
		On(ReactorEventTokenPreIssue, muxAllow).
		Handler()
	if err == nil {
		t.Fatal("a duplicate binding was accepted")
	}
	if !strings.Contains(err.Error(), "already bound") {
		t.Fatalf("error %q does not explain the duplicate", err)
	}
}

func TestReactorMux_RejectsNilHandlerAndEmptyMux(t *testing.T) {
	if _, err := NewReactorMux().On(ReactorEventTokenPreIssue, nil).Handler(); err == nil {
		t.Fatal("a nil handler was accepted")
	}
	if _, err := NewReactorMux().Handler(); err == nil {
		t.Fatal("an empty mux was accepted")
	}
}

// Every rejected binding is reported, not just the first: a chained builder
// that surfaced one error per call would make fixing three typos three runs.
func TestReactorMux_ReportsEveryRejection(t *testing.T) {
	_, err := NewReactorMux().
		On("nope.one", muxAllow).
		On("nope.two", muxAllow).
		Handler()
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{"nope.one", "nope.two"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not mention %q", err, want)
		}
	}
}

// Events() feeds ReactorDefaultFailurePolicy so an author can see what an
// unreachable reactor costs (§22.8) without restating the registration.
func TestReactorMux_EventsFeedFailurePolicy(t *testing.T) {
	mux := NewReactorMux().
		On(ReactorEventTokenPreIssue, muxAllow).
		On(ReactorEventLoginPostAuth, muxAllow)

	events := mux.Events()
	if len(events) != 2 || events[0] != ReactorEventTokenPreIssue || events[1] != ReactorEventLoginPostAuth {
		t.Fatalf("Events() = %v, want binding order", events)
	}

	// token.pre_issue defaults open, login.post_auth defaults closed; the
	// strictest wins.
	if got := ReactorDefaultFailurePolicy(events); got != ReactorFailClosed {
		t.Fatalf("ReactorDefaultFailurePolicy(%v) = %q, want %q", events, got, ReactorFailClosed)
	}

	// The returned slice is a copy: mutating it must not disturb the mux.
	events[0] = "mutated"
	if mux.Events()[0] != ReactorEventTokenPreIssue {
		t.Fatal("Events() handed out the mux's own slice")
	}
}

// The composed handler snapshots its table, so a binding added afterwards
// cannot mutate what a running reactor dispatches through.
func TestReactorMux_HandlerSnapshotsBindings(t *testing.T) {
	mux := NewReactorMux().On(ReactorEventTokenPreIssue, muxAllow)
	handler, err := mux.Handler()
	if err != nil {
		t.Fatalf("Handler() error = %v", err)
	}

	mux.On(ReactorEventGrantPreAssign, muxAllow)

	if _, err := handler(context.Background(), ReactorEvent{Event: ReactorEventGrantPreAssign}); !errors.Is(err, ErrReactorNoHandler) {
		t.Fatalf("error = %v, want ErrReactorNoHandler from the snapshot", err)
	}
}
