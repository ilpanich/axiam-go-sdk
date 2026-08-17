// Reactor handler binding — CONTRACT.md §22.14, the declarative form of a
// §22.10 handler.
//
// ReactorServe takes ONE function from an event to one answer. A reactor
// registered for three events therefore opens with a switch on event.Event,
// and that switch is where two bugs live: a typo'd event name that compiles
// and then never fires, and a `default` arm that returns ReactorAllow because
// allow is the shortest thing to type. The second one is the expensive one —
// it answers on behalf of code that never ran, which is how an operator's
// fail_closed setting gets defeated from inside the library (§22.10 rule 2).
//
// ReactorMux replaces the switch with a binding table. It is PURE SUGAR: it
// produces exactly the ReactorHandler ReactorServe already takes, adds no
// transport, no verification and no signing, and every §22 rule is enforced
// where it already was. What it adds is the two answers the switch got wrong:
//
//   - a name outside the §22.5 registry is refused when you BIND it, not
//     discovered when the event does not arrive;
//   - an event with no handler abstains — no reply, failure_policy decides
//     (§22.8) — rather than being allowed by a default arm.
//
// This mirrors §11's declarative authorization helpers: same discipline, one
// layer up, strictly on top of the runtime rather than beside it. §22.14's six
// rules are the ones enforced below; Go has no annotation mechanism and did not
// get one for §11 either, so the binding table is named for http.ServeMux.
package amqp

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// ErrReactorNoHandler is returned by a ReactorMux handler for an event no
// handler was bound for.
//
// Returning an error means NO REPLY is published and the registration's
// failure_policy decides (§22.8) — the honest outcome for "I do not know what
// this is", and deliberately not a synthesized allow (§22.10 rule 2). An event
// a reactor did not register for should never arrive at all; when one does,
// the registration and the code have drifted, and letting the operator's
// policy resolve it is the answer that cannot silently weaken the operator's
// configuration.
var ErrReactorNoHandler = errors.New("axiam: no reactor handler bound for this event")

// ReactorMux binds one handler per hook event and composes them into the
// single ReactorHandler ReactorServe takes.
//
// Bind with On, which is chainable and records rather than panics; Handler
// surfaces everything that went wrong at once:
//
//	handler, err := amqp.NewReactorMux().
//	    On(amqp.ReactorEventTokenPreIssue, enrichToken).
//	    On(amqp.ReactorEventLoginPostAuth, screenLogin).
//	    Handler()
//	if err != nil {
//	    return err
//	}
//	err = amqp.ReactorServe(ctx, dial, cfg, handler)
//
// A ReactorMux is built once at startup and is read-only afterwards, so the
// composed handler is safe for concurrent dispatch. Binding after Handler has
// been called mutates a table the running handler reads and is NOT supported.
type ReactorMux struct {
	handlers map[string]ReactorHandler
	order    []string
	errs     []error
}

// NewReactorMux returns an empty binding table.
func NewReactorMux() *ReactorMux {
	return &ReactorMux{handlers: make(map[string]ReactorHandler)}
}

// On binds handler to event. It is chainable and never panics: a rejected
// binding is recorded and reported by Handler.
//
// A binding is rejected when:
//
//   - event is not in the §22.5 registry. This is the typo guard, and it is
//     also what refuses §22.7's three hot-path operations — authorization
//     checks and introspection are not hookable, so they are in no registry
//     row and cannot be bound here either.
//   - event is already bound. A second binding is a mistake, never a silent
//     overwrite: which of the two would have run is not something the author
//     of either one can see.
//   - handler is nil.
func (m *ReactorMux) On(event string, handler ReactorHandler) *ReactorMux {
	if handler == nil {
		m.errs = append(m.errs, fmt.Errorf("axiam: reactor handler for %q is nil", event))
		return m
	}
	if _, ok := ReactorEventSpecFor(event); !ok {
		m.errs = append(m.errs, fmt.Errorf(
			"axiam: %q is not a hookable reactor event; the registry is [%s] "+
				"(authorization checks and token introspection are deliberately absent — §22.7)",
			event, strings.Join(reactorRegistryNames(), ", ")))
		return m
	}
	if _, dup := m.handlers[event]; dup {
		m.errs = append(m.errs, fmt.Errorf("axiam: reactor event %q is already bound", event))
		return m
	}
	m.handlers[event] = handler
	m.order = append(m.order, event)
	return m
}

// Events returns the bound event names in binding order.
//
// Pass it to ReactorDefaultFailurePolicy to see what an unreachable reactor
// costs before you go live — the strictest default among the events bound
// (§22.8), which is what the server derives from the registration.
func (m *ReactorMux) Events() []string {
	out := make([]string, len(m.order))
	copy(out, m.order)
	return out
}

// Handler composes the bindings into the single ReactorHandler ReactorServe
// takes, or reports every rejected binding.
//
// An empty mux is an error: a reactor that handles nothing would consume its
// queue and abstain from every event, which looks exactly like an outage.
func (m *ReactorMux) Handler() (ReactorHandler, error) {
	if err := errors.Join(m.errs...); err != nil {
		return nil, err
	}
	if len(m.handlers) == 0 {
		return nil, errors.New("axiam: ReactorMux has no bindings; bind at least one event with On")
	}

	// Snapshot so a later On cannot mutate the table this closure reads.
	bound := make(map[string]ReactorHandler, len(m.handlers))
	for event, handler := range m.handlers {
		bound[event] = handler
	}

	return func(ctx context.Context, event ReactorEvent) (ReactorAnswer, error) {
		handler, ok := bound[event.Event]
		if !ok {
			return ReactorAnswer{}, fmt.Errorf("%w: %s", ErrReactorNoHandler, event.Event)
		}
		// Called directly, NOT wrapped: an error or a panic from the handler
		// must reach ReactorServe unchanged so it publishes nothing (§22.10
		// rule 2). A recover() here would turn a crash into an answer.
		return handler(ctx, event)
	}, nil
}

func reactorRegistryNames() []string {
	specs := ReactorEvents()
	names := make([]string, 0, len(specs))
	for _, spec := range specs {
		names = append(names, spec.Name)
	}
	sort.Strings(names)
	return names
}
