// Reactor event registry — CONTRACT.md §22.5, §22.7, §22.8.
//
// The registry is served live at `GET /api/v1/reactors/events`, and that is
// the copy an admin UI should read. This file restates it because a reactor
// runtime has to validate an incoming event name and a handler's patch keys
// on the delivery path, where a network call is not available — the same
// reason the contract restates it in prose and the server keeps it as pure
// data in `crates/axiam-core/src/models/reactor.rs`.
//
// What is deliberately ABSENT is load-bearing: the three hot-path decision
// operations — the single authorization check, the batch check and token
// introspection — are not hookable (§22.7, a MUST NOT), so they appear in no
// constant, no slice and no example anywhere in this package. Their names
// are not written here either, so that reactor_registry_test.go can enforce
// the rule with a plain scan of the source rather than a judgement call
// about which mentions are innocent.
//
// A reactor round-trip is milliseconds and the check path's budget is
// microseconds — an application that needs external input on an
// authorization decision writes a deny grant, which the engine evaluates at
// hot-path cost.

package amqp

import "strings"

// The five interceptable events in contract v1 (§22.5).
const (
	// ReactorEventTokenPreIssue fires before an access token is issued.
	// Mutable: claims under the `ext.` namespace only.
	ReactorEventTokenPreIssue = "token.pre_issue"
	// ReactorEventLoginPostAuth fires after credentials verify and before
	// any session or token is issued — on password login, on SAML ACS and
	// on the OIDC callback alike (§22.5, SEC-095). Veto-only, and the only
	// event on which `require_mfa` is meaningful.
	ReactorEventLoginPostAuth = "login.post_auth"
	// ReactorEventUserPreCreate fires before a user is created.
	ReactorEventUserPreCreate = "user.pre_create"
	// ReactorEventUserPreUpdate fires before a user profile is updated.
	ReactorEventUserPreUpdate = "user.pre_update"
	// ReactorEventGrantPreAssign fires before a role or permission
	// assignment. Veto-only — four-eyes workflows live here.
	ReactorEventGrantPreAssign = "grant.pre_assign"
)

// Failure policies (§22.8). A registration that names neither inherits the
// strictest default among its events — see ReactorDefaultFailurePolicy.
const (
	// ReactorFailOpen proceeds as if the reactor had replied allow.
	ReactorFailOpen = "fail_open"
	// ReactorFailClosed denies the underlying operation, with an audited
	// reason naming the failure.
	ReactorFailClosed = "fail_closed"
)

// Registration modes (§22.5, §22.9).
const (
	// ReactorModeIntercept is synchronous request/response: the server waits
	// and the reply can veto or mutate within the event's allow-list.
	ReactorModeIntercept = "intercept"
	// ReactorModeListen is fire-and-forget observation. The server never
	// waits and never reads a reply, so a listener cannot affect any
	// outcome — and a listener handler MUST NOT publish one.
	ReactorModeListen = "listen"
)

// Budget constants (§22.8).
const (
	// ReactorDefaultTimeoutMS is the per-dispatch timeout a registration
	// gets when it names none.
	ReactorDefaultTimeoutMS = 500
	// ReactorMinTimeoutMS and ReactorMaxTimeoutMS bound `timeout_ms` at
	// registration; 0 and anything above the max are refused server-side.
	ReactorMinTimeoutMS = 1
	ReactorMaxTimeoutMS = 5000
	// ReactorChainCeilingMS is the wall-clock ceiling on a whole dispatch
	// chain. Reactors not reached inside it are not contacted at all, and
	// each of their own failure policies is applied anyway.
	ReactorChainCeilingMS = 5000
)

// ReactorExchange is the topic exchange every reactor event is published to
// (§22.1). The server declares it; a reactor runtime never does.
const ReactorExchange = "axiam.reactor.events"

// ReactorEventSpec is one hookable event: its name, what a reply may change,
// and what happens when the reactor does not answer.
type ReactorEventSpec struct {
	// Name is the wire name, and the second half of the routing key.
	Name string
	// Interceptable reports whether an interceptor may register for this
	// event at all. False means listen-only.
	Interceptable bool
	// Mutable reports whether an interceptor's reply may carry a patch.
	Mutable bool
	// MutableFields is the complete allow-list: exact field names, or a
	// namespace prefix ending in `.` — see PatchFieldAllowed.
	MutableFields []string
	// DefaultFailurePolicy is what a registration naming no policy gets for
	// this event, before the strictest-wins composition of §22.8.
	DefaultFailurePolicy string
	// Description is the one-liner the admin surface shows.
	Description string
}

// reactorEventRegistry mirrors EVENT_REGISTRY in
// crates/axiam-core/src/models/reactor.rs. Held unexported so a caller
// cannot mutate the SDK's copy of the allow-lists; ReactorEvents returns a
// defensive copy.
var reactorEventRegistry = []ReactorEventSpec{
	{
		Name:          ReactorEventTokenPreIssue,
		Interceptable: true,
		Mutable:       true,
		// Custom claims only. `sub`, `aud`, `exp`, `scope` and every other
		// standard claim are unreachable because none of them begins with
		// `ext.` — a hook that can rewrite `sub` is a hook that can mint a
		// token for anyone, and a correctly signed reply setting it is
		// refused exactly as a forged one is.
		MutableFields:        []string{"ext."},
		DefaultFailurePolicy: ReactorFailOpen,
		Description:          "Enrich or veto token issuance. May add claims under `ext.` only.",
	},
	{
		Name:                 ReactorEventLoginPostAuth,
		Interceptable:        true,
		Mutable:              false,
		MutableFields:        nil,
		DefaultFailurePolicy: ReactorFailClosed,
		Description:          "After credentials verify, before session issuance: veto or require step-up MFA.",
	},
	{
		Name:                 ReactorEventUserPreCreate,
		Interceptable:        true,
		Mutable:              true,
		MutableFields:        []string{"username", "email", "metadata."},
		DefaultFailurePolicy: ReactorFailClosed,
		Description:          "Validate or normalize a new user's profile fields.",
	},
	{
		Name:                 ReactorEventUserPreUpdate,
		Interceptable:        true,
		Mutable:              true,
		MutableFields:        []string{"username", "email", "metadata."},
		DefaultFailurePolicy: ReactorFailClosed,
		Description:          "Validate or normalize a profile update.",
	},
	{
		Name:                 ReactorEventGrantPreAssign,
		Interceptable:        true,
		Mutable:              false,
		MutableFields:        nil,
		DefaultFailurePolicy: ReactorFailClosed,
		Description:          "Veto a role or permission assignment (four-eyes workflows). Veto-only.",
	},
}

// ReactorEvents returns the hookable-event registry (§22.5) as a copy, so a
// caller cannot edit the SDK's own allow-lists in place.
//
// This is the local mirror. `GET /api/v1/reactors/events` serves the live
// list and is what an admin UI should read; this copy exists because the
// delivery path validates against it with no network available.
func ReactorEvents() []ReactorEventSpec {
	out := make([]ReactorEventSpec, len(reactorEventRegistry))
	for i, spec := range reactorEventRegistry {
		out[i] = spec
		if spec.MutableFields != nil {
			out[i].MutableFields = append([]string(nil), spec.MutableFields...)
		}
	}
	return out
}

// ReactorEventSpecFor looks an event up by wire name. The second return is
// false for any name outside the registry — including the three hot-path
// operations §22.7 excludes, which are absent by construction rather than by
// a filter that could be forgotten.
func ReactorEventSpecFor(name string) (ReactorEventSpec, bool) {
	for _, spec := range reactorEventRegistry {
		if spec.Name == name {
			if spec.MutableFields != nil {
				spec.MutableFields = append([]string(nil), spec.MutableFields...)
			}
			return spec, true
		}
	}
	return ReactorEventSpec{}, false
}

// PatchFieldAllowed reports whether field may appear in a patch for this
// event (§22.5).
//
// An allow-list entry ending in `.` is a NAMESPACE PREFIX: it matches a field
// that starts with the entry and has at least one character after the dot. So
// `ext.` admits `ext.department` and `ext.a.b.c`, and refuses `ext.` itself
// (it names the namespace, not a claim), `ext`, `extra`, `external_id` (a
// prefix match on the string is not a match on the namespace) and
// `evil.ext.department` (not a suffix match either).
//
// This mirrors ReactorEventSpec::patch_field_allowed in
// crates/axiam-core/src/models/reactor.rs.
func (s ReactorEventSpec) PatchFieldAllowed(field string) bool {
	if !s.Mutable {
		return false
	}
	for _, allowed := range s.MutableFields {
		if prefix, isNamespace := strings.CutSuffix(allowed, "."); isNamespace {
			if len(field) > len(prefix)+1 && strings.HasPrefix(field, allowed) {
				return true
			}
			continue
		}
		if field == allowed {
			return true
		}
	}
	return false
}

// ReactorDefaultFailurePolicy composes the failure policy a registration
// naming none inherits from its events (§22.8): the STRICTEST default wins,
// in either array order.
//
// A reactor registered for both `token.pre_issue` (open) and
// `login.post_auth` (closed) can veto a login, so it inherits fail_closed.
// Taking the first event's default instead would let the order of a JSON
// array decide whether an unreachable fraud check passes — which is why the
// contract states this as a MUST NOT reimplement rather than a note.
//
// An unknown event name contributes fail_closed: the server will refuse the
// registration outright, and guessing open on a name this SDK does not
// recognise is the wrong way to be wrong. An empty list is fail_closed for
// the same reason.
func ReactorDefaultFailurePolicy(events []string) string {
	if len(events) == 0 {
		return ReactorFailClosed
	}
	for _, name := range events {
		spec, ok := ReactorEventSpecFor(name)
		if !ok || spec.DefaultFailurePolicy == ReactorFailClosed {
			return ReactorFailClosed
		}
	}
	return ReactorFailOpen
}

// ReactorRoutingKey renders the topic routing key for one event:
// `<tenant_id>.<event>` (§22.1). Mirrors routing_key() in
// crates/axiam-amqp/src/reactor/protocol.rs.
//
// It is exported for logging, assertions and admin tooling. A reactor
// runtime never binds it: bindings are the server's, from the
// registration's `events`.
func ReactorRoutingKey(tenantID, event string) string {
	return tenantID + "." + event
}

// ReactorQueueName renders the durable per-reactor queue the SERVER declares:
// `axiam.reactor.q.<tenant_id>.<reactor_id>` (§22.1). Mirrors queue_name() in
// crates/axiam-amqp/src/reactor/protocol.rs.
//
// Deriving the name is not the same as declaring it. A reactor consumes this
// queue and nothing else; it never declares, redeclares or binds it, and
// never derives a name for a reactor other than the one it is configured as.
// A reactor that can bind is a reactor that can bind itself to
// `*.token.pre_issue` and read another tenant's issuance events.
func ReactorQueueName(tenantID, reactorID string) string {
	return "axiam.reactor.q." + tenantID + "." + reactorID
}
