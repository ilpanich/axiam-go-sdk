// Command reactor demonstrates amqp.ReactorServe — an AXIAM Reactor, the
// AMQP extension actor of CONTRACT.md §22.
//
// A reactor is an external process that subscribes to named hook events on
// the AXIAM bus and answers back — allow, deny, or a field-allow-listed
// mutation — inside a timeout the server declared. Zitadel Actions and
// Keycloak SPIs solve the same problem by loading third-party code INTO the
// authorization server; a reactor stays outside it, reachable only through a
// signed reply schema the server validates before it believes a word of it.
//
// The handler below covers all three answers:
//
//   - token.pre_issue -> a mutation adding two claims under the `ext.`
//     namespace, which is the complete allow-list for that event (§22.5).
//   - login.post_auth -> a veto for one embargoed region, an allow for
//     everything else, and a commented step-up branch.
//
// Two things this example deliberately does NOT do, because §22 forbids
// them:
//
//   - It never declares an exchange, a queue or a binding. The server
//     declares the per-reactor queue from the registration; a reactor that
//     could bind could bind itself to another tenant's routing key (§22.1).
//   - It never answers `allow` on its own behalf when something goes wrong.
//     A handler that cannot decide returns an error, no reply is published,
//     and the operator's registered failure_policy decides — which for
//     login.post_auth defaults to fail_closed (§22.8, §22.10 rule 2).
//
// This example is illustrative/compilable: it reads its configuration from
// environment variables and does not require a live broker to
// `go build ./examples/reactor/...`. Running it end to end needs a reachable
// RabbitMQ over TLS at AXIAM_AMQP_URL and a reactor registered through
// POST /api/v1/reactors (§22.9).
//
// Run: go run ./examples/reactor
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/ilpanich/axiam-go-sdk/amqp"
)

func main() {
	amqpURL := getenv("AXIAM_AMQP_URL", "amqps://guest:guest@localhost:5671")
	tenantID := getenv("AXIAM_TENANT_ID", "11111111-1111-1111-1111-111111111111")
	reactorID := getenv("AXIAM_REACTOR_ID", "99999999-9999-9999-9999-999999999999")

	// §8.1: the per-tenant AMQP subkey MUST come from the AXIAM management
	// API — never hardcoded. The same key verifies the server's event and
	// signs this reactor's reply: §22.2's signing is symmetric in direction,
	// with no second key and no asymmetric variant in v1.
	signingKey, err := hex.DecodeString(getenv("AXIAM_AMQP_SIGNING_KEY_HEX", "00112233445566778899aabbccddeeff"))
	if err != nil {
		log.Fatalf("invalid AXIAM_AMQP_SIGNING_KEY_HEX: %v", err)
	}

	// §8b: amqps:// only, with an optional CA bundle. There is no
	// verification-skip switch anywhere in this SDK — HMAC does not
	// substitute for TLS and TLS does not substitute for HMAC.
	var dialOpts []amqp.AMQPSDialerOption
	if caPath := os.Getenv("AXIAM_AMQP_CA_PEM"); caPath != "" {
		caPEM, err := os.ReadFile(caPath)
		if err != nil {
			log.Fatalf("failed to read AXIAM_AMQP_CA_PEM: %v", err)
		}
		dialOpts = append(dialOpts, amqp.WithReactorCABundle(caPEM))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Printf("Reactor %s serving tenant %s\n", reactorID, tenantID)
	fmt.Printf("  queue (declared by the SERVER): %s\n", amqp.ReactorQueueName(tenantID, reactorID))
	fmt.Println("  hookable events:")
	for _, spec := range amqp.ReactorEvents() {
		fmt.Printf("    %-18s mutable=%-5v allow-list=%v default=%s\n",
			spec.Name, spec.Mutable, spec.MutableFields, spec.DefaultFailurePolicy)
	}

	// One handler per event, bound declaratively (README: "Binding handlers
	// per event"). A misspelled name is refused HERE, at startup, rather than
	// becoming an event that silently never fires — and there is no catch-all
	// arm that could answer `allow` for an event nobody wrote code for.
	mux := amqp.NewReactorMux().
		On(amqp.ReactorEventTokenPreIssue, enrichToken).
		On(amqp.ReactorEventLoginPostAuth, screenLogin)
	handler, err := mux.Handler()
	if err != nil {
		log.Fatalf("reactor handlers: %v", err)
	}

	// What an unreachable reactor costs, derived from the events actually
	// bound: the strictest default among them (§22.8). token.pre_issue
	// defaults open and login.post_auth defaults closed, so this prints
	// fail_closed — worth knowing before you go live.
	fmt.Printf("  failure policy when unreachable: %s\n",
		amqp.ReactorDefaultFailurePolicy(mux.Events()))

	err = amqp.ReactorServe(ctx,
		amqp.AMQPSDialer(amqpURL, dialOpts...),
		amqp.ReactorConfig{
			TenantID:   tenantID,
			ReactorID:  reactorID,
			SigningKey: signingKey,
			Mode:       amqp.ReactorModeIntercept,
		},
		handler,
		amqp.WithReactorTelemetryHook(logTelemetry),
	)
	if err != nil && !isShutdown(err) {
		log.Fatalf("reactor exited: %v", err)
	}
	fmt.Println("Reactor stopped; in-flight events drained.")
}

// logEvent prints the fields §22.12 says are explicitly not secrets.
//
// The payload is readable by design — a handler that cannot inspect the event
// cannot decide anything — but it is tenant business data, so it is not logged
// at info level here and should not be in yours.
//
// Chained events also carry the patch earlier reactors already produced, so a
// handler decides against the state that will actually be committed. That is
// READ-ONLY context: echoing it back inside your own patch is not how a field
// is preserved — the server merges (§22.6).
func logEvent(event amqp.ReactorEvent) {
	log.Printf("event=%s correlation=%s budget=%s", event.Event, event.CorrelationID, event.Timeout)
	if prior, ok := event.ChainPatch(); ok {
		log.Printf("  an earlier reactor in the chain already set %d field(s)", len(prior))
	}
}

// enrichToken handles token.pre_issue.
//
// Its context carries the dispatch deadline (§22.3), so a handler doing real
// work — a fraud lookup, a directory query — should honour it and shed load
// rather than answer into a window the server has already closed.
func enrichToken(ctx context.Context, event amqp.ReactorEvent) (amqp.ReactorAnswer, error) {
	logEvent(event)

	var payload struct {
		Sub      string `json:"sub"`
		ClientID string `json:"client_id"`
	}
	if err := event.DecodePayload(&payload); err != nil {
		// No reply: the registration's failure_policy decides. For
		// token.pre_issue that defaults to fail_open, because the mutation is
		// optional enrichment whose absence degrades a feature rather than a
		// decision.
		return amqp.ReactorAnswer{}, err
	}

	// `ext.` is the COMPLETE allow-list for this event. `sub`, `aud`, `exp`,
	// `scope` and every other standard claim are unreachable, and a correctly
	// signed reply setting one is refused exactly as a forged one is.
	//
	// Note also that a single forbidden key rejects the WHOLE patch — the SDK
	// sends what you return, unfiltered, rather than quietly dropping the
	// offender and leaving you believing it was set.
	return amqp.ReactorMutate(map[string]string{
		"ext.cost_center": lookupCostCenter(ctx, payload.Sub),
		"ext.department":  "eng",
	}), nil
}

// screenLogin handles login.post_auth — veto-only, plus step-up.
func screenLogin(_ context.Context, event amqp.ReactorEvent) (amqp.ReactorAnswer, error) {
	logEvent(event)

	var payload struct {
		Sub string `json:"sub"`
		IP  string `json:"ip"`
	}
	if err := event.DecodePayload(&payload); err != nil {
		return amqp.ReactorAnswer{}, err
	}
	if embargoed(payload.IP) {
		// The reason is audited. A deny with no reason still denies — the
		// reason is for the audit trail, not for the decision.
		return amqp.ReactorDeny("embargoed region"), nil
	}

	// Step-up is available here and ONLY here. It is not a separate decision
	// value: it is `allow` + require_mfa, and it means "proceed only after
	// step-up".
	//
	//	if unusualDevice(payload) {
	//	    return amqp.ReactorAllowWithStepUp(), nil
	//	}
	//
	// One caveat worth knowing before you enable it: SAML and OIDC sign-ins
	// complete in one round trip and have no step-up branch, so a require_mfa
	// answer on those paths FAILS the sign-in rather than being dropped. A
	// reactor that needs step-up there answers deny and drives enrolment out
	// of band (§22.5).
	return amqp.ReactorAllow(), nil
}

// logTelemetry is a §19 hook. It must not block: buffering is the caller's
// job so they can pick the policy, and a hook that panics is swallowed
// rather than allowed to fail a decision.
//
// Note what §22.8 makes this worth wiring: a fail_open timeout produces
// `allow` AND an audit record, and that pair is the whole difference between
// "no reactor was configured" and "the reactor never answered". Reactor
// health MUST NOT be inferred from the outcome alone.
func logTelemetry(e amqp.ReactorTelemetryEvent) {
	switch ev := e.(type) {
	case amqp.ReactorRepliedEvent:
		log.Printf("telemetry: replied %s to %s in %s", ev.Decision, ev.Event, ev.Duration)
	case amqp.ReactorNoReplyEvent:
		log.Printf("telemetry: NO REPLY for %s (%s) — the failure_policy now decides", ev.Event, ev.Reason)
	case amqp.ReactorRejectedEvent:
		log.Printf("telemetry: refused a delivery (%s)", ev.Reason)
	case amqp.ReactorReconnectEvent:
		log.Printf("telemetry: reconnecting in %s (attempt %d, %s)", ev.Delay, ev.Attempt, ev.Reason)
	}
}

// lookupCostCenter stands in for whatever this reactor exists to consult.
// A real one would honour ctx: its deadline is the server's, and an answer
// produced after it is discarded.
func lookupCostCenter(ctx context.Context, subject string) string {
	if ctx.Err() != nil || subject == "" {
		return "unknown"
	}
	return "42"
}

func embargoed(ip string) bool {
	return ip == "203.0.113.7"
}

func isShutdown(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// Compile-time proof the example's handlers match the SDK's handler type.
var (
	_ amqp.ReactorHandler = enrichToken
	_ amqp.ReactorHandler = screenLogin
)
