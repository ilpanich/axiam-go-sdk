package axiam

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

const (
	checkPath      = "/api/v1/authz/check"
	batchCheckPath = "/api/v1/authz/check/batch"
)

// AccessCheck is a single access check request (CONTRACT.md §1). ResourceID
// is a string (server-side UUID) rather than a typed UUID so callers can
// pass either a UUID string or, in future, other resource-id encodings
// without a breaking type change; the server is the source of truth for
// validation.
type AccessCheck struct {
	Action     string `json:"action"`
	ResourceID string `json:"resource_id"`
	Scope      string `json:"scope,omitempty"`
	// SubjectID is optional and, when set, asks the server to evaluate the
	// check for this subject rather than the caller's own session
	// (CONTRACT.md §11.2 — declarative authorization helpers pass the
	// request's authenticated user_id here so the check runs for the end
	// user, not the application's own service-account session). Omitted
	// from the wire payload when empty, preserving today's request shape
	// for CheckAccess/Can/BatchCheck callers that never set it.
	SubjectID string `json:"subject_id,omitempty"`
}

// AccessResult is the outcome of a single access check (mirrors
// CheckAccessResponse).
type AccessResult struct {
	// Allowed reports whether the checked action is permitted.
	//
	// THIS FIELD ALONE CARRIES THE OUTCOME. ReasonCode explains it and never
	// contradicts it.
	Allowed bool `json:"allowed"`
	// Reason is the server's human-readable explanation, when it sent one.
	Reason string `json:"reason,omitempty"`
	// ReasonCode is the machine-readable decision reason (CONTRACT.md §11
	// rule 9, B1 deny-override): ReasonCodeAllowed, ReasonCodeNoGrant or
	// ReasonCodeDeniedByRule.
	//
	// THE TWO REFUSALS MEAN OPPOSITE THINGS to the person on the other end.
	// no_grant says "ask an admin for access"; denied_by_rule says "an admin
	// has already decided". An application that cannot tell them apart sends
	// users to raise tickets that will be refused — which is why the contract
	// forbids collapsing them into a bare false.
	//
	// Empty when the server omits the field: a newer SDK against an older
	// server treats it as absent, never as an error. An unrecognised value is
	// surfaced verbatim and never changes Allowed — which is why this is a
	// plain string rather than a defined type with a closed set of constants.
	ReasonCode string `json:"reason_code,omitempty"`
}

// The three reason_code values CONTRACT.md §11 rule 9 defines.
//
// Untyped string constants rather than a named type, so an unrecognised
// server value is still a valid AccessResult.ReasonCode and reaches the
// caller — a closed type would tempt the SDK to drop what it cannot name.
const (
	// ReasonCodeAllowed: an allow grant matched and no deny did.
	ReasonCodeAllowed = "allowed"
	// ReasonCodeNoGrant: nothing matched — default deny. Ask an admin for
	// access.
	ReasonCodeNoGrant = "no_grant"
	// ReasonCodeDeniedByRule: an explicit deny rule matched and overrode any
	// allow. An admin has already decided.
	ReasonCodeDeniedByRule = "denied_by_rule"
)

type batchCheckRequestBody struct {
	Checks []AccessCheck `json:"checks"`
}

type batchCheckResponseWire struct {
	Results []AccessResult `json:"results"`
}

// CheckAccess performs POST /api/v1/authz/check (CONTRACT.md §1),
// evaluating a single authorization check for the given action/
// resourceID/scope. This is a read-only, idempotent operation eligible
// for CF-01's bounded retry on transient NetworkError.
func (c *Client) CheckAccess(ctx context.Context, action, resourceID string, scope ...string) (bool, string, error) {
	req := AccessCheck{Action: action, ResourceID: resourceID}
	if len(scope) > 0 {
		req.Scope = scope[0]
	}
	result, err := c.checkAccessWithRetry(ctx, req)
	if err != nil {
		return false, "", err
	}
	return result.Allowed, result.Reason, nil
}

// CheckAccessDecision performs the same check as CheckAccess but returns the
// FULL AccessResult, including the §11 rule 9 ReasonCode.
//
// It exists because CheckAccess's (bool, string, error) tuple predates that
// field and cannot carry it without a breaking signature change. The
// distinction it surfaces is not cosmetic: no_grant means "ask an admin for
// access", denied_by_rule means "an admin has already decided", and an
// application that cannot tell them apart sends users to raise tickets that
// will be refused.
//
// subjectID may be blank, in which case the check evaluates against this
// Client's own session exactly as CheckAccess does; a non-blank value behaves
// like CheckAccessAs (§11.2).
func (c *Client) CheckAccessDecision(ctx context.Context, subjectID, action, resourceID string, scope ...string) (AccessResult, error) {
	req := AccessCheck{Action: action, ResourceID: resourceID, SubjectID: subjectID}
	if len(scope) > 0 {
		req.Scope = scope[0]
	}
	return c.checkAccessWithRetry(ctx, req)
}

// Can is an alias for CheckAccess targeting browser/UI scenarios
// (CONTRACT.md §1 note) — returns only the allowed boolean.
func (c *Client) Can(ctx context.Context, action, resourceID string, scope ...string) (bool, error) {
	allowed, _, err := c.CheckAccess(ctx, action, resourceID, scope...)
	return allowed, err
}

// CheckAccessAs performs POST /api/v1/authz/check (CONTRACT.md §1) on behalf
// of subjectID rather than this Client's own session (CONTRACT.md §11.2).
// This is additive alongside CheckAccess — existing callers/signatures are
// unchanged — and exists specifically so declarative authorization helpers
// (middleware.RequireAccess) can evaluate the check for the request's
// authenticated user_id instead of the application's own (typically
// service-account) session. A blank subjectID behaves exactly like
// CheckAccess (the subject_id field is omitted from the wire request).
func (c *Client) CheckAccessAs(ctx context.Context, subjectID, action, resourceID string, scope ...string) (bool, string, error) {
	req := AccessCheck{Action: action, ResourceID: resourceID, SubjectID: subjectID}
	if len(scope) > 0 {
		req.Scope = scope[0]
	}
	result, err := c.checkAccessWithRetry(ctx, req)
	if err != nil {
		return false, "", err
	}
	return result.Allowed, result.Reason, nil
}

// BatchCheck performs POST /api/v1/authz/check/batch (CONTRACT.md §1),
// evaluating an ordered list of checks; results are returned in the same
// order as reqs. Eligible for CF-01's bounded retry (read-only).
func (c *Client) BatchCheck(ctx context.Context, reqs []AccessCheck) ([]AccessResult, error) {
	body := batchCheckRequestBody{Checks: reqs}

	var wire batchCheckResponseWire
	err := c.retryReadOnly(ctx, "BatchCheck", func(ctx context.Context, attempt int) error {
		w, err := c.sendAuthzPost(ctx, batchCheckPath, body, "BatchCheck", attempt)
		if err != nil {
			return err
		}
		wire = w
		return nil
	})
	if err != nil {
		return nil, err
	}
	return wire.Results, nil
}

func (c *Client) checkAccessWithRetry(ctx context.Context, req AccessCheck) (AccessResult, error) {
	if err := c.ensureOpen(); err != nil {
		return AccessResult{}, err
	}

	// §17: consult the memo first. Disabled by default, in which case this is
	// one map lookup that always misses.
	key := memoKey(req)
	if memoized, ok := c.memo.get(key); ok {
		return memoized, nil
	}

	var result AccessResult
	err := c.retryReadOnly(ctx, "CheckAccess", func(ctx context.Context, attempt int) error {
		resp, err := c.sendAuthzPostSingle(ctx, checkPath, req, "CheckAccess", attempt)
		if err != nil {
			return err
		}
		result = resp
		return nil
	})
	if err != nil {
		return AccessResult{}, err
	}

	// Only a decision the server actually returned is memoized: reaching here
	// means success, so §17.1 rule 7's ban on caching a failure is structural
	// rather than a check that could be forgotten.
	c.memo.set(key, result)
	return result, nil
}

// sendAuthzPostSingle POSTs body to path and decodes a single AccessResult.
func (c *Client) sendAuthzPostSingle(ctx context.Context, path string, body any, operation string, attempt int) (AccessResult, error) {
	var result AccessResult
	if err := c.sendAuthzPostInto(ctx, path, body, &result, operation, attempt); err != nil {
		return AccessResult{}, err
	}
	return result, nil
}

// sendAuthzPost POSTs body to path and decodes a batchCheckResponseWire.
func (c *Client) sendAuthzPost(ctx context.Context, path string, body any, operation string, attempt int) (batchCheckResponseWire, error) {
	var wire batchCheckResponseWire
	if err := c.sendAuthzPostInto(ctx, path, body, &wire, operation, attempt); err != nil {
		return batchCheckResponseWire{}, err
	}
	return wire, nil
}

// sendAuthzPostInto is the shared HTTP mechanics for the two authz POST
// endpoints: builds the request, decorates it (X-Tenant-ID + CSRF via
// doRequest), sends it, maps non-2xx per §2, and decodes the 2xx body into
// out.
func (c *Client) sendAuthzPostInto(ctx context.Context, path string, body any, out any, operation string, attempt int) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return &NetworkError{Message: fmt.Sprintf("failed to encode authz request: %v", err)}
	}

	req, err := c.newRequest(ctx, http.MethodPost, path, bytes.NewReader(payload))
	if err != nil {
		return err
	}

	// §19: one pair per attempt, with the route constant rather than a
	// substituted URL — a metric label carrying a UUID is a cardinality bomb.
	sp := c.telemetry.startRequest(operation, http.MethodPost, path, attempt)

	resp, err := c.doRequest(req)
	if err != nil {
		sp.end(0, OutcomeFailure)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		sp.end(resp.StatusCode, OutcomeFailure)
		return mapErrorResponse(resp)
	}

	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		sp.end(resp.StatusCode, OutcomeFailure)
		return deserErr(err)
	}
	sp.end(resp.StatusCode, OutcomeSuccess)
	return nil
}
