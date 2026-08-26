package axiam

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// The one request path every §27 management operation goes through.
//
// §27.8 is explicit that the generated layer MUST sit on the SDK's existing
// request path and MUST NOT build its own. That is what this file is: 146
// generated operations all funnel into sendManagement, so they inherit §3
// (CSRF), §4 (the cookie jar), §5 (X-Tenant-ID), §6 (TLS), §16 (retry) and §19
// (telemetry) by construction rather than by 146 opportunities to forget one.

// managementCall is one management call, fully resolved.
type managementCall struct {
	// operation is "users.create" — the registry's namespace-qualified name.
	operation string
	// method is the HTTP verb. Only GET is retry-eligible (§27.4 rule 8).
	method string
	// pathTemplate is "/api/v1/users/{user_id}", ids NOT substituted — the
	// §19.1 telemetry label, which must not carry identifiers.
	pathTemplate string
	// path is the same path with ids substituted, ready to send.
	path string
	// query carries the query parameters; unset ones are never added.
	query url.Values
	// body is the request body, already converted to its wire shape.
	body any
}

// requireSession refuses a management call with no session (§27.4 rule 1).
//
// Letting the request go out trades a clear local error for a 401 that the
// caller must then interpret, two indirections from the actual mistake.
func (c *Client) requireSession(operation string) error {
	if c.cookieValue(accessCookie) == "" {
		return &AuthError{Message: fmt.Sprintf(
			"%s: no active session — call Login before using the management API", operation)}
	}
	return nil
}

// sendManagement issues a management request and decodes its body into T.
//
// Only GET is routed through the §16 retry runner (§27.4 rule 8). No write
// here is retriable, not even the ones that look idempotent — generating a
// certificate twice mints two, and rotating a secret twice invalidates the one
// the caller already stored.
func sendManagement[T any](ctx context.Context, c *Client, call managementCall) (T, error) {
	var zero T
	if err := c.ensureOpen(); err != nil {
		return zero, err
	}
	if err := c.requireSession(call.operation); err != nil {
		return zero, err
	}

	var decoded T
	attempt := func(ctx context.Context, n int) error {
		raw, err := c.sendManagementOnce(ctx, call, n)
		if err != nil {
			return err
		}
		if len(raw) == 0 {
			decoded = zero
			return nil
		}
		if err := json.Unmarshal(raw, &decoded); err != nil {
			return &NetworkError{Message: fmt.Sprintf(
				"%s: could not decode the server's response: %v", call.operation, err)}
		}
		return nil
	}

	if call.method != http.MethodGet {
		if err := attempt(ctx, 1); err != nil {
			return zero, err
		}
		return decoded, nil
	}
	if err := c.retryReadOnly(ctx, call.operation, attempt); err != nil {
		return zero, err
	}
	return decoded, nil
}

// sendManagementNoContent issues a management request that returns no body.
func sendManagementNoContent(ctx context.Context, c *Client, call managementCall) error {
	if err := c.ensureOpen(); err != nil {
		return err
	}
	if err := c.requireSession(call.operation); err != nil {
		return err
	}
	attempt := func(ctx context.Context, n int) error {
		_, err := c.sendManagementOnce(ctx, call, n)
		return err
	}
	if call.method != http.MethodGet {
		return attempt(ctx, 1)
	}
	return c.retryReadOnly(ctx, call.operation, attempt)
}

// sendManagementOnce performs exactly one attempt, with its §19 request pair.
func (c *Client) sendManagementOnce(ctx context.Context, call managementCall, attempt int) ([]byte, error) {
	var payload io.Reader
	if call.body != nil {
		encoded, err := json.Marshal(call.body)
		if err != nil {
			return nil, &NetworkError{Message: fmt.Sprintf(
				"%s: could not encode the request body: %v", call.operation, err)}
		}
		payload = bytes.NewReader(encoded)
	}

	req, err := c.newRequest(ctx, call.method, call.path, payload)
	if err != nil {
		return nil, err
	}
	// The query goes on RawQuery rather than into the path string: newRequest
	// routes through Client.url, which assigns to url.URL.Path, and a "?" in
	// that assignment is escaped into the path rather than starting a query.
	if len(call.query) > 0 {
		req.URL.RawQuery = call.query.Encode()
	}

	// §19.1: the telemetry label is the TEMPLATE, never the substituted path —
	// a label carrying a tenant's user ids is a cardinality explosion and a
	// disclosure at once.
	sp := c.telemetry.startRequest(call.operation, call.method, call.pathTemplate, attempt)

	resp, err := c.doRequest(req)
	if err != nil {
		sp.end(0, OutcomeFailure)
		return nil, err
	}
	defer resp.Body.Close()

	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		sp.end(resp.StatusCode, OutcomeFailure)
		return nil, &NetworkError{Message: fmt.Sprintf(
			"%s: could not read the server's response: %v", call.operation, readErr)}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		sp.end(resp.StatusCode, OutcomeFailure)
		return nil, managementError(call.operation, resp, body)
	}

	sp.end(resp.StatusCode, OutcomeSuccess)
	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	return body, nil
}

// managementError maps a failed management response onto the §2 taxonomy.
//
// Delegates to the shared errorFromHTTPStatus for everything §27 does not
// classify, so the two mappers cannot drift: this function's whole job is the
// three statuses §27.4 rule 7 names, and 404 is the one §2 genuinely lacks.
func managementError(operation string, resp *http.Response, body []byte) error {
	detail := describeManagementFailure(body)

	switch resp.StatusCode {
	case http.StatusNotFound:
		return &NotFoundError{
			Operation: operation,
			Message: fmt.Sprintf(
				"%s: not found (or not visible to this tenant)%s", operation, detail),
		}
	case http.StatusConflict:
		return &ConflictError{
			Operation: operation,
			Message:   fmt.Sprintf("%s: conflict%s", operation, detail),
		}
	case http.StatusBadRequest, http.StatusUnprocessableEntity:
		return &ValidationError{
			Operation: operation,
			Status:    resp.StatusCode,
			Message:   fmt.Sprintf("%s: request rejected%s", operation, detail),
			Fields:    parseFieldErrors(body),
		}
	}
	return errorFromHTTPStatus(resp.StatusCode, operation+detail, resp, nil)
}

// describeManagementFailure is a short suffix naming the server's complaint,
// where it made one.
func describeManagementFailure(body []byte) string {
	var envelope struct {
		Message string `json:"message"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(body, &envelope); err == nil {
		if envelope.Message != "" {
			return ": " + envelope.Message
		}
		if envelope.Error != "" {
			return ": " + envelope.Error
		}
	}
	if len(body) > 0 && !json.Valid(body) {
		text := string(body)
		if len(text) > 200 {
			text = text[:200]
		}
		return ": " + text
	}
	return ""
}
