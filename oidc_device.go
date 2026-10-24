package axiam

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Device Authorization Grant (RFC 8628) — CONTRACT.md §14.

const (
	// deviceCodeGrantType is the grant_type of the device access-token
	// request (RFC 8628 §3.4).
	deviceCodeGrantType = "urn:ietf:params:oauth:grant-type:device_code"

	// DefaultDevicePollInterval is the polling interval used when the
	// authorization response omits `interval` (RFC 8628 §3.2, §14.2 rule 2).
	// An SDK MUST NOT hard-code a faster floor.
	DefaultDevicePollInterval = 5 * time.Second

	// SlowDownIncrement is added to the polling interval on each `slow_down`
	// (§14.2 rule 1). The increase is permanent and cumulative.
	SlowDownIncrement = 5 * time.Second
)

// pollSchedule is the §14.2 polling schedule: the interval, and the deadline
// it stops at.
//
// A plain value type with no I/O, so the arithmetic §14.2 rules 1, 2 and 4
// describe can be tested exhaustively and instantly. Driving that arithmetic
// through an httptest server would test net/http and a sleeping goroutine
// rather than the rule, and would take a real half-minute to assert one
// `slow_down`.
type pollSchedule struct {
	interval  time.Duration
	remaining time.Duration
	// floor is a one-shot minimum for the next wait: the Retry-After of a 429
	// (§14.2 rule 9, contract 1.64). It never changes interval.
	floor time.Duration
	// step is the wait the last tick() granted.
	step time.Duration
	// now and deadline, when set, make the deadline a wall-clock instant
	// (§14.2 rule 4): time spent in OnUserCode, in a request's round trip or in
	// a slow 5xx counts, which the sum of the waits alone does not.
	now      func() time.Time
	deadline time.Time
}

func newPollSchedule(interval, expiresIn time.Duration) *pollSchedule {
	if interval <= 0 {
		interval = DefaultDevicePollInterval
	}
	return &pollSchedule{interval: interval, remaining: expiresIn}
}

// slowDown applies one `slow_down` (§14.2 rule 1): cumulative, never reset.
func (p *pollSchedule) slowDown() { p.interval += SlowDownIncrement }

// rateLimited applies one `429 rate_limit_exceeded` (§14.2 rule 9, contract
// 1.64): the next wait is at least retryAfter, and it still counts as one
// interval. The interval itself is not raised.
func (p *pollSchedule) rateLimited(retryAfter time.Duration) { p.floor = retryAfter }

// tick consumes one wait's worth of the grant's remaining life and reports
// whether polling may continue; the wait it granted is p.step. A wait is the
// interval, or the Retry-After of the previous 429 when that is longer. False
// means the deadline has been reached and the caller MUST stop (§14.2 rule 4)
// — the deadline is authoritative even if the server is still answering
// authorization_pending, and a Retry-After past it is capped there: nothing is
// sent after the deadline.
func (p *pollSchedule) tick() bool {
	p.step = p.interval
	if p.floor > p.step {
		p.step = p.floor
	}
	p.floor = 0
	if p.now != nil && !p.now().Add(p.step).Before(p.deadline) {
		p.remaining = 0
		return false
	}
	if p.step >= p.remaining {
		p.remaining = 0
		return false
	}
	p.remaining -= p.step
	return true
}

// DeviceAuthorize performs `POST /oauth2/device_authorization` (CONTRACT.md
// §14.1) — start the device grant and obtain the code pair.
//
// CLIENT AUTHENTICATION (contract 1.62, §14.1 rules 1 and 2). The endpoint
// authenticates the client by the method it is REGISTERED for, as /token does.
//
//   - A PUBLIC client — the usual device, which cannot hold a secret — is built
//     without WithOidcClientSecret and sends client_id and NO credential here;
//     it is never refused client-side, and the server refuses a public client
//     that does send one.
//   - A client built WITH WithOidcClientSecret sends the secret as
//     `client_secret` in the form body, exactly as at its other token
//     requests, and exactly as the poll does. It NEVER sends
//     `Authorization: Basic`, whatever the client is registered for (§12.1 rule
//     3; the maintainer's 2026-10-16 "same rules" reading): the server accepts
//     either form of a secret here, and only the SDK's choice is fixed.
//   - A client built with WithClientCertificate presents that certificate on
//     the connection (and uses the discovery document's mTLS endpoint alias,
//     §21.3 rule 2), here and at the poll.
//
// This SDK sends a credential only when its caller configured one: it never
// borrows a secret from another configuration and never invents one. It does
// not generate a private_key_jwt client assertion (§21.8 is optional), so a
// client registered for that method cannot be driven by this SDK.
//
// A failed client authentication is 401 invalid_client (§14.1 rule 4) and
// surfaces as an *OAuthProtocolError whose ErrorCode is "invalid_client"; it is
// never retried and never enters the §9 refresh guard. A client that does not
// hold the device grant is 400 unauthorized_client.
//
// Returns an *AuthError when the discovery document advertises no
// device_authorization_endpoint. The URL is never built by concatenation onto
// the issuer: that works against AXIAM and breaks against every other OP the
// same code is pointed at.
func (c *Client) DeviceAuthorize(ctx context.Context, params DeviceAuthorizeParams) (DeviceAuthorization, error) {
	configuration, err := c.resolveOidcConfiguration(ctx, params.Configuration)
	if err != nil {
		return DeviceAuthorization{}, err
	}
	// §21.3 rule 2: prefer the mTLS alias when this call presents a client
	// certificate. An empty result at BOTH levels still means "unsupported" —
	// never a cue to build the URL by concatenation (§14.1).
	deviceEndpoint, err := c.preferredEndpoint(
		&configuration,
		func(a *MtlsEndpointAliases) string { return a.DeviceAuthorizationEndpoint },
		configuration.DeviceAuthorizationEndpoint,
	)
	if err != nil {
		return DeviceAuthorization{}, err
	}
	if deviceEndpoint == "" {
		return DeviceAuthorization{}, &AuthError{Message: "the authorization server's discovery document advertises no device_authorization_endpoint: this server does not support the device grant (CONTRACT.md §14.1)"}
	}

	form := url.Values{}
	form.Set("client_id", c.session.oidc.clientID)
	// §14.1 rule 2: a client configured with a secret authenticates here, in the
	// form body; a public client sends none (appendOidcClientSecret omits it).
	c.appendOidcClientSecret(form)
	if params.Scope != "" {
		form.Set("scope", params.Scope)
	}

	endpoint, err := c.oidcEndpointURL(deviceEndpoint, params.TenantID)
	if err != nil {
		return DeviceAuthorization{}, err
	}

	var wire deviceAuthorizationWire
	if err := c.postOAuth2Form(ctx, endpoint, form, &wire); err != nil {
		return DeviceAuthorization{}, err
	}

	interval := wire.Interval
	if interval <= 0 {
		// §14.2 rule 2: the interval comes from the response; only its absence
		// falls back to the RFC default. A server-sent 0 is treated as absent
		// — polling with no delay is never what the server meant.
		interval = int(DefaultDevicePollInterval / time.Second)
	}

	return DeviceAuthorization{
		DeviceCode:              Sensitive(wire.DeviceCode),
		UserCode:                wire.UserCode,
		VerificationURI:         wire.VerificationURI,
		VerificationURIComplete: wire.VerificationURIComplete,
		ExpiresIn:               wire.ExpiresIn,
		Interval:                interval,
	}, nil
}

// DevicePoll performs ONE `POST /oauth2/token` with the device-code grant
// (CONTRACT.md §14.1).
//
// The raw single call, so an application driving its own loop (a UI rendering
// a countdown, say) can. All five RFC 8628 §3.5 answers surface as
// *OAuthProtocolError — authorization_pending and slow_down included — so a
// hand-rolled loop sees exactly what DeviceLogin sees. Most callers want
// DeviceLogin.
//
// Contract 1.62: the poll NAMES ITS CLIENT — `client_id` is in the form body on
// every poll (a poll without one is 400 invalid_request) — and a client built
// with WithOidcClientSecret sends the secret as `client_secret` in the body,
// the same rule DeviceAuthorize follows and never `Authorization: Basic`. A
// public client sends no credential; an mTLS client presents its certificate.
//
// A 401 `invalid_client` — an unknown client, a failed credential, a public
// client that sent one, a client that no longer holds the grant, or a client
// bound to a key or certificate that sent no proof — is an *OAuthProtocolError
// with ErrorCode "invalid_client" after exactly one request: terminal, never
// retried, and it does not enter the §9 refresh guard (§14.2 rules 5 and 8).
//
// DPoP (§14.2 rule 8): this SDK implements the resource-server half of DPoP
// only (§21.7.3) and generates no proof, so it cannot drive a client
// registered for DPoP-bound tokens; the poll of such a client is refused
// `invalid_client` and surfaces as above.
func (c *Client) DevicePoll(ctx context.Context, params DevicePollParams) (OidcTokenSet, error) {
	return c.devicePoll(ctx, params, nil)
}

// devicePoll is DevicePoll with an optional bound on its §16 retry: from
// DeviceLogin the retry waits are capped at the grant's deadline, and a wait
// that ends there sends nothing after it (§14.2 rule 4).
//
// §14.2 rule 6 (C164-25): the poll is retried inside the attempt, under the
// bounded read-only policy of §16, on a transport failure or a 5xx whatever its
// body — never on a 429 or any 4xx, which are decisive here: the 429's wait is
// the loop's, and is never waited twice. With WithRetryDisabled it is one
// request.
func (c *Client) devicePoll(ctx context.Context, params DevicePollParams, bound *retryDeadline) (OidcTokenSet, error) {
	configuration, err := c.resolveOidcConfiguration(ctx, params.Configuration)
	if err != nil {
		return OidcTokenSet{}, err
	}

	form := url.Values{}
	form.Set("grant_type", deviceCodeGrantType)
	form.Set("device_code", params.DeviceCode.expose())
	form.Set("client_id", c.session.oidc.clientID)
	c.appendOidcClientSecret(form)

	preferred, err := c.preferredEndpoint(
		&configuration,
		func(a *MtlsEndpointAliases) string { return a.TokenEndpoint },
		configuration.TokenEndpoint,
	)
	if err != nil {
		return OidcTokenSet{}, err
	}
	endpoint, err := c.oidcEndpointURL(preferred, params.TenantID)
	if err != nil {
		return OidcTokenSet{}, err
	}

	var (
		wire     tokenResponseWire
		decisive error
	)
	retryErr := c.retryReadOnlyUntil(ctx, "device_poll", bound, func(ctx context.Context, _ int) error {
		req, err := c.newAbsoluteRequest(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
		if err != nil {
			decisive = err
			return errStopRetry
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := c.doRequest(req)
		if err != nil {
			if _, transport := err.(*NetworkError); transport {
				return err
			}
			decisive = err
			return errStopRetry
		}
		defer resp.Body.Close()
		switch {
		case resp.StatusCode >= 500:
			// Status before body: AXIAM answers 500 {"error":"server_error"},
			// which is a transport failure here, not a protocol answer.
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			netErr := newNetworkError(fmt.Sprintf("device_poll failed with HTTP %d", resp.StatusCode), resp, nil)
			netErr.RetryAfter = parseRetryAfter(resp.Header.Get("Retry-After"))
			return netErr
		case resp.StatusCode < 200 || resp.StatusCode >= 300:
			decisive = mapOAuth2ErrorResponse(resp)
			return errStopRetry
		}
		if err := json.NewDecoder(resp.Body).Decode(&wire); err != nil {
			decisive = deserErr(err)
			return errStopRetry
		}
		return nil
	})
	if decisive != nil {
		return OidcTokenSet{}, decisive
	}
	if errors.Is(retryErr, errRetryDeadline) {
		return OidcTokenSet{}, errDeviceExpired()
	}
	if retryErr != nil {
		return OidcTokenSet{}, retryErr
	}

	// No nonce: the device grant has no authorization request to carry one,
	// and §12.4 rule 6 applies to the authorization-code flow.
	return c.toTokenSet(ctx, wire, configuration, idTokenExpectations{
		issuer:       configuration.Issuer,
		clientID:     c.session.oidc.clientID,
		clockSkewSec: c.session.oidc.clockSkewSec,
	})
}

// errDeviceExpired is the typed expired_token outcome of §14.2 rule 4, raised
// locally when the grant's deadline is reached.
func errDeviceExpired() error {
	return &OAuthProtocolError{
		AuthError:        AuthError{Message: "expired_token: the device authorization expired before the user completed it (client-side deadline from expires_in; CONTRACT.md §14.2 rule 4)"},
		ErrorCode:        "expired_token",
		ErrorDescription: "the device authorization expired before the user completed it",
	}
}

// DeviceLogin is the composed §14.3 helper: start the grant, hand the caller
// the user code, poll to completion.
//
// params.OnUserCode is called BEFORE the first poll — §14.3 rule 2 requires
// the caller to have had the chance to display the code before polling
// begins. The SDK never prints it: what the device does with it (screen, QR
// code, e-ink panel) is the application's decision. An error from OnUserCode
// aborts without polling.
//
// Per §14.3 rule 4 (contract 1.7 errata) the token set is RETURNED; whether
// it is adopted is params.AdoptAsCredential, the same opt-in flag
// LoginClientCredentials uses in this SDK.
//
// Polling follows §14.2: the interval comes from the response; slow_down adds
// 5 s PERMANENTLY; authorization_pending loops; a 429 rate_limit_exceeded is
// waited out (Retry-After as a minimum, capped at the deadline, counted as one
// interval, the interval unchanged — rule 9, contract 1.64); access_denied and
// expired_token raise distinct errors; polling stops at ExpiresIn even if the
// server has not yet said expired_token. A 5xx or transport failure mid-poll
// is NOT terminal (rule 6) — the loop absorbs it and tries again, bounded by
// the same deadline, because a server restart must not lose a grant the user
// has already approved.
//
// ctx cancellation is honoured between polls: a device powering down should
// not have to wait out the interval.
func (c *Client) DeviceLogin(ctx context.Context, params DeviceLoginParams) (OidcTokenSet, error) {
	if params.OnUserCode == nil {
		return OidcTokenSet{}, &AuthError{Message: "DeviceLogin requires OnUserCode: the user cannot approve a code no one displayed (CONTRACT.md §14.3 rule 2)"}
	}

	configuration, err := c.resolveOidcConfiguration(ctx, params.Configuration)
	if err != nil {
		return OidcTokenSet{}, err
	}

	authorization, err := c.DeviceAuthorize(ctx, DeviceAuthorizeParams{
		Scope:         params.Scope,
		TenantID:      params.TenantID,
		Configuration: &configuration,
	})
	if err != nil {
		return OidcTokenSet{}, err
	}

	// The grant's lifetime runs from the authorization response (§14.2 rule 4).
	received := c.pollClock()

	// §14.3 rule 2 — before any polling.
	if err := params.OnUserCode(authorization); err != nil {
		return OidcTokenSet{}, fmt.Errorf("OnUserCode reported the code could not be displayed: %w", err)
	}

	schedule := newPollSchedule(
		time.Duration(authorization.Interval)*time.Second,
		time.Duration(authorization.ExpiresIn)*time.Second,
	)
	schedule.now = c.pollClock
	schedule.deadline = received.Add(time.Duration(authorization.ExpiresIn) * time.Second)

	// A §16 retry inside a poll waits on the loop's clock and never past the
	// deadline (§14.2 rules 4 and 6).
	bound := &retryDeadline{at: schedule.deadline, now: c.pollClock, sleep: c.waitPoll}

	for {
		// §14.2 rule 4: the deadline is authoritative. Checking before sleeping
		// keeps the SDK from issuing a request that can only be refused, and
		// reports it under the same expired_token code the server would have
		// used — so a caller's branch does not care which side noticed first.
		if !schedule.tick() {
			return OidcTokenSet{}, errDeviceExpired()
		}

		if err := c.waitPoll(ctx, schedule.step); err != nil {
			return OidcTokenSet{}, err
		}

		tokenSet, err := c.devicePoll(ctx, DevicePollParams{
			DeviceCode:    authorization.DeviceCode,
			TenantID:      params.TenantID,
			Configuration: &configuration,
		}, bound)
		if err == nil {
			if params.AdoptAsCredential {
				// CONTRACT.md 1.52 N5.5/N4.4 (C-12): see the matching
				// comment in oidc.go's LoginClientCredentials — this is the
				// same adoption shape, over the §14 device grant rather
				// than client_credentials.
				c.resetScopeUnknown()
				c.replaceDeviceCredential()
				c.adoptOidcCredential(tokenSet.AccessToken)
			}
			return tokenSet, nil
		}

		var protocolErr *OAuthProtocolError
		if errors.As(err, &protocolErr) {
			switch protocolErr.ErrorCode {
			case "authorization_pending":
				continue
			case "slow_down":
				schedule.slowDown() // §14.2 rule 1: cumulative, never reset.
				continue
			case "rate_limit_exceeded":
				// §14.2 rule 9 (contract 1.64): not terminal. Wait Retry-After
				// as a minimum, count it as one interval, leave the interval
				// alone and poll again. Capped at the deadline by tick().
				schedule.rateLimited(protocolErr.RetryAfter)
				continue
			default:
				// expired_token / access_denied / invalid_grant — terminal.
				return OidcTokenSet{}, err
			}
		}

		// §14.2 rule 6: transport and 5xx failures are not among the five
		// protocol answers and are not terminal. This SDK's §2 mapper folds
		// both into *NetworkError (see errorFromHTTPStatus), so one arm covers
		// "the socket broke" and "the server was restarting" alike — which is
		// exactly the pair rule 6 says must not lose an approved grant.
		//
		// A 429 or 503 that carries Retry-After and is not the typed
		// rate_limit_exceeded answer (an intermediary's, or a body naming
		// something else) is the same wait: the status decides, and Retry-After
		// is a floor (§14.2 rule 9, contract 1.64 as amended). Zero is a no-op.
		var networkErr *NetworkError
		if errors.As(err, &networkErr) {
			schedule.rateLimited(networkErr.RetryAfter)
			continue
		}
		return OidcTokenSet{}, err
	}
}

// pollClock is the device loop's clock: time.Now unless a test injected one.
func (c *Client) pollClock() time.Time {
	if c.pollNow != nil {
		return c.pollNow()
	}
	return time.Now()
}

// waitPoll sleeps d, or returns ctx's error when it ends first. The sleep is
// the Client's pollSleep when a test has injected one.
func (c *Client) waitPoll(ctx context.Context, d time.Duration) error {
	if c.pollSleep != nil {
		return c.pollSleep(ctx, d)
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
