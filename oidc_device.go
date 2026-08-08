package axiam

import (
	"context"
	"errors"
	"fmt"
	"net/url"
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
}

func newPollSchedule(interval, expiresIn time.Duration) *pollSchedule {
	if interval <= 0 {
		interval = DefaultDevicePollInterval
	}
	return &pollSchedule{interval: interval, remaining: expiresIn}
}

// slowDown applies one `slow_down` (§14.2 rule 1): cumulative, never reset.
func (p *pollSchedule) slowDown() { p.interval += SlowDownIncrement }

// tick consumes one interval's worth of the grant's remaining life and
// reports whether polling may continue. False means the deadline has been
// reached and the caller MUST stop (§14.2 rule 4) — the deadline is
// authoritative even if the server is still answering authorization_pending.
func (p *pollSchedule) tick() bool {
	if p.interval >= p.remaining {
		p.remaining = 0
		return false
	}
	p.remaining -= p.interval
	return true
}

// DeviceAuthorize performs `POST /oauth2/device_authorization` (CONTRACT.md
// §14.1) — start the device grant and obtain the code pair.
//
// UNAUTHENTICATED BY DESIGN. A device that cannot show a browser also cannot
// hold a client secret, so this never sends client_secret and never refuses a
// Client built without one (§14.1).
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
	if configuration.DeviceAuthorizationEndpoint == "" {
		return DeviceAuthorization{}, &AuthError{Message: "the authorization server's discovery document advertises no device_authorization_endpoint: this server does not support the device grant (CONTRACT.md §14.1)"}
	}

	form := url.Values{}
	form.Set("client_id", c.oidc.clientID)
	if params.Scope != "" {
		form.Set("scope", params.Scope)
	}

	endpoint, err := c.oidcEndpointURL(configuration.DeviceAuthorizationEndpoint, params.TenantID)
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
func (c *Client) DevicePoll(ctx context.Context, params DevicePollParams) (OidcTokenSet, error) {
	configuration, err := c.resolveOidcConfiguration(ctx, params.Configuration)
	if err != nil {
		return OidcTokenSet{}, err
	}

	form := url.Values{}
	form.Set("grant_type", deviceCodeGrantType)
	form.Set("device_code", params.DeviceCode.expose())
	form.Set("client_id", c.oidc.clientID)

	wire, err := c.postToken(ctx, configuration, form, params.TenantID)
	if err != nil {
		return OidcTokenSet{}, err
	}

	// No nonce: the device grant has no authorization request to carry one,
	// and §12.4 rule 6 applies to the authorization-code flow.
	return c.toTokenSet(ctx, wire, configuration, idTokenExpectations{
		issuer:       configuration.Issuer,
		clientID:     c.oidc.clientID,
		clockSkewSec: c.oidc.clockSkewSec,
	})
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
// 5 s PERMANENTLY; authorization_pending loops; access_denied and
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

	// §14.3 rule 2 — before any polling.
	if err := params.OnUserCode(authorization); err != nil {
		return OidcTokenSet{}, fmt.Errorf("OnUserCode reported the code could not be displayed: %w", err)
	}

	schedule := newPollSchedule(
		time.Duration(authorization.Interval)*time.Second,
		time.Duration(authorization.ExpiresIn)*time.Second,
	)

	for {
		// §14.2 rule 4: the deadline is authoritative. Checking before sleeping
		// keeps the SDK from issuing a request that can only be refused, and
		// reports it under the same expired_token code the server would have
		// used — so a caller's branch does not care which side noticed first.
		if !schedule.tick() {
			return OidcTokenSet{}, &OAuthProtocolError{
				AuthError:        AuthError{Message: "expired_token: the device authorization expired before the user completed it (client-side deadline from expires_in; CONTRACT.md §14.2 rule 4)"},
				ErrorCode:        "expired_token",
				ErrorDescription: "the device authorization expired before the user completed it",
			}
		}

		select {
		case <-ctx.Done():
			return OidcTokenSet{}, ctx.Err()
		case <-time.After(schedule.interval):
		}

		tokenSet, err := c.DevicePoll(ctx, DevicePollParams{
			DeviceCode:    authorization.DeviceCode,
			TenantID:      params.TenantID,
			Configuration: &configuration,
		})
		if err == nil {
			if params.AdoptAsCredential {
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
		var networkErr *NetworkError
		if errors.As(err, &networkErr) {
			continue
		}
		return OidcTokenSet{}, err
	}
}
