// AuthenticateDevice — the mTLS device login (CONTRACT.md §6.1 rules 6-10,
// contract 1.51).
//
// A device (or a service acting as one) that has been configured with a
// client certificate (WithClientCertificate) can authenticate the TLS
// handshake itself rather than a username/password or an OAuth2 grant:
// POST /api/v1/auth/device carries no body, and the certificate the
// transport already presented IS the credential.

package axiam

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/ilpanich/axiam-go-sdk/internal/refreshguard"
)

// deviceAuthPath is CONTRACT.md §6.1's device login route.
const deviceAuthPath = "/api/v1/auth/device"

// DeviceToken is CONTRACT.md §6.1 rule 6's response: the three fields the
// server sends back and nothing else. There is no refresh token — that is
// a server decision (dogfooding remediation plan D-6), not an omission
// here — so a device re-authenticates by calling AuthenticateDevice again,
// at the cost of one more TLS handshake.
type DeviceToken struct {
	// AccessToken is the certificate-bound access token (§6.1 rule 9: it
	// carries cnf.x5t#S256 naming the presented certificate's thumbprint).
	// Secret. Redacted from every fmt verb, log line and JSON rendering.
	AccessToken Sensitive
	// TokenType is always "Bearer" (§6.1 rule 9: token_type does NOT say
	// whether a token is bound — a certificate-bound device token is still
	// reported "Bearer"; §1.1.1 rule 5 says the same for gRPC).
	TokenType string
	// ExpiresIn is the access-token lifetime in seconds (default 900).
	ExpiresIn uint64
}

// deviceTokenResponseWire is the server's JSON body for a successful
// POST /api/v1/auth/device.
type deviceTokenResponseWire struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   uint64 `json:"expires_in"`
}

// AuthenticateDevice performs the CONTRACT.md §6.1 mTLS device login.
//
// Reachable ONLY on a client built with WithClientCertificate (§6.1 rule
// 7). Go has no builder typestate that would make that a compile error —
// AxiamClient/*Client here is one concrete, non-generic type whose identity
// is fixed at NewClient, and threading a type parameter through every
// option for the sake of one operation would widen every caller's type for
// no benefit — so the refusal is a runtime *AuthError, raised with ZERO
// wire calls: without a certificate the server would answer 401 in any
// case, so going to the wire would only turn a configuration mistake into
// an authentication failure once round-tripped.
//
// On success, the returned token is ADOPTED as this Client's credential —
// as a Login result is adopted — for the REST management surface and
// CheckAccess/BatchCheck. The server sets no cookie on this route, so
// unlike a password/OPAQUE/WebAuthn login the device token travels as an
// Authorization: Bearer header rather than through the cookie jar, and
// every subsequent request this Client makes carries NO Cookie header at
// all (via a jar that suppresses OUTBOUND cookies while still absorbing any
// the response sets) so a session cookie left over from an earlier Login()
// on this same Client cannot silently outrank the header — the server reads
// axiam_access before Authorization, and a client that logged in over mTLS
// and then let an old cookie ride along would be handing an attacker
// exactly the credential-confusion bug this guards against.
// Adopting also clears whatever this Client held before: the §9 refresh
// guard is reset to fresh (there is nothing to refresh a device token
// with), any previously adopted §12.1 client-credentials token is
// discarded, the §17 decision memo is cleared, and the §5.2 acting-tenant
// gate resets to "unknown" (a device token carries no LoginUserInfo to
// gate on — see the package doc's "acting tenant" section).
//
// The adopted token is HELD UNTIL REPLACED (CONTRACT.md 1.52 N4.4): it
// keeps being sent on every request until Logout() clears it or a later
// session-establishing call — Login, VerifyMfa, OPAQUE, a WebAuthn
// ceremony, an SSO completion, client-credentials adoption, or another
// AuthenticateDevice — replaces it. Refresh() never touches it.
//
// Rules 6 and 8: this call is NEVER routed through the §9 refresh guard,
// on the way in or on the way out. A 401 here — expired, revoked,
// unbound, unknown or untrusted certificate, or a Server-type certificate,
// all §6.1 rule 8's single authentication_failed shape — is this SDK's
// ordinary *AuthError, surfaced with the server's message verbatim, and a
// LATER 401 on the adopted token (on any endpoint) is likewise returned
// as-is rather than triggering a refresh attempt: this call IS the login,
// so the caller's recovery path is calling it again. A 429 (the route is
// rate-limited per client IP) maps to *NetworkError, per §2's table, and
// is not retried — this call, like Login, is attempted exactly once.
func (c *Client) AuthenticateDevice(ctx context.Context) (DeviceToken, error) {
	if err := c.ensureOpen(); err != nil {
		return DeviceToken{}, err
	}

	// §6.1 rule 7. Checked before anything else in this function touches the
	// network.
	if !c.presentsClientCertificate {
		return DeviceToken{}, &AuthError{Message: "AuthenticateDevice requires a client certificate (CONTRACT.md §6.1 rule 7): configure one with WithClientCertificate before calling it — without one the server would answer 401 on the wire, so this SDK refuses client-side instead of making a call that cannot succeed"}
	}

	resp, err := c.deviceAuthPost(ctx)
	if err != nil {
		return DeviceToken{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// §6.1 rule 8: every refusal — 401 or 429 — reaches the caller as-is;
		// this call never enters the §9 refresh guard (rule 6), because a
		// device credential has no refresh token to spend.
		return DeviceToken{}, mapErrorResponse(resp)
	}

	var wire deviceTokenResponseWire
	if err := json.NewDecoder(resp.Body).Decode(&wire); err != nil {
		return DeviceToken{}, deserErr(err)
	}

	// Adopt. Clear the previous credential FIRST (guard, any adopted §12.1
	// token, the memo, the §5.2 gate) so nothing of an earlier session can
	// survive into one that has none of it, then set the new one.
	c.session.guard.Store(&refreshguard.Guard{})
	c.adoptOidcCredential("")
	c.onCredentialChange()
	c.resetScopeUnknown()
	c.replaceDeviceCredential()

	token := Sensitive(wire.AccessToken)
	c.adoptDeviceCredential(token)

	return DeviceToken{
		AccessToken: token,
		TokenType:   wire.TokenType,
		ExpiresIn:   wire.ExpiresIn,
	}, nil
}

// deviceAuthPost sends the login POST itself carrying NO session credential
// — no Authorization header (a stale adopted credential from a previous
// AuthenticateDevice call would be pointless and confusing to send back to
// the route that is about to replace it) and no cookie (the same "an old
// session must not silently win" concern rule 9's docs above describe,
// applied to the very call that establishes the new one). It deliberately
// bypasses doRequest/decorateRequest for the same reason
// sessionlessWebauthnPost does: this call authenticates by the transport's
// client certificate alone, and nothing decorateRequest would attach
// belongs on it.
func (c *Client) deviceAuthPost(ctx context.Context) (*http.Response, error) {
	req, err := c.newRequest(ctx, http.MethodPost, deviceAuthPath, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Tenant-ID", c.tenantSlug)
	if c.actingTenant != nil {
		req.Header.Set("X-Axiam-Tenant", c.actingTenant.String())
	}

	sender := *c.httpc
	sender.Jar = noOutboundCookieJar{real: c.httpc.Jar}
	resp, err := sender.Do(req)
	if err != nil {
		return nil, newNetworkError(fmt.Sprintf("request failed: %v", err), nil, err)
	}
	c.captureCSRFFromResponse(resp)
	return resp, nil
}
