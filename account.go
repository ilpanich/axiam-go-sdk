package axiam

// Account lifecycle and MFA enrolment — CONTRACT.md §25.
//
// §1 locked the MIDDLE of an account's life: Login, VerifyMfa, Refresh and
// Logout all assume an account that already exists, is verified, and already
// has its second factor. These nine operations are how an account gets into
// that state. None of them is new server surface — all nine have been live and
// unreachable-from-an-SDK since before §1 was written, which meant every
// application hand-rolled a POST against a path this SDK also knew.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

const (
	mfaEnrollPath             = "/api/v1/auth/mfa/enroll"
	mfaConfirmPath            = "/api/v1/auth/mfa/confirm"
	mfaSetupEnrollPath        = "/api/v1/auth/mfa/setup/enroll"
	mfaSetupConfirmPath       = "/api/v1/auth/mfa/setup/confirm"
	verifyEmailPath           = "/api/v1/auth/verify-email"
	resendVerificationPath    = "/api/v1/auth/resend-verification"
	resendOwnVerificationPath = "/api/v1/users/me/resend-verification"
	resetPath                 = "/api/v1/auth/reset"
	resetConfirmPath          = "/api/v1/auth/reset/confirm"
	resetContextPath          = "/api/v1/auth/reset/context"
)

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

// MfaEnrollment is a TOTP enrolment offer.
//
// THE FACTOR IS NOT ACTIVE YET. It becomes active when MfaConfirm accepts a
// code derived from this secret — which is why §25.2 rule 4 forbids a composed
// one-call helper here: the human step in the middle, scanning the URI and
// reading a code, is not something a helper can wait for, and one that returned
// after MfaEnroll would report MFA as enabled when it is not.
type MfaEnrollment struct {
	// SecretBase32 is the shared TOTP secret. Anyone holding it can generate
	// valid codes indefinitely.
	SecretBase32 Sensitive
	// TotpURI is otpauth://totp/...?secret=<SecretBase32> — so it CONTAINS the
	// secret beside it. Both are Sensitive for that reason, and this is the one
	// that actually reaches a log, because it is the one a caller hands to a QR
	// renderer (§25.3).
	TotpURI Sensitive
}

// PasswordResetContext is the effective OPAQUE policy for the account a reset
// token belongs to.
//
// It discloses no identity. Contract 1.26 removed the username from this
// response when OPAQUE replaced SRP — OPAQUE has no identity in its key
// derivation, so nothing needed it, and an unauthenticated endpoint that
// confirms which account a token belongs to is an oracle worth not having
// (§25.4 rule 2).
type PasswordResetContext struct {
	// Opaque carries the tenant's OPAQUE parameters when it has OPAQUE
	// enabled, and is nil when plaintext is accepted.
	Opaque map[string]any `json:"opaque,omitempty"`
}

// PasswordResetRequest names the account a reset mail should go to.
//
// Slugs are accepted here, as on Login — this is not an /oauth2/* endpoint and
// §12.1 rule 2's UUID requirement does not reach it. Empty fields fall back to
// the client's own configuration.
type PasswordResetRequest struct {
	Email      string
	OrgSlug    string
	TenantID   string
	TenantSlug string
}

// PasswordResetConfirmation carries everything ConfirmPasswordReset needs.
type PasswordResetConfirmation struct {
	// Token is the single-use token from the reset mail.
	Token Sensitive
	// NewPassword is the replacement password.
	NewPassword Sensitive
	// TenantID is the tenant the account belongs to. A UUID, and a BODY field —
	// this is not an /oauth2/* endpoint.
	TenantID string
	// Opaque is the §23 registration record, for a tenant whose
	// PasswordResetContext says it requires one. Sending a plaintext
	// NewPassword to a tenant in opaque_mode: required is refused, and refused
	// late (§25.4 rule 1).
	Opaque map[string]any
}

// ---------------------------------------------------------------------------
// Wire shapes
// ---------------------------------------------------------------------------

type mfaEnrollWire struct {
	SecretBase32 string `json:"secret_base32"`
	TotpURI      string `json:"totp_uri"`
}

type mfaConfirmWire struct {
	MfaEnabled bool `json:"mfa_enabled"`
}

type resetBody struct {
	Email      string `json:"email"`
	OrgSlug    string `json:"org_slug,omitempty"`
	TenantID   string `json:"tenant_id,omitempty"`
	TenantSlug string `json:"tenant_slug,omitempty"`
}

type resetConfirmBody struct {
	Token       string         `json:"token"`
	NewPassword string         `json:"new_password"`
	TenantID    string         `json:"tenant_id"`
	Opaque      map[string]any `json:"opaque,omitempty"`
}

// ---------------------------------------------------------------------------
// Voluntary MFA enrolment, by a signed-in user (§25.2)
// ---------------------------------------------------------------------------

// MfaEnroll performs POST /api/v1/auth/mfa/enroll (CONTRACT.md §25.1) — start
// voluntary TOTP enrolment for the signed-in user.
//
// Changes nothing about the current session. In particular it does NOT clear
// the §17 decision memo: the subject has not changed, and discarding a warm
// memo on an unrelated profile action costs a round trip on every check that
// follows (§25.2 rule 3).
func (c *Client) MfaEnroll(ctx context.Context) (MfaEnrollment, error) {
	if err := c.ensureOpen(); err != nil {
		return MfaEnrollment{}, err
	}
	resp, err := c.accountPost(ctx, mfaEnrollPath, struct{}{})
	if err != nil {
		return MfaEnrollment{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return MfaEnrollment{}, mapErrorResponse(resp)
	}
	var wire mfaEnrollWire
	if err := json.NewDecoder(resp.Body).Decode(&wire); err != nil {
		return MfaEnrollment{}, deserErr(err)
	}
	return MfaEnrollment{
		SecretBase32: Sensitive(wire.SecretBase32),
		TotpURI:      Sensitive(wire.TotpURI),
	}, nil
}

// MfaConfirm performs POST /api/v1/auth/mfa/confirm (CONTRACT.md §25.1) —
// activate the factor MfaEnroll offered, by proving a code derived from its
// secret.
func (c *Client) MfaConfirm(ctx context.Context, totpCode string) (bool, error) {
	if err := c.ensureOpen(); err != nil {
		return false, err
	}
	body := struct {
		TotpCode string `json:"totp_code"`
	}{TotpCode: totpCode}

	resp, err := c.accountPost(ctx, mfaConfirmPath, body)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, mapErrorResponse(resp)
	}
	var wire mfaConfirmWire
	if err := json.NewDecoder(resp.Body).Decode(&wire); err != nil {
		return false, deserErr(err)
	}
	return wire.MfaEnabled, nil
}

// ---------------------------------------------------------------------------
// Forced MFA enrolment, during login (§25.2)
// ---------------------------------------------------------------------------

// MfaSetupEnroll performs POST /api/v1/auth/mfa/setup/enroll (CONTRACT.md
// §25.1) — start the enrolment a Login demanded.
//
// Reached when Login returns MFASetupRequired: the tenant requires MFA and this
// account has none. There is no session yet — the setup token IS the
// credential.
func (c *Client) MfaSetupEnroll(ctx context.Context, setupToken Sensitive) (MfaEnrollment, error) {
	if err := c.ensureOpen(); err != nil {
		return MfaEnrollment{}, err
	}
	body := struct {
		SetupToken string `json:"setup_token"`
	}{SetupToken: setupToken.expose()}

	resp, err := c.accountPost(ctx, mfaSetupEnrollPath, body)
	if err != nil {
		return MfaEnrollment{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return MfaEnrollment{}, mapErrorResponse(resp)
	}
	var wire mfaEnrollWire
	if err := json.NewDecoder(resp.Body).Decode(&wire); err != nil {
		return MfaEnrollment{}, deserErr(err)
	}
	return MfaEnrollment{
		SecretBase32: Sensitive(wire.SecretBase32),
		TotpURI:      Sensitive(wire.TotpURI),
	}, nil
}

// MfaSetupConfirm performs POST /api/v1/auth/mfa/setup/confirm (CONTRACT.md
// §25.1) — finish forced enrolment and, with it, the login that was
// interrupted.
//
// Adopts credentials exactly as Login does, because it IS the completion of a
// login (§25.2 rule 2).
func (c *Client) MfaSetupConfirm(ctx context.Context, setupToken Sensitive, totpCode string) (LoginResult, error) {
	if err := c.ensureOpen(); err != nil {
		return LoginResult{}, err
	}
	c.onCredentialChange()

	body := struct {
		SetupToken string `json:"setup_token"`
		TotpCode   string `json:"totp_code"`
	}{SetupToken: setupToken.expose(), TotpCode: totpCode}

	resp, err := c.accountPost(ctx, mfaSetupConfirmPath, body)
	if err != nil {
		return LoginResult{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return LoginResult{}, mapErrorResponse(resp)
	}
	var wire loginSuccessResponseWire
	if err := json.NewDecoder(resp.Body).Decode(&wire); err != nil {
		return LoginResult{}, deserErr(err)
	}
	if err := c.absorbSessionCookies(); err != nil {
		return LoginResult{}, err
	}
	result := LoginResult{
		SessionID:         wire.SessionID.String(),
		ExpiresIn:         wire.ExpiresIn,
		OrganizationLevel: wire.User.OrganizationLevel,
	}
	principalScope(wire.User, &result)
	// §5.2.2: remember where this principal lives, so a later
	// OpaqueEnrollmentForSelf seals against the account's own tenant
	// without a second round trip.
	c.setPrincipalTenantID(result.PrincipalTenantID)
	return result, nil
}

// ---------------------------------------------------------------------------
// Email verification (§25.1)
// ---------------------------------------------------------------------------

// VerifyEmail performs POST /api/v1/auth/verify-email (CONTRACT.md §25.1).
//
// Unauthenticated: a user whose address is unverified may have no session at
// all. tenantID is a BODY field here — this is not an /oauth2/* endpoint, so
// §12.1 rule 2's query-parameter convention does not reach it.
func (c *Client) VerifyEmail(ctx context.Context, token Sensitive, tenantID string) error {
	if err := c.ensureOpen(); err != nil {
		return err
	}
	body := struct {
		Token    string `json:"token"`
		TenantID string `json:"tenant_id"`
	}{Token: token.expose(), TenantID: tenantID}

	return c.accountPostNoContent(ctx, verifyEmailPath, body)
}

// ResendVerification performs POST /api/v1/auth/resend-verification
// (CONTRACT.md §25.1) — the UNAUTHENTICATED resend, for a caller with no
// session.
//
// Returns nil whatever the outcome. The address may not exist, may already be
// verified, or may be over the daily limit, and this answers identically in all
// of them, because it takes an address from an anonymous caller and anything
// else is an oracle for which addresses have accounts (§25.7).
//
// A caller that IS signed in wants ResendOwnVerification, which says which of
// those happened. Do not reach for this one because it is the name you already
// knew.
func (c *Client) ResendVerification(ctx context.Context, email, tenantID string) error {
	if err := c.ensureOpen(); err != nil {
		return err
	}
	body := struct {
		Email    string `json:"email"`
		TenantID string `json:"tenant_id"`
	}{Email: email, TenantID: tenantID}

	return c.accountPostNoContent(ctx, resendVerificationPath, body)
}

// ResendOwnVerification performs POST /api/v1/users/me/resend-verification
// (CONTRACT.md §25.1, §25.7) — resends the SIGNED-IN CALLER'S OWN verification
// mail, and says what happened.
//
// Takes no address. The server reads it off the caller's own record, and this
// signature deliberately offers no way to name a different one: a parameter
// here would let an authenticated session mail an arbitrary address.
//
// Unlike ResendVerification this reports the outcome, because the caller is
// signed in to the account it is asking about and none of the outcomes tells it
// anything it did not already know:
//
//   - nil — a token was minted and the mail ENQUEUED. Delivery is asynchronous
//     and can still fail at the provider; a queue that accepts everything in
//     front of one that rejects it looks exactly like this succeeding.
//   - *AuthzError (from 409) — already verified, or the account is in a state
//     that must not be sent a live token.
//   - *NetworkError (from 429) — the daily resend limit.
//
// §25.7 rule 2 forbids falling back to the unauthenticated endpoint on either
// of those, and this SDK does not: the fallback would turn both failures back
// into a nil error and restore the bug this operation exists to fix, with an
// extra round-trip.
func (c *Client) ResendOwnVerification(ctx context.Context) error {
	if err := c.ensureOpen(); err != nil {
		return err
	}
	return c.accountPostNoContent(ctx, resendOwnVerificationPath, struct{}{})
}

// ---------------------------------------------------------------------------
// Password reset (§25.4)
// ---------------------------------------------------------------------------

// RequestPasswordReset performs POST /api/v1/auth/reset (CONTRACT.md §25.1) —
// ask for a reset mail.
//
// RETURNS NIL WHETHER OR NOT THE ADDRESS EXISTS, and this SDK exposes no way to
// tell the two apart. That is not an omission to improve on: a client that
// surfaced a "no such user" state — even one inferred from timing — would turn
// the endpoint into the account enumeration oracle its uniform response exists
// to prevent (§25.4).
func (c *Client) RequestPasswordReset(ctx context.Context, request PasswordResetRequest) error {
	if err := c.ensureOpen(); err != nil {
		return err
	}
	body := resetBody{
		Email:    request.Email,
		OrgSlug:  request.OrgSlug,
		TenantID: request.TenantID,
	}
	if body.OrgSlug == "" {
		body.OrgSlug = c.org.slug
	}
	if body.TenantID == "" {
		body.TenantSlug = request.TenantSlug
		if body.TenantSlug == "" {
			body.TenantSlug = c.tenantSlug
		}
	}
	return c.accountPostNoContent(ctx, resetPath, body)
}

// PasswordResetContext performs GET /api/v1/auth/reset/context (CONTRACT.md
// §25.1) — the OPAQUE policy for the account a reset token belongs to.
//
// Call this before ConfirmPasswordReset on any tenant that might have §23
// enabled: the client has to build a registration record, and building one
// needs parameters it cannot know before it has a token to ask with. Sending a
// plaintext password to a tenant in opaque_mode: required is refused, and
// refused late (§25.4 rule 1).
//
// A 404 means unknown, expired OR already-consumed, deliberately without
// distinguishing them; this SDK does not distinguish them either (§25.4 rule 3).
func (c *Client) PasswordResetContext(ctx context.Context, token Sensitive) (PasswordResetContext, error) {
	if err := c.ensureOpen(); err != nil {
		return PasswordResetContext{}, err
	}
	req, err := c.newRequest(ctx, http.MethodGet, resetContextPath, nil)
	if err != nil {
		return PasswordResetContext{}, err
	}
	// Set RawQuery on the built URL rather than appending to the path string:
	// Client.url() assigns its argument to url.URL.Path, so a "?" embedded
	// there is percent-escaped into the path and the server sees no query at
	// all.
	query := url.Values{}
	query.Set("token", token.expose())
	req.URL.RawQuery = query.Encode()
	resp, err := c.doRequest(req)
	if err != nil {
		return PasswordResetContext{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return PasswordResetContext{}, mapErrorResponse(resp)
	}
	var context PasswordResetContext
	if err := json.NewDecoder(resp.Body).Decode(&context); err != nil {
		return PasswordResetContext{}, deserErr(err)
	}
	return context, nil
}

// ConfirmPasswordReset performs POST /api/v1/auth/reset/confirm (CONTRACT.md
// §25.1) — set the new password.
func (c *Client) ConfirmPasswordReset(ctx context.Context, confirmation PasswordResetConfirmation) error {
	if err := c.ensureOpen(); err != nil {
		return err
	}
	body := resetConfirmBody{
		Token:       confirmation.Token.expose(),
		NewPassword: confirmation.NewPassword.expose(),
		TenantID:    confirmation.TenantID,
		Opaque:      confirmation.Opaque,
	}
	return c.accountPostNoContent(ctx, resetConfirmPath, body)
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

func (c *Client) accountPost(ctx context.Context, path string, body any) (*http.Response, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, &NetworkError{Message: fmt.Sprintf("failed to encode request: %v", err)}
	}
	req, err := c.newRequest(ctx, http.MethodPost, path, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	return c.doRequest(req)
}

// accountPostNoContent POSTs and discards a success body.
func (c *Client) accountPostNoContent(ctx context.Context, path string, body any) error {
	resp, err := c.accountPost(ctx, path, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK, http.StatusAccepted, http.StatusNoContent:
		return nil
	default:
		return mapErrorResponse(resp)
	}
}
