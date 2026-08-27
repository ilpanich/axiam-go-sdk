package axiam

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ilpanich/axiam-go-sdk/internal/refreshguard"
)

const (
	loginPath     = "/api/v1/auth/login"
	mfaVerifyPath = "/api/v1/auth/mfa/verify"
	refreshPath   = "/api/v1/auth/refresh"
	logoutPath    = "/api/v1/auth/logout"
	accessCookie  = "axiam_access"
	refreshCookie = "axiam_refresh"
)

// ---------------------------------------------------------------------------
// Wire request/response shapes (mirror crates/axiam-api-rest/src/handlers/
// auth.rs exactly — mirror only, no server dependency).
// ---------------------------------------------------------------------------

// workspaceBody is the org/tenant selector every unauthenticated endpoint
// carries.
//
// Extracted from loginRequestBody so the password path, the OPAQUE login path
// and OPAQUE enrolment resolve the workspace through one function. They used
// to share it by embedding the whole login body, which meant OPAQUE enrolment
// would have had to send an empty username and password to reach the two
// fields it actually needs.
type workspaceBody struct {
	TenantID   *uuid.UUID `json:"tenant_id,omitempty"`
	OrgID      *uuid.UUID `json:"org_id,omitempty"`
	TenantSlug *string    `json:"tenant_slug,omitempty"`
	OrgSlug    *string    `json:"org_slug,omitempty"`
}

type loginRequestBody struct {
	workspaceBody
	UsernameOrEmail string `json:"username_or_email"`
	Password        string `json:"password"`
}

type mfaVerifyRequestBody struct {
	ChallengeToken string `json:"challenge_token"`
	TotpCode       string `json:"totp_code"`
}

type refreshRequestBody struct {
	TenantID uuid.UUID `json:"tenant_id"`
	OrgID    uuid.UUID `json:"org_id"`
}

type logoutRequestBody struct {
	SessionID uuid.UUID `json:"session_id"`
}

type loginSuccessResponseWire struct {
	SessionID uuid.UUID         `json:"session_id"`
	ExpiresIn uint64            `json:"expires_in"`
	User      loginUserInfoWire `json:"user"`
}

// loginUserInfoWire is the user object of a login/me response.
//
// Only the one field this SDK surfaces is modelled. OrganizationLevel is absent
// on a server older than contract 1.31, and Go's zero value for bool is false —
// which is the safe reading of absent: the client then offers no cross-tenant
// action rather than one that would 403 (CONTRACT.md §5.2).
type loginUserInfoWire struct {
	OrganizationLevel bool `json:"organization_level"`
}

type mfaRequiredResponseWire struct {
	ChallengeToken   string   `json:"challenge_token"`
	AvailableMethods []string `json:"available_methods"`
}

// mfaSetupRequiredResponseWire is the 403 body of POST /api/v1/auth/login when
// the tenant requires MFA and the account has none (CONTRACT.md §25.2).
type mfaSetupRequiredResponseWire struct {
	MfaSetupRequired bool   `json:"mfa_setup_required"`
	SetupToken       string `json:"setup_token"`
}

type refreshSuccessResponseWire struct {
	ExpiresIn uint64 `json:"expires_in"`
}

// ---------------------------------------------------------------------------
// Public result type — CONTRACT.md §1, CF-04 (discriminated login result)
// ---------------------------------------------------------------------------

// LoginResult is the outcome of Login/VerifyMfa (CF-04). MFA required is an
// expected outcome, not an error: check MFARequired before assuming the
// session is established.
type LoginResult struct {
	// MFARequired is true when the server responded with an MFA challenge
	// instead of a completed session; call VerifyMfa next with MFAToken.
	MFARequired bool
	// MFAToken carries the opaque challenge token when MFARequired is
	// true. Treated as sensitive (short-lived bearer of "logging in as
	// this user").
	MFAToken Sensitive
	// AvailableMethods lists MFA methods available to satisfy the
	// challenge (only populated when MFARequired is true).
	AvailableMethods []string
	// MFASetupRequired is true when the tenant requires MFA and this
	// account has none — CONTRACT.md §25.2 rule 1.
	//
	// An OUTCOME, not an error. The server answers 403 here with the token
	// to finish, and mapping that through §2 to *AuthzError told the caller
	// they lacked permission to log in, when what the server said was
	// recoverable and came with the means to recover. Pass SetupToken to
	// MfaSetupEnroll, show the user the URI, then MfaSetupConfirm, which
	// completes this login.
	//
	// Additive here rather than a new type, because this result has always
	// been one struct with flags rather than a discriminated union — so
	// nothing that reads MFARequired today has to change.
	MFASetupRequired bool
	// SetupToken authorizes the MfaSetupEnroll/MfaSetupConfirm pair, and is
	// populated only when MFASetupRequired is true.
	SetupToken Sensitive
	// SessionID is the server-issued session id (only populated on a
	// completed, non-MFA-pending login/verify_mfa).
	SessionID string
	// ExpiresIn is the access token lifetime in seconds, as reported by
	// the server (only populated on a completed login/verify_mfa).
	ExpiresIn uint64
	// OrganizationLevel reports whether the account that just signed in is
	// an ORGANIZATION-LEVEL principal — CONTRACT.md §5.2.
	//
	// Such a principal's record lives in its organization's reserved tenant,
	// so its global grants apply in every tenant of that organization, and
	// it can act on a different one by sending a different X-Tenant-ID on
	// the next request — no re-login, because it already is a principal of
	// every tenant there.
	//
	// An ordinary tenant principal is a principal of exactly one tenant.
	// Changing the header for one of those produces a 403, so this flag is
	// what an application checks BEFORE offering a tenant switch, rather
	// than discovering the answer from a failed request.
	//
	// False on a completed login against a server older than contract 1.31,
	// and false on the two pending outcomes, where no principal has been
	// established yet.
	OrganizationLevel bool
}

// ---------------------------------------------------------------------------
// Minimal unverified JWT claim decode (org_id resolution only)
// ---------------------------------------------------------------------------

// unverifiedClaims is the subset of access-token claims this plan needs to
// decode WITHOUT verifying the signature — signature verification is the
// middleware/JWKS concern of a later plan (per this task's <action>).
type unverifiedClaims struct {
	Sub      string `json:"sub"`
	TenantID string `json:"tenant_id"`
	OrgID    string `json:"org_id"`
	Jti      string `json:"jti"`
	Exp      int64  `json:"exp"`
}

// decodeUnverifiedClaims base64url-decodes a JWT's payload segment without
// verifying its signature (RESEARCH.md Pitfall 3 / this plan's <action>:
// "base64url JWT payload parse — do not verify signature here").
func decodeUnverifiedClaims(token string) (unverifiedClaims, error) {
	var claims unverifiedClaims
	parts := splitJWT(token)
	if len(parts) != 3 {
		return claims, fmt.Errorf("malformed JWT: expected 3 segments, got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return claims, fmt.Errorf("failed to decode JWT payload: %w", err)
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return claims, fmt.Errorf("failed to parse JWT claims: %w", err)
	}
	return claims, nil
}

func splitJWT(token string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			parts = append(parts, token[start:i])
			start = i + 1
		}
	}
	parts = append(parts, token[start:])
	return parts
}

// ---------------------------------------------------------------------------
// Shared post-success handling: extract cookies, decode claims, cache state
// ---------------------------------------------------------------------------

// absorbSessionCookies reads the access/refresh tokens the server just set
// via Set-Cookie (already captured by the SDK's cookie jar), decodes the
// access token's org_id claim (RESEARCH.md Pitfall 3) and caches it, and
// seeds the refresh guard so a subsequent 401 has the correct observed
// baseline.
func (c *Client) absorbSessionCookies() error {
	access := c.cookieValue(accessCookie)
	if access == "" {
		return &AuthError{Message: "server response did not set the axiam_access cookie"}
	}
	refresh := c.cookieValue(refreshCookie)

	claims, err := decodeUnverifiedClaims(access)
	if err != nil {
		return &AuthError{Message: fmt.Sprintf("failed to decode access token claims: %v", err)}
	}

	if claims.OrgID != "" {
		if orgUUID, err := uuid.Parse(claims.OrgID); err == nil {
			c.setResolvedOrgID(orgUUID)
		}
	}

	c.guard.Load().Seed(refreshguard.Sensitive(access), refreshguard.Sensitive(refresh), claims.Exp)
	return nil
}

// cookieValue reads a named cookie's value out of the SDK's cookie jar for
// the client's configured base URL.
func (c *Client) cookieValue(name string) string {
	for _, ck := range c.httpc.Jar.Cookies(c.baseURL) {
		if ck.Name == name {
			return ck.Value
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Public REST auth methods (CONTRACT.md §1, D-05 ctx-first)
// ---------------------------------------------------------------------------

// Login performs POST /api/v1/auth/login (CONTRACT.md §1). On success (no
// MFA), tokens are already present in the cookie jar and the org_id claim
// has been resolved+cached. When the server signals MFA is required,
// returns LoginResult{MFARequired: true, ...} — this is an expected
// outcome, not an error.
func (c *Client) Login(ctx context.Context, email, password string) (LoginResult, error) {
	if err := c.ensureOpen(); err != nil {
		return LoginResult{}, err
	}
	c.onCredentialChange()

	body := c.buildLoginBody(email, password)
	payload, err := json.Marshal(body)
	if err != nil {
		return LoginResult{}, &NetworkError{Message: fmt.Sprintf("failed to encode login request: %v", err)}
	}

	req, err := c.newRequest(ctx, http.MethodPost, loginPath, bytes.NewReader(payload))
	if err != nil {
		return LoginResult{}, err
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return LoginResult{}, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		var wire loginSuccessResponseWire
		if err := json.NewDecoder(resp.Body).Decode(&wire); err != nil {
			return LoginResult{}, deserErr(err)
		}
		if err := c.absorbSessionCookies(); err != nil {
			return LoginResult{}, err
		}
		return LoginResult{
			SessionID:         wire.SessionID.String(),
			ExpiresIn:         wire.ExpiresIn,
			OrganizationLevel: wire.User.OrganizationLevel,
		}, nil
	case http.StatusAccepted:
		var wire mfaRequiredResponseWire
		if err := json.NewDecoder(resp.Body).Decode(&wire); err != nil {
			return LoginResult{}, deserErr(err)
		}
		return LoginResult{
			MFARequired:      true,
			MFAToken:         Sensitive(wire.ChallengeToken),
			AvailableMethods: wire.AvailableMethods,
		}, nil
	case http.StatusForbidden:
		// CONTRACT.md §25.2 rule 1: a 403 carrying mfa_setup_required is an
		// OUTCOME, not a refusal.
		//
		// Matched on the body's own discriminant rather than the status alone:
		// a genuine authorization refusal is also a 403, and only one of the
		// two carries a setup_token. The body is read into a buffer first so a
		// non-matching 403 still reaches mapErrorResponse with its message
		// intact.
		body, readErr := io.ReadAll(resp.Body)
		if readErr == nil {
			var wire mfaSetupRequiredResponseWire
			if json.Unmarshal(body, &wire) == nil && wire.MfaSetupRequired && wire.SetupToken != "" {
				return LoginResult{
					MFASetupRequired: true,
					SetupToken:       Sensitive(wire.SetupToken),
				}, nil
			}
		}
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return LoginResult{}, mapErrorResponse(resp)
	default:
		return LoginResult{}, mapErrorResponse(resp)
	}
}

// VerifyMfa performs POST /api/v1/auth/mfa/verify (CONTRACT.md §1),
// completing the two-phase flow started by Login when MFARequired was
// true.
func (c *Client) VerifyMfa(ctx context.Context, mfaToken Sensitive, code string) (LoginResult, error) {
	if err := c.ensureOpen(); err != nil {
		return LoginResult{}, err
	}
	c.onCredentialChange()

	body := mfaVerifyRequestBody{
		ChallengeToken: mfaToken.expose(),
		TotpCode:       code,
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return LoginResult{}, &NetworkError{Message: fmt.Sprintf("failed to encode verify_mfa request: %v", err)}
	}

	req, err := c.newRequest(ctx, http.MethodPost, mfaVerifyPath, bytes.NewReader(payload))
	if err != nil {
		return LoginResult{}, err
	}

	resp, err := c.doRequest(req)
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
	return LoginResult{
		SessionID:         wire.SessionID.String(),
		ExpiresIn:         wire.ExpiresIn,
		OrganizationLevel: wire.User.OrganizationLevel,
	}, nil
}

// Refresh performs POST /api/v1/auth/refresh (CONTRACT.md §1), routed
// through the sync.Mutex single-flight guard (§9) so concurrent 401s share
// exactly one in-flight refresh call. A 401 on the refresh call itself is
// AuthError with no retry (§9.3).
func (c *Client) Refresh(ctx context.Context) error {
	if err := c.ensureOpen(); err != nil {
		return err
	}
	c.onCredentialChange()

	observedAccess := c.cookieValue(accessCookie)
	if observedAccess == "" {
		return &AuthError{Message: "no access token to refresh — call Login() first"}
	}

	tenantID, ok := c.resolvedOrgTenantID()
	if !ok {
		return &AuthError{Message: "tenant_id could not be resolved; Login() must succeed before Refresh()"}
	}
	orgID, ok := c.resolvedOrgID()
	if !ok {
		return &AuthError{Message: "org_id could not be resolved; Login() must succeed before Refresh() — supply WithOrgID/WithOrgSlug or call Login() first"}
	}

	_, err := c.guard.Load().RefreshIfNeeded(ctx, observedAccess, func(ctx context.Context) (refreshguard.RefreshedTokens, error) {
		body := refreshRequestBody{TenantID: tenantID, OrgID: orgID}
		payload, err := json.Marshal(body)
		if err != nil {
			return refreshguard.RefreshedTokens{}, &NetworkError{Message: fmt.Sprintf("failed to encode refresh request: %v", err)}
		}

		req, err := c.newRequest(ctx, http.MethodPost, refreshPath, bytes.NewReader(payload))
		if err != nil {
			return refreshguard.RefreshedTokens{}, err
		}

		resp, err := c.doRequest(req)
		if err != nil {
			return refreshguard.RefreshedTokens{}, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			// §9.3: 401 (or any non-200) on the refresh call itself is
			// propagated as-is — no retry loop.
			return refreshguard.RefreshedTokens{}, mapErrorResponse(resp)
		}

		var wire refreshSuccessResponseWire
		if err := json.NewDecoder(resp.Body).Decode(&wire); err != nil {
			return refreshguard.RefreshedTokens{}, deserErr(err)
		}

		newAccess := c.cookieValue(accessCookie)
		if newAccess == "" {
			return refreshguard.RefreshedTokens{}, &AuthError{Message: "refresh response did not set axiam_access"}
		}
		newRefresh := c.cookieValue(refreshCookie)
		claims, err := decodeUnverifiedClaims(newAccess)
		if err != nil {
			return refreshguard.RefreshedTokens{}, &AuthError{Message: fmt.Sprintf("failed to decode refreshed access token claims: %v", err)}
		}
		return refreshguard.RefreshedTokens{
			Access:  refreshguard.Sensitive(newAccess),
			Refresh: refreshguard.Sensitive(newRefresh),
			Exp:     claims.Exp,
		}, nil
	})

	return err
}

// Logout performs POST /api/v1/auth/logout (CONTRACT.md §1) and clears
// in-memory token state.
func (c *Client) Logout(ctx context.Context) error {
	if err := c.ensureOpen(); err != nil {
		return err
	}
	c.onCredentialChange()

	access := c.cookieValue(accessCookie)
	if access == "" {
		return &AuthError{Message: "no active session to log out"}
	}
	claims, err := decodeUnverifiedClaims(access)
	if err != nil {
		return &AuthError{Message: fmt.Sprintf("failed to decode access token claims: %v", err)}
	}
	sessionID, err := uuid.Parse(claims.Jti)
	if err != nil {
		return &AuthError{Message: "access token has no session id (jti) to log out"}
	}

	body := logoutRequestBody{SessionID: sessionID}
	payload, err := json.Marshal(body)
	if err != nil {
		return &NetworkError{Message: fmt.Sprintf("failed to encode logout request: %v", err)}
	}

	req, err := c.newRequest(ctx, http.MethodPost, logoutPath, bytes.NewReader(payload))
	if err != nil {
		return err
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return mapErrorResponse(resp)
	}

	c.guard.Store(&refreshguard.Guard{})
	return nil
}

func (c *Client) buildLoginBody(email, password string) loginRequestBody {
	return loginRequestBody{
		workspaceBody:   c.buildWorkspaceBody(),
		UsernameOrEmail: email,
		Password:        password,
	}
}

// buildWorkspaceBody resolves the org/tenant selector.
//
// One function, so the two login paths and OPAQUE enrolment cannot drift about
// which identifier wins — a drift that would present as a login working on one
// route and 401-ing on the other.
func (c *Client) buildWorkspaceBody() workspaceBody {
	body := workspaceBody{TenantSlug: strPtr(c.tenantSlug)}
	switch {
	case c.org.id != nil:
		body.OrgID = c.org.id
	case c.org.slug != "":
		body.OrgSlug = strPtr(c.org.slug)
	}
	return body
}

// resolvedOrgTenantID returns the tenant UUID to send in the Refresh body.
// The server's RefreshRequest requires a UUID (not a slug) — resolved from
// the access token's tenant_id claim after login, since the client may
// have been constructed with a tenant SLUG.
func (c *Client) resolvedOrgTenantID() (uuid.UUID, bool) {
	access := c.cookieValue(accessCookie)
	if access == "" {
		return uuid.UUID{}, false
	}
	claims, err := decodeUnverifiedClaims(access)
	if err != nil || claims.TenantID == "" {
		return uuid.UUID{}, false
	}
	id, err := uuid.Parse(claims.TenantID)
	if err != nil {
		return uuid.UUID{}, false
	}
	return id, true
}

func strPtr(s string) *string { return &s }

func deserErr(err error) error {
	return &NetworkError{Message: fmt.Sprintf("failed to parse response body: %v", err)}
}

// mapErrorResponse maps a non-2xx REST response to an error per
// CONTRACT.md §2, using the 18-01 status mappers. resp is consumed
// (Body read and discarded) but NOT closed here — callers close it via
// their own defer.
//
// When the mapped error is an *AuthzError (403/409), the raw body bytes are
// additionally best-effort parsed for the structured `action`/`resource_id`
// fields (CONTRACT.md §2) via parseAuthzFields — this is the only part of
// the body ever read into caller-visible state; readBodyForError's WR-01
// redaction of the free-text message is untouched.
func mapErrorResponse(resp *http.Response) error {
	message, body := readBodyForError(resp.Body)
	err := errorFromHTTPStatus(resp.StatusCode, message, resp, nil)
	if authzErr, ok := err.(*AuthzError); ok {
		authzErr.Action, authzErr.ResourceID = parseAuthzFields(body)
	}
	if netErr, ok := err.(*NetworkError); ok {
		netErr.RetryAfter = parseRetryAfter(resp.Header.Get("Retry-After"))
	}
	return err
}

// parseRetryAfter reads an RFC 7231 Retry-After header as a duration, zero when
// absent or unparseable.
//
// Both forms are accepted: delta-seconds and an HTTP-date. The date form is not
// hypothetical — 429 and 503 responses from CDNs and proxies commonly use it,
// and treating it as unparseable would silently drop the server's own
// instruction about when it will be ready.
//
// The parsed DURATION is what reaches NetworkError, never the raw header text,
// so the redaction invariant in errors.go is untouched: a duration cannot carry
// a token. A negative or absurd value collapses to zero rather than becoming a
// floor, since §16 honors this as a minimum wait and a negative minimum is
// meaningless.
func parseRetryAfter(header string) time.Duration {
	header = strings.TrimSpace(header)
	if header == "" {
		return 0
	}
	if secs, err := strconv.Atoi(header); err == nil {
		if secs <= 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	if when, err := http.ParseTime(header); err == nil {
		if d := time.Until(when); d > 0 {
			return d
		}
	}
	return 0
}

// readBodyForError drains a bounded amount of the error response body (so the
// connection can be reused) and returns both a fixed, non-echoing message
// string and the raw bounded body bytes for structured field extraction
// (parseAuthzFields). The returned message deliberately does NOT echo the
// raw body: it flows into an exported error Message field, which
// participates in json.Marshal / %v / %+v / .Error() with no redaction
// surface (unlike Sensitive). A server error body can reflect request headers,
// cookies, or token-shaped payloads (WAF/proxy pages, misconfigured debug
// handlers), so echoing it verbatim would defeat the header-redaction work in
// errors.go (WR-01). Diagnostic detail belongs in the optional WithLogger sink,
// not in caller-visible/loggable error state — the raw body bytes returned
// here are only ever fed into the narrow, typed authzErrorBody parse, never
// surfaced verbatim.
func readBodyForError(r io.Reader) (message string, body []byte) {
	body, _ = io.ReadAll(io.LimitReader(r, 4096))
	return "server returned an error response (body redacted; enable WithLogger for details)", body
}
