package axiam

// WebAuthn and passkeys — CONTRACT.md §24.
//
// A passkey ceremony is two exchanges stacked: one with an *authenticator*,
// which needs a platform API, and one with *AXIAM*, which is four ordinary
// JSON round trips. Go has no authenticator, so this file is the second half.
//
// That is not a consolation prize. A Go service completing a ceremony that ran
// on an Android or iOS handset is the relying party exactly as a browser is,
// and §24.6b rule 2 forbids the alternative outright: an SDK MUST NOT emulate
// an authenticator in software, because a "credential" held in process memory
// is not a second factor.
//
// The rule everything below obeys is §24.0: the server chooses every option
// and verifies every response, so this carries both through untouched. It does
// not default a field, normalize one, or re-encode a buffer.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

const (
	webauthnRegisterStartPath      = "/api/v1/auth/webauthn/register/start"
	webauthnRegisterFinishPath     = "/api/v1/auth/webauthn/register/finish"
	webauthnAuthStartPath          = "/api/v1/auth/webauthn/authenticate/start"
	webauthnAuthFinishPath         = "/api/v1/auth/webauthn/authenticate/finish"
	webauthnDiscoverableStartPath  = "/api/v1/auth/webauthn/authenticate/discoverable/start"
	webauthnDiscoverableFinishPath = "/api/v1/auth/webauthn/authenticate/discoverable/finish"
)

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

// WebauthnChallenge is a started ceremony: the server's options plus the token
// binding a response to them.
//
// Challenge is the raw wire value, unparsed — a {"publicKey": {...}} object
// carrying base64url buffers exactly as the server sent them. Hand it to the
// authenticator unchanged (§24.0), or call RequestJSON for the string a
// platform API takes.
type WebauthnChallenge struct {
	// Challenge is the server's options, untouched.
	Challenge json.RawMessage
	// StateToken binds the authenticator's answer to this challenge.
	//
	// A bearer credential for the length of the ceremony — one that leaks
	// inside that window is a ceremony an attacker can try to complete — so it
	// is Sensitive (§24.5). It is OPAQUE: this SDK never decodes it, and
	// neither should a caller.
	StateToken Sensitive
}

// RequestJSON returns the challenge in the JSON form every platform
// authenticator API takes (§24.6a rule 1).
//
// This is the string an Android app passes to CreatePublicKeyCredentialRequest
// or GetPublicKeyCredentialOption, and the value a browser passes to
// PublicKeyCredential.parseCreationOptionsFromJSON(). It is the inner options
// object: the "publicKey" wrapper belongs to the DOM's
// CredentialCreationOptions, and the platform JSON APIs do not want it.
//
// Pure local computation, no I/O. Nothing is defaulted, dropped or reordered on
// the way through (§24.0).
func (w WebauthnChallenge) RequestJSON() (string, error) {
	var wrapper struct {
		PublicKey json.RawMessage `json:"publicKey"`
	}
	if err := json.Unmarshal(w.Challenge, &wrapper); err != nil {
		return "", &NetworkError{Message: fmt.Sprintf("webauthn challenge is not a JSON object: %v", err)}
	}
	if len(wrapper.PublicKey) == 0 {
		// A server that sent the bare options rather than the wrapper is not
		// wrong for every consumer, and this call has one job: hand a caller
		// something a platform API accepts.
		return string(w.Challenge), nil
	}
	return string(wrapper.PublicKey), nil
}

// WebauthnCredential is a credential the user just enrolled — the 201 body of
// register/finish.
type WebauthnCredential struct {
	// ID is the AXIAM record id (UUID).
	ID string `json:"id"`
	// CredentialID is the base64url credential id, as the authenticator reported it.
	CredentialID string `json:"credential_id"`
	// Name is the caller-supplied label.
	Name string `json:"name"`
	// CredentialType is "passkey" or "security_key", as the server classified it.
	CredentialType string `json:"credential_type"`
	// CreatedAt is an RFC 3339 timestamp.
	CreatedAt string `json:"created_at"`
	// LastUsedAt is an RFC 3339 timestamp, empty when the credential has never
	// produced an assertion.
	LastUsedAt string `json:"last_used_at,omitempty"`
}

// WebauthnLoginResult is the outcome of a completed passkey sign-in.
//
// The client is ALREADY authenticated when this is returned (§24.3 rule 1) —
// the tokens come back as well because a caller may want to hand them onward,
// not because adoption was optional.
type WebauthnLoginResult struct {
	// AccessToken is the new access token, already adopted by this client.
	AccessToken Sensitive
	// RefreshToken is a SESSION refresh token, refreshed through Refresh() and
	// not OidcRefresh (§24.3 rule 5).
	RefreshToken Sensitive
	// SessionID identifies the session just created.
	SessionID string
	// ExpiresIn is the access-token lifetime in seconds.
	ExpiresIn uint64
}

// WebauthnWorkspace names the workspace a usernameless ceremony runs inside.
//
// Unlike the five tenant-scoped /oauth2/* operations of §12.1 rule 2, this
// endpoint ACCEPTS SLUGS, so a slug-only client can run a discoverable
// sign-in. The SDK fills these from its own configured identity when the caller
// passes nothing.
type WebauthnWorkspace struct {
	OrgID      string
	OrgSlug    string
	TenantID   string
	TenantSlug string
}

// ---------------------------------------------------------------------------
// Wire shapes
// ---------------------------------------------------------------------------

type webauthnChallengeWire struct {
	Challenge  json.RawMessage `json:"challenge"`
	StateToken string          `json:"state_token"`
}

type webauthnRegisterFinishBody struct {
	StateToken     string          `json:"state_token"`
	CredentialName string          `json:"credential_name"`
	Response       json.RawMessage `json:"response"`
}

type webauthnFinishBody struct {
	StateToken string          `json:"state_token"`
	Response   json.RawMessage `json:"response"`
}

type webauthnLoginWire struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	SessionID    string `json:"session_id"`
	ExpiresIn    uint64 `json:"expires_in"`
}

type webauthnDiscoverableBody struct {
	OrgID      string `json:"org_id,omitempty"`
	OrgSlug    string `json:"org_slug,omitempty"`
	TenantID   string `json:"tenant_id,omitempty"`
	TenantSlug string `json:"tenant_slug,omitempty"`
}

// ---------------------------------------------------------------------------
// Registration — requires an authenticated session (§24.1)
// ---------------------------------------------------------------------------

// WebauthnRegisterStart performs POST /api/v1/auth/webauthn/register/start
// (CONTRACT.md §24.1).
//
// Enrolling a passkey is something a signed-in user does to their own account,
// so this requires a session and fails client-side with NO wire call when there
// is none.
//
// A 503 means the tenant's attestation policy requires attestation and the FIDO
// metadata service has no usable snapshot. That is a server configuration
// state, not a transient failure, so §24.4 rule 2 deliberately does not retry
// it.
func (c *Client) WebauthnRegisterStart(ctx context.Context) (WebauthnChallenge, error) {
	if err := c.ensureOpen(); err != nil {
		return WebauthnChallenge{}, err
	}
	if err := c.requireWebauthnSession("WebauthnRegisterStart"); err != nil {
		return WebauthnChallenge{}, err
	}
	return c.webauthnStart(ctx, webauthnRegisterStartPath, struct{}{})
}

// WebauthnRegisterFinish performs POST /api/v1/auth/webauthn/register/finish
// (CONTRACT.md §24.1).
//
// response is the authenticator's answer — either a marshalled value or the
// platform's own JSON string (§24.6a rule 2): Android's
// registrationResponseJson, a browser's credential.toJSON(). It reaches the
// server unchanged either way, because it is the input to a signature check
// over bytes this SDK did not produce.
//
// A 403 is the tenant's attestation policy refusing THIS AUTHENTICATOR — an
// AAGUID that is not allow-listed, a missing FIDO certification, a revoked
// status — not a permission problem with the user. The server's message is
// surfaced verbatim (§24.4 rule 1), because it is the only way the person
// holding the key learns a different one would work.
func (c *Client) WebauthnRegisterFinish(
	ctx context.Context,
	stateToken Sensitive,
	credentialName string,
	response any,
) (WebauthnCredential, error) {
	if err := c.ensureOpen(); err != nil {
		return WebauthnCredential{}, err
	}
	if err := c.requireWebauthnSession("WebauthnRegisterFinish"); err != nil {
		return WebauthnCredential{}, err
	}

	raw, err := webauthnResponseJSON(response, "WebauthnRegisterFinish")
	if err != nil {
		return WebauthnCredential{}, err
	}

	resp, err := c.webauthnPost(ctx, webauthnRegisterFinishPath, webauthnRegisterFinishBody{
		StateToken:     stateToken.expose(),
		CredentialName: credentialName,
		Response:       raw,
	})
	if err != nil {
		return WebauthnCredential{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return WebauthnCredential{}, mapWebauthnRegisterError(resp)
	}
	var credential WebauthnCredential
	if err := json.NewDecoder(resp.Body).Decode(&credential); err != nil {
		return WebauthnCredential{}, deserErr(err)
	}
	return credential, nil
}

// ---------------------------------------------------------------------------
// Authentication as a second factor (§24.2)
// ---------------------------------------------------------------------------

// WebauthnAuthenticateStart performs POST
// /api/v1/auth/webauthn/authenticate/start (CONTRACT.md §24.1).
//
// The SECOND-FACTOR ceremony: it continues a Login that answered MFARequired
// with "webauthn" among its AvailableMethods, and challengeToken is that
// result's MFAToken.
//
// A different flow from WebauthnDiscoverableStart, not the same one with an
// optional argument — see §24.2 for why they cannot be merged.
func (c *Client) WebauthnAuthenticateStart(
	ctx context.Context,
	challengeToken Sensitive,
) (WebauthnChallenge, error) {
	if err := c.ensureOpen(); err != nil {
		return WebauthnChallenge{}, err
	}
	body := struct {
		ChallengeToken string `json:"challenge_token"`
	}{ChallengeToken: challengeToken.expose()}
	return c.webauthnStart(ctx, webauthnAuthStartPath, body)
}

// WebauthnAuthenticateFinish performs POST
// /api/v1/auth/webauthn/authenticate/finish (CONTRACT.md §24.1).
//
// Leaves this client authenticated (§24.3 rule 1). That is not §14.3's "MAY
// adopt" posture: DeviceLogin mints tokens a caller may want to route
// elsewhere, and this is the SDK's own primary authentication — returning a
// token set without adopting it would make a passkey sign-in the one way to log
// in that does not log you in.
func (c *Client) WebauthnAuthenticateFinish(
	ctx context.Context,
	stateToken Sensitive,
	response any,
) (WebauthnLoginResult, error) {
	return c.webauthnFinish(ctx, webauthnAuthFinishPath, stateToken, response, "WebauthnAuthenticateFinish")
}

// ---------------------------------------------------------------------------
// Usernameless (discoverable) authentication (§24.2)
// ---------------------------------------------------------------------------

// WebauthnDiscoverableStart performs POST
// /api/v1/auth/webauthn/authenticate/discoverable/start (CONTRACT.md §24.1).
//
// The PRIMARY-FACTOR ceremony: nothing precedes it, the server sends an empty
// allowCredentials, and the assertion itself identifies the user.
//
// The workspace still has to be named — a discoverable credential is resolved
// inside one tenant's isolation boundary — but it comes from this client's own
// configuration unless overridden, and slugs are accepted. Pass nil for the
// configured workspace.
func (c *Client) WebauthnDiscoverableStart(
	ctx context.Context,
	workspace *WebauthnWorkspace,
) (WebauthnChallenge, error) {
	if err := c.ensureOpen(); err != nil {
		return WebauthnChallenge{}, err
	}
	body, err := c.webauthnWorkspaceBody(workspace)
	if err != nil {
		return WebauthnChallenge{}, err
	}
	return c.webauthnStart(ctx, webauthnDiscoverableStartPath, body)
}

// WebauthnDiscoverableFinish performs POST
// /api/v1/auth/webauthn/authenticate/discoverable/finish (CONTRACT.md §24.1).
//
// Leaves this client authenticated (§24.3). Unlike its username-bound twin,
// this fires the server's login.post_auth reactor hook (§22.5): there was no
// password step for the event to have been fired at.
func (c *Client) WebauthnDiscoverableFinish(
	ctx context.Context,
	stateToken Sensitive,
	response any,
) (WebauthnLoginResult, error) {
	return c.webauthnFinish(ctx, webauthnDiscoverableFinishPath, stateToken, response, "WebauthnDiscoverableFinish")
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

// webauthnStart runs either *_start call and returns the options untouched.
func (c *Client) webauthnStart(
	ctx context.Context,
	path string,
	body any,
) (WebauthnChallenge, error) {
	resp, err := c.webauthnPost(ctx, path, body)
	if err != nil {
		return WebauthnChallenge{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return WebauthnChallenge{}, mapErrorResponse(resp)
	}
	var wire webauthnChallengeWire
	if err := json.NewDecoder(resp.Body).Decode(&wire); err != nil {
		return WebauthnChallenge{}, deserErr(err)
	}
	return WebauthnChallenge{
		Challenge:  wire.Challenge,
		StateToken: Sensitive(wire.StateToken),
	}, nil
}

// webauthnFinish is the shared tail of both authentication ceremonies.
func (c *Client) webauthnFinish(
	ctx context.Context,
	path string,
	stateToken Sensitive,
	response any,
	operation string,
) (WebauthnLoginResult, error) {
	if err := c.ensureOpen(); err != nil {
		return WebauthnLoginResult{}, err
	}
	raw, err := webauthnResponseJSON(response, operation)
	if err != nil {
		return WebauthnLoginResult{}, err
	}
	// §17.1 rule 9 / §24.3 rule 4: memo entries are keyed by subject, and this
	// call changes the subject.
	c.onCredentialChange()

	resp, err := c.webauthnPost(ctx, path, webauthnFinishBody{
		StateToken: stateToken.expose(),
		Response:   raw,
	})
	if err != nil {
		return WebauthnLoginResult{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return WebauthnLoginResult{}, mapErrorResponse(resp)
	}
	var wire webauthnLoginWire
	if err := json.NewDecoder(resp.Body).Decode(&wire); err != nil {
		return WebauthnLoginResult{}, deserErr(err)
	}
	// The server sets the same axiam_access/axiam_refresh/axiam_csrf triple
	// here as it does on a password login, so adoption is the same call.
	if err := c.absorbSessionCookies(); err != nil {
		return WebauthnLoginResult{}, err
	}
	return WebauthnLoginResult{
		AccessToken:  Sensitive(wire.AccessToken),
		RefreshToken: Sensitive(wire.RefreshToken),
		SessionID:    wire.SessionID,
		ExpiresIn:    wire.ExpiresIn,
	}, nil
}

// webauthnPost marshals body and POSTs it as JSON.
//
// Deliberately not routed through §16's retry helper, and that is true for the
// whole section: five of the six operations are ceremony steps that consume
// server-side state, and the sixth (register/start) carries the 503 §24.4
// rule 2 forbids retrying. There is nothing here a bounded retry could help.
func (c *Client) webauthnPost(ctx context.Context, path string, body any) (*http.Response, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, &NetworkError{Message: fmt.Sprintf("failed to encode webauthn request: %v", err)}
	}
	req, err := c.newRequest(ctx, http.MethodPost, path, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	return c.doRequest(req)
}

// requireWebauthnSession enforces §24.1's precondition on register/*.
//
// The refusal is raised client-side with NO wire call — the shape §1.1 rule 3
// requires of GetUserInfo. The signal is the access cookie rather than a
// separate flag: this SDK has never kept one, and a second source of truth for
// "am I signed in" is a second thing to get out of step with the jar.
func (c *Client) requireWebauthnSession(operation string) error {
	if c.cookieValue(accessCookie) == "" {
		return &AuthError{Message: operation +
			" requires an authenticated session: enrol a passkey while signed in (CONTRACT.md §24.1)"}
	}
	return nil
}

// webauthnWorkspaceBody fills the discoverable ceremony's workspace from the
// client's own configuration when the caller passed none.
//
// Only fields that actually have a value are emitted: the server takes either
// form at either level, and sending an empty string for the ones it does not
// have is indistinguishable from asking it to resolve nothing.
func (c *Client) webauthnWorkspaceBody(workspace *WebauthnWorkspace) (webauthnDiscoverableBody, error) {
	var body webauthnDiscoverableBody
	if workspace != nil {
		body = webauthnDiscoverableBody{
			OrgID:      workspace.OrgID,
			OrgSlug:    workspace.OrgSlug,
			TenantID:   workspace.TenantID,
			TenantSlug: workspace.TenantSlug,
		}
	}
	if body.OrgID == "" && body.OrgSlug == "" {
		switch {
		case c.org.id != nil:
			body.OrgID = c.org.id.String()
		case c.org.slug != "":
			body.OrgSlug = c.org.slug
		default:
			return body, &AuthError{Message: "WebauthnDiscoverableStart needs an organization: " +
				"construct the client with one, or pass it in the workspace argument (CONTRACT.md §24.1)"}
		}
	}
	if body.TenantID == "" && body.TenantSlug == "" {
		body.TenantSlug = c.tenantSlug
	}
	return body, nil
}

// webauthnResponseJSON accepts either a marshallable value or the platform's
// own JSON string (§24.6a rule 2).
//
// Android's Credential Manager hands back registrationResponseJson /
// authenticationResponseJson, and a browser hands back credential.toJSON().
// Requiring a caller to unmarshal one of those into a struct this SDK
// immediately re-marshals is three chances to corrupt a signed buffer in
// service of nothing — so the string is taken directly, and passes through as
// raw JSON without a round trip through any Go type.
func webauthnResponseJSON(response any, operation string) (json.RawMessage, error) {
	switch value := response.(type) {
	case nil:
		return nil, &AuthError{Message: operation + ": the authenticator response is required (CONTRACT.md §24.1)"}
	case json.RawMessage:
		return value, nil
	case []byte:
		if !json.Valid(value) {
			return nil, webauthnBadJSON(operation)
		}
		return json.RawMessage(value), nil
	case string:
		if !json.Valid([]byte(value)) {
			return nil, webauthnBadJSON(operation)
		}
		return json.RawMessage(value), nil
	default:
		raw, err := json.Marshal(value)
		if err != nil {
			return nil, &NetworkError{Message: fmt.Sprintf("%s: failed to encode the authenticator response: %v", operation, err)}
		}
		return raw, nil
	}
}

func webauthnBadJSON(operation string) error {
	return &AuthError{Message: operation +
		": the authenticator response string is not valid JSON. Pass the platform's response JSON verbatim (CONTRACT.md §24.6a)"}
}

// mapWebauthnRegisterError maps a failed register/finish (CONTRACT.md §24.4
// rule 1).
//
// A 403 here is the tenant's attestation policy refusing THIS AUTHENTICATOR —
// an AAGUID that is not allow-listed, a missing FIDO certification, a revoked
// status — and §24.4 rule 1 requires the server's message to survive, because
// it is the only way the person holding the key learns that a different one
// would work.
//
// That pulls against this SDK's D-15 policy of never putting a response body
// into an error message, and the resolution is the shape D-15 already permits:
// decode ONE NAMED FIELD out of the JSON, exactly as parseAuthzFields does for
// action and resource_id. The raw body still never reaches the error, an
// unparseable or message-less body still yields the redacted text, and no
// other status on no other endpoint gains a message this way.
func mapWebauthnRegisterError(resp *http.Response) error {
	message, body := readBodyForError(resp.Body)
	if resp.StatusCode == http.StatusForbidden {
		var parsed struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(body, &parsed) == nil && parsed.Message != "" {
			message = parsed.Message
		}
	}
	err := errorFromHTTPStatus(resp.StatusCode, message, resp, nil)
	if authzErr, ok := err.(*AuthzError); ok {
		authzErr.Action, authzErr.ResourceID = parseAuthzFields(body)
	}
	if netErr, ok := err.(*NetworkError); ok {
		netErr.RetryAfter = parseRetryAfter(resp.Header.Get("Retry-After"))
	}
	return err
}

// ---------------------------------------------------------------------------
// §24.6b rule 5 — ceremony failure classification
// ---------------------------------------------------------------------------

// WebauthnFailure is a ceremony failure a caller can say something useful about
// (§24.6b rule 5). Five outcomes, and the first two are the ones that matter.
type WebauthnFailure string

const (
	// WebauthnCancelled covers BOTH an explicit refusal and a silent timeout.
	// The WebAuthn spec deliberately refuses to distinguish them, because
	// telling a website which one happened leaks whether an authenticator was
	// present. It must not be recovered by timing the call.
	WebauthnCancelled WebauthnFailure = "cancelled"
	// WebauthnAlreadyRegistered means the authenticator already holds a
	// credential for this account and refused to silently mint a second — the
	// exclusion list working, not a failure. The only classification whose
	// remedy is "use a different device".
	WebauthnAlreadyRegistered WebauthnFailure = "already_registered"
	// WebauthnTimeout is an explicitly aborted ceremony.
	WebauthnTimeout WebauthnFailure = "timeout"
	// WebauthnUnsupported means this device or browser cannot run the ceremony.
	WebauthnUnsupported WebauthnFailure = "unsupported"
	// WebauthnUnknown is everything else.
	WebauthnUnknown WebauthnFailure = "unknown"
)

var webauthnFailureByName = map[string]WebauthnFailure{
	"notallowederror":   WebauthnCancelled,
	"canceled":          WebauthnCancelled,
	"cancelled":         WebauthnCancelled,
	"invalidstateerror": WebauthnAlreadyRegistered,
	"aborterror":        WebauthnTimeout,
	"timeout":           WebauthnTimeout,
	"notsupportederror": WebauthnUnsupported,
	"securityerror":     WebauthnUnsupported,
}

// ClassifyWebauthnError maps a platform ceremony error name to its canonical
// classification (§24.6b rule 5).
//
// Every platform reports a ceremony failure as one opaque type whose only
// machine-readable part is a name, so a handset can relay just that name and a
// Go service can turn it into the same five outcomes a browser would see.
// Anything unrecognized is WebauthnUnknown rather than an error — a classifier
// that can fail is one more thing for an error handler to handle.
func ClassifyWebauthnError(name string) WebauthnFailure {
	if failure, ok := webauthnFailureByName[strings.ToLower(strings.TrimSpace(name))]; ok {
		return failure
	}
	return WebauthnUnknown
}

// WebauthnErrorMessage returns copy for a failure, safe to show a user.
//
// The cancelled string deliberately does not accuse anyone of cancelling: the
// same classification covers a silent timeout, and the spec will not say which
// happened.
func WebauthnErrorMessage(failure WebauthnFailure) string {
	switch failure {
	case WebauthnCancelled:
		return "The request was cancelled or timed out. You can try again."
	case WebauthnAlreadyRegistered:
		return "This device is already registered on your account. Try a different device, or remove the existing one first."
	case WebauthnTimeout:
		return "The request timed out before it completed. Please try again."
	case WebauthnUnsupported:
		return "This browser or device cannot be used for passkeys. Try a different browser, or use another sign-in method."
	default:
		return "Something went wrong. Please try again."
	}
}
