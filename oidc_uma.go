package axiam

// UMA 2.0 — Protection API and ticket grant (CONTRACT.md §20).
//
// The resource-server side of User-Managed Access: a service that guards
// resources on someone else's behalf registers them, asks the authorization
// server what a caller would need, and exchanges the resulting ticket for a
// Requesting Party Token.
//
// The rule this file exists to enforce: a permission ticket is single-use and
// is NOT retryable. Every other refusal in this SDK can be re-sent after the
// caller fixes something; this one cannot.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const (
	// umaTicketGrantType is the grant_type of the UMA 2.0 ticket grant
	// (§20.1).
	umaTicketGrantType = "urn:ietf:params:oauth:grant-type:uma-ticket"

	// umaClaimTokenFormat is the only claim_token_format AXIAM implements.
	// §20.2 rule 2 makes the claim_token itself required rather than
	// defaulted; the FORMAT has one value, so the SDK supplies it.
	umaClaimTokenFormat = "urn:ietf:params:oauth:token-type:access_token"

	// UmaProtectionScope is the scope a PAT must carry (§20.2 rule 1) — for
	// callers minting one through LoginClientCredentials.
	UmaProtectionScope = "uma_protection"

	// umaRregPath is the FedAuthz §2.2 resource registration endpoint.
	umaRregPath = "/uma2/rreg/resource_set"

	// umaPermPath is the UMA 2.0 §3.2 permission endpoint.
	umaPermPath = "/uma2/perm"
)

// UmaRegisterResource performs `POST /uma2/rreg/resource_set` (§20.1) —
// register a resource set.
//
// The returned ID is THE AXIAM RESOURCE ID, not a parallel identifier: the
// same UUID is directly usable as RequestedPermission.ResourceID and as the
// resource id anywhere else in this SDK.
//
// pat is a Protection API Token — an ordinary access token obtained through
// LoginClientCredentials with the uma_protection scope. §20.2 rule 1: it must
// be a CLIENT-credentials token, because a minted ticket is bound to the
// client_id that minted it. This SDK never substitutes the client's own
// session token when the caller passes none; an empty pat is a client-side
// error with no wire call.
func (c *Client) UmaRegisterResource(ctx context.Context, pat Sensitive, resource ResourceSet) (ResourceSet, error) {
	var wire resourceSetWire
	if err := c.umaProtectionRequest(ctx, http.MethodPost, umaRregPath, pat, resourceSetToWire(resource), &wire); err != nil {
		return ResourceSet{}, err
	}
	return wire.toResourceSet(), nil
}

// UmaReadResource performs `GET /uma2/rreg/resource_set/{id}` (§20.1).
func (c *Client) UmaReadResource(ctx context.Context, pat Sensitive, id string) (ResourceSet, error) {
	var wire resourceSetWire
	if err := c.umaProtectionRequest(ctx, http.MethodGet, umaResourcePath(id), pat, nil, &wire); err != nil {
		return ResourceSet{}, err
	}
	return wire.toResourceSet(), nil
}

// UmaUpdateResource performs `PUT /uma2/rreg/resource_set/{id}` (§20.1) —
// replace a resource set's state.
//
// resource.ResourceScopes REPLACES the declared list; it does not merge with
// it (§20.2 rule 8). This method deliberately performs no read-modify-write:
// folding the current scopes into the payload as a convenience would make
// removing a scope impossible through this SDK.
func (c *Client) UmaUpdateResource(ctx context.Context, pat Sensitive, id string, resource ResourceSet) (ResourceSet, error) {
	var wire resourceSetWire
	if err := c.umaProtectionRequest(ctx, http.MethodPut, umaResourcePath(id), pat, resourceSetToWire(resource), &wire); err != nil {
		return ResourceSet{}, err
	}
	return wire.toResourceSet(), nil
}

// UmaDeleteResource performs `DELETE /uma2/rreg/resource_set/{id}` (§20.1) —
// deregister a resource set.
func (c *Client) UmaDeleteResource(ctx context.Context, pat Sensitive, id string) error {
	return c.umaProtectionRequest(ctx, http.MethodDelete, umaResourcePath(id), pat, nil, nil)
}

// UmaListResources performs `GET /uma2/rreg/resource_set` (§20.1) — the ids
// THIS client registered.
//
// Not the tenant's resource tree: the server scopes the listing to the
// registering client, so a PAT is not an enumeration handle.
func (c *Client) UmaListResources(ctx context.Context, pat Sensitive) ([]string, error) {
	var ids []string
	if err := c.umaProtectionRequest(ctx, http.MethodGet, umaRregPath, pat, nil, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// UmaRequestTicket performs `POST /uma2/perm` (§20.1) — mint a permission
// ticket for the (resource, scopes) pairs a caller lacks.
//
// The ticket comes back wrapped: for its 60-second life it is the credential
// that converts into an RPT, and a short lifetime is not the same as a
// harmless one (§20.6).
func (c *Client) UmaRequestTicket(ctx context.Context, pat Sensitive, permissions []RequestedPermission) (Sensitive, error) {
	body := make([]requestedPermissionWire, 0, len(permissions))
	for _, permission := range permissions {
		body = append(body, requestedPermissionWire{
			ResourceID:     permission.ResourceID,
			ResourceScopes: permission.ResourceScopes,
		})
	}

	var wire permissionTicketWire
	if err := c.umaProtectionRequest(ctx, http.MethodPost, umaPermPath, pat, body, &wire); err != nil {
		return "", err
	}
	if wire.Ticket == "" {
		return "", &NetworkError{Message: "uma request ticket: malformed PermissionTicketResponse (missing ticket)"}
	}
	return Sensitive(wire.Ticket), nil
}

// UmaExchangeTicket performs `POST /oauth2/token` with the UMA ticket grant
// (§20.1) — redeem a permission ticket for a Requesting Party Token.
//
// Unlike the Protection API above, this is a token-endpoint grant: the CLIENT
// authenticates through the form body (client_secret_post), so a Client with
// no secret fails here client-side, with no wire call.
//
// What this method deliberately does NOT do:
//
//   - NO RETRY, EVER (§20.2 rule 6) — not on 5xx, not on a timeout, not on
//     invalid_grant. This is the one documented exception to §16, and it is a
//     security rule rather than a performance one: the ticket is consumed
//     BEFORE the request is evaluated, so a failed exchange has already spent
//     it, and a retry is a second redemption — exactly the concurrent
//     redemption a server whose storage engine this SDK cannot attest may
//     admit twice (ilpanich/axiam#302). The property holds structurally
//     here: this call goes straight through
//     doRequest and never touches retry.go's policy.
//   - No defaulted ClaimToken (rule 2). It is the only channel that names the
//     requesting party; defaulting it to the resource server's own PAT would
//     mint an RPT for the resource server rather than for the user.
//   - No auto-narrowing on access_denied (rule 3). A partial grant is refused
//     whole, and whether two-of-three permissions is useful is the calling
//     application's judgement, not this SDK's.
//   - No adoption (rule 4). The RPT is the REQUESTING PARTY's token; adopting
//     it would re-privilege every later call this resource server makes as
//     that user.
//   - No refresh token (rule 5) — the grant issues none, and
//     RequestingPartyToken has nowhere to put one. Re-run the grant with a new
//     ticket to get a fresh RPT.
//
// The four ticket refusals — unknown, expired, already used, minted by another
// client — all arrive as one invalid_grant, and this SDK does not guess which
// (§20.4): the server collapses them because telling them apart lets a caller
// probe for live ticket handles.
func (c *Client) UmaExchangeTicket(ctx context.Context, params UmaExchangeTicketParams) (RequestingPartyToken, error) {
	configuration, err := c.resolveOidcConfiguration(ctx, params.Configuration)
	if err != nil {
		return RequestingPartyToken{}, err
	}
	secret, err := c.requireOidcClientSecret("UmaExchangeTicket")
	if err != nil {
		return RequestingPartyToken{}, err
	}
	if params.Ticket == "" {
		return RequestingPartyToken{}, &AuthError{Message: "UmaExchangeTicket requires a ticket (CONTRACT.md §20.1)"}
	}
	if params.ClaimToken == "" {
		// §20.2 rule 2: required, though UMA 2.0 §3.3.1 marks it optional.
		// Refusing client-side rather than sending the grant without it keeps
		// the ticket unspent for a request that could not have succeeded.
		return RequestingPartyToken{}, &AuthError{Message: "UmaExchangeTicket requires a claim_token naming the requesting party; it is never defaulted (CONTRACT.md §20.2 rule 2)"}
	}

	form := url.Values{}
	form.Set("grant_type", umaTicketGrantType)
	form.Set("ticket", params.Ticket.expose())
	form.Set("claim_token", params.ClaimToken.expose())
	form.Set("claim_token_format", umaClaimTokenFormat)
	form.Set("client_id", c.oidc.clientID)
	form.Set("client_secret", secret)

	endpoint, err := c.oidcEndpointURL(configuration.TokenEndpoint, params.TenantID)
	if err != nil {
		return RequestingPartyToken{}, err
	}

	var wire requestingPartyTokenWire
	if err := c.postUmaTicketGrant(ctx, endpoint, form, &wire); err != nil {
		return RequestingPartyToken{}, err
	}

	return RequestingPartyToken{
		AccessToken: Sensitive(wire.AccessToken),
		TokenType:   wire.TokenType,
		ExpiresIn:   wire.ExpiresIn,
	}, nil
}

// postUmaTicketGrant is postOAuth2Form with one difference: the error mapper.
//
// §20.4 puts access_denied on HTTP 403, where RFC 8628's is a 400, and
// requires an SDK to dispatch on the `error` field rather than the status "so
// this stays correct if either moves". mapOAuth2ErrorResponse gates the
// OAuth2ErrorResponse rows to 400/401 — deliberately, so an ordinary REST 403
// still maps to *AuthzError — so widening it there would change every other
// endpoint's behaviour to fix one grant. The fix is contained here instead.
func (c *Client) postUmaTicketGrant(ctx context.Context, rawURL string, form url.Values, out any) error {
	req, err := c.newAbsoluteRequest(ctx, http.MethodPost, rawURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// One request. No retry wrapper, on any status — see the rule 6 note on
	// UmaExchangeTicket.
	resp, err := c.doRequest(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return mapUmaGrantError(resp)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return deserErr(err)
	}
	return nil
}

// mapUmaGrantError maps a non-2xx from the ticket grant, dispatching on the
// `error` field at ANY status before falling back to the §2 status mapping
// (§20.4). A body that is not an OAuth2ErrorResponse still gets the ordinary
// mapping, so a proxy's HTML 502 does not become an *OAuthProtocolError with
// an empty code.
func mapUmaGrantError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	var wire oauth2ErrorResponseWire
	if err := json.Unmarshal(body, &wire); err == nil && wire.Error != "" {
		return &OAuthProtocolError{
			AuthError:        AuthError{Message: fmt.Sprintf("%s: %s", wire.Error, wire.ErrorDescription)},
			ErrorCode:        wire.Error,
			ErrorDescription: wire.ErrorDescription,
		}
	}
	return errorFromHTTPStatus(resp.StatusCode, "uma ticket exchange failed", resp, nil)
}

// umaProtectionRequest performs one Protection API call, PAT-authenticated
// (§20.2 rule 1).
//
// The PAT is set as an explicit Authorization header, which decorateRequest
// leaves alone — it only fills that header in when it is empty, so an adopted
// session credential can never displace the caller's PAT. An empty PAT is
// refused client-side rather than silently sent as the session's token.
//
// body is JSON-encoded when non-nil; out is JSON-decoded from the 2xx body
// when non-nil (the DELETE 204 case passes nil for both).
func (c *Client) umaProtectionRequest(ctx context.Context, method, path string, pat Sensitive, body, out any) error {
	if pat == "" {
		return &AuthError{Message: "the UMA Protection API requires a PAT — a client-credentials token carrying the uma_protection scope; the SDK does not fall back to this client's own session token (CONTRACT.md §20.2 rule 1)"}
	}

	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return &NetworkError{Message: fmt.Sprintf("failed to encode request body: %v", err)}
		}
		reader = strings.NewReader(string(encoded))
	}

	req, err := c.newRequest(ctx, method, path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+pat.expose())

	resp, err := c.doRequest(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// §20.4 maps the Protection API by status (401 / 403 / 400), not
		// through the OAuth2 `error` rows — those belong to the token
		// endpoint.
		return mapErrorResponse(resp)
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return deserErr(err)
	}
	return nil
}

// umaResourcePath builds the per-resource rreg path with the id escaped.
func umaResourcePath(id string) string {
	return umaRregPath + "/" + url.PathEscape(id)
}

// UmaParseChallenge parses a `WWW-Authenticate: UMA …` header value (§20.3)
// into its three fields, returning ok=false when the header names a different
// scheme.
//
// PURE LOCAL COMPUTATION — it performs NO exchange of the ticket it finds, and
// that is the point. Parsing a challenge and acting on it are separate
// decisions: the as_uri names an authorization server the client has not
// necessarily chosen to trust, and auto-exchanging would send the requesting
// party's claim_token to whatever host answered the 401. Return the parsed
// challenge and let the caller decide.
func UmaParseChallenge(header string) (UmaChallenge, bool) {
	trimmed := strings.TrimSpace(header)
	if !strings.HasPrefix(trimmed, "UMA") {
		return UmaChallenge{}, false
	}
	rest := trimmed[len("UMA"):]
	// "UMA" alone is a valid, if useless, challenge; anything else must be
	// separated by whitespace so `UMAX realm="…"` is not read as UMA.
	if rest != "" && strings.TrimLeft(rest, " \t") == rest {
		return UmaChallenge{}, false
	}

	var challenge UmaChallenge
	for _, part := range strings.Split(rest, ",") {
		key, value, found := strings.Cut(part, "=")
		if !found {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), `"`)
		switch strings.TrimSpace(key) {
		case "realm":
			challenge.Realm = value
		case "as_uri":
			challenge.AsURI = value
		case "ticket":
			challenge.Ticket = Sensitive(value)
		default:
			// Unknown parameters are ignored rather than rejected: UMA 2.0
			// permits a server to add its own, and refusing the whole
			// challenge over one would lose the ticket with it.
		}
	}
	return challenge, true
}

// UmaChallengeHeader formats a `WWW-Authenticate: UMA` header value (§20.3,
// emit half) — for a resource server that has just minted a ticket and wants
// to tell the caller where to redeem it.
func UmaChallengeHeader(realm, asURI string, ticket Sensitive) string {
	return fmt.Sprintf(`UMA realm=%q, as_uri=%q, ticket=%q`, realm, asURI, ticket.expose())
}
