package axiam

import (
	"context"
	"net/url"
	"strings"
)

// Token Exchange (RFC 8693) — CONTRACT.md §15.

const (
	// tokenExchangeGrantType is the grant_type of an RFC 8693 exchange.
	tokenExchangeGrantType = "urn:ietf:params:oauth:grant-type:token-exchange"

	// accessTokenType is the actor_token_type this SDK sends, and the
	// subject_token_type it sends when the caller names none.
	accessTokenType = "urn:ietf:params:oauth:token-type:access_token"
)

// The subject_token_type values AXIAM accepts, for
// TokenExchangeParams.SubjectTokenType (CONTRACT.md §15.7).
//
// Named constants because the difference between these two URNs and a typo'd
// one is an invalid_request the caller has to go read RFC 8693 to decode.
const (
	// SubjectTokenTypeAccessToken is an AXIAM-issued access token — the
	// same-domain exchange of §15.1, and what TokenExchange sends when
	// SubjectTokenType is empty.
	SubjectTokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token"

	// SubjectTokenTypeJWT is a JWT from a trusted external issuer — the
	// cross-domain exchange of §15.7. AXIAM also accepts
	// SubjectTokenTypeAccessToken for an external issuer.
	SubjectTokenTypeJWT = "urn:ietf:params:oauth:token-type:jwt"
)

// TokenExchange performs `POST /oauth2/token` with the RFC 8693 grant
// (CONTRACT.md §15.1) — exchange a token for a NARROWER one.
//
// The exchanging client authenticates (client_secret_post): unlike §14's
// device, this is a confidential service, so a Client with no secret fails
// here client-side, with no wire call.
//
// What this method deliberately does NOT do:
//
//   - No default ActorToken (§15.2 rule 1). Leaving it zero asks for
//     IMPERSONATION; the SDK will not quietly reuse the client's own session
//     token as the actor and turn that into a delegation.
//   - No retry or downgrade on unauthorized_client (rule 2) — a registration
//     fact an operator must fix.
//   - No auto-narrowing on invalid_scope (rule 3). The server refuses instead
//     of silently narrowing precisely so the caller finds out here.
//   - No adoption (rule 5). The returned token is handed onward in one
//     outbound call; adopting it would silently re-privilege every subsequent
//     call this client makes. A MUST NOT, where LoginClientCredentials
//     adoption is an opt-in MAY.
//
// A cross-tenant subject token answers invalid_grant, identically to an
// expired one. The SDK does not try to tell them apart (§15.3): the server
// collapses them because distinguishing them is a tenant-enumeration signal.
func (c *Client) TokenExchange(ctx context.Context, params TokenExchangeParams) (ExchangedToken, error) {
	configuration, err := c.resolveOidcConfiguration(ctx, params.Configuration)
	if err != nil {
		return ExchangedToken{}, err
	}
	secret, err := c.requireOidcClientSecret("TokenExchange")
	if err != nil {
		return ExchangedToken{}, err
	}

	form := url.Values{}
	form.Set("grant_type", tokenExchangeGrantType)
	form.Set("subject_token", params.SubjectToken.expose())
	// Whatever the caller named, verbatim. The subject token is NEVER decoded
	// to pick this (§15.7): which kind of token the caller holds is the
	// caller's to know, and a guess here is the difference between a request
	// that is refused and one that is silently reinterpreted.
	subjectTokenType := params.SubjectTokenType
	if subjectTokenType == "" {
		subjectTokenType = accessTokenType
	}
	form.Set("subject_token_type", subjectTokenType)
	if params.ActorToken != "" {
		form.Set("actor_token", params.ActorToken.expose())
		// Sent exactly when actor_token is: RFC 8693 §2.1 requires the pair,
		// and the type alone is a malformed request.
		form.Set("actor_token_type", accessTokenType)
	}
	if len(params.Scopes) > 0 {
		form.Set("scope", strings.Join(params.Scopes, " "))
	}
	if params.Audience != "" {
		form.Set("audience", params.Audience)
	}
	if params.Resource != "" {
		form.Set("resource", params.Resource)
	}
	form.Set("client_id", c.oidc.clientID)
	form.Set("client_secret", secret)

	endpoint, err := c.oidcEndpointURL(configuration.TokenEndpoint, params.TenantID)
	if err != nil {
		return ExchangedToken{}, err
	}

	var wire tokenExchangeWire
	if err := c.postOAuth2Form(ctx, endpoint, form, &wire); err != nil {
		return ExchangedToken{}, err
	}

	return ExchangedToken{
		AccessToken:     Sensitive(wire.AccessToken),
		IssuedTokenType: wire.IssuedTokenType,
		TokenType:       wire.TokenType,
		ExpiresIn:       wire.ExpiresIn,
		Scope:           wire.Scope,
	}, nil
}
