package axiam

// Pushed Authorization Requests — CONTRACT.md §26 (RFC 9126).
//
// PAR moves the authorization request off the browser. Instead of putting
// scope, redirect_uri, state and the PKCE challenge into a URL the user agent
// carries, the client POSTs them straight to AXIAM over an authenticated back
// channel and puts an opaque request_uri in the redirect. What travels through
// the browser is then a random string that cannot be edited into meaning
// something else.
//
// A §12 extension, not a replacement: OidcExchange afterwards is unchanged.

import (
	"context"
	"fmt"
	"net/url"
)

// PushedAuthorizationRequest is the result of OidcPar (CONTRACT.md §26.1).
//
// The server answered 201 — RFC 9126 §2.2 specifies Created, and a success
// predicate written == 200 would treat every successful push as a failure.
//
// State, Nonce and CodeVerifier are carried straight through from the
// AuthorizationRequest that was pushed: §26.2 rule 1 forbids a second
// generator, and rule 6 wants exactly one CodeVerifier so there is no second
// place for the two to disagree.
type PushedAuthorizationRequest struct {
	// AuthorizationURL is where to redirect the browser.
	//
	// It carries EXACTLY client_id and request_uri. Not response_type, not
	// redirect_uri, not scope, not state — the server refuses a request that
	// mixes a request_uri with inline authorization parameters rather than
	// merging them, because merging is where parameter confusion lives
	// (§26.2 rule 2).
	AuthorizationURL string
	// RequestURI is the opaque, single-use handle.
	//
	// Sensitive per §26.5: short-lived and single-use are both reasons it gets
	// treated as harmless, but between the push and the redirect it is a
	// bearer handle to a fully-formed authorization request, and a log line is
	// the wrong place for it to sit for the length of that window.
	RequestURI Sensitive
	// ExpiresIn is the handle's lifetime in seconds. Not advisory (§26.2 rule 3).
	ExpiresIn int
	// State is the value to compare against what the IdP returns.
	State string
	// Nonce is the value that must equal the ID token's nonce claim.
	Nonce string
	// CodeVerifier is the PKCE verifier to pass into OidcExchange — the same
	// one OidcBegin produced.
	CodeVerifier Sensitive
}

// OidcParParams are the arguments to OidcPar.
type OidcParParams struct {
	// Request is what OidcBegin returned. Its URL is replaced by the
	// PushedAuthorizationRequest's AuthorizationURL.
	Request AuthorizationRequest
	// RedirectURI is the relying party's redirect URI — the same value that
	// will be sent at OidcExchange (§26.2 rule 6).
	RedirectURI string
	// Scope is the requested scope. openid is added when absent, exactly as
	// OidcBegin does.
	Scope string
	// TenantID overrides the mandatory ?tenant_id= query parameter (§12.1 note 2).
	TenantID string
	// Configuration is the discovery document; fetched via OidcDiscover when zero.
	Configuration *OidcConfiguration
}

type pushedAuthorizationWire struct {
	RequestURI string `json:"request_uri"`
	ExpiresIn  int    `json:"expires_in"`
}

// OidcPar performs POST /oauth2/par (CONTRACT.md §26.1) — push the
// authorization request over the back channel and get an opaque handle to
// redirect with.
//
// REQUIRED FOR A FAPI 2.0 CLIENT: profile: "fapi2" refuses a registration that
// does not set require_par, so such a client cannot authorize any other way
// (§21.1).
//
// Not retried on a 5xx or a transport failure — it is a POST that creates
// server state, so it falls outside §16.2's read-only eligibility exactly as
// OidcExchange does. The safe recovery is a fresh push, which costs one round
// trip and cannot double-consume anything (§26.2 rule 4).
//
// Returns an *AuthError when the discovery document advertises no
// pushed_authorization_request_endpoint. The URL is never built by
// concatenation onto the issuer.
func (c *Client) OidcPar(ctx context.Context, params OidcParParams) (PushedAuthorizationRequest, error) {
	if err := c.ensureOpen(); err != nil {
		return PushedAuthorizationRequest{}, err
	}
	configuration, err := c.resolveOidcConfiguration(ctx, params.Configuration)
	if err != nil {
		return PushedAuthorizationRequest{}, err
	}
	if configuration.PushedAuthorizationRequestEndpoint == "" {
		return PushedAuthorizationRequest{}, &AuthError{Message: "the authorization server's discovery document advertises no pushed_authorization_request_endpoint: this server does not support RFC 9126 (CONTRACT.md §26.1)"}
	}

	// §26.2 rule 1: everything below was computed by OidcBegin. There is no
	// second generator here, and there must not be — two sources for state or
	// the PKCE pair are two things that can disagree.
	form := url.Values{}
	form.Set("client_id", c.oidc.clientID)
	form.Set("response_type", "code")
	form.Set("redirect_uri", params.RedirectURI)
	form.Set("scope", normalizeScope(params.Scope))
	form.Set("state", params.Request.State)
	form.Set("nonce", params.Request.Nonce)
	form.Set("code_challenge", computeCodeChallenge(params.Request.CodeVerifier.expose()))
	form.Set("code_challenge_method", codeChallengeMethodS256)
	c.appendOidcClientSecret(form)

	endpoint, err := c.oidcEndpointURL(configuration.PushedAuthorizationRequestEndpoint, params.TenantID)
	if err != nil {
		return PushedAuthorizationRequest{}, err
	}

	var wire pushedAuthorizationWire
	if err := c.postOAuth2Form(ctx, endpoint, form, &wire); err != nil {
		return PushedAuthorizationRequest{}, err
	}

	// §26.2 rule 2: exactly two query parameters. The server REFUSES a request
	// carrying both a request_uri and any inline authorization parameter
	// rather than merging them: an attacker supplies the inline value they
	// want and lets the pushed copy satisfy whichever check reads the other
	// one. Re-adding them "for compatibility" restores the attack.
	target, err := url.Parse(configuration.AuthorizationEndpoint)
	if err != nil {
		return PushedAuthorizationRequest{}, &NetworkError{Message: fmt.Sprintf("invalid authorization_endpoint in discovery document: %v", err)}
	}
	query := url.Values{}
	query.Set("client_id", c.oidc.clientID)
	query.Set("request_uri", wire.RequestURI)
	target.RawQuery = encodeQueryRFC3986(query)

	return PushedAuthorizationRequest{
		AuthorizationURL: target.String(),
		RequestURI:       Sensitive(wire.RequestURI),
		ExpiresIn:        wire.ExpiresIn,
		State:            params.Request.State,
		Nonce:            params.Request.Nonce,
		CodeVerifier:     params.Request.CodeVerifier,
	}, nil
}
