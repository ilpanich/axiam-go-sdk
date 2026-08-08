package axiam

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"time"
)

// RP-initiated and back-channel logout — CONTRACT.md §12.7.

const (
	// backchannelLogoutEvent is the `events` member that distinguishes a
	// logout token from an ID token (OIDC Back-Channel Logout 1.0 §2.4).
	backchannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"

	// maxLogoutTokenAge bounds a logout token's `iat`. AXIAM issues them with
	// a 120 s lifetime; this bound is the same order and stops a token
	// captured from a mis-configured RP being replayed days later.
	maxLogoutTokenAge = 5 * time.Minute
)

// logoutTokenClaims is the claim shape of a back-channel logout token.
//
// Events is decoded as a map to json.RawMessage rather than a concrete type:
// the check is that the back-channel key is PRESENT and holds a JSON object,
// and the spec leaves that object's contents open.
type logoutTokenClaims struct {
	Iss    string                     `json:"iss"`
	Aud    string                     `json:"aud"`
	Iat    int64                      `json:"iat"`
	Exp    int64                      `json:"exp"`
	JTI    string                     `json:"jti"`
	SID    string                     `json:"sid"`
	Sub    string                     `json:"sub"`
	Events map[string]json.RawMessage `json:"events"`
	// Nonce must never legitimately be present — see VerifyLogoutToken.
	// A pointer so "absent" and "present but empty" stay distinguishable:
	// an attacker replaying an ID token with `"nonce": ""` must still be
	// caught.
	Nonce *string `json:"nonce"`
}

// LogoutURL builds the RP-initiated logout URL to redirect the user agent to
// (CONTRACT.md §12.7.2).
//
// Performs NO network I/O beyond the discovery fetch the SDK caches anyway,
// and does NOT clear this Client's own session: whether the local session
// ends is the application's decision — a backend holding a service-account
// session must not lose it because a USER logged out.
//
// end_session_endpoint is read from discovery and never synthesised from the
// issuer (rule 1). Code that concatenates works against AXIAM and breaks
// against every other OP the same application is pointed at.
//
// PostLogoutRedirectURI is passed through UNVALIDATED against any local list
// (rule 3): the allow-list lives in the client's server-side registration,
// and a client-side copy would drift and reject a URI an operator had just
// registered.
func (c *Client) LogoutURL(ctx context.Context, params LogoutURLParams) (string, error) {
	configuration, err := c.resolveOidcConfiguration(ctx, params.Configuration)
	if err != nil {
		return "", err
	}
	if configuration.EndSessionEndpoint == "" {
		return "", &AuthError{Message: "the authorization server's discovery document advertises no end_session_endpoint: this server does not support RP-initiated logout (CONTRACT.md §12.7.2 rule 1)"}
	}

	u, err := url.Parse(configuration.EndSessionEndpoint)
	if err != nil {
		return "", &NetworkError{Message: fmt.Sprintf("invalid end_session_endpoint from discovery document: %v", err)}
	}
	q := u.Query()
	q.Set("id_token_hint", params.IDToken.expose())
	if params.PostLogoutRedirectURI != "" {
		q.Set("post_logout_redirect_uri", params.PostLogoutRedirectURI)
	}
	if params.State != "" {
		q.Set("state", params.State)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// VerifyLogoutToken verifies a back-channel logout token the OP POSTed to
// this application's backchannel_logout_uri (CONTRACT.md §12.7.3).
//
// Every check exists because skipping it has a name:
//
//  1. Signature, through the same §12.4 JWKS verifier the ID-token path uses
//     — no second key-fetching path — which already pins EdDSA and requires a
//     kid, so key rotation cannot be defeated by omitting the header.
//  2. iss/aud: a token minted for another RP is not accepted here.
//  3. `events` carries the back-channel-logout key. This is what
//     distinguishes a logout token from an ID token; skipping it means
//     accepting a replayed ID token as a logout instruction.
//  4. `nonce` is ABSENT. Back-Channel Logout 1.0 §2.4 forbids it, and its
//     presence is the documented signature of an ID token being replayed.
//     Rejected, not ignored.
//  5. At least one of sid/sub — a token naming neither identifies nothing.
//  6. exp in the future, iat recent.
//
// Returns sid/sub/jti — never a bare bool, because the RP has to know WHICH
// session to end. Dedup on JTI yourself: delivery is at-least-once, so a
// valid token legitimately arrives twice, and an SDK-side guard would have no
// durable store and would silently drop a real second logout after a restart.
func (c *Client) VerifyLogoutToken(ctx context.Context, token string, configuration *OidcConfiguration) (VerifiedLogoutToken, error) {
	config, err := c.resolveOidcConfiguration(ctx, configuration)
	if err != nil {
		return VerifiedLogoutToken{}, err
	}

	verifier, err := c.oidcJWKSVerifier(ctx, config.JwksURI)
	if err != nil {
		return VerifiedLogoutToken{}, newNetworkError(fmt.Sprintf("failed to reach jwks_uri: %v", err), nil, err)
	}

	payload, err := verifier.VerifyPayload(ctx, []byte(token))
	if err != nil {
		// mapJWKSVerifyError never embeds the token: an unverifiable logout
		// token is exactly the case a naive implementation logs verbatim.
		return VerifiedLogoutToken{}, mapJWKSVerifyError(err)
	}

	var claims logoutTokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return VerifiedLogoutToken{}, &AuthError{Message: "logout token payload is not a JSON object"}
	}

	if claims.Iss != config.Issuer {
		return VerifiedLogoutToken{}, &AuthError{Message: "logout token issuer does not match the discovery document"}
	}
	if claims.Aud != c.oidc.clientID {
		return VerifiedLogoutToken{}, &AuthError{Message: "logout token audience does not match this client_id"}
	}

	// Without this check the whole method is an elaborate way to accept an ID
	// token.
	if !hasBackchannelLogoutEvent(claims.Events) {
		return VerifiedLogoutToken{}, &AuthError{Message: "not a logout token: the events claim does not carry http://schemas.openid.net/event/backchannel-logout"}
	}

	if claims.Nonce != nil {
		return VerifiedLogoutToken{}, &AuthError{Message: "logout token carries a nonce, which Back-Channel Logout 1.0 §2.4 forbids: this is an ID token being replayed as a logout token"}
	}

	if claims.SID == "" && claims.Sub == "" {
		return VerifiedLogoutToken{}, &AuthError{Message: "logout token names neither sid nor sub, so it identifies no session"}
	}

	now := time.Now()
	skew := time.Duration(c.oidc.clockSkewSec) * time.Second
	if claims.Exp == 0 || time.Unix(claims.Exp, 0).Add(skew).Before(now) {
		return VerifiedLogoutToken{}, &AuthError{Message: "logout token has expired"}
	}
	if claims.Iat == 0 || time.Unix(claims.Iat, 0).Add(-skew).After(now) {
		return VerifiedLogoutToken{}, &AuthError{Message: "logout token was issued in the future"}
	}
	if now.Sub(time.Unix(claims.Iat, 0)) > maxLogoutTokenAge+skew {
		return VerifiedLogoutToken{}, &AuthError{Message: "logout token is too old to be a live delivery"}
	}

	if claims.JTI == "" {
		return VerifiedLogoutToken{}, &AuthError{Message: "logout token carries no jti, so the RP cannot dedup redeliveries"}
	}

	return VerifiedLogoutToken{SID: claims.SID, Sub: claims.Sub, JTI: claims.JTI}, nil
}

// hasBackchannelLogoutEvent reports whether events carries the back-channel
// logout key mapped to a JSON OBJECT.
//
// The object-ness matters: Back-Channel Logout 1.0 §2.4 specifies a JSON
// object (normally empty), and accepting `"...backchannel-logout": null` or a
// string would let a near-miss token through on a technicality.
func hasBackchannelLogoutEvent(events map[string]json.RawMessage) bool {
	raw, ok := events[backchannelLogoutEvent]
	if !ok {
		return false
	}
	var obj map[string]any
	return json.Unmarshal(raw, &obj) == nil && obj != nil
}
