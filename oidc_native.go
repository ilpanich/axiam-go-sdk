package axiam

// Native sign-in with a provider ID token — CONTRACT.md §37 (contract 1.65).
//
// A mobile or desktop app that uses Google, Apple or Facebook's native SDK ends
// up holding an ID token the provider signed for that app, with no browser
// redirect to complete. LoginWithProviderIdToken presents it to AXIAM's token
// endpoint under grant_type=urn:axiam:params:oauth:grant-type:provider-id-token
// and returns the client's ordinary token set.
//
// It is NOT token exchange (§15): TokenExchange refuses ID tokens by name and by
// shape, and this helper neither routes through it nor falls back to it.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// providerIDTokenGrantType is the grant_type of a native sign-in (§37.1).
const providerIDTokenGrantType = "urn:axiam:params:oauth:grant-type:provider-id-token"

// nativeNonceBytes is the size of the raw nonce NativeNonce draws: 32 bytes is
// the RECOMMENDED size of §12.1 rule 1 (the server's documented floor is 128
// bits).
const nativeNonceBytes = 32

// ProviderNonce is the pair a native sign-in needs (CONTRACT.md §37.4).
//
// Give Hashed to the provider's SDK as ITS nonce; keep Raw, and pass it to
// LoginWithProviderIdToken once the provider has returned its ID token.
type ProviderNonce struct {
	// Raw is the nonce AXIAM expects to be sent: at least 32 CSPRNG bytes,
	// base64url without padding. Sensitive (§37.6): it is the preimage of the
	// value inside the provider's token, and is what makes holding that token
	// insufficient to spend it. Hold it only for the length of the attempt.
	Raw Sensitive
	// Hashed is SHA-256 of Raw's bytes as lower-case hexadecimal (64
	// characters) — the value to hand the provider's SDK. Not a secret.
	Hashed string
}

// NativeNonce returns a fresh ProviderNonce (CONTRACT.md §37.4). It performs no
// network I/O and stores nothing; each call returns a different pair.
func NativeNonce() ProviderNonce {
	raw := randomURLSafeToken(nativeNonceBytes)
	return ProviderNonce{Raw: Sensitive(raw), Hashed: hashNativeNonce(raw)}
}

// NativeNonce is the method form of the package-level NativeNonce, for callers
// holding a *Client. It does not touch the Client.
func (c *Client) NativeNonce() ProviderNonce { return NativeNonce() }

// hashNativeNonce is SHA-256 of raw's UTF-8 (= ASCII) bytes, lower-case hex.
func hashNativeNonce(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// LoginWithProviderIdTokenParams are the arguments to LoginWithProviderIdToken.
type LoginWithProviderIdTokenParams struct {
	// Provider is the provider's UUID or its provider_slug — never a kind name
	// such as "google" unless the operator also chose it as the slug (§37.2
	// rule 2). Sent verbatim: not trimmed, case-folded, resolved or looked up.
	// Required.
	Provider string
	// IDToken is the ID token the provider's SDK returned. Required. Single-use
	// across the whole deployment, so a failed call is never retried with it.
	IDToken Sensitive
	// Nonce is the RAW nonce, the one whose SHA-256 hex the provider's SDK was
	// given (NativeNonce().Raw). Sent byte for byte — never hashed, never
	// replaced by the token's own nonce claim. Required.
	Nonce Sensitive
	// Scopes are sent only when named; the SDK adds none. An empty list means
	// no scope at all and therefore no id_token in the response — in particular
	// "openid" is NOT added, unlike OidcBegin (§37.2 rule 7).
	Scopes []string
	// Resource is an optional RFC 8707 resource indicator.
	Resource string
	// TenantID is the tenant UUID for the tenant_id query parameter (§12.3 rule
	// 4). A slug-only Client with no TenantID is refused with no wire call.
	TenantID string
	// Configuration is a pre-fetched discovery document. Fetched via
	// OidcDiscover when nil.
	Configuration *OidcConfiguration
	// AdoptAsCredential adopts the returned access token as this Client's bearer
	// credential, exactly as LoginClientCredentials and DeviceLogin do (§37.2
	// rule 9). False by default.
	AdoptAsCredential bool
}

// LoginWithProviderIdToken performs `POST /oauth2/token` with
// grant_type=urn:axiam:params:oauth:grant-type:provider-id-token (CONTRACT.md
// §37) — sign a user in with the ID token a provider's native SDK produced.
//
// Rules this method keeps, each of them §37.2:
//
//   - Empty Provider, IDToken or Nonce is refused before any request, as is a
//     slug-only Client without a TenantID (which would otherwise need a
//     discovery fetch first).
//   - The form carries exactly grant_type, client_id, provider, id_token, nonce,
//     scope and resource (the last two only when given) and the client's
//     secret when it has one. A public client sends client_id alone.
//   - It is NEVER retried, on any status or transport failure: the provider's
//     token is spent once the server has checked it. invalid_grant is the
//     server's one generic answer to every refusal of that token and is
//     surfaced as received, not interpreted. A transport failure after the
//     request left is indeterminate and is a *NetworkError. The recovery is a
//     fresh provider token with a fresh nonce (NativeNonce).
//   - consent_required is a refusal that has spent the token; it is surfaced as
//     *OAuthProtocolError and never turned into a browser flow.
//   - Neither the ID token nor the raw nonce is logged, kept or placed in an
//     error. Hold the raw nonce only for the length of the attempt.
//
// A 429 rate_limit_exceeded spends nothing, so the caller MAY try again with
// the same pair after the error's RetryAfter; this method does not.
//
// The returned OidcTokenSet carries an id_token only when "openid" was
// requested and granted; it is then validated under §12.4 with the raw Nonce as
// the expected nonce.
func (c *Client) LoginWithProviderIdToken(ctx context.Context, params LoginWithProviderIdTokenParams) (OidcTokenSet, error) {
	if params.Provider == "" {
		return OidcTokenSet{}, errors.New("LoginWithProviderIdToken: Provider is required (CONTRACT.md §37.2 rule 4)")
	}
	if params.IDToken == "" {
		return OidcTokenSet{}, errors.New("LoginWithProviderIdToken: IDToken is required (CONTRACT.md §37.2 rule 4)")
	}
	if params.Nonce == "" {
		return OidcTokenSet{}, errors.New("LoginWithProviderIdToken: Nonce is required (CONTRACT.md §37.2 rule 4)")
	}
	// Resolve the tenant BEFORE discovery: a slug-only client is refused with
	// no wire call at all (§37.1, §37.9 test 5), and a discovery fetch is one.
	if _, err := c.resolveOidcTenantID(params.TenantID); err != nil {
		return OidcTokenSet{}, err
	}
	configuration, err := c.resolveOidcConfiguration(ctx, params.Configuration)
	if err != nil {
		return OidcTokenSet{}, err
	}

	// Exactly §37.1's field set; nothing else may be added.
	form := url.Values{}
	form.Set("grant_type", providerIDTokenGrantType)
	form.Set("client_id", c.session.oidc.clientID)
	form.Set("provider", params.Provider)
	form.Set("id_token", params.IDToken.expose())
	form.Set("nonce", params.Nonce.expose())
	if len(params.Scopes) > 0 {
		form.Set("scope", strings.Join(params.Scopes, " "))
	}
	if params.Resource != "" {
		form.Set("resource", params.Resource)
	}
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

	var wire tokenResponseWire
	if err := c.postOAuth2FormMapped(ctx, endpoint, form, &wire, mapNativeSignInError); err != nil {
		return OidcTokenSet{}, err
	}

	// §37.2 rule 8: the AXIAM ID token carries the request's nonce as sent, so
	// the RAW nonce is the expected one (§12.4 rule 6).
	tokenSet, err := c.toTokenSet(ctx, wire, configuration, idTokenExpectations{
		issuer:       configuration.Issuer,
		clientID:     c.session.oidc.clientID,
		nonce:        params.Nonce.expose(),
		hasNonce:     true,
		clockSkewSec: c.session.oidc.clockSkewSec,
	})
	if err != nil {
		return OidcTokenSet{}, err
	}

	if params.AdoptAsCredential {
		// Same posture as LoginClientCredentials (§37.2 rule 9): a new
		// credential with no LoginUserInfo resets the §5.2 gate and replaces
		// any adopted device credential.
		c.resetScopeUnknown()
		c.replaceDeviceCredential()
		c.adoptOidcCredential(tokenSet.AccessToken)
	}
	return tokenSet, nil
}

// mapNativeSignInError is mapOAuth2ErrorResponse with one difference (§37.3): a
// 5xx carrying a well-formed OAuth2ErrorResponse body — the server's real
// `500 {"error":"server_error", …}` — is an *OAuthProtocolError dispatched on
// the body (§12.3 rule 3), where the device grant's mapper treats every 5xx as
// a transport failure. A 5xx without such a body stays a *NetworkError.
//
// The error built never embeds the request.
func mapNativeSignInError(resp *http.Response) error {
	if resp.StatusCode < 500 {
		return mapOAuth2ErrorResponse(resp)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var wire oauth2ErrorResponseWire
	if json.Unmarshal(body, &wire) == nil && wire.Error != "" {
		return &OAuthProtocolError{
			AuthError:        AuthError{Message: fmt.Sprintf("%s: %s", wire.Error, wire.ErrorDescription)},
			ErrorCode:        wire.Error,
			ErrorDescription: wire.ErrorDescription,
		}
	}
	return mapOAuth2ErrorResponse(&http.Response{
		StatusCode: resp.StatusCode,
		Header:     resp.Header,
		Body:       io.NopCloser(strings.NewReader(string(body))),
	})
}
