package axiam

// Wire mechanics shared by the §12 operations: tenant/endpoint resolution,
// the confidential-client secret helpers, the form-encoded POST plumbing
// (routed through the SAME doRequest choke point every other REST call in
// this SDK uses), the OAuth2ErrorResponse -> *OAuthProtocolError mapping,
// and the token-set / ID-token-verification glue.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ilpanich/axiam-go-sdk/internal/jwks"
)

// resolveOidcConfiguration returns provided as-is when the caller pre-fetched
// a discovery document, else fetches (and caches) one via OidcDiscover.
func (c *Client) resolveOidcConfiguration(ctx context.Context, provided *OidcConfiguration) (OidcConfiguration, error) {
	if provided != nil {
		return *provided, nil
	}
	return c.OidcDiscover(ctx)
}

// resolveOidcTenantID resolves the tenant UUID for the mandatory
// `?tenant_id=` query parameter (CONTRACT.md §12.3 rule 4): the explicit
// per-call argument when given, otherwise the tenant UUID already resolved
// from a prior successful Login/Refresh (the access token's tenant_id
// claim). This Client is always constructed with a tenant SLUG (NewClient's
// required positional argument), so — unlike SDKs whose constructor accepts
// an alternate tenant_id-UUID form — there is no client-level UUID fallback
// to fall back to; a resolved-from-login UUID is the only fallback source.
// Neither source available is a CLIENT-SIDE *AuthError, no wire call (same
// discipline as §1.1 rule 3).
func (c *Client) resolveOidcTenantID(explicit string) (string, error) {
	if explicit != "" {
		if _, err := uuid.Parse(explicit); err != nil {
			return "", &AuthError{Message: "tenant_id must be a UUID for the /oauth2 query parameter; a tenant slug cannot be substituted (CONTRACT.md §12.3 rule 4)"}
		}
		return explicit, nil
	}
	if id, ok := c.resolvedOrgTenantID(); ok {
		return id.String(), nil
	}
	return "", &AuthError{Message: "this operation requires a tenant_id UUID for the /oauth2 query parameter: pass TenantID explicitly, or call Login() first so it can be resolved from the access token (CONTRACT.md §12.3 rule 4)"}
}

// oidcEndpointURL builds the final endpoint URL: the discovery document's
// endpoint (read from the document, NEVER hardcoded — §12.3 rule 6) plus the
// mandatory `?tenant_id=<uuid>` query parameter (§12.1 note 2). Existing
// query parameters on the endpoint, if any, are preserved.
// mtlsAlias returns the RFC 8705 §5 alias selected by pick, or "" when this
// call is not going over mutual TLS, the document publishes no aliases, or it
// publishes none for that endpoint (CONTRACT.md §21.3 rule 2).
//
// Three things this deliberately does NOT do, each of them a documented way to
// get rule 2 wrong:
//
//   - An absent mtls_endpoint_aliases is never an error. It means "no separate
//     mTLS host", not "mTLS unsupported" — a deployment running
//     client_auth = optional on one listener serves both populations at the
//     conventional endpoints and correctly publishes nothing.
//   - pick can only reach MtlsEndpointAliases, so AuthorizationEndpoint,
//     EndSessionEndpoint and JwksURI are unreachable rather than merely
//     unused: they are front-channel or public, and an mTLS host would raise a
//     certificate-chooser dialog in the user's browser.
//   - Issuer is untouched. It is an identifier, not an endpoint, and §12.4
//     rule 3 still compares a token's `iss` against configuration.Issuer by
//     exact string — including for a token minted at an alias endpoint.
func (c *Client) mtlsAlias(
	configuration *OidcConfiguration,
	pick func(*MtlsEndpointAliases) string,
	replaces string,
) (string, error) {
	if !c.presentsClientCertificate || configuration.MtlsEndpointAliases == nil {
		return "", nil
	}
	alias := pick(configuration.MtlsEndpointAliases)
	if alias == "" {
		return "", nil
	}
	if err := assertUsableMtlsAlias(alias, replaces); err != nil {
		return "", err
	}
	return alias, nil
}

// assertUsableMtlsAlias refuses an mtls_endpoint_aliases entry that cannot
// carry a client certificate (CONTRACT.md §21.3.1 vector C, contract 1.43).
//
// Falling back to the top-level endpoint looks like the safe answer and is the
// dangerous one: the caller asked to authenticate with a certificate, the
// operator published something unusable, and sending the certificate to the
// front-channel host authenticates nothing while appearing to work.
//
// Two defects, each a refusal on its own:
//
//   - NOT AN ABSOLUTE URL. A relative alias resolves against nothing the client
//     holds, and the base that might seem obvious — the issuer's host — is
//     precisely the host the alias exists to name a different one from.
//   - A SCHEME WEAKER THAN THE ENDPOINT IT REPLACES. An alias substitutes for
//     exactly one top-level endpoint, so that is what it is compared against:
//     https -> http is a downgrade, while http -> http is a development
//     deployment, which AXIAM's own build_mtls_aliases supports and this
//     suite's harness is.
//
// The refusal is an *AuthError, matching every other "the discovery document
// advertises something this client cannot use" in this package. It also
// matters operationally: §16.3 retries *NetworkError and only *NetworkError,
// so the other choice would have attempted a permanent, deterministic
// misconfiguration three times and reported it as transient.
func assertUsableMtlsAlias(alias, replaces string) error {
	parsed, err := url.Parse(alias)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return &AuthError{Message: fmt.Sprintf(
			"mtls_endpoint_aliases publishes %q, which is not an absolute URL. Refusing rather "+
				"than falling back to the top-level endpoint: this call presents a client "+
				"certificate, and sending it to the front-channel host would authenticate "+
				"nothing while appearing to work (CONTRACT.md §21.3.1 vector C)", alias)}
	}
	replaced, err := url.Parse(replaces)
	replacedIsTLS := replaces != "" && err == nil && replaced.Scheme == "https"
	if replacedIsTLS && parsed.Scheme != "https" {
		return &AuthError{Message: fmt.Sprintf(
			"mtls_endpoint_aliases publishes %q, whose scheme is %q, in place of an https "+
				"endpoint. That is a downgrade, and mutual TLS over cleartext is a "+
				"contradiction; refusing rather than falling back to the top-level endpoint "+
				"(CONTRACT.md §21.3.1 vector C)", alias, parsed.Scheme)}
	}
	return nil
}

// preferredEndpoint returns the §21.3 rule 2 alias for an endpoint, falling
// back to the top-level entry of the same name.
//
// An empty result still means "this server does not support the feature" for a
// conditionally-advertised endpoint — the caller raises that, and never
// concatenates a URL onto the issuer.
// A malformed alias is an error rather than a fallback — see
// assertUsableMtlsAlias.
func (c *Client) preferredEndpoint(
	configuration *OidcConfiguration,
	pick func(*MtlsEndpointAliases) string,
	topLevel string,
) (string, error) {
	alias, err := c.mtlsAlias(configuration, pick, topLevel)
	if err != nil {
		return "", err
	}
	if alias != "" {
		return alias, nil
	}
	return topLevel, nil
}

func (c *Client) oidcEndpointURL(endpoint, tenantIDOverride string) (string, error) {
	tenantID, err := c.resolveOidcTenantID(tenantIDOverride)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", &NetworkError{Message: fmt.Sprintf("invalid endpoint URL from discovery document: %v", err)}
	}
	q := u.Query()
	q.Set("tenant_id", tenantID)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// appendOidcClientSecret adds client_secret to form for a confidential
// client, and omits it entirely for a public client — §12.1 forbids sending
// an empty/null value for an absent optional field.
func (c *Client) appendOidcClientSecret(form url.Values) {
	if c.oidc.clientSecret != "" {
		form.Set("client_secret", c.oidc.clientSecret.expose())
	}
}

// requireOidcClientSecret returns the configured client_secret for an
// operation that cannot be performed without one (§12.1 note 4), or an
// *AuthError naming operation when none was configured.
func (c *Client) requireOidcClientSecret(operation string) (string, error) {
	if c.oidc.clientSecret == "" {
		return "", &AuthError{Message: fmt.Sprintf("%s requires confidential-client credentials: construct the Client with WithOidcClientSecret (CONTRACT.md §12.1 note 4)", operation)}
	}
	return c.oidc.clientSecret.expose(), nil
}

// newAbsoluteRequest builds a request against an ABSOLUTE URL — an endpoint
// taken from the OIDC discovery document (§12.3 rule 6: never hardcoded
// relative to the Client's own base URL) — unlike newRequest, which joins a
// relative path against c.baseURL.
func (c *Client) newAbsoluteRequest(ctx context.Context, method, rawURL string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return nil, &NetworkError{Message: fmt.Sprintf("failed to build request: %v", err)}
	}
	return req, nil
}

// postToken POSTs form to configuration's TokenEndpoint (plus the mandatory
// tenant_id query parameter) and decodes the resulting TokenResponse.
func (c *Client) postToken(ctx context.Context, configuration OidcConfiguration, form url.Values, tenantIDOverride string) (tokenResponseWire, error) {
	preferred, err := c.preferredEndpoint(
		&configuration,
		func(a *MtlsEndpointAliases) string { return a.TokenEndpoint },
		configuration.TokenEndpoint,
	)
	if err != nil {
		return tokenResponseWire{}, err
	}
	endpoint, err := c.oidcEndpointURL(preferred, tenantIDOverride)
	if err != nil {
		return tokenResponseWire{}, err
	}
	var wire tokenResponseWire
	if err := c.postOAuth2Form(ctx, endpoint, form, &wire); err != nil {
		return tokenResponseWire{}, err
	}
	return wire, nil
}

// postOAuth2Form POSTs a `application/x-www-form-urlencoded` body (§12.1
// note 1) to rawURL through the SAME doRequest choke point every other REST
// call in this SDK uses (so §5's X-Tenant-ID header, §3's CSRF echo, and the
// §4 cookie jar / §6 TLS transport all apply unconditionally, exactly as
// CONTRACT.md §12.1 note 2 requires). Non-2xx responses are mapped via
// mapOAuth2ErrorResponse. out may be nil (Revoke's empty-body 2xx case); a
// non-nil out is JSON-decoded from the 2xx body.
func (c *Client) postOAuth2Form(ctx context.Context, rawURL string, form url.Values, out any) error {
	req, err := c.newAbsoluteRequest(ctx, http.MethodPost, rawURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.doRequest(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return mapOAuth2ErrorResponse(resp)
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

// mapOAuth2ErrorResponse maps a non-2xx response from an `/oauth2/*`
// endpoint (CONTRACT.md §2, §12.1, §12.3 rule 3): a 400 (token endpoint) or
// 401 (introspect/revoke) carrying a well-formed OAuth2ErrorResponse body
// maps to *OAuthProtocolError; anything else — including a 400/401 WITHOUT
// that body shape, and every other status — falls through to the existing
// §2 status mapper, which does NOT special-case 400 as an OAuthProtocolError
// (the endpoint-qualified row only wins when the body actually matches).
func mapOAuth2ErrorResponse(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	if resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnauthorized {
		var wire oauth2ErrorResponseWire
		if err := json.Unmarshal(body, &wire); err == nil && wire.Error != "" {
			return &OAuthProtocolError{
				AuthError:        AuthError{Message: fmt.Sprintf("%s: %s", wire.Error, wire.ErrorDescription)},
				ErrorCode:        wire.Error,
				ErrorDescription: wire.ErrorDescription,
			}
		}
	}
	return errorFromHTTPStatus(resp.StatusCode, "oauth2 request failed", resp, nil)
}

// toTokenSet converts a TokenResponse into an OidcTokenSet, validating any
// id_token FIRST (§12.4). Validation precedes construction, so a failure
// discards the whole set — the caller never sees the access or refresh
// token from a response whose ID token was rejected (§12.4 rule 7).
func (c *Client) toTokenSet(ctx context.Context, wire tokenResponseWire, configuration OidcConfiguration, exp idTokenExpectations) (OidcTokenSet, error) {
	var idClaims *IDTokenClaims
	if wire.IDToken != nil && *wire.IDToken != "" {
		claims, err := c.verifyIDToken(ctx, configuration.JwksURI, *wire.IDToken, exp)
		if err != nil {
			return OidcTokenSet{}, err
		}
		idClaims = &claims
	}

	set := OidcTokenSet{
		AccessToken: Sensitive(wire.AccessToken),
		TokenType:   wire.TokenType,
		ExpiresIn:   wire.ExpiresIn,
		IDClaims:    idClaims,
	}
	if wire.Scope != nil {
		set.Scope = *wire.Scope
	}
	if wire.RefreshToken != nil {
		set.RefreshToken = Sensitive(*wire.RefreshToken)
	}
	if wire.IDToken != nil {
		set.IDToken = Sensitive(*wire.IDToken)
	}
	return set, nil
}

// verifyIDToken performs the full §12.4 checklist: signature (via the
// shared internal/jwks verifier, reused not forked) then issuer/audience/
// time/nonce (rules 3-6), returning *AuthError with the matching Reason code
// on ANY failure — never a partial result (§12.4 rule 7).
func (c *Client) verifyIDToken(ctx context.Context, jwksURI, idToken string, exp idTokenExpectations) (IDTokenClaims, error) {
	verifier, err := c.oidcJWKSVerifier(ctx, jwksURI)
	if err != nil {
		return IDTokenClaims{}, newNetworkError(fmt.Sprintf("failed to reach jwks_uri: %v", err), nil, err)
	}

	payload, err := verifier.VerifyPayload(ctx, []byte(idToken))
	if err != nil {
		return IDTokenClaims{}, mapJWKSVerifyError(err)
	}

	return validateIDToken(payload, exp, time.Now())
}

// oidcJWKSVerifier lazily builds (and reuses) the JWKS verifier for a
// jwks_uri (§12.3 rule 6: JWKS is a single global key set, not per-tenant —
// this cache is keyed on jwks_uri, never on tenant).
func (c *Client) oidcJWKSVerifier(ctx context.Context, jwksURI string) (*jwks.Verifier, error) {
	c.oidc.verifiersMu.Lock()
	if v, ok := c.oidc.verifiers[jwksURI]; ok {
		c.oidc.verifiersMu.Unlock()
		return v, nil
	}
	c.oidc.verifiersMu.Unlock()

	v, err := jwks.NewVerifierForURL(ctx, jwksURI, c.httpc)
	if err != nil {
		return nil, err
	}

	c.oidc.verifiersMu.Lock()
	defer c.oidc.verifiersMu.Unlock()
	if existing, ok := c.oidc.verifiers[jwksURI]; ok {
		// Another goroutine won the construction race; both verifiers are
		// functionally identical (same URL, same cache semantics), so keep
		// whichever was stored first and let this one be garbage collected.
		return existing, nil
	}
	if c.oidc.verifiers == nil {
		c.oidc.verifiers = make(map[string]*jwks.Verifier)
	}
	c.oidc.verifiers[jwksURI] = v
	return v, nil
}

// adoptOidcCredential stores accessToken as this Client's bearer credential
// for subsequent REST calls (CONTRACT.md §12.1, an explicit opt-in MAY).
// Applied only in decorateRequest (client.go) — never written to a public
// field, the cookie jar, or logged — and deliberately never sent to
// /oauth2/*, which authenticates via the form body instead (§12.1 note 3).
func (c *Client) adoptOidcCredential(accessToken Sensitive) {
	c.oidc.adoptedMu.Lock()
	c.oidc.adoptedToken = accessToken
	c.oidc.adoptedMu.Unlock()
}

// adoptedOidcCredential reads the currently adopted credential, if any (""
// when none has been adopted).
func (c *Client) adoptedOidcCredential() Sensitive {
	c.oidc.adoptedMu.Lock()
	defer c.oidc.adoptedMu.Unlock()
	return c.oidc.adoptedToken
}
