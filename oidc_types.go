package axiam

// Public types for the OIDC / SSO relying-party helpers (CONTRACT.md §12).
//
// Naming convention, deliberately mirroring the TypeScript reference
// implementation's split (CONTRACT.md §12 T1 judgment call 3):
//
//   - Types that ARE a protocol document keep their wire spelling:
//     OidcConfiguration (the OIDC Discovery 1.0 metadata document) uses the
//     wire's snake_case JSON tags, and IDTokenClaims keeps JWT/OIDC claim
//     names (iss, sub, aud, ...) rather than Go's usual field-name style — a
//     caller cross-references these against OIDC Core / RFC 8414.
//   - Types that are an SDK-shaped RESULT use ordinary Go exported-field
//     casing: AuthorizationRequest, OidcTokenSet, IntrospectionResult,
//     SsoStartResult, SsoCompleteResult. These are not verbatim wire
//     objects — they carry Sensitive-wrapped fields and derived data
//     (IDClaims) the wire body does not have.
//
// The five §12.5 secret fields — access_token, refresh_token, id_token,
// client_secret, code_verifier — are Sensitive wherever they appear below.
// state and nonce are NOT secrets (§12.3 rule 2) and are plain strings.

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

// OidcConfiguration is the OIDC Discovery 1.0 metadata document served by
// `GET /.well-known/openid-configuration` (wire schema OidcDiscoveryDocument,
// CONTRACT.md §12.1). Every field is required by the server's schema.
//
// Issuer is the AUTHORITATIVE issuer for ID-token validation (§12.4 rule 3).
// It may legitimately differ from the client's base URL when AXIAM runs
// behind a proxy, so this SDK never rejects a document on an issuer/base-URL
// mismatch (§12.3 rule 6). Likewise JwksURI is read from here rather than
// hardcoded.
type OidcConfiguration struct {
	// Issuer is the value an ID token's `iss` claim must equal exactly.
	Issuer string `json:"issuer"`
	// AuthorizationEndpoint is what OidcBegin builds its redirect URL from.
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	// TokenEndpoint is used by OidcExchange, OidcRefresh and
	// LoginClientCredentials.
	TokenEndpoint string `json:"token_endpoint"`
	// UserinfoEndpoint is advertised by the server but deliberately NEVER
	// called by this SDK (§12.3 rule 5).
	UserinfoEndpoint string `json:"userinfo_endpoint"`
	// JwksURI is the JWKS document whose keys verify ID-token signatures
	// (§12.4 rule 2).
	JwksURI string `json:"jwks_uri"`
	// RevocationEndpoint is the RFC 7009 endpoint used by Revoke.
	RevocationEndpoint string `json:"revocation_endpoint"`
	// IntrospectionEndpoint is the RFC 7662 endpoint used by Introspect.
	IntrospectionEndpoint string `json:"introspection_endpoint"`
	// ResponseTypesSupported lists OAuth2 response_type values the server
	// supports.
	ResponseTypesSupported []string `json:"response_types_supported"`
	// SubjectTypesSupported lists subject identifier types the server
	// supports.
	SubjectTypesSupported []string `json:"subject_types_supported"`
	// IDTokenSigningAlgValuesSupported is informational only: §12.4 rule 1
	// pins verification to EdDSA regardless of what appears here.
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	// ScopesSupported lists scopes the server supports.
	ScopesSupported []string `json:"scopes_supported"`
	// TokenEndpointAuthMethodsSupported lists the client-authentication
	// methods the token endpoint supports (client_secret_post, §12.1 note 3).
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	// ClaimsSupported lists claims the server may include in an ID token.
	ClaimsSupported []string `json:"claims_supported"`
	// GrantTypesSupported lists grant types the token endpoint supports.
	GrantTypesSupported []string `json:"grant_types_supported"`
}

// ---------------------------------------------------------------------------
// OidcBegin
// ---------------------------------------------------------------------------

// AuthorizationRequest is the result of OidcBegin — everything the caller
// needs to start an authorization-code + PKCE login (CONTRACT.md §12.1).
//
// The caller owns this state (§12.3 rule 1). The SDK stores nothing: persist
// State, Nonce and CodeVerifier in your own HTTP session (or via an
// OidcStateStore), redirect the browser to URL, and pass Nonce and
// CodeVerifier back into OidcExchange when the code arrives.
type AuthorizationRequest struct {
	// URL is the fully-built authorization URL to redirect the browser to.
	URL string
	// State is a CSPRNG CSRF value (>=128 bits, base64url unpadded) to
	// compare against the `state` the IdP returns. Not a secret.
	State string
	// Nonce is a CSPRNG replay-protection value (>=128 bits) that must equal
	// the ID token's `nonce` claim. Not a secret.
	Nonce string
	// CodeVerifier is the PKCE verifier, secret for its whole lifetime
	// (§12.5). Pass it back into OidcExchange.
	CodeVerifier Sensitive
}

// OidcBeginParams are the arguments to OidcBegin — a pure local computation,
// no network I/O. ClientID comes from the Client's own configuration
// (WithOidcClientID), not a per-call argument (§12 T1 judgment call 21).
type OidcBeginParams struct {
	// RedirectURI is the relying party's redirect URI, echoed back into
	// OidcExchange unchanged.
	RedirectURI string
	// Scope is the requested scope, space-separated. "openid" is added
	// automatically when absent (§12.1 rule 4); the zero value requests
	// exactly "openid".
	Scope string
	// ExtraParams are additional caller-supplied authorization-request query
	// parameters (e.g. prompt, login_hint, ui_locales). §12.1 rule 5 allows
	// caller-supplied additions but forbids the SDK from adding any of its
	// own beyond the mandated eight: attempting to override one of those
	// eight is a PROGRAMMING ERROR, returned as a plain error — deliberately
	// NOT the AuthError/AuthzError/NetworkError taxonomy (§12 port addendum
	// item 9).
	ExtraParams map[string]string
}

// ---------------------------------------------------------------------------
// Token sets
// ---------------------------------------------------------------------------

// OidcTokenSet is a token set returned by the OAuth2 token endpoint (wire
// schema TokenResponse), returned by OidcExchange, OidcRefresh and
// LoginClientCredentials.
//
// AccessToken, RefreshToken and IDToken are Sensitive (§12.5): String()/
// fmt/JSON all redact them to "[SENSITIVE]", and the raw value is reachable
// only through the package-internal expose() accessor. RefreshToken and
// IDToken are the empty string when the grant did not issue one — no
// legitimate token is ever the empty string, matching the convention
// LoginResult.MFAToken already uses.
//
// IDClaims is non-nil exactly when IDToken is non-empty, and holds the
// ALREADY-VALIDATED claim set (§12.4) — validation happens before this
// value is ever constructed, so an OidcTokenSet in your hands is never
// partially trusted (§12.4 rule 7).
type OidcTokenSet struct {
	// AccessToken is the OAuth2 access token (§12.5 secret).
	AccessToken Sensitive
	// TokenType is the token type the server issued ("Bearer").
	TokenType string
	// ExpiresIn is the access-token lifetime in seconds from the time of the
	// response.
	ExpiresIn int64
	// Scope is the granted scope, when the server narrowed or echoed it.
	Scope string
	// RefreshToken is the refresh token, when the grant issued one (§12.5
	// secret). Empty when absent.
	RefreshToken Sensitive
	// IDToken is the raw ID token, when the grant issued one (§12.5 secret).
	// Empty when absent.
	IDToken Sensitive
	// IDClaims is the validated ID-token claims — non-nil exactly when
	// IDToken is non-empty (§12.1, §12.4).
	IDClaims *IDTokenClaims
}

// OidcExchangeParams are the arguments to OidcExchange
// (`grant_type=authorization_code`).
type OidcExchangeParams struct {
	// Code is the authorization code the IdP redirected back with.
	Code string
	// CodeVerifier is the verifier from the matching AuthorizationRequest.
	CodeVerifier Sensitive
	// RedirectURI is the same redirect_uri that was sent on the
	// authorization request.
	RedirectURI string
	// Nonce is the nonce from the matching AuthorizationRequest. MANDATORY —
	// §12.4 rule 6 is not optional for this grant.
	Nonce string
	// TenantID is the tenant UUID for the token endpoint's required
	// tenant_id query parameter. When empty, falls back to the tenant UUID
	// resolved from a prior successful Login/Refresh (§12.3 rule 4).
	TenantID string
	// Configuration is a pre-fetched discovery document, to avoid
	// re-reading the (cached) one. Fetched via OidcDiscover when nil.
	Configuration *OidcConfiguration
}

// OidcRefreshParams are the arguments to OidcRefresh
// (`grant_type=refresh_token`).
type OidcRefreshParams struct {
	// RefreshToken is the refresh token to redeem.
	RefreshToken Sensitive
	// Scope is an optional narrowed scope to request. Omitted from the form
	// body when empty.
	Scope string
	// TenantID is the tenant UUID for the tenant_id query parameter (§12.3
	// rule 4).
	TenantID string
	// Configuration is a pre-fetched discovery document. Fetched via
	// OidcDiscover when nil.
	Configuration *OidcConfiguration
}

// LoginClientCredentialsParams are the arguments to LoginClientCredentials
// (`grant_type=client_credentials`).
type LoginClientCredentialsParams struct {
	// Scope is an optional scope to request. This grant requests no "openid"
	// scope and the response carries no id_token (§12.1).
	Scope string
	// TenantID is the tenant UUID for the tenant_id query parameter (§12.3
	// rule 4).
	TenantID string
	// Configuration is a pre-fetched discovery document. Fetched via
	// OidcDiscover when nil.
	Configuration *OidcConfiguration
	// AdoptAsCredential adopts the returned access_token as this Client's
	// bearer credential for subsequent REST calls on the same session — the
	// §12.1 "login_client_credentials as a credential source" allowance (a
	// MAY, hence opt-in and false by default). The token is held behind
	// Sensitive and applied only in decorateRequest (never a public field,
	// never the cookie jar, never sent to /oauth2/*).
	AdoptAsCredential bool
}

// ---------------------------------------------------------------------------
// Introspection / revocation
// ---------------------------------------------------------------------------

// IntrospectParams are the arguments to Introspect (RFC 7662). Requires
// confidential-client credentials (§12.1 note 4).
type IntrospectParams struct {
	// Token is the token to introspect.
	Token Sensitive
	// TokenTypeHint is an optional RFC 7662 token_type_hint (access_token /
	// refresh_token).
	TokenTypeHint string
	// TenantID is the tenant UUID for the tenant_id query parameter (§12.3
	// rule 4).
	TenantID string
	// Configuration is a pre-fetched discovery document. Fetched via
	// OidcDiscover when nil.
	Configuration *OidcConfiguration
}

// RevokeParams are the arguments to Revoke (RFC 7009). Requires
// confidential-client credentials (§12.1 note 4).
type RevokeParams struct {
	// Token is the token to revoke.
	Token Sensitive
	// TokenTypeHint is an optional RFC 7009 token_type_hint.
	TokenTypeHint string
	// TenantID is the tenant UUID for the tenant_id query parameter (§12.3
	// rule 4).
	TenantID string
	// Configuration is a pre-fetched discovery document. Fetched via
	// OidcDiscover when nil.
	Configuration *OidcConfiguration
}

// IntrospectionResult is the RFC 7662 introspection result (wire schema
// IntrospectionResponse). Only Active is guaranteed; the server omits the
// metadata fields for an inactive token (zero values below).
type IntrospectionResult struct {
	// Active reports whether the token is currently active.
	Active bool
	// Sub is the subject the token was issued to.
	Sub string
	// ClientID is the client the token was issued to.
	ClientID string
	// Scope is the scope granted to the token.
	Scope string
	// TokenType is the token type ("Bearer").
	TokenType string
	// Exp is the expiry time, epoch seconds. Zero when absent.
	Exp int64
	// Iat is the issued-at time, epoch seconds. Zero when absent.
	Iat int64
}

// ---------------------------------------------------------------------------
// Federation SSO (upstream IdP)
// ---------------------------------------------------------------------------

// SsoStartParams are the arguments to SsoStart
// (`POST /api/v1/auth/federation/oidc/start`).
//
// One tenant form (TenantID or TenantSlug) and one org form (OrgID or
// OrgSlug) must be resolvable, from these fields or from the Client's own
// construction options (CONTRACT.md §5.1).
type SsoStartParams struct {
	// FederationConfigID is the UUID of the server-side federation
	// configuration identifying the upstream IdP.
	FederationConfigID string
	// RedirectURI is the post-login destination, stored server-side and
	// echoed back by SsoComplete.
	RedirectURI string
	// TenantID is the tenant UUID. Defaults to the Client's own tenant when
	// empty (this SDK always constructs a Client with a tenant slug, so the
	// default tenant form is TenantSlug — see TenantSlug below).
	TenantID string
	// TenantSlug is the tenant slug — the tenant form used by default,
	// since NewClient always requires one.
	TenantSlug string
	// OrgID is the organization UUID. Defaults to the Client's configured
	// organization (WithOrgID) when empty.
	OrgID string
	// OrgSlug is the organization slug. Defaults to the Client's configured
	// organization (WithOrgSlug) when empty.
	OrgSlug string
}

// SsoStartResult is the result of SsoStart (wire schema OidcStartResponse).
//
// There is deliberately no nonce: on the federation path the nonce never
// leaves the server (§12.1 note 7). Round-trip State into SsoComplete
// unmodified — the server stores it single-use with a 10-minute TTL and
// recovers the whole login context from it.
type SsoStartResult struct {
	// AuthorizeURL is the upstream IdP authorization URL to redirect the
	// browser to.
	AuthorizeURL string
	// State is the single-use CSRF state to round-trip back into SsoComplete
	// unmodified.
	State string
	// ExpiresInSecs is the remaining TTL of the server-side state row, in
	// seconds (600 = 10 min).
	ExpiresInSecs int64
}

// SsoCompleteParams are the arguments to SsoComplete
// (`POST /api/v1/auth/federation/oidc/callback`).
type SsoCompleteParams struct {
	// State is the `state` value the IdP redirected back with — must be the
	// one SsoStart returned.
	State string
	// Code is the authorization code the IdP redirected back with.
	Code string
}

// SsoCompleteResult is the result of SsoComplete (wire schema
// SsoLoginSuccessResponse).
//
// It carries NO token material — the session arrives as Set-Cookie, so the
// §4 cookie jar (already owned by every *Client) is what actually captures
// it (§12.1 note 6).
type SsoCompleteResult struct {
	// UserID is the provisioned/linked user's UUID.
	UserID string
	// SessionID is the established session's UUID.
	SessionID string
	// ExpiresIn is the session/access-token lifetime in seconds.
	ExpiresIn int64
	// RedirectURI is the post-login destination that was stored during
	// SsoStart.
	RedirectURI string
}

// ---------------------------------------------------------------------------
// Wire types (unexported, snake_case JSON tags — mirror the server schemas
// verbatim, mirror only, no server dependency)
// ---------------------------------------------------------------------------

// tokenResponseWire is the 200 body of `POST /oauth2/token` (wire schema
// TokenResponse). token_type is required (§12 port addendum item 3).
type tokenResponseWire struct {
	AccessToken  string  `json:"access_token"`
	TokenType    string  `json:"token_type"`
	ExpiresIn    int64   `json:"expires_in"`
	Scope        *string `json:"scope,omitempty"`
	RefreshToken *string `json:"refresh_token,omitempty"`
	IDToken      *string `json:"id_token,omitempty"`
}

// introspectionResponseWire is the 200 body of `POST /oauth2/introspect`
// (wire schema IntrospectionResponse).
type introspectionResponseWire struct {
	Active    bool    `json:"active"`
	Sub       *string `json:"sub,omitempty"`
	ClientID  *string `json:"client_id,omitempty"`
	Scope     *string `json:"scope,omitempty"`
	TokenType *string `json:"token_type,omitempty"`
	Exp       *int64  `json:"exp,omitempty"`
	Iat       *int64  `json:"iat,omitempty"`
}

// oidcStartResponseWire is the 200 body of
// `POST /api/v1/auth/federation/oidc/start` (wire schema OidcStartResponse).
type oidcStartResponseWire struct {
	AuthorizeURL  string `json:"authorize_url"`
	State         string `json:"state"`
	ExpiresInSecs int64  `json:"expires_in_secs"`
}

// ssoLoginSuccessResponseWire is the 200 body of
// `POST /api/v1/auth/federation/oidc/callback` (wire schema
// SsoLoginSuccessResponse).
type ssoLoginSuccessResponseWire struct {
	UserID      string `json:"user_id"`
	SessionID   string `json:"session_id"`
	ExpiresIn   int64  `json:"expires_in"`
	RedirectURI string `json:"redirect_uri"`
}

// oauth2ErrorResponseWire is the RFC 6749 error body an `/oauth2/*` endpoint
// returns on the endpoint-qualified error status (CONTRACT.md §2, §12.1).
type oauth2ErrorResponseWire struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func introspectionResultFromWire(wire introspectionResponseWire) IntrospectionResult {
	result := IntrospectionResult{Active: wire.Active}
	if wire.Sub != nil {
		result.Sub = *wire.Sub
	}
	if wire.ClientID != nil {
		result.ClientID = *wire.ClientID
	}
	if wire.Scope != nil {
		result.Scope = *wire.Scope
	}
	if wire.TokenType != nil {
		result.TokenType = *wire.TokenType
	}
	if wire.Exp != nil {
		result.Exp = *wire.Exp
	}
	if wire.Iat != nil {
		result.Iat = *wire.Iat
	}
	return result
}
