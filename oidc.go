// Package axiam — OIDC / SSO relying-party helpers (CONTRACT.md §12,
// contract 1.4).
//
// The nine canonical §12 operations, under the exact §12.2 Go names, as
// methods on the existing *Client: OidcDiscover, OidcBegin, OidcExchange,
// OidcRefresh, LoginClientCredentials, Introspect, Revoke, SsoStart,
// SsoComplete.
//
// Everything besides the PKCE/CSPRNG primitives (oidc_pkce.go) and the
// issuer/audience/time/nonce checklist (oidc_idtoken.go) is reuse, not
// reimplementation (§12 forbids forking):
//   - transport + §2 error mapping + §3 CSRF + §4 cookie jar + §5 tenant
//     header + §6 TLS -> the SAME *http.Client / doRequest/newRequest choke
//     point client.go already built;
//   - §12.4 signature verification -> internal/jwks.Verifier, extended
//     (never forked) with a raw-payload entry point;
//   - §7/§12.5 redaction -> the existing Sensitive type.
package axiam

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ilpanich/axiam-go-sdk/internal/jwks"
)

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const (
	oidcDiscoveryPath = "/.well-known/openid-configuration"
	ssoStartPath      = "/api/v1/auth/federation/oidc/start"
	ssoCompletePath   = "/api/v1/auth/federation/oidc/callback"
	openIDScope       = "openid"
)

// MinOidcDiscoveryTTL is the CONTRACT.md §12.3 rule 6 FLOOR for the OIDC
// discovery-document cache TTL: 5 minutes. WithOidcDiscoveryTTL raises any
// smaller configured value up to this floor; it is also the default when
// unconfigured.
const MinOidcDiscoveryTTL = 5 * time.Minute

// reservedAuthorizeParams are the eight query parameters OidcBegin owns
// (CONTRACT.md §12.1 rule 5). Caller-supplied ExtraParams may add to the
// authorization request but must never override these.
var reservedAuthorizeParams = map[string]bool{
	"response_type":         true,
	"client_id":             true,
	"redirect_uri":          true,
	"scope":                 true,
	"state":                 true,
	"nonce":                 true,
	"code_challenge":        true,
	"code_challenge_method": true,
}

// ---------------------------------------------------------------------------
// Options (CONTRACT.md §12) — functional options for NewClient, alongside
// the existing WithCustomCA/WithClientCertificate/... in client.go.
// ---------------------------------------------------------------------------

// WithOidcClientID sets the relying party's OAuth2 client_id (CONTRACT.md
// §12.1), used on every §12 grant and matched against the ID token's
// aud/azp (§12.4 rule 4). Required before calling any §12 operation other
// than OidcDiscover.
func WithOidcClientID(clientID string) Option {
	return func(c *clientConfig) { c.oidcClientID = clientID }
}

// WithOidcClientSecret configures a confidential client's client_secret
// (CONTRACT.md §12.1), held behind Sensitive (§12.5). Omit for a public
// client: LoginClientCredentials, Introspect and Revoke then return an
// *AuthError client-side, without a wire call (§12.1 note 4 — a public
// client cannot call them).
func WithOidcClientSecret(clientSecret string) Option {
	return func(c *clientConfig) { c.oidcClientSecret = Sensitive(clientSecret) }
}

// WithOidcDiscoveryTTL overrides the OIDC discovery-document cache TTL.
// Floored at MinOidcDiscoveryTTL (5 minutes) per CONTRACT.md §12.3 rule 6 —
// a smaller configured value is silently raised to the floor.
func WithOidcDiscoveryTTL(ttl time.Duration) Option {
	return func(c *clientConfig) { c.oidcDiscoveryTTL = ttl }
}

// WithOidcClockSkew overrides the permitted ID-token clock skew, in seconds.
// Clamped to [1, MaxIDTokenClockSkewSec] (60s) per CONTRACT.md §12.4 rule 5 —
// the contract forbids configuring it above that bound.
func WithOidcClockSkew(seconds int) Option {
	return func(c *clientConfig) { c.oidcClockSkewSec = seconds }
}

func normalizeDiscoveryTTL(ttl time.Duration) time.Duration {
	if ttl < MinOidcDiscoveryTTL {
		return MinOidcDiscoveryTTL
	}
	return ttl
}

func normalizeClockSkewSec(sec int) int {
	return resolveClockSkewSec(sec)
}

// ---------------------------------------------------------------------------
// Runtime state attached to *Client (a single `oidc oidcState` field in
// client.go's Client struct)
// ---------------------------------------------------------------------------

// oidcDiscoveryFetch is the shared, in-flight discovery fetch: concurrent
// OidcDiscover callers block on done and then read doc/err, giving exactly
// one HTTP request for any number of concurrent callers (CONTRACT.md §12.3
// rule 6 single-flight requirement).
type oidcDiscoveryFetch struct {
	done chan struct{}
	doc  OidcConfiguration
	err  error
}

// oidcRefreshFuture is OidcRefresh's OWN single-flight in-flight marker
// (CONTRACT.md §9's Go mechanism — a mutex plus a channel carrying the
// result — applied to the independent oidc_refresh operation). See
// OidcRefresh's doc comment for why this is a separate guard instance from
// the cookie-session Client.guard (internal/refreshguard.Guard).
//
// It is a result-sharing channel, not a busy flag: set/err are published and
// done is closed BEFORE oidcState.pendingRefresh is vacated, so a caller can
// never find an empty slot whose outcome has not been published yet. See the
// completion-ordering comment in OidcRefresh for why that ordering is
// load-bearing against single-use rotating refresh tokens, and why an
// occupied slot therefore does not imply a live wire call.
type oidcRefreshFuture struct {
	done chan struct{}
	set  OidcTokenSet
	err  error
}

// oidcState is the OIDC / SSO relying-party runtime state attached to a
// *Client (CONTRACT.md §12): configuration set at construction time plus the
// per-client discovery cache, the per-jwks_uri verifier cache, the
// oidc_refresh single-flight guard, and the optional adopted
// LoginClientCredentials bearer token.
//
// Because a *Client is bound to exactly ONE base URL for its whole lifetime,
// the discovery cache below needs no origin-keyed map the way a
// multi-origin SDK would: every OidcDiscover call for a given *Client always
// targets the same origin, so a single cached document already satisfies
// §12.3 rule 6's "keyed by origin, never process-global, never shared
// across tenants" requirement (each *Client owns its own oidcState).
type oidcState struct {
	clientID     string
	clientSecret Sensitive // empty for a public client
	discoveryTTL time.Duration
	clockSkewSec int

	discoveryMu    sync.Mutex
	discoveryDoc   *OidcConfiguration
	discoveryExp   time.Time
	discoveryFetch *oidcDiscoveryFetch

	verifiersMu sync.Mutex
	verifiers   map[string]*jwks.Verifier

	refreshMu      sync.Mutex
	pendingRefresh *oidcRefreshFuture

	// afterRefreshPublish is a visible-for-testing seam: it runs on the
	// refreshing goroutine at the exact instant between OidcRefresh's two
	// completion steps — after the single flight's outcome has been
	// published to waiters and before the pendingRefresh slot is vacated —
	// while that goroutine holds no lock. It lets a test pin that window
	// open deterministically instead of racing for it. Never set in
	// production (always nil); written once, before any concurrent
	// OidcRefresh call, and only read by the refreshing goroutine.
	afterRefreshPublish func()

	adoptedMu    sync.Mutex
	adoptedToken Sensitive
}

// ---------------------------------------------------------------------------
// 1. OidcDiscover
// ---------------------------------------------------------------------------

// OidcDiscover performs `GET /.well-known/openid-configuration`
// (CONTRACT.md §12.1) — fetch and cache the OIDC discovery document, with a
// >=5-minute TTL and single-flight de-duplication of concurrent calls
// (§12.3 rule 6).
//
// The document's own Issuer is authoritative for ID-token validation and
// may legitimately differ from the Client's base URL behind a proxy, so a
// mismatch is never treated as an error.
func (c *Client) OidcDiscover(ctx context.Context) (OidcConfiguration, error) {
	c.oidc.discoveryMu.Lock()
	if c.oidc.discoveryDoc != nil && time.Now().Before(c.oidc.discoveryExp) {
		doc := *c.oidc.discoveryDoc
		c.oidc.discoveryMu.Unlock()
		return doc, nil
	}
	if f := c.oidc.discoveryFetch; f != nil {
		c.oidc.discoveryMu.Unlock()
		<-f.done
		return f.doc, f.err
	}
	f := &oidcDiscoveryFetch{done: make(chan struct{})}
	c.oidc.discoveryFetch = f
	c.oidc.discoveryMu.Unlock()

	doc, err := c.fetchOidcDiscovery(ctx)

	c.oidc.discoveryMu.Lock()
	f.doc, f.err = doc, err
	if err == nil {
		docCopy := doc
		c.oidc.discoveryDoc = &docCopy
		c.oidc.discoveryExp = time.Now().Add(c.oidc.discoveryTTL)
	}
	c.oidc.discoveryFetch = nil
	c.oidc.discoveryMu.Unlock()
	close(f.done)

	return doc, err
}

func (c *Client) fetchOidcDiscovery(ctx context.Context) (OidcConfiguration, error) {
	req, err := c.newRequest(ctx, http.MethodGet, oidcDiscoveryPath, nil)
	if err != nil {
		return OidcConfiguration{}, err
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return OidcConfiguration{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return OidcConfiguration{}, mapErrorResponse(resp)
	}

	var doc OidcConfiguration
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return OidcConfiguration{}, deserErr(err)
	}
	return doc, nil
}

// ---------------------------------------------------------------------------
// 2. OidcBegin
// ---------------------------------------------------------------------------

// OidcBegin builds an authorization request (CONTRACT.md §12.1) — PURE
// LOCAL COMPUTATION, no network I/O.
//
// Generates a 32-byte CSPRNG State and Nonce (base64url, unpadded) and a
// fresh PKCE verifier/challenge pair using S256 ONLY — "plain" is not
// implemented anywhere in this SDK. The URL is built from configuration's
// AuthorizationEndpoint with exactly the eight parameters §12.1 rule 5
// mandates, plus any ExtraParams the caller adds.
//
// Nothing is stored: persist the returned State, Nonce and CodeVerifier
// yourself (§12.3 rule 1).
//
// Returns a plain (non-taxonomy) error — deliberately NOT *AuthError — when
// ExtraParams tries to override one of the eight SDK-owned parameters: this
// is a programming error caught at call time (§12 port addendum item 9).
func (c *Client) OidcBegin(configuration OidcConfiguration, params OidcBeginParams) (AuthorizationRequest, error) {
	state := randomURLSafeToken(pkceCSPRNGBytes)
	nonce := randomURLSafeToken(pkceCSPRNGBytes)
	codeVerifier := generateCodeVerifier()
	codeChallenge := computeCodeChallenge(codeVerifier.expose())

	scope := normalizeScope(params.Scope)

	target, err := url.Parse(configuration.AuthorizationEndpoint)
	if err != nil {
		return AuthorizationRequest{}, &NetworkError{Message: fmt.Sprintf("invalid authorization_endpoint in discovery document: %v", err)}
	}
	query := target.Query()

	for key, value := range params.ExtraParams {
		if reservedAuthorizeParams[key] {
			return AuthorizationRequest{}, fmt.Errorf("OidcBegin: ExtraParams may not override the SDK-owned authorization parameter %q (CONTRACT.md §12.1 rule 5)", key)
		}
		query.Set(key, value)
	}

	query.Set("response_type", "code")
	query.Set("client_id", c.oidc.clientID)
	query.Set("redirect_uri", params.RedirectURI)
	query.Set("scope", scope)
	query.Set("state", state)
	query.Set("nonce", nonce)
	query.Set("code_challenge", codeChallenge)
	query.Set("code_challenge_method", codeChallengeMethodS256)

	target.RawQuery = encodeQueryRFC3986(query)

	return AuthorizationRequest{URL: target.String(), State: state, Nonce: nonce, CodeVerifier: codeVerifier}, nil
}

// encodeQueryRFC3986 renders v with spaces percent-encoded as %20 rather
// than url.Values.Encode's default `+` (CONTRACT.md §12.1 rule 5, §12 port
// addendum item 10). Safe: url.Values.Encode already percent-encodes any
// LITERAL '+' in a value as %2B, so a bare '+' in its output can only ever
// be its own space-encoding, never a value's actual character.
func encodeQueryRFC3986(v url.Values) string {
	return strings.ReplaceAll(v.Encode(), "+", "%20")
}

// normalizeScope returns a space-separated scope string that always
// contains "openid" first (CONTRACT.md §12.1 rule 4), with duplicates
// collapsed.
func normalizeScope(scope string) string {
	fields := strings.Fields(scope)
	ordered := make([]string, 0, len(fields)+1)
	seen := make(map[string]bool, len(fields)+1)
	ordered = append(ordered, openIDScope)
	seen[openIDScope] = true
	for _, f := range fields {
		if f == "" || seen[f] {
			continue
		}
		seen[f] = true
		ordered = append(ordered, f)
	}
	return strings.Join(ordered, " ")
}

// ---------------------------------------------------------------------------
// 3. OidcExchange
// ---------------------------------------------------------------------------

// OidcExchange performs `POST /oauth2/token` with
// `grant_type=authorization_code` (CONTRACT.md §12.1) — exchange an
// authorization code for a token set, validating the returned ID token in
// full before returning.
//
// params.Nonce is mandatory: this grant always requests the "openid" scope,
// so §12.4 rule 6 always applies. If ANY §12.4 rule fails, the whole token
// set is discarded and *AuthError is raised with the matching Reason code —
// the access and refresh tokens from the same response are never returned
// (§12.4 rule 7).
func (c *Client) OidcExchange(ctx context.Context, params OidcExchangeParams) (OidcTokenSet, error) {
	configuration, err := c.resolveOidcConfiguration(ctx, params.Configuration)
	if err != nil {
		return OidcTokenSet{}, err
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", params.Code)
	form.Set("code_verifier", params.CodeVerifier.expose())
	form.Set("redirect_uri", params.RedirectURI)
	form.Set("client_id", c.oidc.clientID)
	c.appendOidcClientSecret(form)

	wire, err := c.postToken(ctx, configuration, form, params.TenantID)
	if err != nil {
		return OidcTokenSet{}, err
	}

	return c.toTokenSet(ctx, wire, configuration, idTokenExpectations{
		issuer:       configuration.Issuer,
		clientID:     c.oidc.clientID,
		nonce:        params.Nonce,
		hasNonce:     true,
		clockSkewSec: c.oidc.clockSkewSec,
	})
}

// ---------------------------------------------------------------------------
// 4. OidcRefresh
// ---------------------------------------------------------------------------

// OidcRefresh performs `POST /oauth2/token` with `grant_type=refresh_token`
// (CONTRACT.md §12.1) under a single-flight refresh guard (§9): concurrent
// callers collapse into ONE HTTP request and all receive the same
// OidcTokenSet (or the same failure), with no retry loop on failure (§9.3).
//
// This is a DISTINCT operation from Client.Refresh, which drives the
// cookie/opaque-token session path at POST /api/v1/auth/refresh (§5.1). The
// two are never merged, aliased, or made to fall back to one another
// (§12.1 "oidc_refresh vs refresh").
//
// This method uses its OWN single-flight guard (oidcState.pendingRefresh) —
// a SEPARATE instance from the cookie-session Client.guard
// (internal/refreshguard.Guard). That type's RefreshIfNeeded API compares an
// "observed" axiam_access cookie value against its own cache, which has no
// meaning for an OAuth2 refresh_token grant operating on an entirely
// different, cookie-independent token namespace; reusing the literal same
// Guard instance for both would corrupt its cookie-session comparison state
// with an unrelated token stream. A dedicated guard, built from the exact
// mechanism CONTRACT.md §9 prescribes for Go (a mutex plus a channel
// carrying the shared result), still satisfies §9's actual requirement for
// THIS operation — exactly one in-flight refresh, waiters share the outcome,
// no retry on failure — without that cross-talk. (Documented deviation from
// the literal wording of the TypeScript reference, which shares one generic
// mutex-based guard across both operations because its guard has no
// token-comparison state to corrupt in the first place.)
//
// An id_token in the response is validated against §12.4 rules 1-5 and 7;
// rule 6 (nonce) is skipped, since OIDC Core §12.2 does not require a nonce
// in a refresh-issued ID token.
func (c *Client) OidcRefresh(ctx context.Context, params OidcRefreshParams) (OidcTokenSet, error) {
	c.oidc.refreshMu.Lock()
	if f := c.oidc.pendingRefresh; f != nil {
		c.oidc.refreshMu.Unlock()
		<-f.done
		return f.set, f.err
	}
	f := &oidcRefreshFuture{done: make(chan struct{})}
	c.oidc.pendingRefresh = f
	c.oidc.refreshMu.Unlock()

	set, err := c.doOidcRefresh(ctx, params)

	// Publish the outcome BEFORE vacating the slot — never the other way
	// round. pendingRefresh is a result-SHARING channel, not a busy flag: it
	// must stay populated until this flight's outcome has been published,
	// because a caller that finds the slot already emptied starts a SECOND
	// refresh_token grant, and AXIAM refresh tokens are single-use with
	// rotation — that second grant replays a consumed token and fails with
	// invalid_grant (CONTRACT.md §9 rule 2's observable requirement: one
	// wire call per burst, that one outcome shared with every concurrent
	// caller). With this ordering a caller at any instant either (a) finds
	// the slot occupied and joins the shared outcome — a CLOSED channel
	// stays readable forever, so joining an already-settled flight is free
	// and returns the published f.set/f.err — or (b) finds the slot empty,
	// with this flight fully retired, and legitimately starts its own. It
	// can never observe "slot empty and nothing published", the one state
	// that permits a redundant second wire call.
	//
	// Publishing under refreshMu pairs the writes to f.set/f.err with the
	// lock every joiner already takes to read pendingRefresh, so the
	// close(f.done) that hands over the result cannot be reordered ahead of
	// the values it publishes. The price of the ordering is a brief window
	// in which the slot holds an already-settled future, so occupancy alone
	// does NOT mean "a refresh is on the wire": anything added later that
	// needs to know whether a refresh is genuinely live must also test
	// f.done for completion (a non-blocking select), not mere occupancy.
	//
	// The failure path is identical by construction: err is published to
	// every waiter exactly once and is never retried here (§9 rule 3 — the
	// caller must re-authenticate), and vacating the slot afterwards leaves
	// the guard immediately usable for a genuinely new refresh.
	c.oidc.refreshMu.Lock()
	f.set, f.err = set, err
	close(f.done)
	c.oidc.refreshMu.Unlock()

	if hook := c.oidc.afterRefreshPublish; hook != nil {
		hook()
	}

	c.oidc.refreshMu.Lock()
	if c.oidc.pendingRefresh == f {
		c.oidc.pendingRefresh = nil
	}
	c.oidc.refreshMu.Unlock()

	return set, err
}

func (c *Client) doOidcRefresh(ctx context.Context, params OidcRefreshParams) (OidcTokenSet, error) {
	configuration, err := c.resolveOidcConfiguration(ctx, params.Configuration)
	if err != nil {
		return OidcTokenSet{}, err
	}

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", params.RefreshToken.expose())
	form.Set("client_id", c.oidc.clientID)
	c.appendOidcClientSecret(form)
	if params.Scope != "" {
		form.Set("scope", params.Scope)
	}

	wire, err := c.postToken(ctx, configuration, form, params.TenantID)
	if err != nil {
		return OidcTokenSet{}, err
	}

	// No nonce: rule 6 does not apply to a refresh-issued ID token.
	return c.toTokenSet(ctx, wire, configuration, idTokenExpectations{
		issuer:       configuration.Issuer,
		clientID:     c.oidc.clientID,
		clockSkewSec: c.oidc.clockSkewSec,
	})
}

// ---------------------------------------------------------------------------
// 5. LoginClientCredentials
// ---------------------------------------------------------------------------

// LoginClientCredentials performs `POST /oauth2/token` with
// `grant_type=client_credentials` (CONTRACT.md §12.1) — service-account
// machine-to-machine login.
//
// Requests no "openid" scope, so the response carries no id_token. Pass
// params.AdoptAsCredential = true to additionally use the returned access
// token as this Client's bearer credential for subsequent REST calls
// (§12.1, a MAY).
//
// Returns *AuthError, client-side with no wire call, when the Client was
// not constructed with WithOidcClientSecret — this grant cannot be
// performed by a public client.
func (c *Client) LoginClientCredentials(ctx context.Context, params LoginClientCredentialsParams) (OidcTokenSet, error) {
	configuration, err := c.resolveOidcConfiguration(ctx, params.Configuration)
	if err != nil {
		return OidcTokenSet{}, err
	}
	secret, err := c.requireOidcClientSecret("LoginClientCredentials")
	if err != nil {
		return OidcTokenSet{}, err
	}

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", c.oidc.clientID)
	form.Set("client_secret", secret)
	if params.Scope != "" {
		form.Set("scope", params.Scope)
	}

	wire, err := c.postToken(ctx, configuration, form, params.TenantID)
	if err != nil {
		return OidcTokenSet{}, err
	}

	// No nonce: rule 6 does not apply to this grant.
	tokenSet, err := c.toTokenSet(ctx, wire, configuration, idTokenExpectations{
		issuer:       configuration.Issuer,
		clientID:     c.oidc.clientID,
		clockSkewSec: c.oidc.clockSkewSec,
	})
	if err != nil {
		return OidcTokenSet{}, err
	}

	if params.AdoptAsCredential {
		c.adoptOidcCredential(tokenSet.AccessToken)
	}
	return tokenSet, nil
}

// ---------------------------------------------------------------------------
// 6. Introspect
// ---------------------------------------------------------------------------

// Introspect performs `POST /oauth2/introspect` (RFC 7662, CONTRACT.md
// §12.1) — ask the server whether a token is active and, if so, for its
// metadata.
//
// Requires confidential-client credentials (§12.1 note 4). A 401 here is a
// CLIENT-CREDENTIAL failure surfaced as *OAuthProtocolError; it never enters
// the §9 refresh guard, because refreshing the session cannot fix a bad
// client_secret (§12.3 rule 3) — Introspect never touches Client.guard or
// the oidc_refresh guard at all.
func (c *Client) Introspect(ctx context.Context, params IntrospectParams) (IntrospectionResult, error) {
	configuration, err := c.resolveOidcConfiguration(ctx, params.Configuration)
	if err != nil {
		return IntrospectionResult{}, err
	}
	secret, err := c.requireOidcClientSecret("Introspect")
	if err != nil {
		return IntrospectionResult{}, err
	}

	form := url.Values{}
	form.Set("token", params.Token.expose())
	form.Set("client_id", c.oidc.clientID)
	form.Set("client_secret", secret)
	if params.TokenTypeHint != "" {
		form.Set("token_type_hint", params.TokenTypeHint)
	}

	endpoint, err := c.oidcEndpointURL(configuration.IntrospectionEndpoint, params.TenantID)
	if err != nil {
		return IntrospectionResult{}, err
	}

	var wire introspectionResponseWire
	if err := c.postOAuth2Form(ctx, endpoint, form, &wire); err != nil {
		return IntrospectionResult{}, err
	}
	return introspectionResultFromWire(wire), nil
}

// ---------------------------------------------------------------------------
// 7. Revoke
// ---------------------------------------------------------------------------

// Revoke performs `POST /oauth2/revoke` (RFC 7009, CONTRACT.md §12.1) —
// revoke an access or refresh token.
//
// Per RFC 7009 the server answers 200 for unknown, expired and
// already-revoked tokens alike, so revocation is IDEMPOTENT: any 2xx is
// success and no error is raised for a token the server has never seen.
// Only a 401 (client authentication failed) is an error, surfaced as
// *OAuthProtocolError (§12.1 note 5, §12.3 rule 3); a 5xx is still a
// *NetworkError (revoke returning void does not make a server error
// "success").
//
// Returns *AuthError, client-side with no wire call, when the Client was
// not constructed with WithOidcClientSecret.
func (c *Client) Revoke(ctx context.Context, params RevokeParams) error {
	configuration, err := c.resolveOidcConfiguration(ctx, params.Configuration)
	if err != nil {
		return err
	}
	secret, err := c.requireOidcClientSecret("Revoke")
	if err != nil {
		return err
	}

	form := url.Values{}
	form.Set("token", params.Token.expose())
	form.Set("client_id", c.oidc.clientID)
	form.Set("client_secret", secret)
	if params.TokenTypeHint != "" {
		form.Set("token_type_hint", params.TokenTypeHint)
	}

	endpoint, err := c.oidcEndpointURL(configuration.RevocationEndpoint, params.TenantID)
	if err != nil {
		return err
	}
	return c.postOAuth2Form(ctx, endpoint, form, nil)
}

// ---------------------------------------------------------------------------
// 8. SsoStart
// ---------------------------------------------------------------------------

// SsoStart performs `POST /api/v1/auth/federation/oidc/start` (CONTRACT.md
// §12.1) — step 1 of first-time SSO against an UPSTREAM IdP. No JWT
// required.
//
// One tenant form (params.TenantID or params.TenantSlug) and one org form
// (params.OrgID or params.OrgSlug) must be resolvable, from the arguments or
// from the Client's own construction options (§5.1) — this Client always
// has a tenant slug (NewClient requires one), so the tenant form is always
// resolvable in practice; the organization form still needs WithOrgID/
// WithOrgSlug (or an explicit argument) unless the Client already resolved
// one from a prior Login.
//
// Redirect the browser to the returned AuthorizeURL and round-trip State
// back into SsoComplete unmodified — the server keeps the nonce to itself
// (§12.1 note 7).
//
// Returns *AuthError, client-side with no wire call, when tenant or org
// context cannot be resolved.
func (c *Client) SsoStart(ctx context.Context, params SsoStartParams) (SsoStartResult, error) {
	tenantID := params.TenantID
	tenantSlug := params.TenantSlug
	if tenantID == "" && tenantSlug == "" {
		tenantSlug = c.tenantSlug
	}

	orgID := params.OrgID
	orgSlug := params.OrgSlug
	if orgID == "" && orgSlug == "" {
		if c.org.id != nil {
			orgID = c.org.id.String()
		} else if c.org.slug != "" {
			orgSlug = c.org.slug
		} else if resolved, ok := c.resolvedOrgID(); ok {
			orgID = resolved.String()
		}
	}

	if tenantID == "" && tenantSlug == "" {
		return SsoStartResult{}, &AuthError{Message: "SsoStart requires tenant context: pass TenantID or TenantSlug, or construct the Client with one (CONTRACT.md §5.1)"}
	}
	if orgID == "" && orgSlug == "" {
		return SsoStartResult{}, &AuthError{Message: "SsoStart requires organization context: pass OrgID or OrgSlug, or construct the Client with WithOrgID/WithOrgSlug (CONTRACT.md §5.1)"}
	}

	body := map[string]string{
		"federation_config_id": params.FederationConfigID,
		"redirect_uri":         params.RedirectURI,
	}
	if tenantID != "" {
		body["tenant_id"] = tenantID
	} else {
		body["tenant_slug"] = tenantSlug
	}
	if orgID != "" {
		body["org_id"] = orgID
	} else {
		body["org_slug"] = orgSlug
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return SsoStartResult{}, &NetworkError{Message: fmt.Sprintf("failed to encode ssoStart request: %v", err)}
	}

	req, err := c.newRequest(ctx, http.MethodPost, ssoStartPath, bytes.NewReader(payload))
	if err != nil {
		return SsoStartResult{}, err
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return SsoStartResult{}, err
	}
	defer resp.Body.Close()

	// §12 port addendum item 12: the federation error body shape is
	// undocumented — fall through to the generic §2 status mapping, never
	// attempt to parse an OAuth2ErrorResponse here.
	if resp.StatusCode != http.StatusOK {
		return SsoStartResult{}, mapErrorResponse(resp)
	}

	var wire oidcStartResponseWire
	if err := json.NewDecoder(resp.Body).Decode(&wire); err != nil {
		return SsoStartResult{}, deserErr(err)
	}
	return SsoStartResult{AuthorizeURL: wire.AuthorizeURL, State: wire.State, ExpiresInSecs: wire.ExpiresInSecs}, nil
}

// ---------------------------------------------------------------------------
// 9. SsoComplete
// ---------------------------------------------------------------------------

// SsoComplete performs `POST /api/v1/auth/federation/oidc/callback`
// (CONTRACT.md §12.1) — step 2 of upstream SSO: consumes the single-use
// state, provisions or links the user, and establishes the session.
//
// The session arrives as Set-Cookie, NOT in the response body (§12.1
// note 6), so this call goes through the SAME §4 cookie-jar path every
// other authenticated call already uses — no separate wiring needed. On
// success the session is marked authenticated via the same absorption
// Login/VerifyMfa perform (decode the org_id claim, seed the refresh
// guard), mirroring the TypeScript reference's onAuthenticated() hook
// (CONTRACT.md §12 T1 judgment call 16).
//
// §12.4 does not apply here — no ID token ever reaches the SDK on the
// federation path.
func (c *Client) SsoComplete(ctx context.Context, params SsoCompleteParams) (SsoCompleteResult, error) {
	body := map[string]string{"state": params.State, "code": params.Code}
	payload, err := json.Marshal(body)
	if err != nil {
		return SsoCompleteResult{}, &NetworkError{Message: fmt.Sprintf("failed to encode ssoComplete request: %v", err)}
	}

	req, err := c.newRequest(ctx, http.MethodPost, ssoCompletePath, bytes.NewReader(payload))
	if err != nil {
		return SsoCompleteResult{}, err
	}

	resp, err := c.doRequest(req)
	if err != nil {
		return SsoCompleteResult{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return SsoCompleteResult{}, mapErrorResponse(resp)
	}

	var wire ssoLoginSuccessResponseWire
	if err := json.NewDecoder(resp.Body).Decode(&wire); err != nil {
		return SsoCompleteResult{}, deserErr(err)
	}

	if err := c.absorbSessionCookies(); err != nil {
		return SsoCompleteResult{}, err
	}

	return SsoCompleteResult{
		UserID:      wire.UserID,
		SessionID:   wire.SessionID,
		ExpiresIn:   wire.ExpiresIn,
		RedirectURI: wire.RedirectURI,
	}, nil
}
