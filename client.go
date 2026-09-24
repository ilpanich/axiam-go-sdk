package axiam

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/ilpanich/axiam-go-sdk/internal/refreshguard"
)

const (
	// defaultConnectRequestTimeout is applied to the built http.Client when
	// no WithTimeout option is supplied (CF-03; mirrors the Rust reference's
	// 30s default request timeout).
	defaultConnectRequestTimeout = 30 * time.Second
)

// orgIdentifier is the optional organization identifier a client may be
// constructed with (RESEARCH.md Pitfall 3 — the real login/refresh
// endpoints require an org_id/org_slug beyond CONTRACT.md §5's documented
// tenant-only minimum). Mutually exclusive slug/id form, last-call-wins.
type orgIdentifier struct {
	slug string
	id   *uuid.UUID
}

// clientConfig accumulates functional-option state before NewClient builds
// the final *Client (D-03).
type clientConfig struct {
	customCAPEM    []byte
	clientCertPEM  []byte
	clientKeyPEM   Sensitive
	requestTimeout time.Duration
	baseHTTPClient *http.Client
	org            orgIdentifier
	logger         *slog.Logger

	// OIDC / SSO relying-party configuration (CONTRACT.md §12). See
	// WithOidcClientID/WithOidcClientSecret/WithOidcDiscoveryTTL/
	// WithOidcClockSkew in oidc.go.
	oidcClientID     string
	oidcClientSecret Sensitive
	oidcDiscoveryTTL time.Duration
	oidcClockSkewSec int

	// D5 / CONTRACT.md §16-§19. See WithRetryDisabled, WithDecisionMemoTTL and
	// WithTelemetryHook below.
	retryDisabled   bool
	decisionMemoTTL time.Duration
	telemetryHook   TelemetryHook
	randSource      func() float64

	// actingTenant is CONTRACT.md §5.2 rule 1's builder-time acting tenant.
	// See WithActingTenant.
	actingTenant *uuid.UUID
}

func defaultConfig() *clientConfig {
	return &clientConfig{
		requestTimeout: defaultConnectRequestTimeout,
	}
}

// Option configures a Client at construction time (D-03).
type Option func(*clientConfig)

// WithCustomCA adds a PEM-encoded CA certificate to the TLS verification
// chain (§6). This is the ONLY TLS-related escape hatch — there is no
// option anywhere in this SDK that disables or weakens certificate
// verification. Returns a construction-time error via NewClient if pem is
// not valid PEM.
func WithCustomCA(pem []byte) Option {
	return func(c *clientConfig) { c.customCAPEM = pem }
}

// WithClientCertificate configures a client-certificate identity for mutual
// TLS (CONTRACT.md §6.1). certPEM is a PEM-encoded X.509 certificate chain
// and keyPEM is the matching PEM-encoded private key (PKCS#8 or PKCS#1). The
// SDK presents this identity on BOTH the REST transport (here) and any gRPC
// channel built for the same logical client (grpc.NewTLSCredentials).
//
// Presenting a client certificate NEVER relaxes server verification: this is
// additive to WithCustomCA/§6 and keeps the SDK's TLS-1.3 floor and strict
// RootCAs behavior unchanged. A non-PEM cert/key pair is a construction-time
// error returned from NewClient, consistent with WithCustomCA.
//
// The private key is secret material (§7): it is held behind the SDK's
// Sensitive type and never appears in any log, error, or display output.
func WithClientCertificate(certPEM, keyPEM []byte) Option {
	return func(c *clientConfig) {
		c.clientCertPEM = certPEM
		c.clientKeyPEM = Sensitive(keyPEM)
	}
}

// WithTimeout overrides the default request timeout applied to the SDK's
// http.Client (CF-03; default 30s).
func WithTimeout(d time.Duration) Option {
	return func(c *clientConfig) { c.requestTimeout = d }
}

// WithHTTPClient supplies a base *http.Client whose Transport/Timeout the
// SDK adopts. D-09: the SDK ALWAYS re-applies its own cookiejar and TLS
// config over the supplied client afterward — an override can never
// silently drop the jar (breaking every post-login request) or bypass TLS
// verification.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *clientConfig) { c.baseHTTPClient = hc }
}

// WithOrgSlug sets the organization slug the real login/refresh endpoints
// require (RESEARCH.md Pitfall 3). Mutually exclusive with WithOrgID —
// last call wins.
func WithOrgSlug(slug string) Option {
	return func(c *clientConfig) { c.org = orgIdentifier{slug: slug} }
}

// WithOrgID sets the organization UUID the real login/refresh endpoints
// require (RESEARCH.md Pitfall 3). Mutually exclusive with WithOrgSlug —
// last call wins.
func WithOrgID(id uuid.UUID) Option {
	return func(c *clientConfig) { c.org = orgIdentifier{id: &id} }
}

// WithLogger supplies an injectable, redaction-aware logger (CF-02). OFF
// by default (nil logger — the SDK never logs unless a logger is
// supplied). The SDK never emits raw token values regardless of the
// logger's configured level (Sensitive redacts itself in any log call).
// WithRetryDisabled turns off the CONTRACT.md §16 bounded read-only retry
// policy, making every operation exactly one attempt.
//
// That is the right choice for a caller who owns their own retry layer — they
// know their deadline and this SDK does not — but it is not a way to make
// failures quieter: a transient *NetworkError simply surfaces immediately.
//
// §16.1 permits this switch but forbids raising the attempt cap, base delay or
// delay cap above the contract's values, so there is no option for those:
// eleven SDKs agreeing on one table is the point.
func WithRetryDisabled() Option {
	return func(c *clientConfig) { c.retryDisabled = true }
}

// WithDecisionMemoTTL enables the CONTRACT.md §17 client-side decision memo.
//
// DISABLED BY DEFAULT — §11.2 rule 6's ban on caching authorization decisions
// is still the default behaviour, and this is the single opt-in exception.
//
// What you are accepting: the staleness bound is ttl IN BOTH DIRECTIONS. A
// grant revoked on the server can still read as allowed for up to the TTL, and
// a grant just added can still read as denied for up to the TTL.
//
// READS-YOUR-OWN-WRITES IS NOT GUARANTEED. An admin UI that grants a role and
// immediately re-checks is the case that breaks, and it breaks silently. If
// that is your workload, do not set this.
//
// ttl is clamped to MaxMemoTTL rather than rejected, so asking for a minute
// gets you five seconds. Allows and denies are memoized identically (asymmetric
// caching leaks the outcome through latency), failures are never memoized, and
// the memo is cleared on any credential change.
func WithDecisionMemoTTL(ttl time.Duration) Option {
	return func(c *clientConfig) { c.decisionMemoTTL = ttl }
}

// WithTelemetryHook installs a CONTRACT.md §19 telemetry sink.
//
// It receives request start/end, §16 retry and §9 refresh events, so metrics
// can be wired without this module depending on any metrics library. See
// examples/telemetry_hook.
//
// A hook that panics cannot fail the operation that fired it (§19.2 rule 2),
// and no event payload can carry a token — TelemetryEvent is a closed interface
// with fixed field sets (§19.2 rule 3). It is invoked on the calling goroutine,
// so it must not block; buffer on your side if you need async delivery.
func WithTelemetryHook(hook TelemetryHook) Option {
	return func(c *clientConfig) { c.telemetryHook = hook }
}

// withJitterSource injects the §16 jitter draw, for tests only.
func withJitterSource(f func() float64) Option {
	return func(c *clientConfig) { c.randSource = f }
}

func WithLogger(logger *slog.Logger) Option {
	return func(c *clientConfig) { c.logger = logger }
}

// clientSession is the mutable state a Client and every handle
// ActingTenant() derives from it SHARE — CONTRACT.md §5.2 rule 1: "acting
// on another tenant" returns "a new handle over the same session". Moving
// every mutex-guarded field that used to live directly on Client into one
// struct reached only through a pointer is what makes that sharing
// possible: two *Client values can point at the same *clientSession while
// each carries its own, independent, never-mutated actingTenant.
//
// Everything else on Client (baseURL, tenantSlug, org, httpc, logger,
// retryEnabled, rand, telemetry, presentsClientCertificate) is read-only
// after construction, so it is copied by value into each handle rather than
// shared — sharing it would cost a pointer indirection for no benefit, since
// nothing ever writes it again.
type clientSession struct {
	// guard is swapped atomically: Logout() replaces it with a fresh Guard
	// while Login/VerifyMfa/Refresh Load() it concurrently. Using an
	// atomic.Pointer (rather than a plain field) prevents the data race
	// between Logout's reassignment and concurrent Refresh reads (CR-01).
	guard atomic.Pointer[refreshguard.Guard]

	// memo is the §17 decision cache; nil-safe and disabled by default.
	memo *decisionMemo
	// closed is set once by Close and read on every operation (§18).
	closed      atomic.Bool
	csrfMu      sync.Mutex
	csrfToken   string
	orgIDMu     sync.Mutex
	resolvedOrg *uuid.UUID

	// principalTenantMu guards principalTenant — the tenant the signed-in
	// principal's record LIVES in, as reported by the login response
	// (CONTRACT.md §5.2.2).
	//
	// Distinct from tenantSlug, which is the tenant being acted on: the two
	// diverge for an organization-level principal that has selected another
	// one. Read by OpaqueEnrollmentForSelf, which must seal a §23 record
	// against the account's own tenant rather than whichever one this client
	// is currently pointed at. Nil until a login completes.
	principalTenantMu sync.Mutex
	principalTenant   *uuid.UUID

	// oidc holds the OIDC / SSO relying-party runtime state (CONTRACT.md
	// §12) — configuration plus the discovery cache, per-jwks_uri verifier
	// cache, and the oidc_refresh single-flight guard. Defined in oidc.go so
	// the whole §12 surface (besides this one field and the small
	// decorateRequest hook below) lives outside client.go.
	oidc oidcState

	// scope is the CONTRACT.md §5.2 rule 1 acting-tenant gate: what this
	// session currently knows about the signed-in principal's reach, kept
	// so ActingTenant() can refuse client-side rather than round-trip a
	// request the server would refuse anyway. See scopeState below.
	scopeMu sync.Mutex
	scope   scopeState

	// deviceMu guards deviceToken — the CONTRACT.md §6.1 mTLS device login's
	// adopted credential (AuthenticateDevice, device_auth.go). Kept apart
	// from oidc.adoptedToken (a distinct §12.1 mechanism, both older and
	// narrower in scope) because adopting one clears the other: the two are
	// mutually exclusive credential sources for one Client, never additive.
	deviceMu    sync.Mutex
	deviceToken Sensitive
}

// scopeState is the §5.2/§5.2.3 gating snapshot a session holds after the
// last credential-establishing call. See setScope/resetScopeUnknown/scope.
type scopeState struct {
	// known is false before any login-shaped call has completed, and after
	// any call that completes a session WITHOUT a LoginUserInfo attached
	// (CONTRACT.md's "For C-12" open question 5) or after Logout. A client
	// holding no login result has nothing to gate on: ActingTenant sends
	// the header and lets the server's 403 answer.
	known bool
	// organizationLevel mirrors LoginResult.OrganizationLevel.
	organizationLevel bool
	// reachableTenantIDs mirrors LoginResult.ReachableTenantIDs. Nil means
	// unrestricted (§5.2.3).
	reachableTenantIDs []uuid.UUID
}

// Client is the AXIAM SDK's REST entry point (CONTRACT.md §1-§10). See
// NewClient.
type Client struct {
	baseURL    *url.URL
	tenantSlug string
	org        orgIdentifier
	httpc      *http.Client
	logger     *slog.Logger

	// §16.1 disable switch. There is deliberately no field for the attempt
	// cap, base delay or delay cap: §16.1 forbids raising them, and eleven
	// SDKs agreeing on one table is the point.
	retryEnabled bool
	// rand supplies the §16 jitter fraction; nil means math/rand. Injected so
	// a test can pin it — a test that really waits 200ms is a test nobody runs.
	rand func() float64
	// telemetry is the §19 dispatcher; its zero value is a no-op.
	telemetry dispatcher

	// presentsClientCertificate reports whether this client was built with a
	// §6.1 mTLS identity (WithClientCertificate), and so whether CONTRACT.md
	// §21.3 rule 2 applies to the calls it makes.
	//
	// The identity is configured once and presented on every request, so "is
	// this call going over mutual TLS" has a whole-client answer here rather
	// than a per-call one. Set at construction and never written again.
	presentsClientCertificate bool

	// actingTenant is CONTRACT.md §5.2 rule 1's X-Axiam-Tenant value. It is
	// set once — at construction (WithActingTenant) or by ActingTenant(),
	// which returns a NEW *Client carrying a different actingTenant over the
	// SAME session — and never mutated afterward on a live handle. That is
	// what makes it safe for two goroutines to act on two tenants over one
	// session without racing each other's header: each holds its own
	// *Client, and neither writes to the other's actingTenant field.
	actingTenant *uuid.UUID

	// session is the state this handle SHARES with every other handle
	// ActingTenant() has derived from it, or that derived this one. See
	// clientSession.
	session *clientSession
}

// setPrincipalTenantID caches the tenant the signed-in principal lives in
// (CONTRACT.md §5.2.2). A nil argument is ignored rather than clearing the
// cache: a server that reports no scope has not told us the principal moved,
// only that it does not send the field.
func (c *Client) setPrincipalTenantID(id *uuid.UUID) {
	if id == nil {
		return
	}
	c.session.principalTenantMu.Lock()
	defer c.session.principalTenantMu.Unlock()
	v := *id
	c.session.principalTenant = &v
}

// principalTenantID returns the cached principal tenant, or nil before a login.
func (c *Client) principalTenantID() *uuid.UUID {
	c.session.principalTenantMu.Lock()
	defer c.session.principalTenantMu.Unlock()
	if c.session.principalTenant == nil {
		return nil
	}
	v := *c.session.principalTenant
	return &v
}

// NewClient constructs a Client. baseURL and tenantSlug are positional and
// required (D-03): an empty tenantSlug returns an *AuthError — AXIAM is
// multi-tenant and there is no default tenant, so this can never be a
// silent default (CONTRACT.md §5, SC#1).
//
// The returned Client always owns a per-instance cookiejar and a
// TLS-1.3-minimum transport; WithHTTPClient may override the
// Transport/timeout, but the SDK re-applies its own jar and TLS config
// over any supplied client afterward (D-09) so neither can be silently
// dropped or bypassed.
func NewClient(baseURL, tenantSlug string, opts ...Option) (*Client, error) {
	// Blank, not just absent (§5.2.1 rule 2). Nothing can carry an empty slug,
	// so tenant_slug: "" on the wire resolves nothing — and on
	// /auth/opaque/login/start it fails on the workspace *before* the tenant's
	// OPAQUE mode is read, so the 404 that means "OPAQUE is not offered here"
	// never arrives and this SDK has no fallback to take. Sign-in then fails
	// even against a tenant with OPAQUE disabled, answered as "invalid
	// credentials", which sends a user off to reset a password that works.
	if strings.TrimSpace(tenantSlug) == "" {
		return nil, &AuthError{Message: `tenantSlug is required and must not be blank — AXIAM is multi-tenant and there is no default tenant; to sign in an organization-level principal, name the organization's reserved tenant, whose slug is "organization" (CONTRACT.md §5, §5.2.1)`}
	}

	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, &NetworkError{Message: fmt.Sprintf("invalid baseURL: %v", err)}
	}

	cfg := defaultConfig()
	for _, opt := range opts {
		opt(cfg)
	}

	httpc, err := buildHTTPClient(cfg)
	if err != nil {
		return nil, err
	}

	session := &clientSession{
		// §17.1 rule 1: off unless the caller asked for it.
		memo: newDecisionMemo(cfg.decisionMemoTTL),
		oidc: oidcState{
			clientID:     cfg.oidcClientID,
			clientSecret: cfg.oidcClientSecret,
			discoveryTTL: normalizeDiscoveryTTL(cfg.oidcDiscoveryTTL),
			clockSkewSec: normalizeClockSkewSec(cfg.oidcClockSkewSec),
		},
	}
	session.guard.Store(&refreshguard.Guard{})

	c := &Client{
		baseURL:    parsed,
		tenantSlug: tenantSlug,
		org:        cfg.org,
		httpc:      httpc,
		logger:     cfg.logger,
		// §16.1: on unless the caller opted out.
		retryEnabled: !cfg.retryDisabled,
		rand:         cfg.randSource,
		telemetry:    dispatcher{hook: cfg.telemetryHook},
		// §6.1 is all-or-nothing: buildHTTPClient above has already refused a
		// half-configured pair, so either half implies both.
		presentsClientCertificate: len(cfg.clientCertPEM) > 0,
		// §5.2 rule 1: the builder form. There is nothing to gate on yet —
		// no login has happened — so it is accepted as given; the server's
		// 403 is the backstop for a principal that turns out not to be
		// organization-level.
		actingTenant: cfg.actingTenant,
		session:      session,
	}

	// §19.2 rule 6: a clamped setting is reported, not swallowed. Emitted once,
	// here, because construction is the only moment an operator can act on it.
	reportMemoClamp(cfg.decisionMemoTTL, c.session.memo.ttl, c.telemetry)

	return c, nil
}

// WithActingTenant sets the CONTRACT.md §5.2 rule 1 acting tenant at
// construction time. tenantID is a UUID, so a non-UUID value cannot be
// expressed — the server silently ignores a header value that fails to
// parse and answers for the caller's own tenant instead, which is exactly
// the "reports success about the wrong tenant" failure §5.2 rule 1 requires
// an SDK to refuse before any wire call; typing the parameter as uuid.UUID
// makes that refusal a compile error rather than a runtime one.
//
// Meaningful only for an organization-level principal (§5.2): switching the
// acting tenant this way, before any login, cannot be gated client-side —
// there is no login result yet to consult — so the server's 403 is the
// backstop if the principal that eventually logs in is not
// organization-level, or the tenant named here is outside its reach.
//
// See the package doc and ActingTenant for the on-client form.
func WithActingTenant(tenantID uuid.UUID) Option {
	return func(c *clientConfig) { c.actingTenant = &tenantID }
}

// ActingTenant returns a NEW *Client that sends X-Axiam-Tenant: tenantID on
// every request, sharing this Client's session — cookie jar, CSRF token,
// refresh guard, decision memo, OIDC caches — but never its actingTenant
// field (CONTRACT.md §5.2 rule 1).
//
// That separation is deliberate and load-bearing: the acting tenant is
// scoped to the returned handle rather than written onto shared state, so
// two goroutines acting on two different tenants over the same login cannot
// rewrite each other's header between deciding which tenant to act on and
// sending the request. Each holds its own *Client; neither mutates the
// other's.
//
// Gated on what this client currently knows (CONTRACT.md §5.2 rule 1's
// "gate it on what the SDK knows, and let the server decide the rest"):
//
//   - Once a call that returned a LoginResult has completed (Login,
//     VerifyMfa, LoginOpaque, a WebAuthn or MFA-setup completion — see the
//     package doc's "acting tenant" section for exactly which calls count),
//     ActingTenant refuses client-side with an *AuthzError, making zero wire
//     calls, unless that result's OrganizationLevel was true, and refuses a
//     tenantID outside ReachableTenantIDs when that field was present
//     (§5.2.3 rule 4).
//   - A session that holds no such result — a device token, a token
//     injected via WithHTTPClient's Authorization header, a client-credentials
//     token, or simply a client that has not logged in yet — has nothing to
//     gate on. ActingTenant returns the new handle unconditionally and lets
//     the server's own 403 answer.
//
// It is REST-only: no gRPC channel built from a Client reads any
// acting-tenant metadata (CONTRACT.md §5.2 rule 1, "the gRPC server reads
// no acting-tenant metadata"). A gRPC call always acts on whatever tenant
// the bearer token itself names, whatever ActingTenant says.
//
// Call ClearActingTenant to return a handle with no acting tenant at all —
// which, like a client that never called ActingTenant, sends no
// X-Axiam-Tenant header.
func (c *Client) ActingTenant(tenantID uuid.UUID) (*Client, error) {
	if err := c.ensureOpen(); err != nil {
		return nil, err
	}
	if err := c.checkActingTenantReach(tenantID); err != nil {
		return nil, err
	}
	next := *c
	next.actingTenant = &tenantID
	return &next, nil
}

// ClearActingTenant returns a NEW *Client, sharing this Client's session
// exactly as ActingTenant does, that sends no X-Axiam-Tenant header
// (CONTRACT.md §5.2 rule 1: "the on-client form MUST also offer a way to
// clear it").
func (c *Client) ClearActingTenant() *Client {
	next := *c
	next.actingTenant = nil
	return &next
}

// checkActingTenantReach applies CONTRACT.md §5.2 rule 1's client-side gate.
func (c *Client) checkActingTenantReach(tenantID uuid.UUID) error {
	c.session.scopeMu.Lock()
	scope := c.session.scope
	c.session.scopeMu.Unlock()

	if !scope.known {
		// Nothing to gate on (device token, injected credential, no login
		// yet). Send the header as asked; the server decides.
		return nil
	}
	if !scope.organizationLevel {
		return &AuthzError{Message: "acting tenant is meaningful only for an organization-level principal (CONTRACT.md §5.2 rule 1); this session's signed-in principal is not one"}
	}
	if scope.reachableTenantIDs != nil {
		reachable := false
		for _, id := range scope.reachableTenantIDs {
			if id == tenantID {
				reachable = true
				break
			}
		}
		if !reachable {
			return &AuthzError{Message: "acting tenant " + tenantID.String() + " is outside this principal's reachable_tenant_ids (CONTRACT.md §5.2.3 rule 4)"}
		}
	}
	return nil
}

// setScope records the §5.2/§5.2.3 gating snapshot from a completed login
// result.
//
// Called from the success branch of every SDK call that returns a
// LoginResult carrying real OrganizationLevel/ReachableTenantIDs fields —
// Login, VerifyMfa, LoginOpaque, WebauthnSetupRegisterFinish and
// MfaSetupConfirm. That is a wider list than the Rust reference's ("For
// C-12" open question 5: Rust treats OPAQUE, WebAuthn and the MFA setup as
// holding no login result at all, and sends the acting-tenant header
// unconditionally for each). The divergence is deliberate, not an
// oversight: unlike the Rust SDK, this SDK's wire types for all five of
// these responses already decode the same loginUserInfoWire object Login
// does — principalScope is the one function every one of them calls to
// copy it out — so OrganizationLevel and ReachableTenantIDs are genuine
// data the server sent, not values this SDK would have to infer. Gating on
// real data the SDK already parses is a strictly better answer than "gate
// on nothing and let the server's 403 decide" wherever the SDK actually has
// the data, so Go's client-side refusal is tighter than Rust's here. A
// session that completes WITHOUT one of these five calls — the mTLS device
// login, a WebAuthn or OIDC/SSO *authentication* (as opposed to WebAuthn
// *setup*, which does return a LoginResult), a client-credentials grant —
// still has nothing to gate on and resets to unknown; see
// resetScopeUnknown.
func (c *Client) setScope(organizationLevel bool, reachableTenantIDs []uuid.UUID) {
	c.session.scopeMu.Lock()
	defer c.session.scopeMu.Unlock()
	c.session.scope = scopeState{
		known:              true,
		organizationLevel:  organizationLevel,
		reachableTenantIDs: reachableTenantIDs,
	}
}

// resetScopeUnknown clears the gating snapshot back to "nothing to gate on"
// — used by Logout and by every credential-establishing call that completes
// a session WITHOUT a LoginUserInfo attached (the device login; a WebAuthn
// or OIDC/SSO completion that returns no LoginResult). A session in that
// state sends the acting-tenant header unconditionally and lets the
// server's 403 decide, exactly as a session that has never logged in does.
func (c *Client) resetScopeUnknown() {
	c.session.scopeMu.Lock()
	defer c.session.scopeMu.Unlock()
	c.session.scope = scopeState{}
}

// Close releases this Client's local resources (CONTRACT.md §18).
//
// It is idempotent — calling it twice is not an error. Cleanup runs from error
// paths, and an error path that itself fails hides the original problem. It
// returns error only to satisfy io.Closer; the error is always nil.
//
// CLOSE DOES NOT LOG OUT. §18.1 rule 5: shutting down a client releases LOCAL
// resources and never reaches the network. The server-side session
// deliberately outlives the Client value, which is what lets a process restart
// and resume; a Close that logged out would silently end every user's session
// on each deploy. Call Logout first if ending the session is what you want.
//
// After Close returns, every operation on this Client fails with *NetworkError
// rather than silently reconnecting.
func (c *Client) Close() error {
	c.session.closed.Store(true)
	c.session.memo.clear()
	// CloseIdleConnections rather than anything more forceful: an in-flight
	// request on another goroutine is the caller's to finish, and tearing its
	// connection out from under it would turn a lifecycle bug into a truncated
	// response.
	c.httpc.CloseIdleConnections()
	return nil
}

// ensureOpen reports an error if Close has been called (§18.1 rule 4).
//
// Use-after-close is an error, not a silent reconnect: a client that quietly
// rebuilt its transport would make Close meaningless and hide the lifecycle bug
// that caused the call.
func (c *Client) ensureOpen() error {
	if c.session.closed.Load() {
		return &NetworkError{Message: "client is closed: this Client was shut down with Close()"}
	}
	return nil
}

// onCredentialChange drops memoized decisions (§17.1 rule 9).
//
// Entries are keyed by subject rather than session, so a re-authentication as a
// DIFFERENT principal would otherwise inherit the previous one's decisions.
func (c *Client) onCredentialChange() {
	c.session.memo.clear()
}

// adoptDeviceCredential stores token as this Client's §6.1 device-login
// bearer credential. Applied only in decorateRequest — never written to a
// public field, the cookie jar, or logged. token == "" clears it.
func (c *Client) adoptDeviceCredential(token Sensitive) {
	c.session.deviceMu.Lock()
	c.session.deviceToken = token
	c.session.deviceMu.Unlock()
}

// deviceCredential reads the currently adopted §6.1 device token, if any
// ("" when none has been adopted).
func (c *Client) deviceCredential() Sensitive {
	c.session.deviceMu.Lock()
	defer c.session.deviceMu.Unlock()
	return c.session.deviceToken
}

// buildHTTPClient constructs the SDK's http.Client per D-09: if cfg
// supplies a base client, its Transport/Timeout are adopted, but the
// SDK's own cookiejar and TLS config are ALWAYS re-applied afterward so an
// override can never drop the jar or weaken TLS verification.
func buildHTTPClient(cfg *clientConfig) (*http.Client, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13} // CLAUDE.md project-wide TLS 1.3 floor.

	if len(cfg.customCAPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(cfg.customCAPEM) {
			return nil, &NetworkError{Message: "invalid custom CA PEM"}
		}
		tlsConfig.RootCAs = pool
	}

	// §6.1 client-certificate (mTLS) identity. Kept in a separate code path
	// from the server-verification config above so it never touches RootCAs
	// or the TLS-bypass surface. A malformed cert/key pair is a
	// construction-time error, consistent with the invalid-custom-CA branch.
	if len(cfg.clientCertPEM) > 0 || len(cfg.clientKeyPEM) > 0 {
		cert, err := tls.X509KeyPair(cfg.clientCertPEM, []byte(cfg.clientKeyPEM.expose()))
		if err != nil {
			return nil, &NetworkError{Message: "invalid client certificate/key PEM"}
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, &NetworkError{Message: fmt.Sprintf("failed to construct cookie jar: %v", err)}
	}

	var httpc *http.Client
	if cfg.baseHTTPClient != nil {
		// Shallow-copy so we never mutate the caller's original client.
		clone := *cfg.baseHTTPClient
		httpc = &clone
	} else {
		httpc = &http.Client{}
	}

	// D-09: the SDK's own jar and TLS config ALWAYS win — re-applied here,
	// unconditionally, regardless of what the supplied client had set.
	httpc.Jar = jar

	transport, ok := httpc.Transport.(*http.Transport)
	if !ok || transport == nil {
		transport = http.DefaultTransport.(*http.Transport).Clone()
	} else {
		transport = transport.Clone()
	}
	transport.TLSClientConfig = tlsConfig
	httpc.Transport = transport

	// Cross-host redirect hardening (D-09: SDK security config always wins).
	// net/http forwards custom request headers across redirect hops and only
	// strips Authorization/Cookie when the host changes — X-Tenant-ID and
	// X-CSRF-Token would otherwise leak to a redirect target on a different
	// host. Delete them on any hop that leaves the original origin. The
	// 10-redirect ceiling reproduces net/http's default (which no longer
	// applies once CheckRedirect is set).
	httpc.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		if len(via) > 0 && req.URL.Host != via[0].URL.Host {
			req.Header.Del("X-Tenant-ID")
			req.Header.Del("X-CSRF-Token")
			req.Header.Del("X-Axiam-Tenant")
		}
		return nil
	}

	if cfg.requestTimeout > 0 {
		httpc.Timeout = cfg.requestTimeout
	}

	return httpc, nil
}

// httpClient returns the SDK's underlying *http.Client (package-internal —
// used by login.go/authz.go request builders and by tests asserting
// override safety).
func (c *Client) httpClient() *http.Client {
	return c.httpc
}

// stateChangingMethods lists the HTTP verbs that echo the captured
// X-CSRF-Token per §3 non-browser CSRF behavior.
var stateChangingMethods = map[string]bool{
	http.MethodPost:   true,
	http.MethodPut:    true,
	http.MethodPatch:  true,
	http.MethodDelete: true,
}

// decorateRequest sets X-Tenant-ID on every outgoing request (§5) and
// echoes the captured X-CSRF-Token on state-changing verbs (§3
// non-browser: capture-from-response-header, echo-on-request).
func (c *Client) decorateRequest(req *http.Request) {
	// Host-isolation (defense in depth): never inject the CSRF token or an
	// adopted bearer credential into a request bound for a host other than
	// this client's own origin (e.g. one built against an absolute
	// third-party URL). The normal path — requests built from c.baseURL via
	// c.url() — shares the base host and is decorated as usual. Mirrors the
	// Python SDK's _prepare_request host guard.
	sameOrigin := req.URL == nil || req.URL.Host == "" || req.URL.Host == c.baseURL.Host

	// X-Tenant-ID is the one deliberate exception to that host guard
	// (cross-SDK conformance review F-15; CONTRACT.md §12.1 note 2 / §5 rule
	// 2 — "the header is still emitted on these requests ... §5 rule 2 is
	// unconditional"). §12's absolute request builder (oidc_wire.go's
	// newAbsoluteRequest) targets an endpoint URL taken verbatim from the
	// OIDC discovery document, which for a proxy-fronted deployment may
	// legitimately advertise a host different from c.baseURL. Without this
	// carve-out, that foreign-host guard would silently drop the header on
	// every /oauth2/* call in exactly that (harmless-today, but
	// contract-mandated) case. X-Tenant-ID carries only a tenant
	// identifier — never a credential — so emitting it cross-host here is
	// not the kind of leak a bearer token or CSRF token would be, which is
	// why only this header gets the carve-out.
	if sameOrigin || strings.Contains(req.URL.Path, "/oauth2/") {
		req.Header.Set("X-Tenant-ID", c.tenantSlug)
	}
	if !sameOrigin {
		return
	}

	// X-Axiam-Tenant (CONTRACT.md §5.2 rule 1). Sent on every same-origin
	// request of a handle that has an acting tenant, byte-for-byte as
	// before 1.51 when it does not: a client that never called
	// WithActingTenant/ActingTenant sends no such header at all. This is
	// deliberately unconditional across the REST surface — management,
	// check_access/batch_check, refresh, logout, and the self-service
	// account and WebAuthn posts all go through this one choke point, and
	// §5.2.2 rule 4 says the self-service ones are sent it "as normal": the
	// server, not the SDK, is what makes those ignore it.
	if c.actingTenant != nil {
		req.Header.Set("X-Axiam-Tenant", c.actingTenant.String())
	}

	if stateChangingMethods[strings.ToUpper(req.Method)] {
		if token := c.getCSRFToken(); token != "" {
			req.Header.Set("X-CSRF-Token", token)
		}
	}

	// An adopted bearer credential — CONTRACT.md §6.1 rule 6 (AuthenticateDevice)
	// or §12.1 "login_client_credentials as a credential source"
	// (LoginClientCredentials(AdoptAsCredential: true)) — is applied here:
	// same-origin only (the foreign-host guard above already returned), and
	// NEVER to an /oauth2/* path, which authenticates via the form body
	// instead (§12.1 note 3). A caller-set Authorization header is never
	// overridden. The two sources are mutually exclusive per Client (adopting
	// one clears the other — see AuthenticateDevice), so checking the device
	// credential first is never a real choice between two live values; it is
	// ordered this way because §6.1 is the newer, narrower mechanism.
	adopted := c.deviceCredential()
	if adopted == "" {
		adopted = c.adoptedOidcCredential()
	}
	if adopted != "" && req.Header.Get("Authorization") == "" && !strings.Contains(req.URL.Path, "/oauth2/") {
		req.Header.Set("Authorization", "Bearer "+adopted.expose())
	}
}

// captureCSRFFromResponse stores a freshly observed X-CSRF-Token response
// header value (§3 non-browser CSRF capture).
func (c *Client) captureCSRFFromResponse(resp *http.Response) {
	if token := resp.Header.Get("X-CSRF-Token"); token != "" {
		c.session.csrfMu.Lock()
		c.session.csrfToken = token
		c.session.csrfMu.Unlock()
	}
}

func (c *Client) getCSRFToken() string {
	c.session.csrfMu.Lock()
	defer c.session.csrfMu.Unlock()
	return c.session.csrfToken
}

// doRequest decorates req with the tenant + CSRF headers, executes it
// against the SDK's http.Client (cookie jar + TLS 1.3 transport), and
// captures any X-CSRF-Token the response carries. This is the single
// choke point every REST call in login.go/authz.go/oidc*.go routes through.
//
// Structural invariant (cross-SDK conformance review F-14; CONTRACT.md
// §12.3 rule 3): doRequest contains NO 401-to-refresh interceptor of any
// kind — a response's status code is returned to the caller exactly as
// received, whatever it is. The single-flight refresh guard
// (internal/refreshguard.Guard, reached via c.session.guard.Load().RefreshIfNeeded)
// is invoked from exactly one place in this entire module: Refresh() in
// login.go. Nothing in authz.go's checkAccessWithRetry/sendAuthzPostInto or
// any §12 OIDC/SSO operation in oidc*.go (which all route through
// postOAuth2Form -> doRequest, see oidc_wire.go) ever calls RefreshIfNeeded.
// So a 401 from ANY endpoint — /oauth2/* included — cannot reach the guard
// as a side effect of doRequest; only an explicit application call to
// Refresh() can. This is intentionally fragile to a future change that adds
// automatic refresh-on-401 at this choke point (or inside sendAuthzPostInto)
// rather than leaving it to the caller: such a change would have to
// explicitly exclude /oauth2/* or this invariant — and the regression test
// at oidc_test.go's TestIntrospectRevoke_401DoesNotEnterRefreshGuard — would
// silently break.
func (c *Client) doRequest(req *http.Request) (*http.Response, error) {
	c.decorateRequest(req)

	sender := c.httpc
	// CONTRACT.md §6.1: once a device token is adopted, every request this
	// Client makes carries an explicit empty Cookie rather than whatever the
	// jar has accumulated — the server reads axiam_access before
	// Authorization, so a cookie left over from an earlier Login() on this
	// same Client would otherwise silently outrank the device credential.
	// noOutboundCookieJar still absorbs any Set-Cookie the response sends
	// (there should not be one on this credential's routes, but nothing here
	// assumes that), it only suppresses what goes OUT.
	if c.deviceCredential() != "" {
		clone := *c.httpc
		clone.Jar = noOutboundCookieJar{real: c.httpc.Jar}
		sender = &clone
	}

	resp, err := sender.Do(req)
	if err != nil {
		return nil, newNetworkError(fmt.Sprintf("request failed: %v", err), nil, err)
	}
	c.captureCSRFFromResponse(resp)
	return resp, nil
}

// setResolvedOrgID caches the organization UUID resolved from the access
// token's org_id claim after a successful login/refresh (RESEARCH.md
// Pitfall 3), so Refresh can supply it without requiring the caller to
// have configured WithOrgID/WithOrgSlug up front.
func (c *Client) setResolvedOrgID(id uuid.UUID) {
	c.session.orgIDMu.Lock()
	defer c.session.orgIDMu.Unlock()
	c.session.resolvedOrg = &id
}

// resolvedOrgID returns the organization UUID to use in a request body:
// the explicitly configured WithOrgID value if present, otherwise the
// value resolved from the access token's org_id claim after login, if
// any.
func (c *Client) resolvedOrgID() (uuid.UUID, bool) {
	if c.org.id != nil {
		return *c.org.id, true
	}
	c.session.orgIDMu.Lock()
	defer c.session.orgIDMu.Unlock()
	if c.session.resolvedOrg != nil {
		return *c.session.resolvedOrg, true
	}
	return uuid.UUID{}, false
}

// url joins path against the client's configured base URL.
func (c *Client) url(path string) string {
	u := *c.baseURL
	u.Path = strings.TrimRight(u.Path, "/") + "/" + strings.TrimLeft(path, "/")
	return u.String()
}

// newRequest builds an *http.Request against the client's base URL with a
// context, without decorating or sending it.
func (c *Client) newRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.url(path), body)
	if err != nil {
		return nil, &NetworkError{Message: fmt.Sprintf("failed to build request: %v", err)}
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

// logf writes a redaction-safe log line via the configured logger, if any
// (CF-02: OFF by default, never emits raw token values since any Sensitive
// argument redacts itself through fmt/slog's Stringer/LogValuer paths).
func (c *Client) logf(ctx context.Context, msg string, args ...any) {
	if c.logger == nil {
		return
	}
	c.logger.InfoContext(ctx, msg, args...)
}
