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

// Client is the AXIAM SDK's REST entry point (CONTRACT.md §1-§10). See
// NewClient.
type Client struct {
	baseURL    *url.URL
	tenantSlug string
	org        orgIdentifier
	httpc      *http.Client
	logger     *slog.Logger
	// guard is swapped atomically: Logout() replaces it with a fresh Guard
	// while Login/VerifyMfa/Refresh Load() it concurrently. Using an
	// atomic.Pointer (rather than a plain field) prevents the data race
	// between Logout's reassignment and concurrent Refresh reads (CR-01).
	guard atomic.Pointer[refreshguard.Guard]

	// §16.1 disable switch. There is deliberately no field for the attempt
	// cap, base delay or delay cap: §16.1 forbids raising them, and eleven
	// SDKs agreeing on one table is the point.
	retryEnabled bool
	// rand supplies the §16 jitter fraction; nil means math/rand. Injected so
	// a test can pin it — a test that really waits 200ms is a test nobody runs.
	rand func() float64
	// telemetry is the §19 dispatcher; its zero value is a no-op.
	telemetry dispatcher
	// memo is the §17 decision cache; nil-safe and disabled by default.
	memo *decisionMemo
	// closed is set once by Close and read on every operation (§18).
	closed      atomic.Bool
	csrfMu      sync.Mutex
	csrfToken   string
	orgIDMu     sync.Mutex
	resolvedOrg *uuid.UUID

	// oidc holds the OIDC / SSO relying-party runtime state (CONTRACT.md
	// §12) — configuration plus the discovery cache, per-jwks_uri verifier
	// cache, and the oidc_refresh single-flight guard. Defined in oidc.go so
	// the whole §12 surface (besides this one field and the small
	// decorateRequest hook below) lives outside client.go.
	oidc oidcState
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
	if tenantSlug == "" {
		return nil, &AuthError{Message: "tenantSlug is required — AXIAM is multi-tenant and there is no default tenant (CONTRACT.md §5)"}
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
		// §17.1 rule 1: off unless the caller asked for it.
		memo: newDecisionMemo(cfg.decisionMemoTTL),
		oidc: oidcState{
			clientID:     cfg.oidcClientID,
			clientSecret: cfg.oidcClientSecret,
			discoveryTTL: normalizeDiscoveryTTL(cfg.oidcDiscoveryTTL),
			clockSkewSec: normalizeClockSkewSec(cfg.oidcClockSkewSec),
		},
	}
	c.guard.Store(&refreshguard.Guard{})

	// §19.2 rule 6: a clamped setting is reported, not swallowed. Emitted once,
	// here, because construction is the only moment an operator can act on it.
	reportMemoClamp(cfg.decisionMemoTTL, c.memo.ttl, c.telemetry)

	return c, nil
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
	c.closed.Store(true)
	c.memo.clear()
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
	if c.closed.Load() {
		return &NetworkError{Message: "client is closed: this Client was shut down with Close()"}
	}
	return nil
}

// onCredentialChange drops memoized decisions (§17.1 rule 9).
//
// Entries are keyed by subject rather than session, so a re-authentication as a
// DIFFERENT principal would otherwise inherit the previous one's decisions.
func (c *Client) onCredentialChange() {
	c.memo.clear()
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
	// Host-isolation (defense in depth): never inject the tenant identifier
	// or CSRF token into a request bound for a host other than this client's
	// own origin (e.g. one built against an absolute third-party URL). The
	// normal path — requests built from c.baseURL via c.url() — shares the
	// base host and is decorated as usual. Mirrors the Python SDK's
	// _prepare_request host guard.
	if req.URL != nil && req.URL.Host != "" && req.URL.Host != c.baseURL.Host {
		return
	}
	req.Header.Set("X-Tenant-ID", c.tenantSlug)
	if stateChangingMethods[strings.ToUpper(req.Method)] {
		if token := c.getCSRFToken(); token != "" {
			req.Header.Set("X-CSRF-Token", token)
		}
	}

	// CONTRACT.md §12.1 "login_client_credentials as a credential source":
	// a token adopted via LoginClientCredentials(AdoptAsCredential: true) is
	// applied here — same-origin only (the foreign-host guard above already
	// returned) — and NEVER to an /oauth2/* path, which authenticates via
	// the form body instead (§12.1 note 3). A caller-set Authorization
	// header is never overridden.
	if adopted := c.adoptedOidcCredential(); adopted != "" && req.Header.Get("Authorization") == "" && !strings.Contains(req.URL.Path, "/oauth2/") {
		req.Header.Set("Authorization", "Bearer "+adopted.expose())
	}
}

// captureCSRFFromResponse stores a freshly observed X-CSRF-Token response
// header value (§3 non-browser CSRF capture).
func (c *Client) captureCSRFFromResponse(resp *http.Response) {
	if token := resp.Header.Get("X-CSRF-Token"); token != "" {
		c.csrfMu.Lock()
		c.csrfToken = token
		c.csrfMu.Unlock()
	}
}

func (c *Client) getCSRFToken() string {
	c.csrfMu.Lock()
	defer c.csrfMu.Unlock()
	return c.csrfToken
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
// (internal/refreshguard.Guard, reached via c.guard.Load().RefreshIfNeeded)
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
	resp, err := c.httpc.Do(req)
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
	c.orgIDMu.Lock()
	defer c.orgIDMu.Unlock()
	c.resolvedOrg = &id
}

// resolvedOrgID returns the organization UUID to use in a request body:
// the explicitly configured WithOrgID value if present, otherwise the
// value resolved from the access token's org_id claim after login, if
// any.
func (c *Client) resolvedOrgID() (uuid.UUID, bool) {
	if c.org.id != nil {
		return *c.org.id, true
	}
	c.orgIDMu.Lock()
	defer c.orgIDMu.Unlock()
	if c.resolvedOrg != nil {
		return *c.resolvedOrg, true
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
