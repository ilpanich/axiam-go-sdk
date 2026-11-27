package jwks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"

	"github.com/ilpanich/axiam-go-sdk/internal/revocation"
)

// jwksPath is the AXIAM JWKS endpoint path — organization-wide, not
// tenant-scoped, serving exactly one Ed25519 key today (RESEARCH.md D-11,
// mirrors the Rust SDK's src/token/jwks.rs::JWKS_PATH). This is NOT a generic
// OIDC discovery-style `/.well-known/jwks.json` path; do not substitute one.
const jwksPath = "/oauth2/jwks"

const (
	// minRefetchInterval is the re-fetch window (CF-03; matches the Rust
	// reference's FORCED_REFETCH_MIN_INTERVAL): at most one unknown-kid
	// re-fetch per window, and a failed fetch of any kind opens it too
	// (CONTRACT.md §12.4 rule 2).
	minRefetchInterval = 60 * time.Second
	// maxCacheInterval is the cache TTL: the default, and the ceiling an
	// advertised Cache-Control max-age is clamped to (CONTRACT.md §12.4
	// rule 2, contract 1.69; the Rust reference's JWKS_CACHE_TTL).
	maxCacheInterval = 300 * time.Second
	// maxStale is how long past the TTL held keys keep verifying while every
	// refresh fails (CONTRACT.md §12.4 rule 2 "Stale-if-error, bounded",
	// contract 1.69, D-10): exactly 300 s, then every token is refused until
	// a fetch succeeds.
	maxStale = 300 * time.Second
	// maxJWKSBody bounds the JWKS response read.
	maxJWKSBody = 1 << 20
	// defaultFetchTimeout bounds a fetch made with the default client.
	defaultFetchTimeout = 10 * time.Second
)

// errNoJWKS reports that no JWKS was ever fetched successfully.
var errNoJWKS = errors.New("jwks: no JWKS has been fetched successfully")

// errJWKSStale reports held keys past the stale-if-error bound.
var errJWKSStale = errors.New("jwks: the held JWKS is older than its TTL plus 300 s and no refresh has succeeded")

// Verifier fetches, caches, and locally verifies AXIAM access tokens against
// the organization-wide EdDSA JWKS (D-06). It is the shared local-verify
// primitive consumed by the net/http middleware (Plan 05).
//
// The cache (CONTRACT.md §12.4 rule 2, contract 1.69): the held set answers
// for its TTL (the response's Cache-Control max-age, 300 s when absent, at
// most 300 s) with no fetch. Past it a refresh is due, made conditional on the
// held ETag. A successful fetch — a 200 whose body is a JWKS holding at least
// one key, or a 304 to the conditional request — replaces or re-confirms the
// held set and moves the anchor the age is measured from. A failed one — a
// transport error, any other status, a body that is not a JWKS, an empty key
// set — changes neither: the held keys keep verifying until exactly TTL +
// 300 s after the anchor and are refused from then on, until a fetch
// succeeds. A failed fetch opens the re-fetch window, so a failing endpoint
// costs one fetch per window, not one per token.
type Verifier struct {
	hc      *http.Client
	jwksURL string

	// mu guards the cache state below. It is held only to read or update that
	// state, never across a fetch or jws.Verify. Fetches are single-flight
	// (inflight): a concurrent burst of due or unknown-kid verifications
	// collapses to one network fetch (D-08/D-09).
	mu sync.Mutex
	// inflight is the fetch running now, nil when none is.
	inflight *fetchCall
	// fetchTimeout bounds every fetch, whatever hc's own timeout.
	fetchTimeout time.Duration
	// set is the held key set; nil until the first successful fetch.
	set jwk.Set
	// etag is the held set's ETag, for the conditional refresh.
	etag string
	// anchor is when the last successful fetch started; ttl is its lifetime.
	anchor time.Time
	ttl    time.Duration
	// lastFailed reports whether the most recent fetch failed.
	lastFailed bool
	// windowStart is when the current re-fetch window opened: the last forced
	// (unknown-kid) fetch or the last failed fetch. A further forced fetch is
	// skipped until minRefetchInterval has passed (CONTRACT.md §12.4 rule 2,
	// cited by §10.1 rule 12): at most one forced fetch per window, however
	// many unknown kids arrive, and whether the fetch succeeded or not; after
	// a failed fetch a due refresh waits for the window too.
	windowStart time.Time
	// lastTTLFetch is when the last TTL-driven (non-forced) fetch started,
	// successful or not. A further TTL-driven fetch waits until
	// minRefetchInterval has passed (ADDENDUM point 10 of §12.4 rule 2's
	// window): an advertised max-age below 60 s, max-age=0 included, is still
	// the TTL, but it can trigger at most one fetch per window. This stamp
	// does not block the forced fetch: an unknown kid still gets its one
	// fetch per window after a successful TTL refresh. A failed fetch of
	// either kind stamps windowStart, which blocks both.
	lastTTLFetch time.Time
	// now is the clock the cache reads; time.Now unless a test injects one.
	now func() time.Time

	// feed is the optional CONTRACT.md §10.4 revocation feed (contract 1.44).
	// nil — the default — means this Verifier behaves exactly as it did before
	// 1.44: a revoked session's access token verifies locally until it
	// expires, which is the §10.2 posture the feed narrows rather than
	// replaces.
	feed *revocation.Feed
}

// WithRevocationFeed attaches the optional §10.4 session-revocation feed and
// returns v, so construction reads as one expression.
//
// It can only ever turn an accept into a reject: every §10.1 rule runs first
// and still decides, and a feed that cannot be read denies nothing.
func (v *Verifier) WithRevocationFeed(feed *revocation.Feed) *Verifier {
	v.feed = feed
	return v
}

// NewVerifier constructs a Verifier bound to {baseURL}/oauth2/jwks (trailing
// slash on baseURL trimmed before joining). The cache is not eagerly
// populated; the first Verify call triggers the initial fetch.
func NewVerifier(ctx context.Context, baseURL string, hc *http.Client) (*Verifier, error) {
	jwksURL := strings.TrimRight(baseURL, "/") + jwksPath
	return NewVerifierForURL(ctx, jwksURL, hc)
}

// NewVerifierForURL constructs a Verifier bound to the EXACT jwksURL given —
// no /oauth2/jwks path is concatenated. NewVerifier itself, and its
// fixed-path resource-server callers, are unchanged; this constructor exists
// for the OIDC relying-party helpers (CONTRACT.md §12.3 rule 6), which MUST
// read jwks_uri from the discovery document rather than assume the fixed
// AXIAM resource-server path.
//
// Every fetch goes out on hc — the SDK's CA, client certificate and timeout
// (C163-16); a nil hc means a default client with a 10 s timeout. Every fetch
// is also bounded by its own 10 s timeout, whatever hc's, on a context no
// caller can cancel. A TTL-driven refresh runs at most once per 60 s window,
// whatever max-age the server advertises.
func NewVerifierForURL(_ context.Context, jwksURL string, hc *http.Client) (*Verifier, error) {
	u, err := url.Parse(jwksURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("jwks: invalid JWKS URL %q", jwksURL)
	}
	if hc == nil {
		hc = &http.Client{Timeout: defaultFetchTimeout}
	}
	return &Verifier{hc: hc, jwksURL: jwksURL, now: time.Now, fetchTimeout: defaultFetchTimeout}, nil
}

// fetchCall is one fetch in flight; done is closed once its outcome has been
// applied to the cache.
type fetchCall struct {
	done chan struct{}
}

// currentSet returns the set to verify with now. When a refresh is due and
// the window allows one, it starts it; it waits for that fetch (or one already
// in flight) only when no held set is usable, and then no longer than ctx
// allows. A verification whose held set is usable never waits for a fetch. It
// refuses (errNoJWKS, errJWKSStale) when no set is usable.
func (v *Verifier) currentSet(ctx context.Context) (jwk.Set, error) {
	v.mu.Lock()
	now := v.now()
	// A clock that moved back before the anchor (a negative age) makes a
	// refresh due, never fresh.
	due := v.set == nil || now.Before(v.anchor) || !now.Before(v.anchor.Add(v.ttl))
	var call *fetchCall
	if v.inflight != nil {
		call = v.inflight
	} else if due && !inWindow(v.lastTTLFetch, now) && (!v.lastFailed || !v.inWindowLocked(now)) {
		v.lastTTLFetch = now
		call = v.startFetchLocked(ctx, now)
	}
	set, err := v.usableLocked(now)
	v.mu.Unlock()
	if err == nil || call == nil {
		return set, err
	}
	if werr := wait(ctx, call); werr != nil {
		return nil, werr
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.usableLocked(v.now())
}

// refreshForUnknownKid forces one re-fetch when the window allows it (and
// opens a new window), or joins the fetch already in flight, waits for it as
// long as ctx allows, and returns the set to retry with. fetched reports
// whether a fetch ran. Called for a kid the usable set does not hold, or when
// no set is usable; a fetch that fails here is a failed refresh like any
// other and never moves the anchor.
func (v *Verifier) refreshForUnknownKid(ctx context.Context) (set jwk.Set, fetched bool, err error) {
	v.mu.Lock()
	now := v.now()
	call := v.inflight
	if call == nil && !v.inWindowLocked(now) {
		v.windowStart = now
		call = v.startFetchLocked(ctx, now)
	}
	v.mu.Unlock()
	if call != nil {
		if werr := wait(ctx, call); werr != nil {
			return nil, true, werr
		}
		fetched = true
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	set, err = v.usableLocked(v.now())
	return set, fetched, err
}

// wait blocks until call is done or ctx ends.
func wait(ctx context.Context, call *fetchCall) error {
	select {
	case <-call.done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("jwks: gave up waiting for the JWKS fetch: %w", ctx.Err())
	}
}

// inWindowLocked reports whether the forced/failure re-fetch window is open
// at now.
func (v *Verifier) inWindowLocked(now time.Time) bool {
	return inWindow(v.windowStart, now)
}

// inWindow reports whether a window that opened at start is still open at
// now. A window whose start lies after now (the clock stepped back) is over,
// so the refresh a negative age makes due actually happens.
func inWindow(start, now time.Time) bool {
	if start.IsZero() {
		return false
	}
	d := now.Sub(start)
	return d >= 0 && d < minRefetchInterval
}

// usableLocked returns the held set unless there is none, it is past TTL +
// maxStale after the anchor, or the clock reads before the anchor (a negative
// age is never trusted).
func (v *Verifier) usableLocked(now time.Time) (jwk.Set, error) {
	if v.set == nil {
		return nil, errNoJWKS
	}
	if now.Before(v.anchor) || now.After(v.anchor.Add(v.ttl+maxStale)) {
		return nil, errJWKSStale
	}
	return v.set, nil
}

// startFetchLocked starts the one fetch (called with mu held and no fetch in
// flight) and returns its call. The fetch runs on a context that keeps the
// starting caller's values but not its cancellation (context.WithoutCancel)
// — a caller that gives up, or disconnects, neither cancels it nor turns it
// into a failed refresh — bounded by fetchTimeout whatever hc's own timeout. Its outcome is applied as of start: a success replaces
// (200) or re-confirms (304) the held set and moves the anchor to start; a
// failure leaves the set and the anchor as they were and opens the re-fetch
// window.
func (v *Verifier) startFetchLocked(caller context.Context, start time.Time) *fetchCall {
	call := &fetchCall{done: make(chan struct{})}
	v.inflight = call
	held, etag := v.set, v.etag
	timeout := v.fetchTimeout
	if timeout <= 0 {
		timeout = defaultFetchTimeout
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(caller), timeout)
		set, newETag, ttl, notModified, err := v.fetch(ctx, held, etag)
		cancel()
		v.mu.Lock()
		if err != nil {
			v.lastFailed = true
			v.windowStart = start
		} else {
			if !notModified {
				v.set = set
				v.etag = newETag
			}
			v.anchor = start
			v.ttl = ttl
			v.lastFailed = false
		}
		v.inflight = nil
		v.mu.Unlock()
		close(call.done)
	}()
	return call
}

// fetch GETs the JWKS, conditionally on the held ETag when a set is held.
// Only a 200 holding a JWKS with at least one key, or a 304 answering the
// conditional request, is a success.
func (v *Verifier) fetch(ctx context.Context, held jwk.Set, heldETag string) (set jwk.Set, etag string, ttl time.Duration, notModified bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return nil, "", 0, false, err
	}
	req.Header.Set("Accept", "application/json")
	conditional := held != nil && heldETag != ""
	if conditional {
		req.Header.Set("If-None-Match", heldETag)
	}
	resp, err := v.hc.Do(req)
	if err != nil {
		return nil, "", 0, false, err
	}
	defer resp.Body.Close()
	ttl = ttlFrom(resp.Header)
	switch resp.StatusCode {
	case http.StatusNotModified:
		if !conditional {
			return nil, "", 0, false, fmt.Errorf("jwks: unexpected 304 to an unconditional request")
		}
		return nil, "", ttl, true, nil
	case http.StatusOK:
	default:
		return nil, "", 0, false, fmt.Errorf("jwks: JWKS endpoint answered %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBody+1))
	if err != nil {
		return nil, "", 0, false, err
	}
	if len(body) > maxJWKSBody {
		return nil, "", 0, false, errors.New("jwks: JWKS response too large")
	}
	// A JWKS document: a `keys` array with at least one JWK object carrying
	// a string `kty`. `{"keys":[]}`, `{"keys":[{}]}`, `[0]` or `[null]` is
	// a failed refresh, never a replacement.
	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil || !hasJWK(doc.Keys) {
		return nil, "", 0, false, errors.New("jwks: response is not a JWKS document holding a key")
	}
	// Each entry is parsed on its own: one this library cannot use (an
	// unknown kty, RSA without alg, …) is skipped, never a reason to refuse
	// the set; it still counts as a key the document holds (hasJWK above).
	set = jwk.NewSet()
	for _, raw := range doc.Keys {
		key, err := jwk.ParseKey(raw)
		if err != nil {
			continue
		}
		_ = set.AddKey(key)
	}
	return set, sanitizeETag(resp.Header.Get("ETag")), ttl, false, nil
}

// hasJWK reports whether keys holds at least one JSON object with a string
// `kty` member.
func hasJWK(keys []json.RawMessage) bool {
	for _, raw := range keys {
		var k struct {
			Kty *string `json:"kty"`
		}
		t := strings.TrimSpace(string(raw))
		if strings.HasPrefix(t, "{") && json.Unmarshal(raw, &k) == nil && k.Kty != nil {
			return true
		}
	}
	return false
}

// sanitizeETag returns etag, or "" (no conditional refresh) when it is
// longer than 256 bytes or carries a control character, so a hostile value is
// never stored or echoed in If-None-Match.
func sanitizeETag(etag string) string {
	if len(etag) > 256 {
		return ""
	}
	for i := 0; i < len(etag); i++ {
		if c := etag[i]; c < 0x20 || c == 0x7f {
			return ""
		}
	}
	return etag
}

// ttlFrom is the lifetime of a fetched set: the response's Cache-Control
// max-age clamped to at most maxCacheInterval, or maxCacheInterval when it
// advertises none.
func ttlFrom(h http.Header) time.Duration {
	for _, directive := range strings.Split(h.Get("Cache-Control"), ",") {
		name, value, ok := strings.Cut(strings.TrimSpace(directive), "=")
		if !ok || !strings.EqualFold(name, "max-age") {
			continue
		}
		secs, err := strconv.ParseInt(strings.Trim(value, `"`), 10, 64)
		if err != nil || secs < 0 {
			return maxCacheInterval
		}
		if d := time.Duration(secs) * time.Second; secs < int64(maxCacheInterval/time.Second) {
			return d
		}
		return maxCacheInterval
	}
	return maxCacheInterval
}

// VerifyAccessToken is the full CONTRACT.md §10.1 local-verification entry
// point, and the one every guard in this SDK routes through: it verifies the
// signature (rule 1, alg pinned to EdDSA BEFORE any key lookup) and then
// applies rules 2–7 via ValidateClaims — required exp, honoured nbf, asserted
// tenant_id, conditional iss/aud, all under the single named ClockSkewLeeway.
//
// It fails closed on every rule: a required claim that is absent, unparseable
// or of the wrong JSON type is a rejection, never a skipped check.
//
// Rule 9 (contract 1.51 fix — see CHANGELOG "Breaking"): this call has NO
// transport evidence to offer, so it applies rule 9 as "a different
// certificate, or none" — a token carrying ANY cnf confirmation is refused,
// whatever it names. An unbound token (no cnf at all) is unaffected. Call
// VerifyAccessTokenWithProofs when you hold evidence — a peer certificate
// from the connection, a verified DPoP proof — and want a bound token
// accepted on the strength of it.
func (v *Verifier) VerifyAccessToken(ctx context.Context, token []byte, opts ValidationOptions) (Claims, error) {
	return v.verifyAccessToken(ctx, token, opts, PresentedProofs{})
}

// VerifyAccessTokenWithProofs is VerifyAccessToken plus CONTRACT.md §10.1
// rule 9 applied IN FULL against proofs — evidence the caller has itself
// established belongs to this connection/request (a TLS peer certificate's
// thumbprint; the key thumbprint of a DPoP proof this caller has already
// verified per §21.7.2 — see jwks.VerifyDPoPProof). A token naming no
// confirmation is accepted regardless of proofs, exactly as
// VerifyAccessToken accepts it. A token naming one IS accepted when proofs
// satisfies it, and refused otherwise — never on the strength of the
// proof's mere presence.
//
// proofs MUST come from the transport, never from a request header a caller
// could set (CONTRACT.md §10.1 rule 9, normative detail 2): a
// PresentedProofs.CertificateThumbprint built from anything but the TLS
// layer's own verified peer certificate makes the whole mechanism
// decorative.
func (v *Verifier) VerifyAccessTokenWithProofs(ctx context.Context, token []byte, opts ValidationOptions, proofs PresentedProofs) (Claims, error) {
	return v.verifyAccessToken(ctx, token, opts, proofs)
}

func (v *Verifier) verifyAccessToken(ctx context.Context, token []byte, opts ValidationOptions, proofs PresentedProofs) (Claims, error) {
	claims, err := v.VerifySignatureOnlyUnchecked(ctx, token)
	if err != nil {
		return Claims{}, err
	}
	// §10.1 rules 10-12 (contract 1.68; N14, D-7): the token must BE an access
	// token. Each rule alone refuses every purpose token AXIAM mints, so none
	// is skipped because another is present.
	if err := requireAccessTokenHeader(token); err != nil {
		return Claims{}, err
	}
	if claims.HasPurpose {
		return Claims{}, ErrPurposeToken
	}
	if err := ValidateClaims(claims, opts); err != nil {
		return Claims{}, err
	}
	// Rule 9 — a token carrying cnf is not a bearer token, and MUST NOT be
	// accepted as one without evidence that satisfies it. Nil-safe: an
	// unbound token (claims.Confirmation == nil) always passes this,
	// proofs or not.
	if err := claims.Confirmation.Verify(proofs); err != nil {
		return Claims{}, err
	}
	// §10.4 (contract 1.44) — last, and only ever a rejection. The rules above
	// have already decided the token is valid; a feed that cannot be read, or
	// a token with no session behind it, changes nothing here.
	if v.feed != nil && claims.SessionID != "" && v.feed.IsRevoked(ctx, claims.SessionID) {
		return Claims{}, ErrSessionRevoked
	}
	return claims, nil
}

// ErrNotAccessToken reports a token whose protected-header `typ` is present
// and is not `at+jwt` (§10.1 rule 10): an MFA challenge, a WebAuthn state
// token, a back-channel logout token, or a pre-1.67 access token (`typ: JWT`).
var ErrNotAccessToken = errors.New("jwks: token typ is not at+jwt; not an access token")

// ErrPurposeToken reports a token carrying a `purpose` claim (§10.1 rule 11):
// the MFA challenge, MFA setup and WebAuthn state tokens AXIAM signs with the
// access-token key.
var ErrPurposeToken = errors.New("jwks: token carries a purpose claim; not an access token")

// requireAccessTokenHeader applies §10.1 rule 10 to token's protected header:
// `typ`, when present, must be `at+jwt` (case-insensitive, an `application/`
// prefix allowed). Rule 12 (no `kid`, no single-key fallback) is enforced by
// the JWKS library's key-set verification, which refuses a header with no
// `kid`; internal/jwks/n14_access_token_test.go pins that. A token with no `typ` is not refused by rule 10 (rule 11 and the other rules
// still apply).
func requireAccessTokenHeader(token []byte) error {
	msg, err := jws.Parse(token)
	if err != nil {
		return fmt.Errorf("jwks: invalid token: %w", err)
	}
	sigs := msg.Signatures()
	if len(sigs) == 0 {
		return ErrNoSignatures
	}
	for _, sig := range sigs {
		h := sig.ProtectedHeaders()
		if typ, ok := h.Type(); ok {
			t := strings.ToLower(typ)
			t = strings.TrimPrefix(t, "application/")
			if t != "at+jwt" {
				return ErrNotAccessToken
			}
		}
	}
	return nil
}

// VerifySignatureOnlyUnchecked parses and verifies token's SIGNATURE ONLY
// against the cached JWKS, returning the token's Claims without applying any
// claim policy whatsoever.
//
// The protected header's alg is checked against an explicit EdDSA allowlist
// BEFORE any keyset lookup — the token's own alg header never selects the
// verification algorithm (algorithm-confusion defense). An unknown or
// missing kid triggers one forced JWKS refetch and a single retry, at most
// once per 60 s cooldown window across all tokens (CONTRACT.md §12.4 rule 2);
// inside the window, or if the kid is still unknown after the refetch,
// verification fails.
//
// The deliberately alarming name is CONTRACT.md §10.1's requirement: this is
// the raw primitive kept for integrators implementing their own policy, and
// it is NOT a guard. It does not check exp, nbf, tenant_id, iss or aud, so a
// signature-valid token that is expired, not yet valid, or minted for a
// DIFFERENT TENANT under the same organization-wide JWKS verifies
// successfully here. Use VerifyAccessToken (or middleware.Middleware, which
// wraps it) unless you are implementing §10.1 rules 2–12 yourself.
func (v *Verifier) VerifySignatureOnlyUnchecked(ctx context.Context, token []byte) (Claims, error) {
	msg, err := jws.Parse(token)
	if err != nil {
		return Claims{}, fmt.Errorf("jwks: invalid token: %w", err)
	}

	// Fail closed if the message carries no signatures: an empty loop would
	// otherwise skip the EdDSA allowlist entirely and fall through to keyset
	// verification, silently violating the "only EdDSA, checked BEFORE any
	// keyset lookup" invariant above (WR-02).
	sigs := msg.Signatures()
	if len(sigs) == 0 {
		return Claims{}, fmt.Errorf("jwks: token has no signatures")
	}
	for _, sig := range sigs {
		alg, ok := sig.ProtectedHeaders().Algorithm()
		if !ok || alg != jwa.EdDSA() {
			return Claims{}, fmt.Errorf("jwks: unexpected alg %q: only EdDSA is accepted", alg.String())
		}
	}

	// Unknown kid (or a key rotated since the set was fetched), or no usable
	// set → one forced refetch per window, then one retry. Inside the window
	// the retry uses the set as it is now, with no network call (§12.4 rule
	// 2): another verification may have refreshed it meanwhile.
	var payload []byte
	keySet, verifyErr := v.currentSet(ctx)
	if verifyErr == nil {
		payload, verifyErr = jws.Verify(token, jws.WithKeySet(keySet, jws.WithInferAlgorithmFromKey(false)))
	}
	if verifyErr != nil {
		refreshed, fetched, setErr := v.refreshForUnknownKid(ctx)
		if setErr != nil {
			return Claims{}, fmt.Errorf("jwks: JWKS fetch failed: %w", setErr)
		}
		p, retryErr := jws.Verify(token, jws.WithKeySet(refreshed, jws.WithInferAlgorithmFromKey(false)))
		if retryErr != nil {
			if !fetched {
				return Claims{}, fmt.Errorf("jwks: token signature invalid; kid missing or unknown and the JWKS re-fetch is cooling down: %w", retryErr)
			}
			return Claims{}, fmt.Errorf("jwks: token signature invalid after forced refetch: %w", retryErr)
		}
		payload = p
	}

	return parseClaims(payload)
}

// Sentinel errors classifying a VerifyPayload failure. A caller wraps these
// with fmt.Errorf("...: %w", ...) is never done on OUR side beyond the
// wrapping below — callers instead use errors.Is against these values to
// classify the failure, e.g. the OIDC relying-party ID-token validator
// (CONTRACT.md §12.4) maps each one onto its own stable reason-code
// vocabulary without parsing error strings.
var (
	// ErrNoSignatures reports a JWS message carrying zero signatures.
	ErrNoSignatures = errors.New("jwks: token has no signatures")
	// ErrUnexpectedAlg reports a protected-header `alg` other than EdDSA
	// (including "none" and a missing alg header) — checked BEFORE any
	// keyset lookup, so the token can never select its own verification
	// algorithm.
	ErrUnexpectedAlg = errors.New("jwks: unexpected alg: only EdDSA is accepted")
	// ErrUnknownKid reports a missing `kid` header, or a `kid` still not
	// present in the key set after exactly one forced refetch.
	ErrUnknownKid = errors.New("jwks: kid missing or unknown, even after one forced refetch")
	// ErrSignatureInvalid reports a `kid` that WAS found in the key set, but
	// whose signature failed to verify against that specific key.
	ErrSignatureInvalid = errors.New("jwks: signature verification failed")
)

// VerifyPayload performs the SAME alg-allowlist + kid-lookup + one-shot
// unknown-kid-refetch signature verification as Verify — sharing this
// Verifier's cache, jwksURL and mutex, never a forked copy of the fetch
// mechanism — but returns the raw, UNINTERPRETED JWS payload bytes plus one
// of the sentinel errors above, instead of this package's own AXIAM-specific
// Claims shape.
//
// It exists for the OIDC relying-party ID-token validator (CONTRACT.md
// §12.4), which needs a token's iss/aud/nonce/etc. claims — a shape this
// package does not itself model — while still sharing all of this package's
// signature-verification machinery. Unlike Verify, VerifyPayload also
// distinguishes an unknown/missing kid (ErrUnknownKid) from a known kid with
// a bad signature (ErrSignatureInvalid), which §12.4 rule 2 requires and
// Verify's AXIAM-resource-server callers have never needed.
func (v *Verifier) VerifyPayload(ctx context.Context, token []byte) ([]byte, error) {
	msg, err := jws.Parse(token)
	if err != nil {
		return nil, fmt.Errorf("jwks: invalid token: %w", err)
	}

	sigs := msg.Signatures()
	if len(sigs) == 0 {
		return nil, ErrNoSignatures
	}

	var kid string
	for _, sig := range sigs {
		alg, ok := sig.ProtectedHeaders().Algorithm()
		if !ok || alg != jwa.EdDSA() {
			return nil, fmt.Errorf("%w: got %s", ErrUnexpectedAlg, algOrNone(alg, ok))
		}
		if k, ok := sig.ProtectedHeaders().KeyID(); ok && k != "" {
			kid = k
		}
	}
	// A missing kid header is treated identically to an unknown kid, not a
	// separate failure mode (CONTRACT.md §12 port addendum item 12).
	if kid == "" {
		return nil, ErrUnknownKid
	}

	key, err := v.lookupKeyID(ctx, kid)
	if err != nil {
		return nil, err
	}

	payload, verifyErr := jws.Verify(token, jws.WithKey(jwa.EdDSA(), key))
	if verifyErr != nil {
		return nil, fmt.Errorf("%w: %v", ErrSignatureInvalid, verifyErr)
	}
	return payload, nil
}

// lookupKeyID resolves kid against the usable key set, forcing one refetch
// when it is not (yet) known — at most once per window, shared with
// VerifySignatureOnlyUnchecked (§12.4 rule 2) — and serialized by the SAME
// mutex, so a concurrent burst of unknown-kid lookups still collapses to a
// single fetch (D-08/D-09). A refetch that fails refuses the token and leaves
// the held set, and its anchor, as they were.
func (v *Verifier) lookupKeyID(ctx context.Context, kid string) (jwk.Key, error) {
	if set, err := v.currentSet(ctx); err == nil {
		if key, ok := set.LookupKeyID(kid); ok {
			return key, nil
		}
	}
	set, fetched, err := v.refreshForUnknownKid(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnknownKid, err)
	}
	if key, ok := set.LookupKeyID(kid); ok {
		return key, nil
	}
	if !fetched {
		return nil, fmt.Errorf("%w: the JWKS re-fetch is cooling down", ErrUnknownKid)
	}
	return nil, ErrUnknownKid
}

// algOrNone renders a protected header's algorithm for an error message,
// covering the case where the header is absent entirely (ok == false).
func algOrNone(alg jwa.SignatureAlgorithm, ok bool) string {
	if !ok {
		return "(absent)"
	}
	return fmt.Sprintf("%q", alg.String())
}
