package jwks

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

// jwksPath is the AXIAM JWKS endpoint path — organization-wide, not
// tenant-scoped, serving exactly one Ed25519 key today (RESEARCH.md D-11,
// mirrors the Rust SDK's src/token/jwks.rs::JWKS_PATH). This is NOT a generic
// OIDC discovery-style `/.well-known/jwks.json` path; do not substitute one.
const jwksPath = "/oauth2/jwks"

const (
	// minRefetchInterval is the forced-refetch cooldown floor (CF-03;
	// matches the Rust reference's FORCED_REFETCH_MIN_INTERVAL).
	minRefetchInterval = 60 * time.Second
	// maxCacheInterval is the normal (non-forced) refresh TTL ceiling
	// (CF-03; matches the Rust reference's JWKS_CACHE_TTL).
	maxCacheInterval = 300 * time.Second
)

// Verifier fetches, caches, and locally verifies AXIAM access tokens against
// the organization-wide EdDSA JWKS (D-06). It is the shared local-verify
// primitive consumed by the net/http middleware (Plan 05).
type Verifier struct {
	cache   *jwk.Cache
	jwksURL string

	// refreshMu serializes the forced-refetch path so a concurrent burst of
	// unknown-kid verifications collapses to exactly one network fetch
	// (D-08/D-09). We do NOT rely on jwx/httprc's internal coalescing
	// (Assumption A2) — the mutex wraps only the fetch/refresh decision,
	// never the jws.Verify call itself.
	refreshMu sync.Mutex
}

// NewVerifier constructs a Verifier bound to {baseURL}/oauth2/jwks (trailing
// slash on baseURL trimmed before joining). The cache is registered but not
// eagerly populated; the first Verify call triggers the initial fetch.
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
func NewVerifierForURL(ctx context.Context, jwksURL string, hc *http.Client) (*Verifier, error) {
	var client *httprc.Client
	if hc != nil {
		client = httprc.NewClient(httprc.WithHTTPClient(hc))
	} else {
		client = httprc.NewClient()
	}

	cache, err := jwk.NewCache(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("jwks: failed to construct cache: %w", err)
	}

	if err := cache.Register(ctx, jwksURL,
		jwk.WithMinInterval(minRefetchInterval),
		jwk.WithMaxInterval(maxCacheInterval),
	); err != nil {
		return nil, fmt.Errorf("jwks: failed to register %s: %w", jwksURL, err)
	}

	return &Verifier{cache: cache, jwksURL: jwksURL}, nil
}

// VerifyAccessToken is the full CONTRACT.md §10.1 local-verification entry
// point, and the one every guard in this SDK routes through: it verifies the
// signature (rule 1, alg pinned to EdDSA BEFORE any key lookup) and then
// applies rules 2–7 via ValidateClaims — required exp, honoured nbf, asserted
// tenant_id, conditional iss/aud, all under the single named ClockSkewLeeway.
//
// It fails closed on every rule: a required claim that is absent, unparseable
// or of the wrong JSON type is a rejection, never a skipped check.
func (v *Verifier) VerifyAccessToken(ctx context.Context, token []byte, opts ValidationOptions) (Claims, error) {
	claims, err := v.VerifySignatureOnlyUnchecked(ctx, token)
	if err != nil {
		return Claims{}, err
	}
	if err := ValidateClaims(claims, opts); err != nil {
		return Claims{}, err
	}
	return claims, nil
}

// VerifySignatureOnlyUnchecked parses and verifies token's SIGNATURE ONLY
// against the cached JWKS, returning the token's Claims without applying any
// claim policy whatsoever.
//
// The protected header's alg is checked against an explicit EdDSA allowlist
// BEFORE any keyset lookup — the token's own alg header never selects the
// verification algorithm (algorithm-confusion defense). An unknown kid
// triggers exactly one forced JWKS refetch, then a single retry; if the kid
// is still unknown after that, verification fails.
//
// The deliberately alarming name is CONTRACT.md §10.1's requirement: this is
// the raw primitive kept for integrators implementing their own policy, and
// it is NOT a guard. It does not check exp, nbf, tenant_id, iss or aud, so a
// signature-valid token that is expired, not yet valid, or minted for a
// DIFFERENT TENANT under the same organization-wide JWKS verifies
// successfully here. Use VerifyAccessToken (or middleware.Middleware, which
// wraps it) unless you are implementing §10.1 rules 2–7 yourself.
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

	keySet, err := v.cache.CachedSet(v.jwksURL)
	if err != nil {
		return Claims{}, fmt.Errorf("jwks: JWKS fetch failed: %w", err)
	}

	payload, verifyErr := jws.Verify(token, jws.WithKeySet(keySet, jws.WithInferAlgorithmFromKey(false)))
	if verifyErr != nil {
		// Unknown kid (or stale cache after key rotation) → force exactly
		// one refetch, then retry verification exactly once. The mutex
		// serializes this section so a concurrent burst of unknown-kid
		// verifications triggers a single v.cache.Refresh call (D-08/D-09):
		// each waiter re-checks CachedSet under the lock first, since
		// another goroutine may have already performed the refetch while
		// this one was waiting.
		v.refreshMu.Lock()
		if cachedSet, cachedErr := v.cache.CachedSet(v.jwksURL); cachedErr == nil {
			if p, retryErr := jws.Verify(token, jws.WithKeySet(cachedSet, jws.WithInferAlgorithmFromKey(false))); retryErr == nil {
				v.refreshMu.Unlock()
				return parseClaims(p)
			}
		}
		refreshed, refreshErr := v.cache.Refresh(ctx, v.jwksURL)
		v.refreshMu.Unlock()
		if refreshErr != nil {
			return Claims{}, fmt.Errorf("jwks: token verification failed and JWKS refetch also failed: %w", verifyErr)
		}
		payload, verifyErr = jws.Verify(token, jws.WithKeySet(refreshed, jws.WithInferAlgorithmFromKey(false)))
		if verifyErr != nil {
			return Claims{}, fmt.Errorf("jwks: token signature invalid after forced refetch: %w", verifyErr)
		}
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
// Verifier's cache, jwksURL and refreshMu, never a forked copy of the fetch
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

// lookupKeyID resolves kid against the cached key set, forcing exactly one
// refetch when it is not (yet) known — mirroring Verify's one-shot refetch
// discipline and serialized by the SAME refreshMu, so a concurrent burst of
// unknown-kid lookups still collapses to a single fetch (D-08/D-09).
func (v *Verifier) lookupKeyID(ctx context.Context, kid string) (jwk.Key, error) {
	if set, err := v.cache.CachedSet(v.jwksURL); err == nil {
		if key, ok := set.LookupKeyID(kid); ok {
			return key, nil
		}
	}

	v.refreshMu.Lock()
	defer v.refreshMu.Unlock()

	// Double-check: another goroutine may have already performed the
	// refetch while this one waited for the lock.
	if set, err := v.cache.CachedSet(v.jwksURL); err == nil {
		if key, ok := set.LookupKeyID(kid); ok {
			return key, nil
		}
	}

	refreshed, err := v.cache.Refresh(ctx, v.jwksURL)
	if err != nil {
		return nil, fmt.Errorf("%w: refetch failed: %v", ErrUnknownKid, err)
	}
	if key, ok := refreshed.LookupKeyID(kid); ok {
		return key, nil
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
