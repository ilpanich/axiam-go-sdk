// Package dpop implements DPoP proof verification — CONTRACT.md §21.7.2
// (RFC 9449), contract 1.16.
//
// The resource-server half of DPoP: given the "DPoP" header a caller
// presented, decide whether it proves possession for THIS request and THIS
// access token, and return the key thumbprint that jwks.VerifyTokenBinding
// then matches against the token's cnf.jkt.
//
// # Why this lives in the SDK
//
// §21.7.2 is a ten-check list, and the contract is blunt about partial
// implementations: "Partial verification is worse than none, because it
// produces a guard that reports success." Nine of the ten look optional until
// someone builds an attack out of the one that was skipped, so they belong in
// one audited place rather than in every application guarding an endpoint.
//
// The two most often missing, and what they cost:
//
//   - typ — without pinning it to "dpop+jwt", any OTHER JWT signed by the same
//     key (an access token, an ID token) is replayable as a proof.
//   - ath — without it, a proof captured on one request can be re-aimed at a
//     different token held by the same key. ath binds the proof to the token
//     rather than merely to the key.
//
// # The algorithm comes from the key, never from the header
//
// "alg: none" and RSA-public-key-as-HMAC-secret are the same bug wearing
// different clothes: the token told the verifier how to check the token. This
// package derives the expected algorithm from the embedded key's kty/crv and
// verifies under that one algorithm.
package dpop

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

// IatLeeway is §21.7.2 check 7's "iat" acceptance window, applied in BOTH
// directions. RFC 9449 recommends a small window without fixing a number; 60
// seconds is the contract's RECOMMENDED value. A named constant, because a
// bare 60 three call frames deep is a number nobody ever revisits.
const IatLeeway = 60 * time.Second

// privateJWKMembers are RFC 9449 §4.3's private key material, which must never
// appear in a proof's embedded public jwk. "k" is the symmetric-key member:
// its presence means the "public key" is a shared secret.
var privateJWKMembers = []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"}

// Errors returned by VerifyProof. Sentinels so a guard can distinguish "no
// proof was presented" (which may warrant a 401 with a DPoP challenge) from
// "the proof was wrong" (which does not).
var (
	ErrMalformedProof    = errors.New("dpop: proof is malformed")
	ErrWrongTyp          = errors.New("dpop: proof typ header must be 'dpop+jwt'")
	ErrUnsupportedKey    = errors.New("dpop: proof key type is not permitted by CONTRACT.md §21.7.2")
	ErrPrivateKeyInJWK   = errors.New("dpop: proof jwk carries private key material (RFC 9449 §4.3)")
	ErrBadSignature      = errors.New("dpop: proof signature is invalid")
	ErrHTMMismatch       = errors.New("dpop: proof htm does not match the request method")
	ErrHTUMismatch       = errors.New("dpop: proof htu does not match the request URI")
	ErrStaleProof        = errors.New("dpop: proof iat is outside the freshness window")
	ErrReplayedProof     = errors.New("dpop: proof jti has already been used (replay)")
	ErrATHMismatch       = errors.New("dpop: proof ath does not match the presented access token")
	ErrThumbprintNoMatch = errors.New("dpop: proof key does not match the token's cnf.jkt")
)

// JtiStore is §21.7.2 check 8 — single-use "jti" tracking.
//
// One method, and its contract is the point: Claim must be atomic. A
// contains-then-add pair read as two calls is a race that two concurrent
// replays of the same proof can both win.
type JtiStore interface {
	// Claim records jti as used until expiresAt. It reports true if this is
	// the first sighting, false if it is a replay.
	Claim(jti string, expiresAt time.Time) bool
}

// InMemoryJtiStore is a JtiStore for a single process.
//
// PER-PROCESS, THEREFORE PER-INSTANCE. Four replicas behind a load balancer
// give an attacker four chances to replay a proof inside its freshness window,
// and a restart clears the window entirely. Any deployment running more than
// one process needs a shared store (Redis, a database table).
type InMemoryJtiStore struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

// NewInMemoryJtiStore returns an empty store.
func NewInMemoryJtiStore() *InMemoryJtiStore {
	return &InMemoryJtiStore{seen: make(map[string]time.Time)}
}

// Claim implements JtiStore.
func (s *InMemoryJtiStore) Claim(jti string, expiresAt time.Time) bool {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	// Prune under the same lock as the insert. Entries only ever live for the
	// freshness window, so this stays small with no background goroutine.
	if len(s.seen) > 128 {
		for k, v := range s.seen {
			if !v.After(now) {
				delete(s.seen, k)
			}
		}
	}
	if existing, ok := s.seen[jti]; ok && existing.After(now) {
		return false
	}
	s.seen[jti] = expiresAt
	return true
}

// ThumbprintS256 computes the RFC 7638 SHA-256 thumbprint of a JWK — the "jkt".
//
// Only the members RFC 7638 names for the key type take part, serialised as
// compact JSON with lexicographically ordered keys. Members outside that set
// (kid, use, alg, x5c) are excluded by the spec, which is what makes the
// thumbprint stable across two encodings of the same key.
func ThumbprintS256(raw map[string]any) (string, error) {
	get := func(member string) (string, error) {
		v, ok := raw[member].(string)
		if !ok || v == "" {
			return "", fmt.Errorf("%w: jwk is missing the required member %q", ErrUnsupportedKey, member)
		}
		return v, nil
	}

	var canonical string
	// Built by hand rather than through a map, so the member set and their
	// order are visible where they are required rather than depending on a
	// serialiser's ordering behaviour.
	switch raw["kty"] {
	case "RSA":
		e, err := get("e")
		if err != nil {
			return "", err
		}
		n, err := get("n")
		if err != nil {
			return "", err
		}
		canonical = fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, e, n)
	case "EC":
		crv, err := get("crv")
		if err != nil {
			return "", err
		}
		x, err := get("x")
		if err != nil {
			return "", err
		}
		y, err := get("y")
		if err != nil {
			return "", err
		}
		canonical = fmt.Sprintf(`{"crv":%q,"kty":"EC","x":%q,"y":%q}`, crv, x, y)
	case "OKP":
		crv, err := get("crv")
		if err != nil {
			return "", err
		}
		x, err := get("x")
		if err != nil {
			return "", err
		}
		canonical = fmt.Sprintf(`{"crv":%q,"kty":"OKP","x":%q}`, crv, x)
	default:
		return "", fmt.Errorf("%w: unsupported kty %v", ErrUnsupportedKey, raw["kty"])
	}

	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// AccessTokenHash is the "ath" claim value for accessToken — RFC 9449 §4.2.
//
// base64url-unpadded SHA-256 over the token's bytes exactly as they travelled
// in the Authorization header, not over anything decoded out of them.
func AccessTokenHash(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// CanonicalHTU is the "htu" comparison form — §21.7.2 check 6.
//
// Query and fragment removed, and NOTHING ELSE. No case folding, no
// default-port elision, no percent-decoding, no trailing-slash fixing: a
// normalising comparison is precisely where two unequal URIs become equal, and
// an attacker who finds such a pair can aim a proof at an endpoint it was never
// minted for.
func CanonicalHTU(uri string) string {
	if i := strings.IndexByte(uri, '#'); i >= 0 {
		uri = uri[:i]
	}
	if i := strings.IndexByte(uri, '?'); i >= 0 {
		uri = uri[:i]
	}
	return uri
}

// expectedAlg is §21.7.2 check 2 — derive the algorithm from the key itself.
//
// This function is why the proof header's alg never selects anything: the
// key's own type determines how a signature over it can be checked, and that
// is not a matter the presenter gets an opinion on.
func expectedAlg(raw map[string]any) (jwa.SignatureAlgorithm, error) {
	kty, _ := raw["kty"].(string)
	crv, _ := raw["crv"].(string)
	switch {
	case kty == "RSA":
		return jwa.PS256(), nil
	case kty == "EC" && crv == "P-256":
		return jwa.ES256(), nil
	case kty == "OKP" && crv == "Ed25519":
		return jwa.EdDSA(), nil
	default:
		return jwa.SignatureAlgorithm{}, fmt.Errorf("%w (kty=%q, crv=%q; permitted: ES256, EdDSA, PS256)",
			ErrUnsupportedKey, kty, crv)
	}
}

// Request carries everything VerifyProof needs. Each field feeds a check that
// cannot be made without it — there is no "just check the signature" mode,
// because that is exactly the partial verification the contract calls worse
// than none.
type Request struct {
	// Method is the request method, e.g. "POST".
	Method string
	// URI is the full request URI. Query and fragment are stripped here, so
	// passing it with a query string is fine and expected.
	URI string
	// AccessToken is the token from the Authorization header, exactly as it
	// arrived — this is hashed for the ath check.
	AccessToken string
	// ExpectedJkt is the token's cnf.jkt, when the caller has it. Supplying it
	// performs check 10 here; leaving it empty means the caller must do that
	// comparison itself, which jwks.VerifyTokenBinding does.
	ExpectedJkt string
	// Leeway overrides the iat window, both directions. Zero means IatLeeway.
	Leeway time.Duration
	// Now overrides the current time, for tests. Zero means time.Now().
	Now time.Time
}

// proofClaims are the claims §21.7.2 reads out of a proof.
type proofClaims struct {
	HTM string `json:"htm"`
	HTU string `json:"htu"`
	IAT *int64 `json:"iat"`
	JTI string `json:"jti"`
	ATH string `json:"ath"`
}

// VerifyProof verifies a DPoP proof against this request — all ten §21.7.2
// checks.
//
// It returns the proof key's RFC 7638 thumbprint (jkt) on success. Feed it to
// jwks.VerifyTokenBinding as PresentedProofs.DPoPThumbprint; returning it
// rather than a bare nil error is deliberate, so the value a guard passes
// onward could only have come from a proof that actually verified.
func VerifyProof(proof string, req Request, store JtiStore) (string, error) {
	if proof == "" {
		return "", fmt.Errorf("%w: empty", ErrMalformedProof)
	}
	// RFC 9449 §4.2 makes exactly one proof the rule. Rejecting beats picking
	// the first, which is how a verifier and a downstream parser end up
	// reading different proofs.
	if strings.ContainsAny(strings.TrimSpace(proof), ", \t\r\n") {
		return "", fmt.Errorf("%w: header must carry exactly one proof", ErrMalformedProof)
	}

	// The header as RAW JSON. §21.7.2 check 4 insists the private-material
	// check run against this rather than a parsed key type, because many JWK
	// libraries quietly drop d/p/q when parsing into a public key — the check
	// would then pass by virtue of the library having hidden the evidence.
	segments := strings.Split(proof, ".")
	if len(segments) != 3 {
		return "", fmt.Errorf("%w: not a compact JWS with three segments", ErrMalformedProof)
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(segments[0])
	if err != nil {
		return "", fmt.Errorf("%w: header is not valid base64url", ErrMalformedProof)
	}
	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return "", fmt.Errorf("%w: header is not valid JSON", ErrMalformedProof)
	}

	// Check 1 — typ. First, because it is what stops any other JWT signed by
	// the same key from standing in as a proof.
	typ, _ := header["typ"].(string)
	if !strings.EqualFold(typ, "dpop+jwt") {
		return "", fmt.Errorf("%w, got %q", ErrWrongTyp, typ)
	}

	// Check 3 (first half) — the header carries a public jwk.
	rawJWK, ok := header["jwk"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("%w: header must carry a public 'jwk'", ErrMalformedProof)
	}

	// Check 4 — no private material, tested against the raw header JSON.
	var leaked []string
	for _, m := range privateJWKMembers {
		if _, present := rawJWK[m]; present {
			leaked = append(leaked, m)
		}
	}
	if len(leaked) > 0 {
		return "", fmt.Errorf("%w: %s", ErrPrivateKeyInJWK, strings.Join(leaked, ", "))
	}

	// Check 2 — algorithm from the key, never from the header.
	alg, err := expectedAlg(rawJWK)
	if err != nil {
		return "", err
	}

	// Check 3 (second half) — the signature verifies under that key.
	keyBytes, err := json.Marshal(rawJWK)
	if err != nil {
		return "", fmt.Errorf("%w: jwk is not serialisable", ErrMalformedProof)
	}
	key, err := jwk.ParseKey(keyBytes)
	if err != nil {
		return "", fmt.Errorf("%w: jwk is not a usable public key: %v", ErrMalformedProof, err)
	}
	payload, err := jws.Verify([]byte(proof), jws.WithKey(alg, key))
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrBadSignature, err)
	}

	var claims proofClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("%w: payload is not valid JSON", ErrMalformedProof)
	}

	// Check 5 — htm.
	if claims.HTM != req.Method {
		return "", fmt.Errorf("%w (proof %q, request %q)", ErrHTMMismatch, claims.HTM, req.Method)
	}

	// Check 6 — htu, with query and fragment stripped from BOTH sides and
	// nothing else touched.
	expectedHTU := CanonicalHTU(req.URI)
	if CanonicalHTU(claims.HTU) != expectedHTU {
		return "", fmt.Errorf("%w (proof %q, request %q)", ErrHTUMismatch, claims.HTU, expectedHTU)
	}

	// Check 7 — iat freshness, in both directions. A proof from the future is
	// as suspect as a stale one: it is how a one-sided skew allowance becomes
	// a long-lived proof.
	if claims.IAT == nil {
		return "", fmt.Errorf("%w: iat is missing or not a number", ErrMalformedProof)
	}
	leeway := req.Leeway
	if leeway == 0 {
		leeway = IatLeeway
	}
	now := req.Now
	if now.IsZero() {
		now = time.Now()
	}
	iat := time.Unix(*claims.IAT, 0)
	if delta := now.Sub(iat); delta > leeway || delta < -leeway {
		return "", fmt.Errorf("%w (%s)", ErrStaleProof, leeway)
	}

	// Check 9 — ath ties the proof to this specific access token.
	if claims.ATH == "" {
		return "", fmt.Errorf("%w: ath is missing", ErrMalformedProof)
	}
	if subtle.ConstantTimeCompare([]byte(claims.ATH), []byte(AccessTokenHash(req.AccessToken))) != 1 {
		return "", ErrATHMismatch
	}

	// Check 10 — the thumbprint that ties the proof to the token's cnf.
	jkt, err := ThumbprintS256(rawJWK)
	if err != nil {
		return "", err
	}
	if req.ExpectedJkt != "" &&
		subtle.ConstantTimeCompare([]byte(jkt), []byte(req.ExpectedJkt)) != 1 {
		return "", ErrThumbprintNoMatch
	}

	// Check 8 — jti single-use. LAST on purpose: claiming a jti is a mutation,
	// and doing it before the cheap checks would let an attacker burn arbitrary
	// jti values out of the store with proofs that were never going to verify.
	if claims.JTI == "" {
		return "", fmt.Errorf("%w: jti is missing", ErrMalformedProof)
	}
	if !store.Claim(claims.JTI, iat.Add(leeway)) {
		return "", ErrReplayedProof
	}

	return jkt, nil
}
