package axiam

// PKCE + CSPRNG primitives for the OIDC relying-party flow (CONTRACT.md
// §12.1 "oidc_begin inputs and construction", RFC 7636).
//
// crypto/rand + crypto/sha256 + encoding/base64 cover everything needed, so
// §12 adds NO new runtime dependency. This file is deliberately tiny, pure
// and synchronous: OidcBegin performs no network I/O, and every value here
// is derived locally.
//
// S256 ONLY. "plain" is not implemented, not reachable, and not
// configurable: there is no code path in this SDK that can emit
// code_challenge_method=plain.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// codeChallengeMethodS256 is the only PKCE code-challenge method this SDK
// emits (RFC 7636 §4.2, CONTRACT.md §12.1 rule 3).
const codeChallengeMethodS256 = "S256"

// pkceCSPRNGBytes is the entropy, in bytes, of a generated state / nonce /
// code_verifier. §12.1 rule 1 requires at least 16 bytes (128 bits) and
// RECOMMENDS 32; rule 2 RECOMMENDS 32 bytes for the verifier, which
// base64url-encodes to exactly 43 characters — the RFC 7636 §4.1 minimum
// length, drawn only from the unreserved set `[A-Za-z0-9-._~]`.
const pkceCSPRNGBytes = 32

// randomURLSafeToken returns n CSPRNG bytes, base64url-encoded WITHOUT
// padding (RFC 4648 §5 — base64.RawURLEncoding never emits `=`).
//
// Used for both `state` and `nonce`, which §12.3 rule 2 classes as
// NON-SECRET: they are returned as plain strings, are echoed through the
// browser's address bar by construction, and are safe to log.
func randomURLSafeToken(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand.Read failing indicates a fundamentally broken host
		// environment (no readable CSPRNG source); panicking surfaces that
		// loudly rather than silently emitting a low- or zero-entropy token.
		panic("axiam: crypto/rand unavailable: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

// generateCodeVerifier returns a fresh PKCE code_verifier (RFC 7636 §4.1):
// 32 CSPRNG bytes, base64url-encoded without padding (43 characters, drawn
// only from the unreserved set).
//
// Returned already wrapped in Sensitive — §12.5 makes the verifier secret
// for its WHOLE lifetime, including while it sits in the
// AuthorizationRequest handed back to the caller and in any OidcStateStore
// entry.
func generateCodeVerifier() Sensitive {
	return Sensitive(randomURLSafeToken(pkceCSPRNGBytes))
}

// computeCodeChallenge derives the PKCE code_challenge from a verifier:
// BASE64URL-ENCODE(SHA256(ASCII(code_verifier))), unpadded (RFC 7636 §4.2,
// CONTRACT.md §12.1 rule 3).
//
// Verified against the RFC 7636 Appendix B test vector in oidc_pkce_test.go,
// which every SDK must carry (§12.1 rule 3). The challenge is a one-way
// digest and is NOT secret — it travels in the authorization URL — so it is
// returned as a plain string.
func computeCodeChallenge(codeVerifier string) string {
	sum := sha256.Sum256([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
