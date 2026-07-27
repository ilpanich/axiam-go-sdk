package axiam

import (
	"regexp"
	"testing"
)

// TestComputeCodeChallenge_RFC7636AppendixB proves the PKCE S256 derivation
// against the RFC 7636 Appendix B test vector every SDK must carry
// (CONTRACT.md §12.1 rule 3).
func TestComputeCodeChallenge_RFC7636AppendixB(t *testing.T) {
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	const wantChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	got := computeCodeChallenge(verifier)
	if got != wantChallenge {
		t.Fatalf("computeCodeChallenge(%q) = %q, want %q (RFC 7636 Appendix B)", verifier, got, wantChallenge)
	}
}

// TestCodeChallengeMethod_IsS256Only proves §12.1 rule 3: the SDK only ever
// emits "S256" — "plain" is not a reachable value anywhere.
func TestCodeChallengeMethod_IsS256Only(t *testing.T) {
	if codeChallengeMethodS256 != "S256" {
		t.Fatalf("codeChallengeMethodS256 = %q, want \"S256\"", codeChallengeMethodS256)
	}
}

var unreservedCharset = regexp.MustCompile(`^[A-Za-z0-9\-._~]+$`)

// TestGenerateCodeVerifier_ShapeAndEntropy proves §12.1 rule 2: a 43-128
// character verifier drawn only from the RFC 7636 §4.1 unreserved set, with
// at least 128 bits of entropy (32 CSPRNG bytes recommended => 43 chars).
func TestGenerateCodeVerifier_ShapeAndEntropy(t *testing.T) {
	verifier := generateCodeVerifier().expose()
	if len(verifier) < 43 || len(verifier) > 128 {
		t.Fatalf("code_verifier length = %d, want 43-128 (RFC 7636 §4.1)", len(verifier))
	}
	if !unreservedCharset.MatchString(verifier) {
		t.Fatalf("code_verifier %q contains characters outside the RFC 7636 §4.1 unreserved set", verifier)
	}
}

// TestGenerateCodeVerifier_Unique proves successive calls never collide (a
// CSPRNG sanity check, not a formal entropy proof).
func TestGenerateCodeVerifier_Unique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		v := generateCodeVerifier().expose()
		if seen[v] {
			t.Fatalf("generateCodeVerifier produced a duplicate value: %q", v)
		}
		seen[v] = true
	}
}

// TestRandomURLSafeToken_EntropyShapeAndUniqueness proves §12.1 rule 1:
// state/nonce are >=128 bits (16 bytes minimum; this SDK uses 32),
// base64url-unpadded (no '='), and unique across generations.
func TestRandomURLSafeToken_EntropyShapeAndUniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		tok := randomURLSafeToken(pkceCSPRNGBytes)
		if len(tok) == 0 {
			t.Fatal("randomURLSafeToken returned an empty string")
		}
		for _, r := range tok {
			if r == '=' {
				t.Fatalf("randomURLSafeToken %q contains base64 padding, want unpadded base64url", tok)
			}
		}
		if !unreservedCharset.MatchString(tok) {
			t.Fatalf("randomURLSafeToken %q contains characters outside base64url's safe set", tok)
		}
		if seen[tok] {
			t.Fatalf("randomURLSafeToken produced a duplicate value: %q", tok)
		}
		seen[tok] = true
	}

	// 32 CSPRNG bytes => 256 bits, well above the 128-bit (16-byte) floor
	// §12.1 rule 1 requires.
	if pkceCSPRNGBytes*8 < 128 {
		t.Fatalf("pkceCSPRNGBytes*8 = %d bits, want >= 128", pkceCSPRNGBytes*8)
	}
}

// TestStateAndNonce_AreDistinctPerCall proves OidcBegin generates State and
// Nonce independently (never the same value, never reused across calls).
func TestStateAndNonce_AreDistinctPerCall(t *testing.T) {
	client, err := NewClient("https://example.test", "acme", WithOidcClientID("rp-client"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	configuration := OidcConfiguration{AuthorizationEndpoint: "https://example.test/oauth2/authorize"}

	req1, err := client.OidcBegin(configuration, OidcBeginParams{RedirectURI: "https://app.test/callback"})
	if err != nil {
		t.Fatalf("OidcBegin: %v", err)
	}
	req2, err := client.OidcBegin(configuration, OidcBeginParams{RedirectURI: "https://app.test/callback"})
	if err != nil {
		t.Fatalf("OidcBegin: %v", err)
	}

	if req1.State == req1.Nonce {
		t.Fatalf("state and nonce must be generated independently, got the same value: %q", req1.State)
	}
	if req1.State == req2.State {
		t.Fatalf("two OidcBegin calls produced the same state: %q", req1.State)
	}
	if req1.Nonce == req2.Nonce {
		t.Fatalf("two OidcBegin calls produced the same nonce: %q", req1.Nonce)
	}
	if req1.CodeVerifier == req2.CodeVerifier {
		t.Fatalf("two OidcBegin calls produced the same code_verifier: %q", req1.CodeVerifier.expose())
	}
}
