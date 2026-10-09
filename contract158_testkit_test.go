package axiam

// Shared helpers for the contract 1.53–1.58 tests (§28.12, §29–§33).
//
// Every secret these tests use is generated at run time: a literal would be a
// credential in the repository, and a redaction test needs a value no fixture
// shares. And no failure message here — or in the tests using these — prints a
// secret, a fragment of one, or a rendering that may contain one: a failing
// redaction test must not itself log what it caught.

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// randomSecret returns prefix plus 32 random base64url characters.
func randomSecret(t *testing.T, prefix string) string {
	t.Helper()
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("crypto/rand: %v", err)
	}
	return prefix + base64.RawURLEncoding.EncodeToString(buf)
}

// assertNoFragment fails when any 8-character substring of secret appears in
// haystack. The failure names only the offset.
func assertNoFragment(t *testing.T, haystack, secret, what string) {
	t.Helper()
	if len(secret) < 8 {
		t.Fatalf("%s: test secret shorter than 8 characters", what)
	}
	for i := 0; i+8 <= len(secret); i++ {
		if strings.Contains(haystack, secret[i:i+8]) {
			t.Fatalf("%s: an 8-character fragment of the secret (offset %d) appears in a rendering", what, i)
		}
	}
}

// renderings is every stringification sink a caller might hand v to: the
// four fmt verbs and a JSON encoding.
func renderings(v any) string {
	encoded, err := json.Marshal(v)
	if err != nil {
		encoded = []byte("json-error")
	}
	return fmt.Sprintf("%v | %+v | %#v | %s | %s", v, v, v, fmt.Sprint(v), encoded)
}

// assertNoFragmentIn checks every rendering of v.
func assertNoFragmentIn(t *testing.T, v any, secret, what string) {
	t.Helper()
	assertNoFragment(t, renderings(v), secret, what)
}

// errorRenderings is every way an error is commonly logged.
func errorRenderings(err error) string {
	if err == nil {
		return ""
	}
	return fmt.Sprintf("%v | %+v | %#v | %s", err, err, err, err.Error())
}
