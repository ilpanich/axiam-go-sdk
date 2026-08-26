package axiam

import (
	"encoding/json"
	"fmt"
	"io"
)

// redacted is the placeholder every Sensitive redaction surface emits in
// place of the raw value (CONTRACT.md §7 / D-08).
const redacted = "[SENSITIVE]"

// Sensitive wraps a token-carrying string so it can never accidentally leak
// via fmt verbs, Go-syntax representation, or JSON encoding (CONTRACT.md §7,
// D-08). All token-carrying fields (access token, refresh token, MFA
// challenge token, AMQP signing key) MUST use this type.
//
// The raw value is reachable two ways: Expose, which is the greppable one to
// use and to audit, and a plain string(...) conversion, which Go permits on any
// defined string type and which this type cannot prevent. The protection here is
// against ACCIDENTAL disclosure — a %v in a log line, a struct marshalled into a
// request, a panic dump — not against a caller who means to read the value.
//
// Callers do sometimes mean to. CONTRACT.md §25.3 hands back a TOTP URI that has
// to reach a QR renderer, and §27.5 rule 3 hands back one-time secrets — a
// certificate's private key, a SCIM provisioning token, a service account's
// client secret — that are returned by exactly one call and never again, so the
// caller must store them or lose them.
type Sensitive string

// String implements fmt.Stringer. Covers direct String() calls and the
// default fmt verb behavior for types without a more specific Format/GoString
// override (String() alone would still leak on %#v without GoString below).
func (Sensitive) String() string {
	return redacted
}

// Format implements fmt.Formatter, closing the fmt-verb leak path
// (%v/%+v/%s/%q/width/precision) that a bare String() method does not fully
// cover — this is the CR-04 leak class this type exists to prevent.
func (Sensitive) Format(f fmt.State, verb rune) {
	_, _ = io.WriteString(f, redacted)
}

// GoString implements fmt.GoStringer, covering %#v (Go-syntax
// representation), which bypasses String()/Format() entirely if not
// implemented.
func (Sensitive) GoString() string {
	return redacted
}

// MarshalJSON implements json.Marshaler so any struct embedding a Sensitive
// field serializes the redacted placeholder rather than the raw value.
func (Sensitive) MarshalJSON() ([]byte, error) {
	return json.Marshal(redacted)
}

// Expose returns the raw wrapped value.
//
// Use it at exactly the point the secret is needed — written to a file, handed
// to a QR renderer, put on a socket — and never in between. Its whole value is
// that "this is where a secret becomes a plain string" is one greppable call
// rather than an ordinary-looking conversion, so an audit can find every such
// point by searching for this name.
//
// Never pass the result to a log, fmt, or JSON sink: doing so throws away the
// redaction this type exists to provide.
func (s Sensitive) Expose() string {
	return string(s)
}

// expose is the package-internal spelling of Expose.
//
// It delegates rather than duplicating, so there is one implementation. Kept as
// an alias because thirty-odd call sites inside this package predate the
// exported name, and renaming them all would be a large diff through files that
// have nothing else to say.
func (s Sensitive) expose() string {
	return s.Expose()
}
