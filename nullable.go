package axiam

import "encoding/json"

// Nullable is a member where an explicit JSON null is a different value from an
// absent member (CONTRACT.md §27.4 rule 5, "null is not absent").
//
// Go's pointer fields cannot say this: a nil *string with omitempty is never
// sent, and decoding leaves it nil whether the member was null or missing. The
// contract names exactly four members where the difference matters:
//
//   - UpdateDirectoryConfig.GroupBaseDn and .GroupFilter (§30.2): absent leaves
//     the stored value, an explicit null CLEARS it.
//   - SAMLIdpInfo.ActiveCredentialID and .NextCredentialID (§29.8 test 8): null
//     means "the slot is empty", while absent means the server did not send
//     the member at all — which a client must be able to notice.
//
// The zero value is ABSENT. Fields of this type carry `omitzero`, so an absent
// value is not sent; NullOf sends `null`, ValueOf sends the value.
type Nullable[T any] struct {
	value T
	state nullableState
}

type nullableState uint8

const (
	nullableAbsent nullableState = iota
	nullableNull
	nullablePresent
)

// ValueOf is a Nullable carrying v.
func ValueOf[T any](v T) Nullable[T] {
	return Nullable[T]{value: v, state: nullablePresent}
}

// NullOf is an explicit JSON null — on a request, "clear this member".
func NullOf[T any]() Nullable[T] {
	return Nullable[T]{state: nullableNull}
}

// IsZero reports whether the member is absent. encoding/json's omitzero calls
// it, which is what keeps an absent member off the wire.
func (n Nullable[T]) IsZero() bool { return n.state == nullableAbsent }

// IsAbsent reports whether the member was not set (on a request) or not sent
// (on a response).
func (n Nullable[T]) IsAbsent() bool { return n.state == nullableAbsent }

// IsNull reports whether the member is an explicit null.
func (n Nullable[T]) IsNull() bool { return n.state == nullableNull }

// Get returns the value and true when the member carries one; the zero value
// and false when it is absent or null.
func (n Nullable[T]) Get() (T, bool) {
	return n.value, n.state == nullablePresent
}

// MarshalJSON writes the value, or null. An absent Nullable is never reached
// through a field tagged omitzero; marshalled directly, it too is null.
func (n Nullable[T]) MarshalJSON() ([]byte, error) {
	if n.state != nullablePresent {
		return []byte("null"), nil
	}
	return json.Marshal(n.value)
}

// UnmarshalJSON reads null as an explicit null and anything else as a value.
// A member the document does not carry never calls it, and stays absent.
func (n *Nullable[T]) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*n = NullOf[T]()
		return nil
	}
	var v T
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	*n = ValueOf(v)
	return nil
}
