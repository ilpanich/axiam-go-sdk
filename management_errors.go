package axiam

import (
	"encoding/json"
	"fmt"
)

// The §27.4 rule 7 error sub-types.
//
// CONTRACT.md §2 fixes the taxonomy at three error types and §27 does not
// widen it. What it adds is a *classification* inside two of them, because a
// management surface produces refusals §2 never had to describe — §2 has no
// 404 row at all, since nothing before §27 could return one.
//
// Go has no subclassing, so the relationship the other SDKs get from a class
// hierarchy is expressed here through Is: each of these matches its §2
// sentinel as well as its own. Every errors.Is(err, ErrAuthz) written before
// §27 keeps working, and a caller who needs the distinction reaches for
// errors.As or the narrower sentinel.

// Sentinel errors for the §27 sub-types, for errors.Is discrimination
// alongside the §2 sentinels they also match.
var (
	// ErrNotFound matches any *NotFoundError. Also matches ErrAuthz.
	ErrNotFound = fmt.Errorf("axiam: management resource not found")
	// ErrConflict matches any *ConflictError. Also matches ErrAuthz.
	ErrConflict = fmt.Errorf("axiam: management conflict")
	// ErrValidation matches any *ValidationError. Also matches ErrNetwork.
	ErrValidation = fmt.Errorf("axiam: management request rejected")
)

// FieldError is one field-level complaint inside a *ValidationError.
type FieldError struct {
	// Field is the offending field's name, as the server names it.
	Field string `json:"field"`
	// Message is what is wrong with it.
	Message string `json:"message"`
}

// NotFoundError reports HTTP 404: the resource does not exist, OR it belongs
// to another tenant.
//
// The server answers identically in both cases on purpose: a distinguishable
// "exists but not yours" lets a caller enumerate another tenant's ids. That is
// why this matches ErrAuthz rather than being a category of its own — in a
// multi-tenant IAM the two really are one outcome.
type NotFoundError struct {
	// Operation is the registry operation that found nothing, e.g. "users.get".
	Operation string
	// Message is the full, caller-facing description.
	Message string
}

func (e *NotFoundError) Error() string { return e.Message }

// Is matches both ErrNotFound and the §2 ErrAuthz sentinel this refusal is a
// kind of.
func (e *NotFoundError) Is(target error) bool {
	return target == ErrNotFound || target == ErrAuthz
}

// ConflictError reports HTTP 409: a uniqueness or state conflict, such as a
// role name already taken.
//
// Never retried (§27.4 rule 8): a 409 is the server telling the truth, not a
// transient fault, and a retry produces the identical answer one round-trip
// later.
type ConflictError struct {
	// Operation is the registry operation that conflicted.
	Operation string
	// Message is the full, caller-facing description.
	Message string
}

func (e *ConflictError) Error() string { return e.Message }

// Is matches both ErrConflict and the §2 ErrAuthz sentinel.
func (e *ConflictError) Is(target error) bool {
	return target == ErrConflict || target == ErrAuthz
}

// ValidationError reports HTTP 400 or 422: the request was rejected.
//
// §2 maps 400 to ErrNetwork, described as an "SDK programming error". That
// description was written when nothing but the SDK itself could produce a 400.
// On this surface a 400 is usually a *user's* invalid input — an email that is
// not an email, a slug already taken — and an application needs to tell that
// from a broken socket without matching on message text. The sentinel it also
// matches is inherited from §2 rather than chosen here.
type ValidationError struct {
	// Operation is the registry operation that was rejected.
	Operation string
	// Status is the HTTP status the server answered with — 400 or 422.
	Status int
	// Message is the full, caller-facing description.
	Message string
	// Fields carries per-field detail, where the server sent any. Empty is
	// normal.
	Fields []FieldError
}

func (e *ValidationError) Error() string { return e.Message }

// Is matches both ErrValidation and the §2 ErrNetwork sentinel.
func (e *ValidationError) Is(target error) bool {
	return target == ErrValidation || target == ErrNetwork
}

// parseFieldErrors pulls field-level detail out of an error body, on a
// best-effort basis.
//
// Two shapes are recognised — an array of {field, message} and an object keyed
// by field name. A body in neither shape yields no fields rather than an
// error: failing to parse an error body would replace a useful message with a
// useless one.
func parseFieldErrors(body []byte) []FieldError {
	var asArray struct {
		Errors []FieldError `json:"errors"`
	}
	if err := json.Unmarshal(body, &asArray); err == nil && len(asArray.Errors) > 0 {
		out := make([]FieldError, 0, len(asArray.Errors))
		for _, fe := range asArray.Errors {
			if fe.Field != "" {
				out = append(out, fe)
			}
		}
		if len(out) > 0 {
			return out
		}
	}

	var asObject struct {
		Errors map[string]string `json:"errors"`
	}
	if err := json.Unmarshal(body, &asObject); err == nil && len(asObject.Errors) > 0 {
		out := make([]FieldError, 0, len(asObject.Errors))
		for _, field := range sortedKeys(asObject.Errors) {
			out = append(out, FieldError{Field: field, Message: asObject.Errors[field]})
		}
		return out
	}
	return nil
}
