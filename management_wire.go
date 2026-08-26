package axiam

// Small helpers the §27 surface leans on, kept beside the generated code they
// serve rather than scattered through it.

// ptr returns a pointer to v.
//
// Every optional field on the §27 models is a pointer, because that is what
// distinguishes "not mentioned" — omitted from the wire body entirely — from
// "explicitly set" (§27.4 rule 5). Building one inline otherwise needs a named
// local per field, which turns a five-field sparse update into eleven lines.
//
//	client.Users().Update(ctx, id, UpdateUserRequest{Email: ptr("new@example.test")})
func ptr[T any](v T) *T { return &v }

// exposeOptional unwraps an optional Sensitive for the wire, preserving the
// difference between "absent" and "present".
//
// A nil in stays a nil out, so an unset secret is omitted from the request body
// rather than sent as an empty string — the same distinction ptr preserves for
// every other optional field.
func exposeOptional(s *Sensitive) *string {
	if s == nil {
		return nil
	}
	raw := s.expose()
	return &raw
}
