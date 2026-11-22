// Package middleware implements the net/http middleware / route-guard
// interface (CONTRACT.md §10, D-06). It runs inside the CONSUMER's own Go
// process, wrapping their handlers — not the AXIAM server.
package middleware

import "context"

// User is the authenticated identity injected into the request context on a
// successful verification (CONTRACT.md §10 closing requirement: "at minimum
// user_id, tenant_id, roles").
type User struct {
	UserID   string
	TenantID string
	// Roles is the token's "roles" claim — the names of the subject's global
	// roles in the tenant (CONTRACT.md §11.2 rule 11). It is never derived
	// from the OAuth2 "scope" claim. The server emits the claim only when the
	// client requested, and is registered for, the "roles" scope.
	Roles []string
	// HasRoles reports whether the token carried a well-formed "roles" claim.
	// false (Roles nil) means the token says nothing about roles — the
	// application did not obtain the "roles" scope — and true with an empty
	// Roles means the scope was granted and the user holds no such role. Both
	// fail every RequireRole; they stay distinguishable for diagnosis.
	HasRoles bool
	// Scopes is the token's space-separated "scope" claim, split on spaces.
	// RequireScope reads it; RequireRole never does.
	Scopes []string
}

// contextKey is an unexported type so this package's context key can never
// collide with a key defined by another package (standard Go context-key
// idiom).
type contextKey struct{}

// userContextKey is the single key this package uses to store/retrieve the
// authenticated *User.
var userContextKey = contextKey{}

// UserFromContext retrieves the authenticated identity injected by
// Middleware, if present. ok is false when no identity was injected (e.g.
// the request never passed through the middleware, or the caller is
// inspecting a context that predates injection).
func UserFromContext(ctx context.Context) (*User, bool) {
	u, ok := ctx.Value(userContextKey).(*User)
	return u, ok
}

// withUser returns a copy of ctx carrying user, retrievable via
// UserFromContext.
func withUser(ctx context.Context, user *User) context.Context {
	return context.WithValue(ctx, userContextKey, user)
}
