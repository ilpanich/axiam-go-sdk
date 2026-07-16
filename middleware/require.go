package middleware

// This file adds the CONTRACT.md §11 declarative authorization helpers:
// RequireAuth, RequireAccess, and RequireRole. Go has no macro/annotation/
// decorator facility, so the idiomatic equivalent under the §11 canonical
// vocabulary is a per-route http.Handler wrapper, composed with (never
// duplicating) the §10 Middleware guard in nethttp.go: these wrappers
// consume the identity Middleware already injected into the request
// context via UserFromContext and never perform their own token extraction
// or JWKS verification.

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
)

// ResourceResolver extracts the resource id (a UUID string) that an
// authorization check should be evaluated against, from the incoming
// request (CONTRACT.md §11.2.3). A non-nil error is treated as a
// programming/request error and surfaced as 400 invalid_request — it is
// never a silent allow and never a nil/empty fallback.
type ResourceResolver func(*http.Request) (string, error)

// ResourceFromPath returns a ResourceResolver that reads the named path
// parameter via the standard library's http.Request.PathValue (Go 1.22+
// net/http routing, e.g. mux.Handle("/docs/{id}", ...)). An empty or
// missing path value is reported as an error so RequireAccess surfaces a
// 400, never a nil-UUID fallback (CONTRACT.md §11.2.3).
func ResourceFromPath(name string) ResourceResolver {
	return func(r *http.Request) (string, error) {
		v := r.PathValue(name)
		if v == "" {
			return "", errMissingPathValue(name)
		}
		return v, nil
	}
}

// StaticResource returns a ResourceResolver that always resolves to the
// given literal resource id, for singleton resources that aren't keyed off
// a request path parameter (CONTRACT.md §11.2.3.a). An empty literal is
// still reported as an error at call time, never silently allowed through.
func StaticResource(id string) ResourceResolver {
	return func(*http.Request) (string, error) {
		if id == "" {
			return "", errEmptyStaticResource
		}
		return id, nil
	}
}

var errEmptyStaticResource = errors.New("middleware: StaticResource id must not be empty")

// pathValueError reports a missing/empty named path value; kept as a
// distinct type (rather than a bare errors.New) so its message can name the
// parameter without string-formatting at every call site.
type pathValueError struct {
	name string
}

func (e pathValueError) Error() string {
	return "middleware: path value \"" + e.name + "\" is missing or empty"
}

func errMissingPathValue(name string) error {
	return pathValueError{name: name}
}

// AccessChecker is the minimal interface RequireAccess needs from an authz
// client — satisfied by *axiam.Client's CheckAccessAs method. Kept as an
// interface (mirroring this package's unexported jwksVerifier pattern) so
// tests can substitute a fake checker without a live AXIAM server, and so
// this file does not hard-depend on axiam.Client's full concrete surface.
type AccessChecker interface {
	CheckAccessAs(ctx context.Context, subjectID, action, resourceID string, scope ...string) (bool, string, error)
}

// requireConfig holds RequireAccess's optional settings.
type requireConfig struct {
	scope  string
	logger *slog.Logger
}

// RequireOption configures optional RequireAccess behavior.
type RequireOption func(*requireConfig)

// WithScope sets the optional scope argument passed through to the
// underlying access check verbatim (CONTRACT.md §11.2.4).
func WithScope(scope string) RequireOption {
	return func(c *requireConfig) { c.scope = scope }
}

// WithRequireLogger sets an optional structured logger for denied/erroring
// requests. The logger is never given a raw token value; on a deny it logs
// only the action and resolved resource id at debug level (CONTRACT.md
// §11.2.8). Named distinctly from this package's existing WithLogger
// (Middleware's option) since both are exported from the same package.
func WithRequireLogger(logger *slog.Logger) RequireOption {
	return func(c *requireConfig) { c.logger = logger }
}

// RequireAuth returns a middleware (CONTRACT.md §11.1 require_auth) that
// requires an authenticated AXIAM identity to already be present in the
// request context — i.e. that the request already passed through Middleware
// successfully. It performs no token extraction or verification of its own;
// it is pure sugar over checking UserFromContext, for route trees where the
// §10 guard is mounted selectively rather than globally. Responds 401
// authentication_failed when no identity is present.
func RequireAuth() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, ok := UserFromContext(r.Context()); !ok {
				writeError(w, &config{}, http.StatusUnauthorized, "authentication_failed", "no authenticated AXIAM identity in request context")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAccess returns a middleware (CONTRACT.md §11.1 require_access) that
// requires the request's authenticated caller to pass an authorization
// check for action on a resource resolved via resolve. It runs strictly
// after the §10 guard: it never extracts or verifies a token itself, only
// consuming the identity Middleware already injected.
//
// Behavior (CONTRACT.md §11.2):
//   - No authenticated identity in context -> 401 authentication_failed.
//   - resolve returns an error, or an empty resource id -> 400 invalid_request
//     (a programming/request error, never a silent allow, never a nil-UUID
//     fallback).
//   - The check is made for the REQUEST'S authenticated user
//     (subject_id = user.UserID), not the application's own client session
//     — this is why checker takes an explicit subjectID argument.
//   - checker returns allowed=false -> 403 authorization_denied.
//   - checker returns a *axiam.NetworkError (transport failure while calling
//     the authz endpoint) -> fail CLOSED with 503 authz_unavailable; the
//     failure is never treated as an allow, and this helper does not retry
//     beyond whatever bounded retry checker's own implementation already
//     performs.
//   - Any other error from checker is also treated as fail-closed 503
//     authz_unavailable (an authz decision the helper cannot confirm is
//     never surfaced as an allow).
//
// No decision caching is performed (CONTRACT.md §11.2.6): every request
// with this middleware installed performs a fresh check.
func RequireAccess(checker AccessChecker, action string, resolve ResourceResolver, opts ...RequireOption) func(http.Handler) http.Handler {
	cfg := &requireConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logCfg := &config{logger: cfg.logger}

			user, ok := UserFromContext(r.Context())
			if !ok {
				writeError(w, logCfg, http.StatusUnauthorized, "authentication_failed", "no authenticated AXIAM identity in request context")
				return
			}

			resourceID, err := resolve(r)
			if err != nil || resourceID == "" {
				msg := "unable to resolve a resource id from the request"
				if err != nil {
					msg = err.Error()
				}
				writeError(w, logCfg, http.StatusBadRequest, "invalid_request", msg)
				return
			}

			var scope []string
			if cfg.scope != "" {
				scope = []string{cfg.scope}
			}

			allowed, reason, err := checker.CheckAccessAs(r.Context(), user.UserID, action, resourceID, scope...)
			if err != nil {
				// Fail CLOSED (CONTRACT.md §11.2.5): ANY error contacting the
				// authz endpoint — a *axiam.NetworkError or otherwise — is
				// surfaced as 503, never treated as an allow. This SDK's
				// bounded read-only retry already happens inside
				// checker.CheckAccessAs itself (axiam.Client.CheckAccessAs);
				// this helper never retries beyond that.
				logAuthzOutcome(cfg.logger, action, resourceID, "authz check failed")
				writeError(w, logCfg, http.StatusServiceUnavailable, "authz_unavailable", "authorization service unavailable")
				return
			}

			if !allowed {
				logAuthzOutcome(cfg.logger, action, resourceID, "authorization denied: "+reason)
				writeError(w, logCfg, http.StatusForbidden, "authorization_denied", "you do not have permission to perform this action")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// logAuthzOutcome logs a denial/error at debug level, never including a raw
// token value (CONTRACT.md §11.2.8). No-op when logger is nil (off by
// default, matching Middleware's WithLogger convention).
func logAuthzOutcome(logger *slog.Logger, action, resourceID, message string) {
	if logger == nil {
		return
	}
	logger.Debug(message, slog.String("action", action), slog.String("resource_id", resourceID))
}

// RequireRole returns a middleware (CONTRACT.md §11.1 require_role) that
// locally checks whether the verified token's roles (already injected by
// Middleware) contain at least one of the given roles. It never calls the
// AXIAM server — it is cheaper but coarser than RequireAccess, and is NOT a
// substitute for a resource-level check: role names are tenant-defined, and
// RequireAccess remains the authoritative authorization check (CONTRACT.md
// §11.2.9). Responds 401 authentication_failed when no identity is present,
// 403 authorization_denied when the identity has none of the given roles.
func RequireRole(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, ok := UserFromContext(r.Context())
			if !ok {
				writeError(w, &config{}, http.StatusUnauthorized, "authentication_failed", "no authenticated AXIAM identity in request context")
				return
			}
			if !hasAnyRole(user.Roles, roles) {
				writeError(w, &config{}, http.StatusForbidden, "authorization_denied", "you do not have the required role for this action")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// hasAnyRole reports whether userRoles contains at least one of required.
func hasAnyRole(userRoles, required []string) bool {
	if len(required) == 0 {
		return false
	}
	set := make(map[string]struct{}, len(userRoles))
	for _, r := range userRoles {
		set[r] = struct{}{}
	}
	for _, want := range required {
		if _, ok := set[want]; ok {
			return true
		}
	}
	return false
}
