package middleware

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/ilpanich/axiam-go-sdk/internal/jwks"
)

// csrfCookieName is the non-httpOnly cookie AXIAM's login flow sets
// alongside axiam_access specifically so same-site consumer apps can read it
// back for a cookie double-submit check (CONTRACT.md §3).
const csrfCookieName = "axiam_csrf"

// csrfHeaderName is the request header a same-site browser client is
// expected to echo the axiam_csrf cookie value into on state-changing
// requests (CONTRACT.md §3).
const csrfHeaderName = "X-CSRF-Token"

// safeMethods are exempt from the cookie double-submit CSRF check: they must
// not have side effects (RFC 9110 §9.2.1), so there is nothing for a
// cross-site forgery to change.
var safeMethods = map[string]bool{
	http.MethodGet:     true,
	http.MethodHead:    true,
	http.MethodOptions: true,
}

// jwksVerifier is the minimal interface this package needs from
// internal/jwks.Verifier (Plan 04) — kept as an interface so tests may
// substitute a fake without a live JWKS server, and so this package does not
// hard-depend on the concrete type's constructor signature.
//
// It deliberately names VerifyAccessToken — the FULL CONTRACT.md §10.1
// local-verification set — and not the raw
// VerifySignatureOnlyUnchecked primitive: a guard must never be wired to a
// signature-only check (§10.1 "The SDK's own guards MUST route through the
// full set").
type jwksVerifier interface {
	VerifyAccessToken(ctx context.Context, token []byte, opts jwks.ValidationOptions) (jwks.Claims, error)
}

// errorBody is the standardized JSON error body surfaced on 401/403
// (CONTRACT.md §10 closing requirement). It carries no raw token value.
type errorBody struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

// Middleware constructs a net/http middleware (CONTRACT.md §10, D-06) that:
//  1. Extracts the session from the `Authorization: Bearer <token>` header,
//     falling back to the `axiam_access` session cookie.
//  2. Verifies the token LOCALLY via the supplied JWKS verifier's
//     VerifyAccessToken — no per-request round-trip to the AXIAM server on a
//     cache hit.
//  3. Injects the authenticated identity (user_id, tenant_id, roles) via
//     context.WithValue, retrievable by UserFromContext.
//  4. Surfaces AuthError -> HTTP 401 and AuthzError -> HTTP 403 with a
//     standardized JSON error body; the wrapped handler is never called on
//     failure.
//
// Local verification applies the COMPLETE CONTRACT.md §10.1 minimum
// local-verification set, every rule of which fails closed:
//
//  1. signature   — alg pinned to EdDSA BEFORE any key lookup, so `alg: none`
//     and HS-family confusion are rejected without consulting a
//     key.
//  2. exp         — REQUIRED. A token with no exp, or a non-numeric exp, is
//     rejected; an absent exp is a permanent credential, not an
//     absent constraint.
//  3. nbf         — honoured when present; a future nbf is rejected. Absent
//     nbf is valid.
//  4. tenant_id   — REQUIRED and asserted against configuredTenant. An absent
//     claim, or an empty configuredTenant, is rejected: the JWKS
//     is organization-wide, so signature validity alone does not
//     bound a token to a tenant (TS CR-03 carry-forward).
//  5. iss         — checked only when WithExpectedIssuer is configured.
//  6. aud         — checked only when WithExpectedAudience is configured.
//  7. clock skew  — jwks.ClockSkewLeeway (60 s), a named constant applied to
//     rules 2 and 3, deliberately not operator-configurable.
//
// Every rejection produces the same opaque 401 body, so a caller learns
// nothing about WHICH rule it tripped.
//
// CSRF (cookie double-submit, CONTRACT.md §3): when the credential was
// sourced from the axiam_access COOKIE (not the Authorization header) and
// the request method is state-changing (anything other than GET/HEAD/
// OPTIONS), this middleware additionally requires the X-CSRF-Token request
// header to be present and equal, constant-time, to the axiam_csrf cookie
// value — rejecting with 403 on mismatch/absence. Bearer-header requests are
// CSRF-immune by construction (a cross-site attacker cannot set arbitrary
// request headers), but a cookie the browser attaches automatically is not:
// in any same-site deployment where axiam_access reaches this app, the
// non-httpOnly axiam_csrf cookie does too. This mirrors, locally, the same
// double-submit check the AXIAM server performs on its own endpoints (§3;
// see also the equivalent gate in the Java Spring filter,
// AxiamAuthenticationFilter#isCsrfValid).
//
// logger is optional (nil is safe) and, when supplied, MUST NOT be given a
// logger that would emit raw token values — this middleware never passes
// the token itself to the logger regardless.
func Middleware(verifier jwksVerifier, configuredTenant string, opts ...Option) func(http.Handler) http.Handler {
	cfg := &config{}
	for _, opt := range opts {
		opt(cfg)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, fromCookie, err := extractToken(r)
			if err != nil {
				writeError(w, cfg, http.StatusUnauthorized, "authentication_failed", err.Error())
				return
			}

			// Cookie-sourced credentials aren't CSRF-immune the way a
			// Bearer header is: a cross-site form/fetch can't set custom
			// headers, but the browser attaches cookies automatically. Gate
			// state-changing requests behind the cookie double-submit check
			// BEFORE spending a JWKS verification on them.
			if fromCookie && !safeMethods[r.Method] && !isCsrfValid(r) {
				writeError(w, cfg, http.StatusForbidden, "csrf_validation_failed", "missing or invalid X-CSRF-Token for cookie-sourced credentials")
				return
			}

			// The FULL §10.1 set — signature, required exp, honoured nbf,
			// asserted tenant_id, conditional iss/aud, bounded skew — all in
			// one call. The middleware never reimplements a subset of these
			// checks itself; that divergence is what produced SEC-071/SEC-080.
			claims, err := verifier.VerifyAccessToken(r.Context(), []byte(token), jwks.ValidationOptions{
				Tenant:           configuredTenant,
				ExpectedIssuer:   cfg.expectedIssuer,
				ExpectedAudience: cfg.expectedAudience,
			})
			if err != nil {
				// One opaque body for every §10.1 rejection: a caller must not
				// learn which claim failed.
				writeError(w, cfg, http.StatusUnauthorized, "authentication_failed", "invalid or expired token")
				return
			}

			// If the caller also supplied an X-Tenant-ID header, it must agree
			// with the token's own tenant_id claim — the header narrows which
			// tenant is being asserted for this request and can never
			// substitute for or override the claim (WR-04). Absent the header,
			// the claim check above is sufficient.
			if h := r.Header.Get("X-Tenant-ID"); h != "" && h != claims.TenantID {
				writeError(w, cfg, http.StatusUnauthorized, "authentication_failed", "X-Tenant-ID header does not match token tenant_id")
				return
			}

			user := &User{
				UserID:   claims.Subject,
				TenantID: claims.TenantID,
				Roles:    claims.Roles,
			}

			ctx := withUser(r.Context(), user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// extractToken reads the bearer token from the Authorization header,
// falling back to the axiam_access session cookie (CONTRACT.md §10.1). The
// returned bool reports whether the credential came from the cookie (as
// opposed to the header) — callers use it to decide whether the CSRF
// double-submit check applies (§3).
func extractToken(r *http.Request) (string, bool, error) {
	if header := r.Header.Get("Authorization"); header != "" {
		scheme, credentials, found := strings.Cut(strings.TrimSpace(header), " ")
		if !found || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(credentials) == "" {
			return "", false, errMissingCredentials
		}
		return strings.TrimSpace(credentials), false, nil
	}

	if cookie, err := r.Cookie("axiam_access"); err == nil && cookie.Value != "" {
		return cookie.Value, true, nil
	}

	return "", false, errMissingCredentials
}

// isCsrfValid implements the cookie double-submit check (CONTRACT.md §3):
// the X-CSRF-Token request header must be present and equal, constant-time,
// to the axiam_csrf cookie value. Absence of either side fails closed.
func isCsrfValid(r *http.Request) bool {
	header := r.Header.Get(csrfHeaderName)
	if header == "" {
		return false
	}
	cookie, err := r.Cookie(csrfCookieName)
	if err != nil || cookie.Value == "" {
		return false
	}
	// ConstantTimeCompare requires equal-length inputs to say anything about
	// content; a length mismatch is itself decisive (and safe to short
	// circuit on, since the lengths of a header/cookie pair aren't secret).
	if len(header) != len(cookie.Value) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(header), []byte(cookie.Value)) == 1
}

var errMissingCredentials = missingCredentialsError{}

// missingCredentialsError is a small sentinel-style error type; kept local
// (not the root package's AuthError) since this failure occurs before any
// verifier call and never carries a raw token value.
type missingCredentialsError struct{}

func (missingCredentialsError) Error() string { return "missing authentication credentials" }

// writeError writes the standardized JSON error body (CONTRACT.md §10) and
// status code. No raw token value is ever included.
func writeError(w http.ResponseWriter, cfg *config, status int, errCode, message string) {
	if cfg.logger != nil {
		cfg.logger.Warn("axiam middleware rejected request", slog.Int("status", status), slog.String("error", errCode))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorBody{Error: errCode, Message: message})
}

// config holds the middleware's optional settings (CF-02: injectable,
// redaction-aware logger, OFF by default).
type config struct {
	logger           *slog.Logger
	expectedIssuer   string
	expectedAudience string
}

// Option configures optional Middleware behavior.
type Option func(*config)

// WithLogger sets an optional structured logger for rejected requests. The
// logger is never given a raw token value. Off by default (nil logger).
func WithLogger(logger *slog.Logger) Option {
	return func(c *config) { c.logger = logger }
}

// WithExpectedIssuer configures the `iss` claim this guard requires
// (CONTRACT.md §10.1 rule 5). The check is CONDITIONAL: unset (the default)
// means no issuer check is performed at all; once set, a token whose `iss`
// differs is rejected.
//
// There is no default value and no hardcoded AXIAM issuer anywhere in this
// SDK — supply your deployment's own issuer URL.
func WithExpectedIssuer(issuer string) Option {
	return func(c *config) { c.expectedIssuer = issuer }
}

// WithExpectedAudience configures the `aud` value this guard requires
// (CONTRACT.md §10.1 rule 6). The check is CONDITIONAL: unset (the default)
// means no audience check is performed at all; once set, a token whose `aud`
// does not contain the value — including a token carrying no `aud` at all —
// is rejected.
//
// A guard fronting a user-facing resource server SHOULD configure
// "axiam:user" (§10.1 rule 6). It is not defaulted, because a service-to-
// service guard legitimately expects a different audience.
func WithExpectedAudience(audience string) Option {
	return func(c *config) { c.expectedAudience = audience }
}
