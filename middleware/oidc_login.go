package middleware

// OidcLoginHandler / OidcCallbackHandler — the "Login with AXIAM" glue
// (CONTRACT.md §12), following the SAME per-framework conventions as
// nethttp.go: a config struct, a small unexported error-body writer, and
// plain http.Handler factories.
//
// This file is framework-agnostic net/http glue only. It performs no token
// extraction, sets no cookie, and touches no request/response object beyond
// what an http.Handler naturally does — establishing the application's OWN
// session (a cookie, a session row, ...) is deliberately left to
// OidcLoginOptions.OnSuccess, exactly as CONTRACT.md §12 leaves "what a
// session means" to the application.
//
// The state store is what makes the two HTTP requests of a redirect flow
// into one login: OidcBegin produces State/Nonce/CodeVerifier in the login
// request, and only State survives the round trip through the IdP, so the
// other two must be parked somewhere the callback request can reach (§12.3
// rule 1 — the SDK's core §12 operations store nothing themselves).

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	axiam "github.com/ilpanich/axiam-go-sdk"
)

// OidcLoginClient is the minimal set of *axiam.Client methods
// OidcLoginHandler/OidcCallbackHandler need (CONTRACT.md §12), kept as an
// interface — mirroring this package's existing jwksVerifier/AccessChecker
// pattern — so tests can substitute a fake without a live AXIAM server.
type OidcLoginClient interface {
	OidcDiscover(ctx context.Context) (axiam.OidcConfiguration, error)
	OidcBegin(configuration axiam.OidcConfiguration, params axiam.OidcBeginParams) (axiam.AuthorizationRequest, error)
	OidcExchange(ctx context.Context, params axiam.OidcExchangeParams) (axiam.OidcTokenSet, error)
}

// OidcLoginOptions configures OidcLoginHandler and OidcCallbackHandler
// (CONTRACT.md §12). Both handlers share one options value so the two
// routes of a login flow cannot drift apart (same client, same store, same
// redirect URI).
type OidcLoginOptions struct {
	// Client is the relying-party client driving the flow (an *axiam.Client
	// constructed with axiam.WithOidcClientID / axiam.WithOidcClientSecret).
	Client OidcLoginClient
	// Store is where in-flight login state is parked between the login
	// redirect and the callback. axiam.NewMemoryOidcStateStore is a ready
	// single-process implementation; a multi-instance deployment needs a
	// shared one.
	Store axiam.OidcStateStore
	// RedirectURI is the relying party's redirect URI — the public URL of
	// the callback route — replayed verbatim on the token exchange (the
	// server compares the two).
	RedirectURI string
	// Scope is the requested scope. "openid" is added automatically when
	// absent (CONTRACT.md §12.1 rule 4).
	Scope string
	// SuccessRedirect is where to send the browser after a successful
	// login. Falls back to the ReturnTo captured at login time (from the
	// `?return_to=` query parameter), then to a 200 JSON summary.
	SuccessRedirect string
	// OnSuccess is called with the validated token set once the exchange
	// succeeds — the hook where an application establishes its OWN session
	// (sign a cookie, write a session row, ...). This package deliberately
	// does not do this for you: what a session means is the application's
	// decision. Receives the consumed state entry too, so ReturnTo and any
	// other application data captured at login time is available. May be
	// nil.
	OnSuccess func(w http.ResponseWriter, r *http.Request, tokens axiam.OidcTokenSet, entry axiam.OidcStateEntry)
	// Logger is a debug-only logger. It never receives token material,
	// state, nonce, or the PKCE verifier. May be nil (off by default,
	// matching this package's existing WithLogger convention).
	Logger *slog.Logger
}

// OidcLoginHandler returns an http.Handler implementing step 1 of "Login
// with AXIAM" (CONTRACT.md §12.1 oidc_begin): it fetches discovery, builds
// the authorization request, parks its state in opts.Store, and redirects
// the browser to the IdP.
//
// An optional `?return_to=` query parameter on the incoming request is
// captured with the state entry and used as the post-login destination when
// opts.SuccessRedirect is unset — the caller (this application) owns the
// destination it names; that URL is never validated here (documented
// open-redirect responsibility of whoever populates `return_to`, CONTRACT.md
// §12 T1 judgment call 19).
//
// Discovery is fetched through OidcDiscover, so its per-origin cache and
// single-flight de-duplication apply (§12.3 rule 6) — a busy login route
// does not hammer the discovery endpoint.
func OidcLoginHandler(opts OidcLoginOptions) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		configuration, err := opts.Client.OidcDiscover(r.Context())
		if err != nil {
			logOidcDebug(opts.Logger, "oidc discovery failed", "reason", err.Error())
			writeOidcError(w, opts.Logger, http.StatusServiceUnavailable, "oidc_unavailable", "could not start the OIDC login flow")
			return
		}

		request, err := opts.Client.OidcBegin(configuration, axiam.OidcBeginParams{
			RedirectURI: opts.RedirectURI,
			Scope:       opts.Scope,
		})
		if err != nil {
			logOidcDebug(opts.Logger, "oidc begin failed", "reason", err.Error())
			writeOidcError(w, opts.Logger, http.StatusServiceUnavailable, "oidc_unavailable", "could not start the OIDC login flow")
			return
		}

		entry := axiam.OidcStateEntry{
			State:        request.State,
			Nonce:        request.Nonce,
			CodeVerifier: request.CodeVerifier,
			RedirectURI:  opts.RedirectURI,
			ReturnTo:     r.URL.Query().Get("return_to"),
		}
		if err := opts.Store.Save(entry); err != nil {
			logOidcDebug(opts.Logger, "oidc state store save failed", "reason", err.Error())
			writeOidcError(w, opts.Logger, http.StatusServiceUnavailable, "oidc_unavailable", "could not persist login state")
			return
		}

		http.Redirect(w, r, request.URL, http.StatusFound)
	})
}

// OidcCallbackHandler returns an http.Handler implementing step 2
// (CONTRACT.md §12.1 oidc_exchange): validates the IdP callback, consumes
// the stored state, exchanges the code, and either redirects to
// opts.SuccessRedirect (or the ReturnTo captured at login time), or replies
// 200 with a token-free JSON summary.
//
// Failure mapping (a login-glue convention, not itself contract-specified —
// CONTRACT.md §12 T1 judgment call 19): 400 invalid_request for a malformed
// callback; 401 authentication_failed for an IdP error, an unknown/expired/
// already-used login state, an ID-token failure, or an OAuth2 protocol
// error; 503 oidc_unavailable for a network failure reaching AXIAM.
func OidcCallbackHandler(opts OidcLoginOptions) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()

		if idpErr := query.Get("error"); idpErr != "" {
			message := idpErr
			if desc := query.Get("error_description"); desc != "" {
				message = idpErr + ": " + desc
			}
			logOidcDebug(opts.Logger, "idp returned an authorization error", "error", idpErr)
			writeOidcError(w, opts.Logger, http.StatusUnauthorized, "authentication_failed", message)
			return
		}

		state := query.Get("state")
		code := query.Get("code")
		if state == "" || code == "" {
			writeOidcError(w, opts.Logger, http.StatusBadRequest, "invalid_request", "callback is missing the state or code query parameter")
			return
		}

		// Single-use consume (§12.3 rule 1): a replayed callback finds
		// nothing. Unknown, already-consumed, and expired states are
		// deliberately indistinguishable to the caller.
		entry, ok := opts.Store.Consume(state)
		if !ok {
			logOidcDebug(opts.Logger, "no stored login state for the callback state")
			writeOidcError(w, opts.Logger, http.StatusUnauthorized, "authentication_failed", "unknown, expired, or already-used login state")
			return
		}

		tokens, err := opts.Client.OidcExchange(r.Context(), axiam.OidcExchangeParams{
			Code:         code,
			CodeVerifier: entry.CodeVerifier,
			RedirectURI:  entry.RedirectURI,
			Nonce:        entry.Nonce,
		})
		if err != nil {
			var netErr *axiam.NetworkError
			if errors.As(err, &netErr) {
				logOidcDebug(opts.Logger, "token exchange transport failure")
				writeOidcError(w, opts.Logger, http.StatusServiceUnavailable, "oidc_unavailable", "the AXIAM token endpoint is unreachable")
				return
			}
			// *AuthError (including *OAuthProtocolError and every §12.4
			// reason code) and anything unexpected: a login that cannot be
			// proven is a failed login.
			logOidcDebug(opts.Logger, "token exchange failed", "reason", err.Error())
			writeOidcError(w, opts.Logger, http.StatusUnauthorized, "authentication_failed", err.Error())
			return
		}

		if opts.OnSuccess != nil {
			opts.OnSuccess(w, r, tokens, entry)
		}

		destination := opts.SuccessRedirect
		if destination == "" {
			destination = entry.ReturnTo
		}
		if destination != "" {
			http.Redirect(w, r, destination, http.StatusFound)
			return
		}

		body := map[string]any{"authenticated": true, "expires_in": tokens.ExpiresIn}
		if tokens.IDClaims != nil && tokens.IDClaims.Sub != "" {
			body["sub"] = tokens.IDClaims.Sub
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(body)
	})
}

// writeOidcError writes the standardized JSON error body (matching
// nethttp.go's errorBody/writeError shape) for an OIDC login-glue failure.
// No raw token, state, nonce, or verifier value is ever included.
func writeOidcError(w http.ResponseWriter, logger *slog.Logger, status int, errCode, message string) {
	if logger != nil {
		logger.Warn("axiam oidc login rejected request", slog.Int("status", status), slog.String("error", errCode))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorBody{Error: errCode, Message: message})
}

// logOidcDebug logs at debug level, never including a raw token/state/
// nonce/verifier value. No-op when logger is nil.
func logOidcDebug(logger *slog.Logger, msg string, args ...any) {
	if logger == nil {
		return
	}
	logger.Debug(msg, args...)
}
