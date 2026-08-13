package axiam

// Token Exchange (RFC 8693) — CONTRACT.md §15.
//
// Most of §15 is a list of things an SDK must NOT helpfully do, so most of
// these tests assert an absence: no defaulted ActorToken, no auto-narrow after
// invalid_scope, no synthesised refresh token, no adoption.

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

const (
	testSubjectToken = "subject-token-value"
	testActorToken   = "actor-token-value"
	testIssuedToken  = "issued-narrow-token"
)

func exchangeBody(overrides map[string]any) map[string]any {
	body := map[string]any{
		"access_token":      testIssuedToken,
		"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
		"token_type":        "Bearer",
		"expires_in":        300,
		"scope":             "orders:read",
	}
	for k, v := range overrides {
		body[k] = v
	}
	return body
}

func newExchangeClient(t *testing.T, srv *oidcTestServer, withSecret bool) *Client {
	t.Helper()
	opts := []Option{WithOidcClientID("api-gateway")}
	if withSecret {
		opts = append(opts, WithOidcClientSecret("gateway-secret"))
	}
	client, err := NewClient(srv.URL, "acme", opts...)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return client
}

// ---------------------------------------------------------------------------
// §15.1 wire shape
// ---------------------------------------------------------------------------

func TestTokenExchangeSendsTheRFC8693GrantAndAuthenticates(t *testing.T) {
	srv := newOidcTestServer(t)
	var form url.Values
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		form = r.PostForm
		writeStatusJSON(w, http.StatusOK, exchangeBody(nil))
	}

	result, err := newExchangeClient(t, srv, true).TokenExchange(context.Background(), TokenExchangeParams{
		SubjectToken:     Sensitive(testSubjectToken),
		SubjectTokenType: SubjectTokenTypeAccessToken,
		Scopes:           []string{"orders:read", "orders:write"},
		Audience:         "orders-service",
		TenantID:         testTenantUUID,
	})
	if err != nil {
		t.Fatalf("TokenExchange: %v", err)
	}

	if got := form.Get("grant_type"); got != "urn:ietf:params:oauth:grant-type:token-exchange" {
		t.Errorf("grant_type: got %q", got)
	}
	if got := form.Get("subject_token"); got != testSubjectToken {
		t.Errorf("subject_token: got %q", got)
	}
	if got := form.Get("subject_token_type"); got != "urn:ietf:params:oauth:token-type:access_token" {
		t.Errorf("subject_token_type: got %q", got)
	}
	if got := form.Get("scope"); got != "orders:read orders:write" {
		t.Errorf("scope: got %q", got)
	}
	if got := form.Get("audience"); got != "orders-service" {
		t.Errorf("audience: got %q", got)
	}
	if got := form.Get("client_secret"); got != "gateway-secret" {
		t.Error("§15.1: the exchanging client is confidential and authenticates")
	}

	if result.AccessToken.expose() != testIssuedToken {
		t.Error("issued token not returned")
	}
	if result.IssuedTokenType != "urn:ietf:params:oauth:token-type:access_token" {
		t.Error("§15.2 rule 6: issued_token_type is surfaced, not dropped")
	}
}

func TestTokenExchangeFailsClientSideForAPublicClient(t *testing.T) {
	srv := newOidcTestServer(t)
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		t.Error("a public client must fail before any wire call")
	}

	_, err := newExchangeClient(t, srv, false).TokenExchange(context.Background(), TokenExchangeParams{
		SubjectToken:     Sensitive(testSubjectToken),
		SubjectTokenType: SubjectTokenTypeAccessToken,
		TenantID:         testTenantUUID,
	})
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("want *AuthError, got %T: %v", err, err)
	}
	if srv.TokenCalls() != 0 {
		t.Error("no request should have been sent")
	}
}

// ---------------------------------------------------------------------------
// §15.2 rule 1 — delegation vs impersonation
// ---------------------------------------------------------------------------

func TestAbsentActorTokenIsNeverDefaulted(t *testing.T) {
	srv := newOidcTestServer(t)
	var form url.Values
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		form = r.PostForm
		writeStatusJSON(w, http.StatusOK, exchangeBody(nil))
	}

	_, err := newExchangeClient(t, srv, true).TokenExchange(context.Background(), TokenExchangeParams{
		SubjectToken:     Sensitive(testSubjectToken),
		SubjectTokenType: SubjectTokenTypeAccessToken,
		TenantID:         testTenantUUID,
	})
	if err != nil {
		t.Fatalf("TokenExchange: %v", err)
	}

	// §15.2 rule 1: leaving ActorToken zero asks for IMPERSONATION. An SDK
	// that helpfully substituted its own session token would silently turn
	// that into a delegation — a different operation with different risk.
	if form.Has("actor_token") {
		t.Error("actor_token must be absent when the caller did not supply one")
	}
	if form.Has("actor_token_type") {
		t.Error("actor_token_type must not be sent without actor_token")
	}
}

func TestActorTokenAndTypeAreSentAsAPair(t *testing.T) {
	srv := newOidcTestServer(t)
	var form url.Values
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		form = r.PostForm
		writeStatusJSON(w, http.StatusOK, exchangeBody(nil))
	}

	_, err := newExchangeClient(t, srv, true).TokenExchange(context.Background(), TokenExchangeParams{
		SubjectToken:     Sensitive(testSubjectToken),
		SubjectTokenType: SubjectTokenTypeAccessToken,
		ActorToken:       Sensitive(testActorToken),
		TenantID:         testTenantUUID,
	})
	if err != nil {
		t.Fatalf("TokenExchange: %v", err)
	}
	if got := form.Get("actor_token"); got != testActorToken {
		t.Errorf("actor_token: got %q", got)
	}
	// RFC 8693 §2.1 requires the pair; the type alone is a malformed request.
	if got := form.Get("actor_token_type"); got != "urn:ietf:params:oauth:token-type:access_token" {
		t.Errorf("actor_token_type: got %q", got)
	}
}

// ---------------------------------------------------------------------------
// §15.2 rules 2-3 and §15.3 — refusals surface unchanged
// ---------------------------------------------------------------------------

func TestExchangeErrorCodesReachTheCallerUnchanged(t *testing.T) {
	// Including cross-tenant, which the server deliberately collapses into
	// invalid_grant — the SDK must not re-derive the distinction it withheld
	// (that is a tenant-enumeration signal).
	for _, code := range []string{
		"invalid_request", "invalid_grant", "invalid_scope",
		"invalid_target", "unauthorized_client", "invalid_client",
	} {
		t.Run(code, func(t *testing.T) {
			srv := newOidcTestServer(t)
			status := http.StatusBadRequest
			if code == "invalid_client" {
				status = http.StatusUnauthorized
			}
			srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
				writeStatusJSON(w, status, oauthErrorBody(code))
			}

			_, err := newExchangeClient(t, srv, true).TokenExchange(context.Background(), TokenExchangeParams{
				SubjectToken:     Sensitive(testSubjectToken),
				SubjectTokenType: SubjectTokenTypeAccessToken,
				Scopes:           []string{"orders:read", "orders:admin"},
				TenantID:         testTenantUUID,
			})
			var protocolErr *OAuthProtocolError
			if !errors.As(err, &protocolErr) {
				t.Fatalf("want *OAuthProtocolError, got %T: %v", err, err)
			}
			if protocolErr.ErrorCode != code {
				t.Errorf("ErrorCode: got %q, want %q", protocolErr.ErrorCode, code)
			}
			// §15.2 rules 2-3: no retry, no downgrade, no auto-narrowing. The
			// server refuses rather than silently narrowing precisely so the
			// caller finds out HERE.
			if srv.TokenCalls() != 1 {
				t.Errorf("exactly one request expected, got %d", srv.TokenCalls())
			}
		})
	}
}

// ---------------------------------------------------------------------------
// §15.2 rules 4-7 — what the result is, and is not
// ---------------------------------------------------------------------------

func TestExchangeDoesNotSurfaceAServerSentRefreshToken(t *testing.T) {
	// Deliberately hostile fixture: RFC 8693 issues no refresh token, so the
	// type has no field for one and there is nothing to synthesise.
	srv := newOidcTestServer(t)
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		writeStatusJSON(w, http.StatusOK, exchangeBody(map[string]any{"refresh_token": "should-not-exist"}))
	}

	result, err := newExchangeClient(t, srv, true).TokenExchange(context.Background(), TokenExchangeParams{
		SubjectToken:     Sensitive(testSubjectToken),
		SubjectTokenType: SubjectTokenTypeAccessToken,
		TenantID:         testTenantUUID,
	})
	if err != nil {
		t.Fatalf("TokenExchange: %v", err)
	}
	if strings.Contains(result.AccessToken.expose(), "should-not-exist") {
		t.Error("a refresh token must not leak into the access token")
	}
}

func TestExchangeReportsTheGrantedScope(t *testing.T) {
	srv := newOidcTestServer(t)
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		writeStatusJSON(w, http.StatusOK, exchangeBody(map[string]any{"scope": "orders:read"}))
	}

	result, err := newExchangeClient(t, srv, true).TokenExchange(context.Background(), TokenExchangeParams{
		SubjectToken:     Sensitive(testSubjectToken),
		SubjectTokenType: SubjectTokenTypeAccessToken,
		Scopes:           []string{"orders:read", "orders:write"},
		TenantID:         testTenantUUID,
	})
	if err != nil {
		t.Fatalf("TokenExchange: %v", err)
	}
	// §15.2 rule 7: the response scope is the GRANTED set and may be narrower
	// than requested even on success.
	if result.Scope != "orders:read" {
		t.Errorf("Scope: got %q, want the granted (narrower) set", result.Scope)
	}
}

func TestExchangeNeverAdoptsTheIssuedToken(t *testing.T) {
	srv := newOidcTestServer(t)
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		writeStatusJSON(w, http.StatusOK, exchangeBody(nil))
	}

	client := newExchangeClient(t, srv, true)
	if _, err := client.TokenExchange(context.Background(), TokenExchangeParams{
		SubjectToken:     Sensitive(testSubjectToken),
		SubjectTokenType: SubjectTokenTypeAccessToken,
		TenantID:         testTenantUUID,
	}); err != nil {
		t.Fatalf("TokenExchange: %v", err)
	}

	// §15.2 rule 5: a MUST NOT, with no opt-in flag — unlike
	// LoginClientCredentials and DeviceLogin, where adoption is a MAY.
	// Adopting a narrowed, short-lived token would re-privilege every later
	// call this client makes, and most would then fail far from here.
	if client.adoptedOidcCredential() != "" {
		t.Error("the exchanged token must never become this client's credential")
	}
}

func TestExchangedTokenIsRedacted(t *testing.T) {
	srv := newOidcTestServer(t)
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		writeStatusJSON(w, http.StatusOK, exchangeBody(nil))
	}

	result, err := newExchangeClient(t, srv, true).TokenExchange(context.Background(), TokenExchangeParams{
		SubjectToken:     Sensitive(testSubjectToken),
		SubjectTokenType: SubjectTokenTypeAccessToken,
		TenantID:         testTenantUUID,
	})
	if err != nil {
		t.Fatalf("TokenExchange: %v", err)
	}
	if strings.Contains(result.AccessToken.String(), testIssuedToken) {
		t.Error("§15.5: the issued token is a bearer credential and must not render")
	}
}

func TestAFailedExchangeNeverEchoesTheSubjectToken(t *testing.T) {
	// §15.5 calls this out specifically: an exchange failure is exactly when a
	// naive implementation logs the request body.
	srv := newOidcTestServer(t)
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		writeStatusJSON(w, http.StatusBadRequest, oauthErrorBody("invalid_grant"))
	}

	_, err := newExchangeClient(t, srv, true).TokenExchange(context.Background(), TokenExchangeParams{
		SubjectToken:     Sensitive(testSubjectToken),
		SubjectTokenType: SubjectTokenTypeAccessToken,
		ActorToken:       Sensitive(testActorToken),
		TenantID:         testTenantUUID,
	})
	if err == nil {
		t.Fatal("want an error")
	}
	if strings.Contains(err.Error(), testSubjectToken) || strings.Contains(err.Error(), testActorToken) {
		t.Errorf("error text leaked token material: %q", err.Error())
	}
}

// ---------------------------------------------------------------------------
// §15.7 — external-IdP subject tokens (X4)
//
// No new operation: the same TokenExchange carries a partner IdP's token. What
// changes is which subject tokens the server accepts and what its refusals
// mean, so these tests are about not getting in the way of either.
// ---------------------------------------------------------------------------

const (
	// A token minted by a partner's IdP. Opaque to the SDK — deliberately not
	// a well-formed JWT, because nothing here may decode it.
	testExternalSubjectToken = "partner-idp-subject-token"

	// The one normative error_description (§15.7). It means "fix the AXIAM
	// trust configuration", not "fix your token".
	issuerNotConfigured = "the subject token's issuer is not configured for token exchange"
)

func TestExternalSubjectTokenTypeIsSentVerbatim(t *testing.T) {
	srv := newOidcTestServer(t)
	var form url.Values
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		form = r.PostForm
		writeStatusJSON(w, http.StatusOK, exchangeBody(map[string]any{
			"scope": "read:orders",
		}))
	}

	result, err := newExchangeClient(t, srv, true).TokenExchange(context.Background(), TokenExchangeParams{
		SubjectToken:     Sensitive(testExternalSubjectToken),
		SubjectTokenType: SubjectTokenTypeJWT,
		TenantID:         testTenantUUID,
	})
	if err != nil {
		t.Fatalf("TokenExchange: %v", err)
	}

	// The caller named …:jwt, so …:jwt goes on the wire. §15.7: the SDK must
	// not inspect the subject token to pick this, and must not override it.
	if got := form.Get("subject_token_type"); got != "urn:ietf:params:oauth:token-type:jwt" {
		t.Errorf("subject_token_type: got %q, want the caller's …:jwt", got)
	}
	if got := form.Get("subject_token"); got != testExternalSubjectToken {
		t.Errorf("subject_token: got %q", got)
	}
	// Delegation across a trust boundary is unsupported; nothing may add one.
	if form.Has("actor_token") {
		t.Error("§15.7: no actor_token may be invented for an external exchange")
	}

	// The result surfaces unchanged — the cross-domain path is not a different
	// result shape, and §15.2 rules 6-7 still hold.
	if result.AccessToken.expose() != testIssuedToken {
		t.Error("the issued token must reach the caller unchanged")
	}
	if result.IssuedTokenType != "urn:ietf:params:oauth:token-type:access_token" {
		t.Error("§15.2 rule 6: issued_token_type is surfaced")
	}
	if result.Scope != "read:orders" {
		t.Errorf("§15.2 rule 7: Scope is the granted set, got %q", result.Scope)
	}
}

func TestSubjectTokenTypeIsNeverInferredFromTheToken(t *testing.T) {
	srv := newOidcTestServer(t)
	var form url.Values
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		form = r.PostForm
		writeStatusJSON(w, http.StatusOK, exchangeBody(nil))
	}

	// A subject token that *looks* exactly like a JWT, presented as an access
	// token. An SDK that sniffed the token would "correct" this to …:jwt;
	// §15.7 says it must not look, so what the caller named is what goes out.
	// Being able to hold this wrong is the point: only the caller knows.
	jwtShaped := "eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJodHRwczovL3BhcnRuZXIuZXhhbXBsZS8ifQ.sig"

	_, err := newExchangeClient(t, srv, true).TokenExchange(context.Background(), TokenExchangeParams{
		SubjectToken:     Sensitive(jwtShaped),
		SubjectTokenType: SubjectTokenTypeAccessToken,
		TenantID:         testTenantUUID,
	})
	if err != nil {
		t.Fatalf("TokenExchange: %v", err)
	}
	if got := form.Get("subject_token_type"); got != "urn:ietf:params:oauth:token-type:access_token" {
		t.Errorf("§15.7: the token's shape must not override the caller, got %q", got)
	}
}

func TestAnOmittedSubjectTokenTypeNeverReachesTheWire(t *testing.T) {
	// §15.1: the type is REQUIRED and has no default. Go cannot demand a struct
	// field at compile time, so the demand lands here instead — client-side,
	// with no wire call. Silently sending …:access_token would be the SDK
	// choosing on the caller's behalf, which is what §15.7 forbids; and for a
	// caller who actually held a refresh token it would trade the
	// invalid_request that NAMES the type for a generic invalid_grant.
	srv := newOidcTestServer(t)
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		t.Error("an omitted subject_token_type must fail before any wire call")
	}

	_, err := newExchangeClient(t, srv, true).TokenExchange(context.Background(), TokenExchangeParams{
		SubjectToken: Sensitive(testSubjectToken),
		TenantID:     testTenantUUID,
	})

	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("want *AuthError, got %T: %v", err, err)
	}
	if srv.TokenCalls() != 0 {
		t.Errorf("no request should have been sent, got %d", srv.TokenCalls())
	}
	// The message has to name the way out, or the caller has to go read §15.1.
	if !strings.Contains(authErr.Error(), "SubjectTokenType") {
		t.Errorf("the error should name the missing field, got %q", authErr.Error())
	}
}

func TestActorTokenWithAnExternalSubjectTokenIsRefusedWithoutRetry(t *testing.T) {
	srv := newOidcTestServer(t)
	var forms []url.Values
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		forms = append(forms, r.PostForm)
		writeStatusJSON(w, http.StatusBadRequest, map[string]any{
			"error":             "invalid_request",
			"error_description": "actor_token is not supported for an external subject token",
		})
	}

	_, err := newExchangeClient(t, srv, true).TokenExchange(context.Background(), TokenExchangeParams{
		SubjectToken:     Sensitive(testExternalSubjectToken),
		SubjectTokenType: SubjectTokenTypeJWT,
		ActorToken:       Sensitive(testActorToken),
		TenantID:         testTenantUUID,
	})

	var protocolErr *OAuthProtocolError
	if !errors.As(err, &protocolErr) {
		t.Fatalf("want *OAuthProtocolError, got %T: %v", err, err)
	}
	if protocolErr.ErrorCode != "invalid_request" {
		t.Errorf("ErrorCode: got %q, want invalid_request", protocolErr.ErrorCode)
	}
	// §15.7: no retry, and no rewriting. Dropping the actor token and
	// re-sending would turn a delegation the caller asked for into an
	// impersonation they did not.
	if len(forms) != 1 {
		t.Fatalf("exactly one request expected, got %d", len(forms))
	}
	if got := forms[0].Get("actor_token"); got != testActorToken {
		t.Error("the request must be sent as written, actor token included")
	}
	if got := forms[0].Get("subject_token_type"); got != "urn:ietf:params:oauth:token-type:jwt" {
		t.Errorf("subject_token_type must not be rewritten, got %q", got)
	}
}

func TestRefusedSubjectTokenTypeIsNeverRetriedAsAnother(t *testing.T) {
	// A refresh or ID token type is refused BY NAME. Retrying as …:jwt or
	// …:access_token would present a re-authentication credential, or an
	// assertion about a login, as if it were an API bearer token (§15.7).
	for _, refused := range []string{
		"urn:ietf:params:oauth:token-type:refresh_token",
		"urn:ietf:params:oauth:token-type:id_token",
	} {
		t.Run(refused, func(t *testing.T) {
			srv := newOidcTestServer(t)
			var sentTypes []string
			srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
				_ = r.ParseForm()
				sentTypes = append(sentTypes, r.PostForm.Get("subject_token_type"))
				writeStatusJSON(w, http.StatusBadRequest, map[string]any{
					"error":             "invalid_request",
					"error_description": "unsupported subject_token_type " + refused,
				})
			}

			_, err := newExchangeClient(t, srv, true).TokenExchange(context.Background(), TokenExchangeParams{
				SubjectToken:     Sensitive(testExternalSubjectToken),
				SubjectTokenType: refused,
				TenantID:         testTenantUUID,
			})
			if err == nil {
				t.Fatal("want a refusal")
			}
			if len(sentTypes) != 1 || sentTypes[0] != refused {
				t.Errorf("§15.7: the refused type must be sent once and not retried, got %v", sentTypes)
			}
		})
	}
}

func TestIssuerNotConfiguredDescriptionReachesTheCallerIntact(t *testing.T) {
	srv := newOidcTestServer(t)
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		writeStatusJSON(w, http.StatusBadRequest, map[string]any{
			"error":             "invalid_grant",
			"error_description": issuerNotConfigured,
		})
	}

	_, err := newExchangeClient(t, srv, true).TokenExchange(context.Background(), TokenExchangeParams{
		SubjectToken:     Sensitive(testExternalSubjectToken),
		SubjectTokenType: SubjectTokenTypeJWT,
		TenantID:         testTenantUUID,
	})

	var protocolErr *OAuthProtocolError
	if !errors.As(err, &protocolErr) {
		t.Fatalf("want *OAuthProtocolError, got %T: %v", err, err)
	}
	if protocolErr.ErrorCode != "invalid_grant" {
		t.Errorf("ErrorCode: got %q, want invalid_grant", protocolErr.ErrorCode)
	}
	// This is the ONLY distinguishable external failure, and the whole point
	// of it is that an integrator can tell "fix the AXIAM trust config" from
	// "fix your token". Truncating or rewording it destroys that.
	if protocolErr.ErrorDescription != issuerNotConfigured {
		t.Errorf("ErrorDescription: got %q, want it intact", protocolErr.ErrorDescription)
	}
}

func TestNoHelperReExchangesAnExternallyExchangedToken(t *testing.T) {
	// Tokens minted from an external subject token carry `ext_exchange`, and
	// BOTH exchange paths refuse a subject token bearing it: exchanges do not
	// compose. The SDK's part is to never feed a result back in by itself.
	srv := newOidcTestServer(t)
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		writeStatusJSON(w, http.StatusOK, exchangeBody(nil))
	}

	client := newExchangeClient(t, srv, true)
	result, err := client.TokenExchange(context.Background(), TokenExchangeParams{
		SubjectToken:     Sensitive(testExternalSubjectToken),
		SubjectTokenType: SubjectTokenTypeJWT,
		TenantID:         testTenantUUID,
	})
	if err != nil {
		t.Fatalf("TokenExchange: %v", err)
	}

	// Exactly one exchange happened: nothing looped the result back in.
	if srv.TokenCalls() != 1 {
		t.Errorf("exactly one exchange expected, got %d", srv.TokenCalls())
	}
	// §15.2 rule 5 restated for the cross-domain path: had the result been
	// adopted, the next refresh or exchange this client ran would carry it as
	// a subject token — the re-exchange §15.7 forbids, arrived at by accident.
	if client.adoptedOidcCredential() != "" {
		t.Error("an externally exchanged token must never become this client's credential")
	}
	if result.AccessToken.expose() == "" {
		t.Error("the issued token should have reached the caller")
	}
}
