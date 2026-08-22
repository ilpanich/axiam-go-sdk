package axiam

// Error-path coverage for the contract-1.28 surface: §24 WebAuthn, §25 account
// lifecycle and §26 PAR.
//
// The happy paths and the contract's own named requirements live in
// webauthn_test.go, account_test.go and oidc_par_test.go. What is here is the
// other half of every branch those files take: a client that has been Closed, a
// 2xx whose body is not the shape the operation expects, and the five ways
// §24.6a rule 2 can be handed an authenticator response.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// §1.4: every operation refuses on a closed client, and refuses BEFORE it
// reaches the wire. A table rather than twenty functions, because the point is
// that the set is exhaustive — a new operation that forgets ensureOpen shows up
// as a missing row.
func TestClosedClientRefusesEveryContract128Operation(t *testing.T) {
	server, capture := acServer(t, nil)
	client := acClient(t, server)
	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	ctx := context.Background()

	operations := map[string]func() error{
		"MfaEnroll":      func() error { _, err := client.MfaEnroll(ctx); return err },
		"MfaConfirm":     func() error { _, err := client.MfaConfirm(ctx, "123456"); return err },
		"MfaSetupEnroll": func() error { _, err := client.MfaSetupEnroll(ctx, Sensitive(acSetupToken)); return err },
		"MfaSetupConfirm": func() error {
			_, err := client.MfaSetupConfirm(ctx, Sensitive(acSetupToken), "123456")
			return err
		},
		"VerifyEmail":        func() error { return client.VerifyEmail(ctx, Sensitive(acResetToken), waOrgUUID) },
		"ResendVerification": func() error { return client.ResendVerification(ctx, "alice@example.com", waOrgUUID) },
		"RequestPasswordReset": func() error {
			return client.RequestPasswordReset(ctx, PasswordResetRequest{Email: "alice@example.com"})
		},
		"PasswordResetContext": func() error {
			_, err := client.PasswordResetContext(ctx, Sensitive(acResetToken))
			return err
		},
		"ConfirmPasswordReset": func() error {
			return client.ConfirmPasswordReset(ctx, PasswordResetConfirmation{
				Token: Sensitive(acResetToken), NewPassword: Sensitive("pw"), TenantID: waOrgUUID,
			})
		},
		"WebauthnRegisterStart": func() error { _, err := client.WebauthnRegisterStart(ctx); return err },
		"WebauthnRegisterFinish": func() error {
			_, err := client.WebauthnRegisterFinish(ctx, Sensitive(waStateToken), "laptop", json.RawMessage(`{}`))
			return err
		},
		"WebauthnAuthenticateStart": func() error {
			_, err := client.WebauthnAuthenticateStart(ctx, Sensitive(waChallengeToken))
			return err
		},
		"WebauthnAuthenticateFinish": func() error {
			_, err := client.WebauthnAuthenticateFinish(ctx, Sensitive(waStateToken), json.RawMessage(`{}`))
			return err
		},
		"WebauthnDiscoverableStart": func() error { _, err := client.WebauthnDiscoverableStart(ctx, nil); return err },
		"WebauthnDiscoverableFinish": func() error {
			_, err := client.WebauthnDiscoverableFinish(ctx, Sensitive(waStateToken), json.RawMessage(`{}`))
			return err
		},
	}

	before := len(capture.hits)
	for name, call := range operations {
		if err := call(); err == nil {
			t.Errorf("%s on a closed client must return an error", name)
		}
	}
	if len(capture.hits) != before {
		t.Errorf("a closed client must not reach the wire: %v", capture.hits)
	}
}

// A 200 whose body is not the documented shape is a deserialization failure,
// not a silently-empty success. The distinction matters most on
// PasswordResetContext: an empty context reads as "no OPAQUE policy", which is
// the plaintext-password path (§25.4 rule 1).
func TestMalformedSuccessBodiesAreDeserializationFailures(t *testing.T) {
	garbage := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"secret_base32":`))
	}
	server, _ := acServer(t, map[string]http.HandlerFunc{
		mfaEnrollPath:       garbage,
		mfaSetupEnrollPath:  garbage,
		mfaSetupConfirmPath: garbage,
		resetContextPath:    garbage,
	})
	client := acClient(t, server)
	ctx := context.Background()

	if _, err := client.MfaEnroll(ctx); err == nil {
		t.Error("MfaEnroll must not report success on an unparsable body")
	}
	if _, err := client.MfaSetupEnroll(ctx, Sensitive(acSetupToken)); err == nil {
		t.Error("MfaSetupEnroll must not report success on an unparsable body")
	}
	if _, err := client.MfaSetupConfirm(ctx, Sensitive(acSetupToken), "123456"); err == nil {
		t.Error("MfaSetupConfirm must not report success on an unparsable body")
	}
	if _, err := client.PasswordResetContext(ctx, Sensitive(acResetToken)); err == nil {
		t.Error("PasswordResetContext must not report an empty policy on an unparsable body")
	}
}

// Every non-2xx on the no-content operations maps through §2 rather than being
// swallowed by the "discard the body" path.
func TestNoContentOperationsSurfaceServerErrors(t *testing.T) {
	refuse := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"message":"nope"}`))
	}
	server, _ := acServer(t, map[string]http.HandlerFunc{
		verifyEmailPath:        refuse,
		resendVerificationPath: refuse,
		resetPath:              refuse,
		resetConfirmPath:       refuse,
	})
	client := acClient(t, server)
	ctx := context.Background()

	if err := client.VerifyEmail(ctx, Sensitive(acResetToken), waOrgUUID); err == nil {
		t.Error("VerifyEmail must surface a 400")
	}
	if err := client.ResendVerification(ctx, "alice@example.com", waOrgUUID); err == nil {
		t.Error("ResendVerification must surface a 400")
	}
	if err := client.RequestPasswordReset(ctx, PasswordResetRequest{Email: "a@b.test"}); err == nil {
		t.Error("RequestPasswordReset must surface a 400")
	}
	err := client.ConfirmPasswordReset(ctx, PasswordResetConfirmation{
		Token: Sensitive(acResetToken), NewPassword: Sensitive("pw"), TenantID: waOrgUUID,
	})
	if err == nil {
		t.Error("ConfirmPasswordReset must surface a 400")
	}
}

// §24.6a rule 2: the response is taken in whatever form the platform produced
// it and passed through as raw JSON. Five accepted shapes, two refusals — and
// the refusals are client-side, so nothing reaches the wire.
func TestAuthenticatorResponseAcceptsEveryPlatformShape(t *testing.T) {
	server, capture := waServer(t, nil)
	client := waSignedIn(t, waClient(t, server), server)
	ctx := context.Background()

	accepted := map[string]any{
		"json.RawMessage": json.RawMessage(registrationResponseJSON),
		"[]byte":          []byte(registrationResponseJSON),
		"string":          registrationResponseJSON,
		"map":             map[string]any{"id": "credential-id", "type": "public-key"},
	}
	for name, response := range accepted {
		if _, err := client.WebauthnRegisterFinish(
			ctx, Sensitive(waStateToken), "laptop", response,
		); err != nil {
			t.Errorf("a %s response must be accepted: %v", name, err)
		}
	}

	hitsBefore := capture.hits[webauthnRegisterFinishPath]
	refused := map[string]any{
		"nil":                       nil,
		"a string that is not JSON": "not json at all",
		"bytes that are not JSON":   []byte("{unbalanced"),
	}
	for name, response := range refused {
		if _, err := client.WebauthnRegisterFinish(
			ctx, Sensitive(waStateToken), "laptop", response,
		); err == nil {
			t.Errorf("%s must be refused", name)
		}
	}
	if capture.hits[webauthnRegisterFinishPath] != hitsBefore {
		t.Error("a malformed authenticator response must be refused client-side, with no wire call")
	}
}

// §24.6a rule 1 hands back the INNER options object. A server that sent the
// bare options rather than the DOM wrapper still gets a usable string — this
// call has one job, and failing it over a missing wrapper helps nobody.
func TestRequestJSONHandlesBothWrappedAndBareOptions(t *testing.T) {
	bare := WebauthnChallenge{Challenge: json.RawMessage(`{"challenge":"Y2hhbGxlbmdl"}`)}
	got, err := bare.RequestJSON()
	if err != nil {
		t.Fatalf("bare options: %v", err)
	}
	if got != `{"challenge":"Y2hhbGxlbmdl"}` {
		t.Errorf("bare options must pass through unchanged, got %s", got)
	}

	notAnObject := WebauthnChallenge{Challenge: json.RawMessage(`["not","an","object"]`)}
	if _, err := notAnObject.RequestJSON(); err == nil {
		t.Error("a challenge that is not a JSON object must be an error, not a silent empty string")
	}
}

// §24.7 rule 5: five outcomes, five distinct strings, and none of them accuses
// the user of cancelling — the same classification covers a silent timeout.
func TestWebauthnErrorMessageCoversEveryFailure(t *testing.T) {
	seen := map[string]WebauthnFailure{}
	for _, failure := range []WebauthnFailure{
		WebauthnCancelled,
		WebauthnAlreadyRegistered,
		WebauthnTimeout,
		WebauthnUnsupported,
		WebauthnUnknown,
	} {
		message := WebauthnErrorMessage(failure)
		if message == "" {
			t.Errorf("%v has no message", failure)
		}
		if previous, duplicate := seen[message]; duplicate {
			t.Errorf("%v and %v share a message: %q", previous, failure, message)
		}
		seen[message] = failure
	}
	if strings.Contains(WebauthnErrorMessage(WebauthnCancelled), "you cancel") {
		t.Error("the cancelled copy must not accuse the user: the same outcome covers a timeout")
	}
}

var _ = httptest.NewServer

// A closed client refuses the push, and an authorization_endpoint that is not
// a URL is a failure rather than a redirect to a string nobody can parse.
func TestOidcParRefusesOnAClosedClientAndOnAnUnparsableAuthorizationEndpoint(t *testing.T) {
	server, capture := parServer(t, parCreated)
	client := parClient(t, server, WithOidcClientSecret(parSecret))
	configuration := discoveryDoc(server.URL)
	request, err := client.OidcBegin(configuration, OidcBeginParams{
		RedirectURI: parRedirectURI, Scope: "openid",
	})
	if err != nil {
		t.Fatalf("OidcBegin: %v", err)
	}

	broken := configuration
	broken.AuthorizationEndpoint = "://not-a-url"
	if _, err := client.OidcPar(context.Background(), OidcParParams{
		Request: request, RedirectURI: parRedirectURI, TenantID: parTenantUUID,
		Configuration: &broken,
	}); err == nil {
		t.Error("an unparsable authorization_endpoint must not yield a redirect URL")
	}

	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	calls := capture.calls
	if _, err := client.OidcPar(context.Background(), OidcParParams{
		Request: request, RedirectURI: parRedirectURI, TenantID: parTenantUUID,
		Configuration: &configuration,
	}); err == nil {
		t.Error("OidcPar on a closed client must return an error")
	}
	if capture.calls != calls {
		t.Error("a closed client must not push")
	}
}

// Both ceremony halves refuse an unparsable 200 rather than returning an empty
// challenge or an empty token set.
func TestWebauthnCeremonyRefusesUnparsableSuccessBodies(t *testing.T) {
	garbage := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"challenge":`))
	}
	server, _ := waServer(t, map[string]http.HandlerFunc{
		webauthnDiscoverableStartPath:  garbage,
		webauthnDiscoverableFinishPath: garbage,
	})
	client := waClient(t, server)
	ctx := context.Background()

	if _, err := client.WebauthnDiscoverableStart(ctx, nil); err == nil {
		t.Error("an unparsable start body must not yield an empty challenge")
	}
	if _, err := client.WebauthnDiscoverableFinish(
		ctx, Sensitive(waStateToken), json.RawMessage(registrationResponseJSON),
	); err == nil {
		t.Error("an unparsable finish body must not yield an empty token set")
	}
}

// The three remaining refusals on the §24 edges, each of which produces an
// empty-but-successful result if it is ever removed.
func TestWebauthnRefusesUnmarshallableResponsesAndAnUnnamedWorkspace(t *testing.T) {
	server, capture := waServer(t, nil)
	ctx := context.Background()

	// §24.6a rule 2's default branch: a value Go cannot marshal is a client-side
	// refusal, not an empty response field the server would reject as a bad
	// signature.
	signedIn := waSignedIn(t, waClient(t, server), server)
	hits := capture.hits[webauthnRegisterFinishPath]
	if _, err := signedIn.WebauthnRegisterFinish(
		ctx, Sensitive(waStateToken), "laptop", make(chan int),
	); err == nil {
		t.Error("a value that cannot be marshalled must be refused")
	}
	if capture.hits[webauthnRegisterFinishPath] != hits {
		t.Error("the refusal must be client-side, with no wire call")
	}

	// §24.1: a discoverable credential is resolved inside one tenant's
	// isolation boundary, so the workspace has to be named — and a client
	// configured with neither an org id nor an org slug cannot name it.
	bare, err := NewClient(server.URL, "acme")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	hits = capture.hits[webauthnDiscoverableStartPath]
	if _, err := bare.WebauthnDiscoverableStart(ctx, nil); err == nil {
		t.Error("a client with no organization must refuse the discoverable ceremony")
	}
	if capture.hits[webauthnDiscoverableStartPath] != hits {
		t.Error("the refusal must be client-side, with no wire call")
	}
}

// Every §25 read maps a non-2xx through §2 rather than returning a zero value
// alongside a nil error. MfaSetupConfirm matters most: a zero LoginResult
// reads as "signed in, no MFA required".
func TestAccountReadsMapNon2xxThroughSection2(t *testing.T) {
	refuse := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"nope"}`))
	}
	server, _ := acServer(t, map[string]http.HandlerFunc{
		mfaEnrollPath:       refuse,
		mfaSetupEnrollPath:  refuse,
		mfaSetupConfirmPath: refuse,
		resetContextPath:    refuse,
	})
	client := acClient(t, server)
	ctx := context.Background()

	if _, err := client.MfaEnroll(ctx); err == nil {
		t.Error("MfaEnroll must surface a 401")
	}
	if _, err := client.MfaSetupEnroll(ctx, Sensitive(acSetupToken)); err == nil {
		t.Error("MfaSetupEnroll must surface a 401")
	}
	if _, err := client.MfaSetupConfirm(ctx, Sensitive(acSetupToken), "123456"); err == nil {
		t.Error("MfaSetupConfirm must surface a 401 rather than a zero LoginResult")
	}
	if _, err := client.PasswordResetContext(ctx, Sensitive(acResetToken)); err == nil {
		t.Error("PasswordResetContext must surface a 401")
	}
}

// §25.4: the OPAQUE envelope is a caller-supplied map, so it is the one place
// a §25 body can fail to marshal. The refusal is client-side — a half-encoded
// reset confirmation must never reach the wire.
func TestConfirmPasswordResetRefusesAnUnmarshallableOpaqueEnvelope(t *testing.T) {
	server, capture := acServer(t, nil)
	client := acClient(t, server)
	hits := capture.hits[resetConfirmPath]

	err := client.ConfirmPasswordReset(context.Background(), PasswordResetConfirmation{
		Token:       Sensitive(acResetToken),
		NewPassword: Sensitive("new-password"),
		TenantID:    waOrgUUID,
		Opaque:      map[string]any{"registration_record": make(chan int)},
	})
	if err == nil {
		t.Fatal("an unmarshallable opaque envelope must be refused")
	}
	if capture.hits[resetConfirmPath] != hits {
		t.Error("the refusal must be client-side, with no wire call")
	}
}
