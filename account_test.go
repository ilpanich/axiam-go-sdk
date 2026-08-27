package axiam

// §25 account lifecycle and MFA enrolment — the CONTRACT.md §25.6 test set.
//
// The assertion worth reading is TestMfaSecretNeverRenders: it scans for the
// secret VALUE, not the field name, which is what catches TotpURI — the field
// that actually reaches a log, because it is the one a caller hands to a QR
// renderer, and the one that silently contains the secret it sits beside.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	acSecret     = "JBSWY3DPEHPK3PXPSECRETVALUE"
	acTotpURI    = "otpauth://totp/AXIAM:alice@example.com?secret=" + acSecret + "&issuer=AXIAM"
	acSetupToken = "setup-token-value-do-not-log"
	acResetToken = "reset-token-value-do-not-log"
	acTenantUUID = "44444444-4444-4444-4444-444444444444"
)

type acCapture struct {
	bodies map[string]map[string]any
	urls   map[string]string
	hits   map[string]int
}

// acServer stands up the §25 endpoints, with per-path overrides.
func acServer(t *testing.T, overrides map[string]http.HandlerFunc) (*httptest.Server, *acCapture) {
	t.Helper()
	capture := &acCapture{
		bodies: map[string]map[string]any{},
		urls:   map[string]string{},
		hits:   map[string]int{},
	}
	token := makeAccessTokenWithOrgID(t, waOrgUUID)

	enroll := func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"secret_base32": acSecret,
			"totp_uri":      acTotpURI,
		})
	}
	sessionBody := func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "axiam_access", Value: token, Path: "/"})
		http.SetCookie(w, &http.Cookie{Name: "axiam_refresh", Value: "refresh-cookie", Path: "/"})
		w.Header().Set("X-CSRF-Token", "csrf-tok")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"user":       map[string]any{"id": "11111111-1111-1111-1111-111111111111"},
			"session_id": "33333333-3333-3333-3333-333333333333",
			"expires_in": 900,
		})
	}

	defaults := map[string]http.HandlerFunc{
		loginPath: func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"mfa_setup_required": true,
				"setup_token":        acSetupToken,
			})
		},
		mfaEnrollPath: enroll,
		mfaConfirmPath: func(w http.ResponseWriter, r *http.Request) {
			body := capture.bodies[mfaConfirmPath]
			if body["totp_code"] != "123456" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"message":"invalid code"}`))
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"mfa_enabled": true})
		},
		mfaSetupEnrollPath:     enroll,
		mfaSetupConfirmPath:    sessionBody,
		verifyEmailPath:        func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) },
		resendVerificationPath: func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) },
		resendOwnVerificationPath: func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{"sent": true})
		},
		// A uniform 200 whether or not the address exists — the whole point.
		resetPath:        func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) },
		resetConfirmPath: func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) },
		resetContextPath: func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("token") != acResetToken {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"opaque": map[string]any{"mode": "required", "ksf": "argon2id"},
			})
		},
	}
	for path, handler := range overrides {
		defaults[path] = handler
	}

	mux := http.NewServeMux()
	for path, handler := range defaults {
		p, h := path, handler
		mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) {
			capture.hits[p]++
			capture.urls[p] = r.URL.String()
			if r.Body != nil {
				var body map[string]any
				if json.NewDecoder(r.Body).Decode(&body) == nil {
					capture.bodies[p] = body
				}
			}
			h(w, r)
		})
	}
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server, capture
}

func acClient(t *testing.T, server *httptest.Server) *Client {
	t.Helper()
	client, err := NewClient(server.URL, "acme", WithOrgSlug("globex"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return client
}

// ---------------------------------------------------------------------------
// §25.2 rule 1 — login's third outcome
// ---------------------------------------------------------------------------

func TestLoginSurfacesTheSetupBranchAsAnOutcome(t *testing.T) {
	server, _ := acServer(t, nil)
	client := acClient(t, server)

	result, err := client.Login(context.Background(), "alice@example.com", "pw")
	if err != nil {
		t.Fatalf("the setup branch must be an outcome, not an error: %v", err)
	}
	if !result.MFASetupRequired {
		t.Fatal("expected MFASetupRequired")
	}
	if result.MFARequired {
		t.Fatal("MFARequired and MFASetupRequired are different states")
	}
	if result.SetupToken.expose() != acSetupToken {
		t.Fatalf("setup token: got %q", result.SetupToken.expose())
	}
}

func TestAGenuine403StillRaises(t *testing.T) {
	// Matched on the body's discriminant, not on the status: a real
	// authorization failure is also a 403 and must not be read as a setup
	// branch just because it shares a status code.
	server, _ := acServer(t, map[string]http.HandlerFunc{
		loginPath: func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"tenant suspended"}`))
		},
	})
	client := acClient(t, server)

	_, err := client.Login(context.Background(), "alice@example.com", "pw")
	var authzErr *AuthzError
	if !errors.As(err, &authzErr) {
		t.Fatalf("expected *AuthzError, got %T (%v)", err, err)
	}
}

func TestTheSetupTokenNeverRenders(t *testing.T) {
	server, _ := acServer(t, nil)
	result, err := acClient(t, server).Login(context.Background(), "alice@example.com", "pw")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	for _, format := range []string{"%v", "%+v", "%s", "%q", "%#v"} {
		if rendered := fmt.Sprintf(format, result); strings.Contains(rendered, acSetupToken) {
			t.Fatalf("setup token leaked via %s: %s", format, rendered)
		}
	}
}

// ---------------------------------------------------------------------------
// MFA enrolment
// ---------------------------------------------------------------------------

func TestMfaEnrollReturnsTheSecretAndURI(t *testing.T) {
	server, _ := acServer(t, nil)
	enrolment, err := acClient(t, server).MfaEnroll(context.Background())
	if err != nil {
		t.Fatalf("MfaEnroll: %v", err)
	}
	if enrolment.SecretBase32.expose() != acSecret {
		t.Fatalf("secret: got %q", enrolment.SecretBase32.expose())
	}
	if !strings.Contains(enrolment.TotpURI.expose(), acSecret) {
		t.Fatal("the URI should carry the secret — that is why both are Sensitive")
	}
}

func TestMfaSecretNeverRenders(t *testing.T) {
	server, _ := acServer(t, nil)
	enrolment, err := acClient(t, server).MfaEnroll(context.Background())
	if err != nil {
		t.Fatalf("MfaEnroll: %v", err)
	}

	surfaces := []string{
		enrolment.SecretBase32.String(),
		enrolment.TotpURI.String(),
	}
	for _, format := range []string{"%v", "%+v", "%s", "%q", "%#v"} {
		surfaces = append(surfaces, fmt.Sprintf(format, enrolment))
	}
	if marshalled, err := json.Marshal(enrolment); err == nil {
		surfaces = append(surfaces, string(marshalled))
	}
	// Scanning for the VALUE, not the field name. TotpURI contains the secret,
	// so an SDK that wrapped only SecretBase32 fails right here.
	for _, surface := range surfaces {
		if strings.Contains(surface, acSecret) {
			t.Fatalf("the TOTP secret leaked into %q", surface)
		}
	}
}

func TestMfaConfirmActivatesTheFactor(t *testing.T) {
	server, _ := acServer(t, nil)
	enabled, err := acClient(t, server).MfaConfirm(context.Background(), "123456")
	if err != nil {
		t.Fatalf("MfaConfirm: %v", err)
	}
	if !enabled {
		t.Fatal("expected mfa_enabled=true")
	}
}

func TestMfaConfirmRaisesOnAWrongCode(t *testing.T) {
	server, _ := acServer(t, nil)
	_, err := acClient(t, server).MfaConfirm(context.Background(), "000000")
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("expected *AuthError, got %T (%v)", err, err)
	}
}

func TestTheForcedPathRunsEndToEnd(t *testing.T) {
	server, capture := acServer(t, nil)
	client := acClient(t, server)

	login, err := client.Login(context.Background(), "alice@example.com", "pw")
	if err != nil || !login.MFASetupRequired {
		t.Fatalf("expected the setup branch: %v %#v", err, login)
	}

	enrolment, err := client.MfaSetupEnroll(context.Background(), login.SetupToken)
	if err != nil {
		t.Fatalf("MfaSetupEnroll: %v", err)
	}
	if enrolment.SecretBase32.expose() != acSecret {
		t.Fatal("wrong secret")
	}
	if capture.bodies[mfaSetupEnrollPath]["setup_token"] != acSetupToken {
		t.Fatalf("setup token not sent: %#v", capture.bodies[mfaSetupEnrollPath])
	}

	done, err := client.MfaSetupConfirm(context.Background(), login.SetupToken, "123456")
	if err != nil {
		t.Fatalf("MfaSetupConfirm: %v", err)
	}
	if done.MFARequired || done.MFASetupRequired {
		t.Fatal("the login should be complete")
	}
	// It IS the completion of a login, so it adopts credentials (§25.2 rule 2).
	if client.cookieValue(accessCookie) == "" {
		t.Fatal("MfaSetupConfirm did not adopt the session")
	}
}

// ---------------------------------------------------------------------------
// Email verification
// ---------------------------------------------------------------------------

func TestVerifyEmailSendsTheTokenInTheBody(t *testing.T) {
	server, capture := acServer(t, nil)
	if err := acClient(t, server).VerifyEmail(context.Background(), "verify-tok", acTenantUUID); err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}
	body := capture.bodies[verifyEmailPath]
	if body["token"] != "verify-tok" || body["tenant_id"] != acTenantUUID {
		t.Fatalf("unexpected body: %#v", body)
	}
	if strings.Contains(capture.urls[verifyEmailPath], "token=") {
		t.Fatal("the token must be a body field, not a query parameter")
	}
}

func TestResendVerification(t *testing.T) {
	server, capture := acServer(t, nil)
	if err := acClient(t, server).ResendVerification(context.Background(), "alice@example.com", acTenantUUID); err != nil {
		t.Fatalf("ResendVerification: %v", err)
	}
	body := capture.bodies[resendVerificationPath]
	if body["email"] != "alice@example.com" || body["tenant_id"] != acTenantUUID {
		t.Fatalf("unexpected body: %#v", body)
	}
}

// ---------------------------------------------------------------------------
// §25.4 — password reset
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// §25.7 — the two resends are two operations
// ---------------------------------------------------------------------------

// The authenticated resend carries NO address, and hits its own path.
//
// The body assertion is the one that matters: a signature with no address
// parameter proves nothing about what the SDK serializes, and an address on
// this endpoint would let an authenticated session mail an arbitrary one.
func TestResendOwnVerificationSendsNoAddress(t *testing.T) {
	server, capture := acServer(t, nil)
	if err := acClient(t, server).ResendOwnVerification(context.Background()); err != nil {
		t.Fatalf("ResendOwnVerification: %v", err)
	}
	if body := capture.bodies[resendOwnVerificationPath]; len(body) != 0 {
		t.Fatalf("caller-supplied data went out: %v", body)
	}
}

// The two resends are distinct operations against distinct paths.
//
// An SDK that aliased one to the other would reintroduce the exact defect §25.7
// exists to describe, and every other test here would still pass — so this
// asserts on the path each one actually reached.
func TestTheTwoResendsReachDifferentEndpoints(t *testing.T) {
	server, capture := acServer(t, nil)
	c := acClient(t, server)

	if err := c.ResendVerification(context.Background(), "alice@example.com", acTenantUUID); err != nil {
		t.Fatalf("ResendVerification: %v", err)
	}
	if err := c.ResendOwnVerification(context.Background()); err != nil {
		t.Fatalf("ResendOwnVerification: %v", err)
	}
	if capture.hits[resendVerificationPath] != 1 || capture.hits[resendOwnVerificationPath] != 1 {
		t.Fatalf("expected one call each, got public=%d own=%d",
			capture.hits[resendVerificationPath], capture.hits[resendOwnVerificationPath])
	}
}

// 409 surfaces, and is NOT retried through the public endpoint.
//
// The bug this operation exists to fix was a success return on a request that
// achieved nothing, so "returns an error" is the assertion — and the public
// endpoint's zero calls is what rules out the §25.7 rule 2 fallback, which
// would turn both failures back into a nil error with an extra round-trip.
func TestResendOwnVerificationSurfacesA409WithoutFallingBack(t *testing.T) {
	server, capture := acServer(t, map[string]http.HandlerFunc{
		resendOwnVerificationPath: func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusConflict)
		},
	})

	err := acClient(t, server).ResendOwnVerification(context.Background())
	if err == nil {
		t.Fatal("a 409 must not resolve into success")
	}
	var authzErr *AuthzError
	if !errors.As(err, &authzErr) {
		t.Fatalf("409 mapped to %T, want *AuthzError", err)
	}
	if capture.hits[resendVerificationPath] != 0 {
		t.Fatal("fell back to the enumeration-safe endpoint, rebuilding the bug")
	}
}

// 429 surfaces too, as the §2 mapping of a rate limit.
func TestResendOwnVerificationSurfacesTheDailyLimit(t *testing.T) {
	server, capture := acServer(t, map[string]http.HandlerFunc{
		resendOwnVerificationPath: func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusTooManyRequests)
		},
	})

	err := acClient(t, server).ResendOwnVerification(context.Background())
	var netErr *NetworkError
	if !errors.As(err, &netErr) {
		t.Fatalf("429 mapped to %T, want *NetworkError", err)
	}
	if capture.hits[resendVerificationPath] != 0 {
		t.Fatal("fell back to the enumeration-safe endpoint")
	}
}

// ---------------------------------------------------------------------------
// §5.2 — organization-level principals
// ---------------------------------------------------------------------------

// OrganizationLevel is carried through from the login response.
//
// It is what an application checks BEFORE offering a tenant switch: such a
// principal changes the tenant it acts on with a header on the next request,
// and an ordinary one cannot, so offering the switch to both turns a
// distinction the server made into a 403 the user discovers.
func TestLoginReportsAnOrganizationLevelPrincipal(t *testing.T) {
	// The nil row is the one that matters: a server older than contract 1.31
	// omits the field, and false is the safe reading — the client then offers
	// no cross-tenant action rather than one that would fail.
	for _, tc := range []struct {
		name string
		user map[string]any
		want bool
	}{
		{"true", map[string]any{"id": "u1", "organization_level": true}, true},
		{"false", map[string]any{"id": "u1", "organization_level": false}, false},
		{"absent", map[string]any{"id": "u1"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token := makeAccessTokenWithOrgID(t, waOrgUUID)
			user := tc.user
			server, _ := acServer(t, map[string]http.HandlerFunc{
				loginPath: func(w http.ResponseWriter, r *http.Request) {
					http.SetCookie(w, &http.Cookie{Name: "axiam_access", Value: token, Path: "/"})
					http.SetCookie(w, &http.Cookie{Name: "axiam_refresh", Value: "refresh-cookie", Path: "/"})
					_ = json.NewEncoder(w).Encode(map[string]any{
						"user":       user,
						"session_id": "33333333-3333-3333-3333-333333333333",
						"expires_in": 900,
					})
				},
			})

			result, err := acClient(t, server).Login(
				context.Background(), "alice@example.com", "correct horse battery staple")
			if err != nil {
				t.Fatalf("Login: %v", err)
			}
			if result.OrganizationLevel != tc.want {
				t.Fatalf("OrganizationLevel was %v, want %v", result.OrganizationLevel, tc.want)
			}
		})
	}
}

func TestRequestResetResolvesForAnUnknownAddress(t *testing.T) {
	// The uniform response is the whole mechanism; an SDK that surfaced a
	// "no such user" signal would rebuild the enumeration oracle it prevents.
	server, capture := acServer(t, nil)
	client := acClient(t, server)

	if err := client.RequestPasswordReset(context.Background(), PasswordResetRequest{
		Email: "nobody@example.com",
	}); err != nil {
		t.Fatalf("an unknown address must not raise: %v", err)
	}
	body := capture.bodies[resetPath]
	if body["org_slug"] != "globex" || body["tenant_slug"] != "acme" {
		t.Fatalf("workspace not filled from the client: %#v", body)
	}
}

func TestResetContextReturnsTheOpaquePolicyAndNoIdentity(t *testing.T) {
	server, _ := acServer(t, nil)
	context_, err := acClient(t, server).PasswordResetContext(context.Background(), acResetToken)
	if err != nil {
		t.Fatalf("PasswordResetContext: %v", err)
	}
	if context_.Opaque["mode"] != "required" {
		t.Fatalf("unexpected policy: %#v", context_.Opaque)
	}
	// Contract 1.26 removed the username. The struct has exactly one field, so
	// reintroducing an identity downstream fails to compile rather than
	// slipping through a security review.
	marshalled, err := json.Marshal(context_)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(marshalled, &fields); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(fields) != 1 {
		t.Fatalf("the reset context must disclose only the OPAQUE policy: %#v", fields)
	}
}

func TestResetContext404IsOneIndistinguishableFailure(t *testing.T) {
	server, _ := acServer(t, nil)
	if _, err := acClient(t, server).PasswordResetContext(context.Background(), "some-other-token"); err == nil {
		t.Fatal("expected an error for an unknown token")
	}
}

func TestConfirmResetSendsTheOpaqueRecordWhenThereIsOne(t *testing.T) {
	server, capture := acServer(t, nil)
	client := acClient(t, server)

	if err := client.ConfirmPasswordReset(context.Background(), PasswordResetConfirmation{
		Token:       acResetToken,
		NewPassword: "new-password",
		TenantID:    acTenantUUID,
		Opaque:      map[string]any{"registration_record": "abc"},
	}); err != nil {
		t.Fatalf("ConfirmPasswordReset: %v", err)
	}
	opaque, ok := capture.bodies[resetConfirmPath]["opaque"].(map[string]any)
	if !ok || opaque["registration_record"] != "abc" {
		t.Fatalf("opaque record not sent: %#v", capture.bodies[resetConfirmPath])
	}
}

func TestConfirmResetOmitsOpaqueEntirelyWhenThereIsNone(t *testing.T) {
	server, capture := acServer(t, nil)
	if err := acClient(t, server).ConfirmPasswordReset(context.Background(), PasswordResetConfirmation{
		Token:       acResetToken,
		NewPassword: "new-password",
		TenantID:    acTenantUUID,
	}); err != nil {
		t.Fatalf("ConfirmPasswordReset: %v", err)
	}
	if _, present := capture.bodies[resetConfirmPath]["opaque"]; present {
		t.Fatal("an absent OPAQUE record must be omitted, not sent as null")
	}
}
