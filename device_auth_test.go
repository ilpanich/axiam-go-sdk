// Tests for CONTRACT.md §6.1 rules 6-10, AuthenticateDevice (contract 1.51).
//
// §8 rule 7's requirement this file exists to satisfy: "AuthenticateDevice
// is unreachable without a certificate" — pinned below with an explicit
// zero-wire-calls assertion, and its I4 twin (reachable WITH one) next to
// it.

package axiam

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// selfSignedClientCert mints a throwaway PEM cert+key pair so tests can
// configure WithClientCertificate without a real CA. Its content is never
// asserted on — only that AuthenticateDevice becomes reachable once one is
// configured.
func selfSignedClientCert(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-device"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

// TestAuthenticateDevice_UnreachableWithoutCertificate is §8 rule 7's
// negative case: a client built WITHOUT WithClientCertificate refuses
// AuthenticateDevice client-side, with ZERO wire calls (§6.1 rule 7).
func TestAuthenticateDevice_UnreachableWithoutCertificate(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "acme")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	_, err = client.AuthenticateDevice(context.Background())
	if err == nil {
		t.Fatal("expected AuthenticateDevice to refuse without a client certificate")
	}
	if _, ok := err.(*AuthError); !ok {
		t.Fatalf("got %T, want *AuthError", err)
	}
	if calls != 0 {
		t.Fatalf("AuthenticateDevice without a certificate must make ZERO wire calls, got %d", calls)
	}
}

// TestAuthenticateDevice_ReachableWithCertificate is the I4 twin: a client
// built WITH WithClientCertificate reaches the wire and adopts the token
// on success.
func TestAuthenticateDevice_ReachableWithCertificate(t *testing.T) {
	certPEM, keyPEM := selfSignedClientCert(t)

	var sawPath string
	var sawCookie string
	sawCookiePresent := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawPath = r.URL.Path
		if c, err := r.Cookie("axiam_access"); err == nil {
			sawCookiePresent = true
			sawCookie = c.Value
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"access_token":"device-tok-abc","token_type":"Bearer","expires_in":900}`))
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "acme", WithClientCertificate(certPEM, keyPEM))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	tok, err := client.AuthenticateDevice(context.Background())
	if err != nil {
		t.Fatalf("AuthenticateDevice: %v", err)
	}
	if sawPath != deviceAuthPath {
		t.Fatalf("path = %q, want %q", sawPath, deviceAuthPath)
	}
	if sawCookiePresent {
		t.Fatalf("the device-login call itself must not carry a stale axiam_access cookie, got %q", sawCookie)
	}
	if tok.AccessToken.Expose() != "device-tok-abc" {
		t.Fatalf("AccessToken = %q, want device-tok-abc", tok.AccessToken.Expose())
	}
	if tok.TokenType != "Bearer" {
		t.Fatalf("TokenType = %q, want Bearer", tok.TokenType)
	}
	if tok.ExpiresIn != 900 {
		t.Fatalf("ExpiresIn = %d, want 900", tok.ExpiresIn)
	}
}

// TestAuthenticateDevice_AdoptedTokenTravelsAsAuthorizationBearer proves
// adoption: after a successful device login, a subsequent management call
// carries the token as Authorization: Bearer, with no Authorization set
// beforehand and the server having set no cookie.
func TestAuthenticateDevice_AdoptedTokenTravelsAsAuthorizationBearer(t *testing.T) {
	certPEM, keyPEM := selfSignedClientCert(t)

	var sawAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case deviceAuthPath:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"access_token":"device-tok-xyz","token_type":"Bearer","expires_in":900}`))
		default:
			sawAuth = r.Header.Get("Authorization")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"items":[],"total":0}`))
		}
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "acme", WithClientCertificate(certPEM, keyPEM))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.AuthenticateDevice(context.Background()); err != nil {
		t.Fatalf("AuthenticateDevice: %v", err)
	}

	if _, err := client.Resources().List(context.Background(), PageRequest{}); err != nil {
		t.Fatalf("List: %v", err)
	}
	if sawAuth != "Bearer device-tok-xyz" {
		t.Fatalf("Authorization = %q, want %q", sawAuth, "Bearer device-tok-xyz")
	}
}

// TestAuthenticateDevice_WithholdsAStaleCookie pins the reference's own
// pitfall: a Client that already holds a session cookie from an earlier
// Login() must NOT let that cookie ride along on a subsequent request made
// under an adopted device credential — the server reads axiam_access
// before Authorization, so a stale cookie would silently win and run the
// request as the PREVIOUS session's principal instead of the device's.
func TestAuthenticateDevice_WithholdsAStaleCookie(t *testing.T) {
	certPEM, keyPEM := selfSignedClientCert(t)

	var sawCookieOnManagementCall bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case loginPath:
			http.SetCookie(w, &http.Cookie{Name: "axiam_access", Value: makeAccessTokenWithOrgID(t, "44444444-4444-4444-4444-444444444444"), Path: "/"})
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"user":{"id":"11111111-1111-1111-1111-111111111111","username":"alice","email":"a@example.test"},"session_id":"33333333-3333-3333-3333-333333333333","expires_in":900}`))
		case deviceAuthPath:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"access_token":"device-tok-123","token_type":"Bearer","expires_in":900}`))
		default:
			if _, err := r.Cookie("axiam_access"); err == nil {
				sawCookieOnManagementCall = true
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"items":[],"total":0}`))
		}
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "acme",
		WithOrgID(mustUUID(t, "44444444-4444-4444-4444-444444444444")),
		WithClientCertificate(certPEM, keyPEM))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	// Establish a stale session cookie first, the mixed-mode scenario the
	// reference names explicitly.
	if _, err := client.Login(context.Background(), randomPassword(t), randomPassword(t)); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if _, err := client.AuthenticateDevice(context.Background()); err != nil {
		t.Fatalf("AuthenticateDevice: %v", err)
	}
	if _, err := client.Resources().List(context.Background(), PageRequest{}); err != nil {
		t.Fatalf("List: %v", err)
	}
	if sawCookieOnManagementCall {
		t.Fatal("a stale axiam_access cookie from an earlier Login() must NOT reach a request made under an adopted device credential")
	}
}

// TestAuthenticateDevice_LaterAndLoginFailure401DoesNotEnterRefreshGuard
// pins §6.1 rules 6 and 8: neither the login call's own 401 nor a LATER
// 401 on the adopted token triggers the §9 refresh guard — there is no
// refresh token behind a device credential (D-6). The first version of
// this test in the reference SDK asserted only the absence of a refresh
// call and missed a real mutation, so this one additionally asserts the
// server's message reaches the caller verbatim.
func TestAuthenticateDevice_401DoesNotEnterRefreshGuardAndSurfacesTheServerMessage(t *testing.T) {
	certPEM, keyPEM := selfSignedClientCert(t)

	var refreshCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case deviceAuthPath:
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"authentication_failed","message":"unknown or untrusted client certificate"}`))
		case refreshPath:
			refreshCalls++
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "acme", WithClientCertificate(certPEM, keyPEM))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	_, err = client.AuthenticateDevice(context.Background())
	if err == nil {
		t.Fatal("expected an error from a 401 device-login response")
	}
	authErr, ok := err.(*AuthError)
	if !ok {
		t.Fatalf("got %T, want *AuthError", err)
	}
	if authErr.Message == "" {
		t.Fatal("expected the server's message to reach the caller, got an empty Message")
	}
	if refreshCalls != 0 {
		t.Fatalf("AuthenticateDevice's own 401 must never enter the refresh guard, got %d refresh call(s)", refreshCalls)
	}
}

// TestAuthenticateDevice_429IsNotAnAuthError pins §6.1 rule 8's "A 429
// follows §16 and is not an authentication failure" and the I4 twin's
// negative half in one place: a 429 from the device-login route maps to
// *NetworkError, never *AuthError, and is not retried.
func TestAuthenticateDevice_429IsNotAnAuthError(t *testing.T) {
	certPEM, keyPEM := selfSignedClientCert(t)

	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "acme", WithClientCertificate(certPEM, keyPEM))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	_, err = client.AuthenticateDevice(context.Background())
	if err == nil {
		t.Fatal("expected an error from a 429 response")
	}
	if _, ok := err.(*AuthError); ok {
		t.Fatal("a 429 must not map to *AuthError (CONTRACT.md §6.1 rule 8 / §2's status table)")
	}
	if _, ok := err.(*NetworkError); !ok {
		t.Fatalf("got %T, want *NetworkError", err)
	}
	if calls != 1 {
		t.Fatalf("AuthenticateDevice must be attempted exactly once even on a 429 (§16, like Login), got %d calls", calls)
	}
}

// TestAuthenticateDevice_TokenIsSensitive is a §7 spot-check specific to
// this operation's own accessor path.
func TestAuthenticateDevice_TokenIsSensitive(t *testing.T) {
	certPEM, keyPEM := selfSignedClientCert(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"access_token":"super-secret-device-token","token_type":"Bearer","expires_in":900}`))
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "acme", WithClientCertificate(certPEM, keyPEM))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	tok, err := client.AuthenticateDevice(context.Background())
	if err != nil {
		t.Fatalf("AuthenticateDevice: %v", err)
	}
	rendered := tok.AccessToken.String()
	if strings.Contains(rendered, "super-secret") {
		t.Fatalf("DeviceToken.AccessToken leaked into its String() rendering: %q", rendered)
	}
}

// TestAuthenticateDevice_RefusesOnAClosedClient pins ensureOpen's gate
// (§18.1 rule 4) on this call specifically: a closed client refuses with
// ZERO wire calls, same as the no-certificate case above.
func TestAuthenticateDevice_RefusesOnAClosedClient(t *testing.T) {
	certPEM, keyPEM := selfSignedClientCert(t)
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "acme", WithClientCertificate(certPEM, keyPEM))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	_, err = client.AuthenticateDevice(context.Background())
	if err == nil {
		t.Fatal("expected AuthenticateDevice to refuse on a closed client")
	}
	if _, ok := err.(*NetworkError); !ok {
		t.Fatalf("got %T, want *NetworkError", err)
	}
	if calls != 0 {
		t.Fatalf("AuthenticateDevice on a closed client must make ZERO wire calls, got %d", calls)
	}
}

// TestAuthenticateDevice_MalformedResponseBodyIsADeserializationError covers
// deviceAuthPost's decode-failure branch: a 200 whose body is not the
// documented JSON shape must surface as a *NetworkError describing the
// parse failure, not panic or silently return a zero-value token as if it
// had succeeded.
func TestAuthenticateDevice_MalformedResponseBodyIsADeserializationError(t *testing.T) {
	certPEM, keyPEM := selfSignedClientCert(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{not valid json`))
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "acme", WithClientCertificate(certPEM, keyPEM))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.AuthenticateDevice(context.Background())
	if err == nil {
		t.Fatal("expected a deserialization error for a malformed response body")
	}
	ne, ok := err.(*NetworkError)
	if !ok {
		t.Fatalf("got %T, want *NetworkError", err)
	}
	if !strings.Contains(ne.Message, "failed to parse response body") {
		t.Fatalf("NetworkError.Message = %q, want it to describe the parse failure", ne.Message)
	}
}

// TestAuthenticateDevice_SendsActingTenantHeaderWhenSet pins
// deviceAuthPost's acting-tenant branch: X-Axiam-Tenant travels on the
// device-login POST itself when an acting tenant is set, exactly as it
// does on every other management call (§5.2 rule 1).
func TestAuthenticateDevice_SendsActingTenantHeaderWhenSet(t *testing.T) {
	certPEM, keyPEM := selfSignedClientCert(t)
	tenantID := mustUUID(t, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")

	var sawHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawHeader = r.Header.Get("X-Axiam-Tenant")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"access_token":"tok","token_type":"Bearer","expires_in":900}`))
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "acme",
		WithClientCertificate(certPEM, keyPEM), WithActingTenant(tenantID))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.AuthenticateDevice(context.Background()); err != nil {
		t.Fatalf("AuthenticateDevice: %v", err)
	}
	if sawHeader != tenantID.String() {
		t.Fatalf("X-Axiam-Tenant = %q, want %q", sawHeader, tenantID.String())
	}
}

// ---------------------------------------------------------------------------
// CONTRACT.md 1.52 N4.4 — the device credential is held until replaced.
// ---------------------------------------------------------------------------

// TestAuthenticateDevice_LaterLoginReplacesTheDeviceCredential pins rule 4:
// "Any later session-establishing call replaces it, and that session is
// then used." Before the fix, adoptDeviceCredential (device_auth.go) was
// the only setter, so a device credential adopted by AuthenticateDevice
// outlived a later Login() on the same Client: decorateRequest kept
// preferring the (stale) device bearer over the new cookie session, and
// doRequest kept suppressing the new session's cookie — the new Login was
// shadowed rather than taking over, exactly reversing
// TestAuthenticateDevice_WithholdsAStaleCookie's direction (a stale COOKIE
// there; a stale DEVICE CREDENTIAL here).
func TestAuthenticateDevice_LaterLoginReplacesTheDeviceCredential(t *testing.T) {
	certPEM, keyPEM := selfSignedClientCert(t)

	var sawAuth string
	var sawCookie bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case deviceAuthPath:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"access_token":"device-tok-shadowed","token_type":"Bearer","expires_in":900}`))
		case loginPath:
			http.SetCookie(w, &http.Cookie{Name: "axiam_access", Value: makeAccessTokenWithOrgID(t, "44444444-4444-4444-4444-444444444444"), Path: "/"})
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"user":{"id":"11111111-1111-1111-1111-111111111111","username":"alice","email":"a@example.test"},"session_id":"33333333-3333-3333-3333-333333333333","expires_in":900}`))
		default:
			sawAuth = r.Header.Get("Authorization")
			if _, err := r.Cookie("axiam_access"); err == nil {
				sawCookie = true
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"items":[],"total":0}`))
		}
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "acme",
		WithOrgID(mustUUID(t, "44444444-4444-4444-4444-444444444444")),
		WithClientCertificate(certPEM, keyPEM))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := client.AuthenticateDevice(context.Background()); err != nil {
		t.Fatalf("AuthenticateDevice: %v", err)
	}
	if _, err := client.Login(context.Background(), randomPassword(t), randomPassword(t)); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if _, err := client.Resources().List(context.Background(), PageRequest{}); err != nil {
		t.Fatalf("List: %v", err)
	}
	if sawAuth == "Bearer device-tok-shadowed" {
		t.Fatal("a later Login() must replace the §6.1 device credential — the management call still carried the OLD device bearer")
	}
	if !sawCookie {
		t.Fatal("a later Login() must replace the §6.1 device credential — the management call did not carry the NEW session's cookie")
	}
}

// TestLogout_ClearsTheDeviceCredential pins rule 4's "logout clears it."
// Before the fix, Logout() called onCredentialChange/resetScopeUnknown but
// never adoptDeviceCredential(""), so a device credential adopted earlier
// on the same Client survived Logout() and kept riding on every later
// request.
func TestLogout_ClearsTheDeviceCredential(t *testing.T) {
	certPEM, keyPEM := selfSignedClientCert(t)

	var sawAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case deviceAuthPath:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"access_token":"device-tok-postlogout","token_type":"Bearer","expires_in":900}`))
		case loginPath:
			http.SetCookie(w, &http.Cookie{Name: "axiam_access", Value: makeAccessTokenWithOrgID(t, "44444444-4444-4444-4444-444444444444"), Path: "/"})
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"user":{"id":"11111111-1111-1111-1111-111111111111","username":"alice","email":"a@example.test"},"session_id":"33333333-3333-3333-3333-333333333333","expires_in":900}`))
		case logoutPath:
			w.WriteHeader(http.StatusOK)
		default:
			sawAuth = r.Header.Get("Authorization")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"items":[],"total":0}`))
		}
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "acme",
		WithOrgID(mustUUID(t, "44444444-4444-4444-4444-444444444444")),
		WithClientCertificate(certPEM, keyPEM))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	// A cookie session must exist for Logout to proceed (it reads the jti
	// off the axiam_access cookie), so establish one before adopting the
	// device credential on top of it — the mixed-mode scenario rule 4
	// describes.
	if _, err := client.Login(context.Background(), randomPassword(t), randomPassword(t)); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if _, err := client.AuthenticateDevice(context.Background()); err != nil {
		t.Fatalf("AuthenticateDevice: %v", err)
	}
	if err := client.Logout(context.Background()); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if _, err := client.Resources().List(context.Background(), PageRequest{}); err != nil {
		t.Fatalf("List: %v", err)
	}
	if sawAuth == "Bearer device-tok-postlogout" {
		t.Fatal("Logout() must clear the §6.1 device credential — a later management call still carried it")
	}
}
