package axiam

// Contract 1.62, §14.1 rules 1 to 4 and §14.2 rules 5 and 8 (item (m), the
// maintainer's option (a) and the 2026-10-16 "same rules" reading): the device
// grant authenticates its client at BOTH device_authorize and the poll.
//
// What this SDK can configure as a credential is a client secret
// (WithOidcClientSecret) and an mTLS certificate (WithClientCertificate). It
// generates no private_key_jwt assertion (§21.8 is optional) and no DPoP proof
// (§21.7.3: the resource-server half only), so those two forms are asserted as
// ABSENT from the wire, and a refusal of a client that needs them is asserted as
// the 401 invalid_client it is.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
)

// recordedDeviceRequest is what one device-endpoint request carried.
type recordedDeviceRequest struct {
	path          string
	form          url.Values
	authorization string
	dpop          string
	peerCerts     int
}

// deviceRecorder collects the requests the two device endpoints saw.
type deviceRecorder struct {
	mu       sync.Mutex
	requests []recordedDeviceRequest
}

func (d *deviceRecorder) add(r *http.Request) {
	_ = r.ParseForm()
	rec := recordedDeviceRequest{
		path: r.URL.Path, form: r.PostForm,
		authorization: r.Header.Get("Authorization"), dpop: r.Header.Get("DPoP"),
	}
	if r.TLS != nil {
		rec.peerCerts = len(r.TLS.PeerCertificates)
	}
	d.mu.Lock()
	d.requests = append(d.requests, rec)
	d.mu.Unlock()
}

func (d *deviceRecorder) at(path string) []recordedDeviceRequest {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []recordedDeviceRequest
	for _, r := range d.requests {
		if r.path == path {
			out = append(out, r)
		}
	}
	return out
}

const (
	deviceAuthorizePath = "/oauth2/device_authorization"
	deviceTokenPath     = "/oauth2/token"
)

// wireDeviceServer routes both device endpoints through the recorder. approveOn
// is the 1-based poll that is approved; earlier polls are authorization_pending.
func wireDeviceServer(srv *oidcTestServer, rec *deviceRecorder, approveOn int) {
	srv.DeviceAuthHandler = func(w http.ResponseWriter, r *http.Request) {
		rec.add(r)
		writeStatusJSON(w, http.StatusOK, deviceAuthBody(nil))
	}
	polls := 0
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		rec.add(r)
		polls++
		if polls < approveOn {
			writeStatusJSON(w, http.StatusBadRequest, oauthErrorBody("authorization_pending"))
			return
		}
		writeStatusJSON(w, http.StatusOK, deviceSuccessBody())
	}
}

// assertNoOtherCredential fails when a request carries anything that
// authenticates a client beyond client_id and (when want is non-empty) the
// secret: no Authorization header at all (so no Basic, whatever the client is
// registered for), no assertion, no DPoP proof.
func assertNoOtherCredential(t *testing.T, where string, r recordedDeviceRequest) {
	t.Helper()
	if r.authorization != "" {
		t.Errorf("%s: sent Authorization %q; no SDK sends Authorization: Basic to a device endpoint (§14.1 rule 2)", where, r.authorization)
	}
	for _, key := range []string{"client_assertion", "client_assertion_type"} {
		if r.form.Has(key) {
			t.Errorf("%s: sent %s, but this SDK generates no private_key_jwt assertion", where, key)
		}
	}
	if r.dpop != "" {
		t.Errorf("%s: sent a DPoP proof, but this SDK generates none (§21.7.3)", where)
	}
}

// A client configured with a secret sends it as client_secret in the body at
// device_authorize AND at every poll, with no Authorization header at either,
// whichever of client_secret_post and client_secret_basic the client is
// registered for (the discovery document here advertises ONLY basic).
func TestDeviceGrant_AConfidentialClientSendsItsSecretInTheBodyAtBothEndpointsAndNeverBasic(t *testing.T) {
	for _, method := range []string{"client_secret_post", "client_secret_basic"} {
		t.Run(method, func(t *testing.T) {
			srv := newOidcTestServer(t)
			method := method
			srv.DiscoveryDoc = func(base string) OidcConfiguration {
				doc := discoveryDoc(base)
				doc.TokenEndpointAuthMethodsSupported = []string{method}
				return doc
			}
			rec := &deviceRecorder{}
			wireDeviceServer(srv, rec, 2)
			client := newDeviceClient(t, srv, WithOidcClientSecret("device-secret-value"))
			t.Cleanup(func() { _ = client.Close() })

			var shown DeviceAuthorization
			_, err := client.DeviceLogin(context.Background(), DeviceLoginParams{
				TenantID:   testTenantUUID,
				OnUserCode: func(a DeviceAuthorization) error { shown = a; return nil },
			})
			if err != nil {
				t.Fatalf("DeviceLogin: %v", err)
			}
			if shown.UserCode != testUserCode {
				t.Fatalf("user code not surfaced: %+v", shown)
			}

			authorize, polls := rec.at(deviceAuthorizePath), rec.at(deviceTokenPath)
			if len(authorize) != 1 || len(polls) != 2 {
				t.Fatalf("want one authorize and two polls, got %d and %d", len(authorize), len(polls))
			}
			if got := authorize[0].form.Get("client_secret"); got != "device-secret-value" {
				t.Errorf("device_authorize client_secret = %q", got)
			}
			assertNoOtherCredential(t, "device_authorize", authorize[0])
			for i, poll := range polls {
				if got := poll.form.Get("client_secret"); got != "device-secret-value" {
					t.Errorf("poll %d client_secret = %q, want it in the form body on every poll", i+1, got)
				}
				if got := poll.form.Get("client_id"); got != "my-device" {
					t.Errorf("poll %d client_id = %q: the poll names its client (§14.1 rule 3)", i+1, got)
				}
				if got := poll.form.Get("grant_type"); got != deviceCodeGrantType {
					t.Errorf("poll %d grant_type = %q", i+1, got)
				}
				assertNoOtherCredential(t, "device_poll", poll)
			}
			if got := authorize[0].form.Get("client_id"); got != "my-device" {
				t.Errorf("device_authorize client_id = %q", got)
			}
		})
	}
}

// A client configured with no credential sends neither a client_secret nor any
// other credential at either endpoint, sends client_id on every poll, and is
// not refused client-side (§14.1 rule 1).
func TestDeviceGrant_APublicClientSendsNoCredentialAtEitherEndpointAndIsNotRefused(t *testing.T) {
	srv := newOidcTestServer(t)
	rec := &deviceRecorder{}
	wireDeviceServer(srv, rec, 3)
	client := newDeviceClient(t, srv) // no secret, no certificate
	t.Cleanup(func() { _ = client.Close() })

	if _, err := client.DeviceLogin(context.Background(), DeviceLoginParams{
		TenantID:   testTenantUUID,
		OnUserCode: func(DeviceAuthorization) error { return nil },
	}); err != nil {
		t.Fatalf("a public client is not refused client-side: %v", err)
	}
	authorize, polls := rec.at(deviceAuthorizePath), rec.at(deviceTokenPath)
	if len(authorize) != 1 || len(polls) != 3 {
		t.Fatalf("want one authorize and three polls, got %d and %d", len(authorize), len(polls))
	}
	for i, r := range append(authorize, polls...) {
		if r.form.Has("client_secret") {
			t.Errorf("request %d: a public client sends no client_secret", i)
		}
		if r.form.Get("client_id") != "my-device" {
			t.Errorf("request %d: client_id = %q", i, r.form.Get("client_id"))
		}
		assertNoOtherCredential(t, "public client", r)
	}
}

// The single calls behave the same outside DeviceLogin: DeviceAuthorize and
// DevicePoll each carry the credential on their own.
func TestDeviceGrant_TheSingleCallsCarryTheCredentialWithoutDeviceLogin(t *testing.T) {
	srv := newOidcTestServer(t)
	rec := &deviceRecorder{}
	wireDeviceServer(srv, rec, 1)
	ctx := context.Background()

	confidential := newDeviceClient(t, srv, WithOidcClientSecret("s3cr3t"))
	t.Cleanup(func() { _ = confidential.Close() })
	auth, err := confidential.DeviceAuthorize(ctx, DeviceAuthorizeParams{TenantID: testTenantUUID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := confidential.DevicePoll(ctx, DevicePollParams{DeviceCode: auth.DeviceCode, TenantID: testTenantUUID}); err != nil {
		t.Fatal(err)
	}
	public := newDeviceClient(t, srv)
	t.Cleanup(func() { _ = public.Close() })
	if _, err := public.DeviceAuthorize(ctx, DeviceAuthorizeParams{TenantID: testTenantUUID}); err != nil {
		t.Fatal(err)
	}
	if _, err := public.DevicePoll(ctx, DevicePollParams{DeviceCode: auth.DeviceCode, TenantID: testTenantUUID}); err != nil {
		t.Fatal(err)
	}

	authorize, polls := rec.at(deviceAuthorizePath), rec.at(deviceTokenPath)
	if authorize[0].form.Get("client_secret") != "s3cr3t" || polls[0].form.Get("client_secret") != "s3cr3t" {
		t.Error("the confidential client's single calls carry the secret")
	}
	if authorize[1].form.Has("client_secret") || polls[1].form.Has("client_secret") {
		t.Error("the public client's single calls carry none")
	}
}

// An mTLS client presents its certificate at BOTH device endpoints (on the
// connection, not in the body), and without a secret configured sends no
// client_secret.
func TestDeviceGrant_AnMTLSClientPresentsItsCertificateAtBothEndpoints(t *testing.T) {
	pki := newMTLSPKI(t)
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(pki.caCertPEM) {
		t.Fatal("client CA pool")
	}
	rec := &deviceRecorder{}
	var base string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(discoveryDoc(base))
	})
	mux.HandleFunc(deviceAuthorizePath, func(w http.ResponseWriter, r *http.Request) {
		rec.add(r)
		writeStatusJSON(w, http.StatusOK, deviceAuthBody(nil))
	})
	mux.HandleFunc(deviceTokenPath, func(w http.ResponseWriter, r *http.Request) {
		rec.add(r)
		writeStatusJSON(w, http.StatusOK, deviceSuccessBody())
	})
	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientCAs}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	base = srv.URL
	serverCAPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})

	client, err := NewClient(srv.URL, "acme",
		WithOidcClientID("my-device"),
		WithCustomCA(serverCAPEM),
		WithClientCertificate(pki.clientCertPEM, pki.clientKeyPEM),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })

	ctx := context.Background()
	auth, err := client.DeviceAuthorize(ctx, DeviceAuthorizeParams{TenantID: testTenantUUID})
	if err != nil {
		t.Fatalf("DeviceAuthorize over mTLS: %v", err)
	}
	if _, err := client.DevicePoll(ctx, DevicePollParams{DeviceCode: auth.DeviceCode, TenantID: testTenantUUID}); err != nil {
		t.Fatalf("DevicePoll over mTLS: %v", err)
	}
	for _, path := range []string{deviceAuthorizePath, deviceTokenPath} {
		got := rec.at(path)
		if len(got) != 1 {
			t.Fatalf("%s: %d requests", path, len(got))
		}
		if got[0].peerCerts != 1 {
			t.Errorf("%s: the server saw %d client certificates, want the configured one", path, got[0].peerCerts)
		}
		if got[0].form.Has("client_secret") {
			t.Errorf("%s: no secret was configured, so none is sent", path)
		}
		assertNoOtherCredential(t, path, got[0])
		if got[0].form.Get("client_id") != "my-device" {
			t.Errorf("%s: client_id = %q", path, got[0].form.Get("client_id"))
		}
	}
}

// §14.1 rule 4 and §14.2 rule 5: a 401 {"error":"invalid_client"} from either
// operation is an *OAuthProtocolError with that error, after exactly one
// request (no retry), and the §9 refresh guard is not entered.
func TestDeviceGrant_AnInvalidClientIsAnOAuthProtocolErrorAfterOneRequestAtEitherEndpoint(t *testing.T) {
	ctx := context.Background()

	t.Run("device_authorize", func(t *testing.T) {
		srv := newOidcTestServer(t)
		srv.DeviceAuthHandler = func(w http.ResponseWriter, r *http.Request) {
			writeStatusJSON(w, http.StatusUnauthorized, oauthErrorBody("invalid_client"))
		}
		client := newDeviceClient(t, srv, WithOidcClientSecret("wrong"))
		t.Cleanup(func() { _ = client.Close() })
		_, err := client.DeviceAuthorize(ctx, DeviceAuthorizeParams{TenantID: testTenantUUID})
		var protoErr *OAuthProtocolError
		if !errors.As(err, &protoErr) || protoErr.ErrorCode != "invalid_client" {
			t.Fatalf("want OAuthProtocolError invalid_client, got %T %v", err, err)
		}
		if srv.DeviceAuthCalls() != 1 {
			t.Fatalf("exactly one request, got %d", srv.DeviceAuthCalls())
		}
	})

	t.Run("device_poll", func(t *testing.T) {
		srv := newOidcTestServer(t)
		srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
			writeStatusJSON(w, http.StatusUnauthorized, oauthErrorBody("invalid_client"))
		}
		client := newDeviceClient(t, srv, WithOidcClientSecret("wrong"))
		t.Cleanup(func() { _ = client.Close() })
		_, err := client.DevicePoll(ctx, DevicePollParams{DeviceCode: Sensitive(testDeviceCode), TenantID: testTenantUUID})
		var protoErr *OAuthProtocolError
		if !errors.As(err, &protoErr) || protoErr.ErrorCode != "invalid_client" {
			t.Fatalf("want OAuthProtocolError invalid_client, got %T %v", err, err)
		}
		if srv.TokenCalls() != 1 {
			t.Fatalf("exactly one request, got %d", srv.TokenCalls())
		}
	})

	// Inside DeviceLogin the refusal is terminal: raised, never retried, and
	// never mistaken for a session that a refresh could cure.
	t.Run("device_login", func(t *testing.T) {
		srv := newOidcTestServer(t)
		srv.DeviceAuthHandler = func(w http.ResponseWriter, r *http.Request) {
			writeStatusJSON(w, http.StatusOK, deviceAuthBody(nil))
		}
		srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
			writeStatusJSON(w, http.StatusUnauthorized, oauthErrorBody("invalid_client"))
		}
		client := newDeviceClient(t, srv)
		t.Cleanup(func() { _ = client.Close() })
		_, err := client.DeviceLogin(ctx, DeviceLoginParams{
			TenantID: testTenantUUID, OnUserCode: func(DeviceAuthorization) error { return nil },
		})
		var protoErr *OAuthProtocolError
		if !errors.As(err, &protoErr) || protoErr.ErrorCode != "invalid_client" {
			t.Fatalf("want OAuthProtocolError invalid_client, got %T %v", err, err)
		}
		if srv.TokenCalls() != 1 {
			t.Fatalf("a terminal refusal is one poll, got %d", srv.TokenCalls())
		}
		// The refresh guard lives behind Refresh() alone (doRequest has no 401
		// interceptor); an invalid_client that had entered it would have come
		// back as the plain *AuthError of a failed refresh, not this type.
	})
}

// §14.6 (contract 1.62) and §12.1 rule 3 (C162-05): no Authorization header at
// either device endpoint or at a token request, even on a client that holds an
// adopted credential. The credential-adoption path applies a bearer to every
// same-origin non-/oauth2/ request; this pins, on the wire, that it never
// reaches /oauth2/device_authorization or /oauth2/token — whichever of the two
// credential sources (§6.1 device token, §12.1 adopted OIDC token) is held.
func TestDeviceGrant_NoAuthorizationHeaderAtEitherDeviceEndpointOrATokenRequestWhenACredentialIsAdopted(t *testing.T) {
	adopters := map[string]func(*Client){
		"device credential":  func(c *Client) { c.adoptDeviceCredential(Sensitive("adopted-device-token")) },
		"adopted oidc token": func(c *Client) { c.adoptOidcCredential(Sensitive("adopted-oidc-token")) },
	}
	for name, adopt := range adopters {
		t.Run(name, func(t *testing.T) {
			srv := newOidcTestServer(t)
			rec := &deviceRecorder{}
			wireDeviceServer(srv, rec, 1)
			client := newDeviceClient(t, srv, WithOidcClientSecret("device-secret-value"))
			t.Cleanup(func() { _ = client.Close() })
			adopt(client)

			ctx := context.Background()
			auth, err := client.DeviceAuthorize(ctx, DeviceAuthorizeParams{TenantID: testTenantUUID})
			if err != nil {
				t.Fatalf("DeviceAuthorize: %v", err)
			}
			if _, err := client.DevicePoll(ctx, DevicePollParams{DeviceCode: auth.DeviceCode, TenantID: testTenantUUID}); err != nil {
				t.Fatalf("DevicePoll: %v", err)
			}

			authorize, polls := rec.at(deviceAuthorizePath), rec.at(deviceTokenPath)
			if len(authorize) != 1 || len(polls) != 1 {
				t.Fatalf("want one authorize and one token request, got %d and %d", len(authorize), len(polls))
			}
			assertNoOtherCredential(t, "device_authorize", authorize[0])
			assertNoOtherCredential(t, "token request", polls[0])
		})
	}
}
