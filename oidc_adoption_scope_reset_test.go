package axiam

import (
	"context"
	"net/http"
	"testing"
)

// CONTRACT.md 1.52 N5.5 (C-12): client-credentials adoption and
// device-grant adoption are session-establishing calls that carry no
// LoginUserInfo, so — exactly like the device login and a WebAuthn/SSO
// completion — they must reset the §5.2 acting-tenant gate to unknown
// rather than leaving whatever gate an earlier login on the same Client
// set. Mirrors sso_scope_reset_test.go's shape for the federation
// completions.

// TestActingTenant_LoginClientCredentialsAdoptionResetsAStaleGate pins
// oidc.go's LoginClientCredentials(AdoptAsCredential: true).
func TestActingTenant_LoginClientCredentialsAdoptionResetsAStaleGate(t *testing.T) {
	tenantID := mustUUID(t, "cccccccc-cccc-cccc-cccc-cccccccccccc")
	srv := newOidcTestServer(t)
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, map[string]any{"access_token": "m2m-token", "token_type": "Bearer", "expires_in": 3600})
	}

	client, err := NewClient(srv.URL, "acme", WithOidcClientID(testClientID), WithOidcClientSecret("shh"))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	// Simulate a stale non-organization-level gate an earlier password
	// login on this same Client left behind (setScope is what Login's
	// success branch calls).
	client.setScope(false, nil)
	if _, err := client.ActingTenant(tenantID); err == nil {
		t.Fatal("precondition: a non-organization-level gate must refuse ActingTenant")
	}

	if _, err := client.LoginClientCredentials(context.Background(), LoginClientCredentialsParams{
		TenantID: testTenantID, AdoptAsCredential: true,
	}); err != nil {
		t.Fatalf("LoginClientCredentials: %v", err)
	}
	if _, err := client.ActingTenant(tenantID); err != nil {
		t.Fatalf("after LoginClientCredentials(AdoptAsCredential) the gate must be unknown, so ActingTenant sends the header and lets the server decide; got %v", err)
	}
}

// TestActingTenant_DeviceGrantAdoptionResetsAStaleGate pins
// oidc_device.go's DevicePoll adoption inside DeviceLogin's polling loop
// (AdoptAsCredential: true), the §14 device authorization grant — a
// different mechanism from the §6.1 mTLS AuthenticateDevice this file's
// neighbours also cover.
func TestActingTenant_DeviceGrantAdoptionResetsAStaleGate(t *testing.T) {
	tenantID := mustUUID(t, "cccccccc-cccc-cccc-cccc-cccccccccccc")
	srv := newOidcTestServer(t)
	srv.DeviceAuthHandler = func(w http.ResponseWriter, r *http.Request) {
		writeStatusJSON(w, http.StatusOK, deviceAuthBody(nil))
	}
	srv.TokenHandler = func(w http.ResponseWriter, r *http.Request) {
		writeStatusJSON(w, http.StatusOK, deviceSuccessBody())
	}

	client := newDeviceClient(t, srv)
	client.setScope(false, nil)
	if _, err := client.ActingTenant(tenantID); err == nil {
		t.Fatal("precondition: a non-organization-level gate must refuse ActingTenant")
	}

	_, err := client.DeviceLogin(context.Background(), DeviceLoginParams{
		TenantID:          testTenantUUID,
		OnUserCode:        func(DeviceAuthorization) error { return nil },
		AdoptAsCredential: true,
	})
	if err != nil {
		t.Fatalf("DeviceLogin: %v", err)
	}
	if _, err := client.ActingTenant(tenantID); err != nil {
		t.Fatalf("after device-grant adoption the gate must be unknown, so ActingTenant sends the header and lets the server decide; got %v", err)
	}
}
