// A mock AXIAM server that really speaks OPAQUE, for the happy paths.
//
// The error-path tests in opaque_test.go can get away with canned JSON; the
// success paths cannot, because there is no way to fake a KE2 that the client
// will actually open. So this file stands up the server half — `bytemare`'s
// own, which is the same library the client half uses — behind the three
// endpoints the SDK calls.
//
// Using the same library for both halves is fine *here* and would not be fine
// as the only check: it proves the SDK drives the protocol correctly, not that
// the protocol matches AXIAM's. That second question is what
// opaque_interop_test.go answers, against the Rust implementation.

package axiam

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bytemare/opaque"
)

// opaqueMockServer is one tenant's worth of OPAQUE server state.
type opaqueMockServer struct {
	t        *testing.T
	conf     *opaque.Configuration
	keys     *opaque.ServerKeyMaterial
	credID   []byte
	record   *opaque.ClientRecord
	ksfWire  map[string]any
	// Overridable so a test can drive the MFA and failure branches without a
	// second mock.
	finishStatus int
	finishBody   map[string]any
}

func newOpaqueMockServer(t *testing.T) *opaqueMockServer {
	t.Helper()
	conf := opaqueConfiguration()

	server, err := opaque.NewServer(conf)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	privateKey := conf.AKE.Group().NewScalar().Random()
	keys := &opaque.ServerKeyMaterial{
		PrivateKey:     privateKey,
		PublicKeyBytes: conf.AKE.Group().Base().Multiply(privateKey).Encode(),
		OPRFGlobalSeed: opaque.RandomBytes(conf.Hash.Size()),
	}
	if err := server.SetKeyMaterial(keys); err != nil {
		t.Fatalf("SetKeyMaterial: %v", err)
	}

	return &opaqueMockServer{
		t:      t,
		conf:   conf,
		keys:   keys,
		// Random per credential, exactly as AXIAM mints it — nothing here
		// derives from a username, which is the property that makes a rename
		// free.
		credID: opaque.RandomBytes(32),
		ksfWire: map[string]any{
			"ksf":         "argon2id",
			"memory_kib":  8192,
			"iterations":  1,
			"parallelism": 1,
		},
		finishStatus: http.StatusOK,
	}
}

func (s *opaqueMockServer) newServer() *opaque.Server {
	server, err := opaque.NewServer(s.conf)
	if err != nil {
		s.t.Fatalf("NewServer: %v", err)
	}
	if err := server.SetKeyMaterial(s.keys); err != nil {
		s.t.Fatalf("SetKeyMaterial: %v", err)
	}
	return server
}

func (s *opaqueMockServer) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case opaqueRegisterStartPath:
			s.registerStart(w, r)
		case opaqueLoginStartPath:
			s.loginStart(w, r)
		case opaqueLoginFinishPath:
			s.loginFinish(w, r)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func (s *opaqueMockServer) writeJSON(w http.ResponseWriter, status int, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		s.t.Fatalf("encode: %v", err)
	}
}

func (s *opaqueMockServer) registerStart(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RegistrationRequest string `json:"registration_request"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		s.t.Fatalf("decode: %v", err)
	}

	deser, _ := s.conf.Deserializer()
	raw, err := hex.DecodeString(body.RegistrationRequest)
	if err != nil {
		s.t.Fatalf("the SDK sent a non-hex registration_request: %v", err)
	}
	req, err := deser.RegistrationRequest(raw)
	if err != nil {
		s.t.Fatalf("the SDK sent a malformed registration_request: %v", err)
	}

	resp, err := s.newServer().RegistrationResponse(req, s.credID, nil)
	if err != nil {
		s.t.Fatalf("RegistrationResponse: %v", err)
	}

	out := map[string]any{
		"opaque_session":        "sealed-registration-session",
		"registration_response": hex.EncodeToString(resp.Serialize()),
		"suite":                 "ristretto255_sha512",
	}
	for k, v := range s.ksfWire {
		out[k] = v
	}
	s.writeJSON(w, http.StatusOK, out)
}

// enrol runs a registration through the SDK and keeps the record, so a
// subsequent login has something to answer with.
func (s *opaqueMockServer) enrol(t *testing.T, client *Client, password string) *OpaqueEnrollment {
	t.Helper()
	enrollment, err := client.OpaqueEnrollment(t.Context(), password)
	if err != nil {
		t.Fatalf("OpaqueEnrollment: %v", err)
	}

	deser, _ := s.conf.Deserializer()
	raw, err := hex.DecodeString(enrollment.RegistrationRecord)
	if err != nil {
		t.Fatalf("the SDK produced a non-hex record: %v", err)
	}
	record, err := deser.RegistrationRecord(raw)
	if err != nil {
		t.Fatalf("the SDK produced a malformed record: %v", err)
	}
	s.record = &opaque.ClientRecord{
		RegistrationRecord:   record,
		CredentialIdentifier: s.credID,
	}
	return enrollment
}

func (s *opaqueMockServer) loginStart(w http.ResponseWriter, r *http.Request) {
	var body struct {
		KE1 string `json:"ke1"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		s.t.Fatalf("decode: %v", err)
	}

	deser, _ := s.conf.Deserializer()
	raw, err := hex.DecodeString(body.KE1)
	if err != nil {
		s.t.Fatalf("the SDK sent a non-hex ke1: %v", err)
	}
	ke1, err := deser.KE1(raw)
	if err != nil {
		s.t.Fatalf("the SDK sent a malformed ke1: %v", err)
	}

	ke2, _, err := s.newServer().GenerateKE2(ke1, s.record)
	if err != nil {
		s.t.Fatalf("GenerateKE2: %v", err)
	}

	out := map[string]any{
		"opaque_session": "sealed-login-session",
		"ke2":            hex.EncodeToString(ke2.Serialize()),
		"suite":          "ristretto255_sha512",
	}
	for k, v := range s.ksfWire {
		out[k] = v
	}
	s.writeJSON(w, http.StatusOK, out)
}

func (s *opaqueMockServer) loginFinish(w http.ResponseWriter, r *http.Request) {
	var body opaqueLoginFinishRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		s.t.Fatalf("decode: %v", err)
	}
	// The session token is opaque sealed server state; the SDK must echo it
	// verbatim (§23.4 rule 8).
	if body.OpaqueSession != "sealed-login-session" {
		s.t.Fatalf("the SDK did not echo opaque_session verbatim: %q", body.OpaqueSession)
	}
	if _, err := hex.DecodeString(body.KE3); err != nil {
		s.t.Fatalf("the SDK sent a non-hex ke3: %v", err)
	}

	if s.finishBody != nil {
		s.writeJSON(w, s.finishStatus, s.finishBody)
		return
	}
	// A structurally valid access token: the SDK decodes its claims to learn
	// the tenant and org, so a placeholder string fails after the protocol has
	// already succeeded — which would make this test look like an OPAQUE
	// failure when it is not one.
	http.SetCookie(w, &http.Cookie{
		Name:  "axiam_access",
		Value: makeAccessTokenWithOrgID(s.t, "44444444-4444-4444-4444-444444444444"),
		Path:  "/",
	})
	http.SetCookie(w, &http.Cookie{Name: "axiam_refresh", Value: "refresh-token", Path: "/"})
	s.writeJSON(w, http.StatusOK, map[string]any{
		"session_id": "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
		"expires_in": 900,
	})
}

func newOpaqueLiveClient(t *testing.T) (*Client, *opaqueMockServer) {
	t.Helper()
	mock := newOpaqueMockServer(t)
	server := httptest.NewServer(mock.handler())
	client, err := NewClient(server.URL, "default", WithOrgSlug("acme"))
	if err != nil {
		server.Close()
		t.Fatalf("client: %v", err)
	}
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})
	return client, mock
}

// ---------------------------------------------------------------------------

func TestAFullExchangeSignsIn(t *testing.T) {
	client, mock := newOpaqueLiveClient(t)
	password := "a-real-round-trip"

	mock.enrol(t, client, password)

	result, err := client.LoginOpaque(t.Context(), "alice", password)
	if err != nil {
		t.Fatalf("LoginOpaque: %v", err)
	}
	if result.MFARequired {
		t.Fatal("no MFA was configured")
	}
	if result.SessionID != "3f2504e0-4f89-11d3-9a0c-0305e82c3301" {
		t.Fatalf("session id: %q", result.SessionID)
	}
	if result.ExpiresIn != 900 {
		t.Fatalf("expires_in: %d", result.ExpiresIn)
	}
}

func TestAWrongPasswordFailsAgainstARealRecord(t *testing.T) {
	// The negative half of the round trip, and the one that matters: the
	// envelope must not open. A mock that only ever succeeds would pass every
	// test in this file while the SDK was broken.
	client, mock := newOpaqueLiveClient(t)
	mock.enrol(t, client, "the-right-password")

	_, err := client.LoginOpaque(t.Context(), "alice", "the-wrong-password")
	if err == nil {
		t.Fatal("a wrong password signed in")
	}
	if _, ok := err.(*AuthError); !ok {
		t.Fatalf("want *AuthError, got %T: %v", err, err)
	}
}

func TestAnMfaChallengeIsReturnedFromTheOpaquePath(t *testing.T) {
	// The same LoginResult shape the password path returns, which is what lets
	// an application switch a tenant to OPAQUE without touching its own code.
	client, mock := newOpaqueLiveClient(t)
	password := "mfa-round-trip"
	mock.enrol(t, client, password)

	mock.finishStatus = http.StatusAccepted
	mock.finishBody = map[string]any{
		"challenge_token":   "challenge-abc",
		"available_methods": []string{"totp", "webauthn"},
	}

	result, err := client.LoginOpaque(t.Context(), "alice", password)
	if err != nil {
		t.Fatalf("LoginOpaque: %v", err)
	}
	if !result.MFARequired {
		t.Fatal("expected an MFA challenge")
	}
	if string(result.MFAToken) != "challenge-abc" {
		t.Fatalf("challenge token: %q", string(result.MFAToken))
	}
	if len(result.AvailableMethods) != 2 {
		t.Fatalf("available methods: %v", result.AvailableMethods)
	}
}

func TestAnErrorStatusFromLoginFinishIsMapped(t *testing.T) {
	client, mock := newOpaqueLiveClient(t)
	password := "finish-rejects"
	mock.enrol(t, client, password)

	mock.finishStatus = http.StatusUnauthorized
	mock.finishBody = map[string]any{"error": "invalid_credentials"}

	if _, err := client.LoginOpaque(t.Context(), "alice", password); err == nil {
		t.Fatal("a 401 from login/finish must not sign in")
	}
}

func TestEnrolmentProducesAWellFormedRecord(t *testing.T) {
	client, mock := newOpaqueLiveClient(t)
	enrollment := mock.enrol(t, client, "enrolment-shape")

	if enrollment.OpaqueSession != "sealed-registration-session" {
		t.Fatalf("the session must be echoed verbatim: %q", enrollment.OpaqueSession)
	}
	// 192 bytes of RegistrationRecord, hex.
	if len(enrollment.RegistrationRecord) != 384 {
		t.Fatalf("record is %d hex chars, want 384", len(enrollment.RegistrationRecord))
	}
}

func TestScryptIsHonouredEndToEnd(t *testing.T) {
	// The other KSF, driven all the way through a real exchange rather than
	// only through clientOptions().
	client, mock := newOpaqueLiveClient(t)
	mock.ksfWire = map[string]any{"ksf": "scrypt", "log_n": 14, "r": 8, "p": 1}
	password := "scrypt-round-trip"

	mock.enrol(t, client, password)

	if _, err := client.LoginOpaque(t.Context(), "alice", password); err != nil {
		t.Fatalf("LoginOpaque with scrypt: %v", err)
	}
}
