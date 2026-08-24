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
	"errors"
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
	// finishCalls counts what reached login/finish, so a test can assert that
	// a failed KE2 sent nothing (§23.4 rule 7).
	finishCalls int

	// mode is the tenant's opaque_mode as login/start reports it. Empty means
	// the field is omitted from the response entirely — a server older than
	// contract 1.29, which §23.4 rule 7 treats as "required".
	mode string
	// The plaintext path, so the rule 7 "optional" fallback has somewhere to
	// land. passwordLoginCalls is the assertion that matters in the cases
	// where the SDK must NOT fall back.
	passwordLoginCalls  int
	passwordLoginStatus int
	passwordLoginBody   map[string]any
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
		case loginPath:
			s.passwordLogin(w, r)
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
	// Absent, not empty, when the tenant is served by a pre-1.29 server: the
	// distinction is the whole of the "no mode field" branch of rule 7.
	if s.mode != "" {
		out["mode"] = s.mode
	}
	for k, v := range s.ksfWire {
		out[k] = v
	}
	s.writeJSON(w, http.StatusOK, out)
}

// passwordLogin is POST /api/v1/auth/login — the route §23.4 rule 7 sends an
// "optional" tenant down after a failed exchange, and the route every other
// mode must leave untouched.
func (s *opaqueMockServer) passwordLogin(w http.ResponseWriter, r *http.Request) {
	s.passwordLoginCalls++
	if s.passwordLoginStatus != 0 && s.passwordLoginStatus != http.StatusOK {
		s.writeJSON(w, s.passwordLoginStatus, s.passwordLoginBody)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:  "axiam_access",
		Value: makeAccessTokenWithOrgID(s.t, "44444444-4444-4444-4444-444444444444"),
		Path:  "/",
	})
	http.SetCookie(w, &http.Cookie{Name: "axiam_refresh", Value: "refresh-token", Path: "/"})
	s.writeJSON(w, http.StatusOK, map[string]any{
		"session_id": passwordPathSessionID,
		"expires_in": 1800,
	})
}

// passwordPathSessionID is deliberately different from the OPAQUE path's, so a
// test can tell which route produced the result it was handed.
const passwordPathSessionID = "11111111-2222-3333-4444-555555555555"

func (s *opaqueMockServer) loginFinish(w http.ResponseWriter, r *http.Request) {
	s.finishCalls++
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

// ---------------------------------------------------------------------------
// §23.4 rule 7 — what a failed KE2 does next, decided by `mode` and nothing
// else.
//
// Every case below opens with a real record enrolled under one password and a
// login attempted with another, so the KE2 the SDK is handed is genuinely
// unopenable rather than merely malformed. That is the same failure an account
// with no registration record produces, which is the case rule 7 exists for —
// the two are indistinguishable to a client by design, which is exactly why
// the SDK may only branch on the tenant's mode.
// ---------------------------------------------------------------------------

func TestAnOptionalTenantRetriesOverThePasswordPath(t *testing.T) {
	// Mid-migration, an account with no record is the ordinary case: every
	// account has none the moment an operator enables OPAQUE. Reporting the
	// failed exchange here would lock out the whole tenant.
	client, mock := newOpaqueLiveClient(t)
	mock.mode = "optional"
	mock.enrol(t, client, "the-right-password")

	result, err := client.LoginOpaque(t.Context(), "alice", "not-the-record's-password")
	if err != nil {
		t.Fatalf("an optional tenant must fall back, got: %v", err)
	}
	if result.SessionID != passwordPathSessionID {
		t.Fatalf("the result must be the password path's, got session %q", result.SessionID)
	}
	if result.ExpiresIn != 1800 {
		t.Fatalf("expires_in: %d", result.ExpiresIn)
	}
	if mock.passwordLoginCalls != 1 {
		t.Fatalf("/auth/login was called %d times, want 1", mock.passwordLoginCalls)
	}
	if mock.finishCalls != 0 {
		t.Fatal("nothing may be sent to login/finish after KE2 fails")
	}
}

func TestAnOptionalTenantReportsThePasswordPathsFailure(t *testing.T) {
	// The retry's outcome IS the call's outcome, failure included — the caller
	// must not see a synthesised OPAQUE error in front of the real answer.
	client, mock := newOpaqueLiveClient(t)
	mock.mode = "optional"
	mock.passwordLoginStatus = http.StatusUnauthorized
	mock.passwordLoginBody = map[string]any{"error": "invalid_credentials"}
	mock.enrol(t, client, "the-right-password")

	_, err := client.LoginOpaque(t.Context(), "alice", "the-wrong-password")
	if err == nil {
		t.Fatal("a wrong password signed in")
	}
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("want *AuthError, got %T: %v", err, err)
	}
	if mock.passwordLoginCalls != 1 {
		t.Fatalf("/auth/login was called %d times, want 1", mock.passwordLoginCalls)
	}
	if mock.finishCalls != 0 {
		t.Fatal("nothing may be sent to login/finish after KE2 fails")
	}
}

func TestARequiredTenantDoesNotTouchThePasswordPath(t *testing.T) {
	// `required` answers 403 opaque_required for every principal, so the retry
	// would put a plaintext password on the wire for nothing.
	client, mock := newOpaqueLiveClient(t)
	mock.mode = "required"
	mock.enrol(t, client, "the-right-password")

	_, err := client.LoginOpaque(t.Context(), "alice", "the-wrong-password")
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("want *AuthError, got %T: %v", err, err)
	}
	if mock.passwordLoginCalls != 0 {
		t.Fatalf("a required tenant must not be retried over /auth/login (%d calls)", mock.passwordLoginCalls)
	}
	if mock.finishCalls != 0 {
		t.Fatal("nothing may be sent to login/finish after KE2 fails")
	}
}

func TestAResponseWithNoModeFieldIsTreatedAsRequired(t *testing.T) {
	// A server older than contract 1.29. Guessing `optional` here would put a
	// plaintext password on the wire on the strength of a field the server
	// never sent.
	client, mock := newOpaqueLiveClient(t)
	mock.mode = "" // omitted from the response entirely
	mock.enrol(t, client, "the-right-password")

	_, err := client.LoginOpaque(t.Context(), "alice", "the-wrong-password")
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("want *AuthError, got %T: %v", err, err)
	}
	if mock.passwordLoginCalls != 0 {
		t.Fatalf("a response with no mode must not be retried over /auth/login (%d calls)", mock.passwordLoginCalls)
	}
	if mock.finishCalls != 0 {
		t.Fatal("nothing may be sent to login/finish after KE2 fails")
	}
}

func TestAnUnrecognisedModeFailsClosed(t *testing.T) {
	// Fail closed: only the exact string "optional" opens the fallback.
	client, mock := newOpaqueLiveClient(t)
	mock.mode = "Optional-ish"
	mock.enrol(t, client, "the-right-password")

	_, err := client.LoginOpaque(t.Context(), "alice", "the-wrong-password")
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("want *AuthError, got %T: %v", err, err)
	}
	if mock.passwordLoginCalls != 0 {
		t.Fatalf("an unrecognised mode must not be retried over /auth/login (%d calls)", mock.passwordLoginCalls)
	}
	if mock.finishCalls != 0 {
		t.Fatal("nothing may be sent to login/finish after KE2 fails")
	}
}
