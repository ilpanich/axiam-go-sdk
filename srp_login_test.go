// LoginSrp end-to-end, against a fake server that performs REAL SRP
// arithmetic (CONTRACT.md §23.7 rules 5, 7 and 8).
//
// A fake that echoed canned values would pass whatever the client computed.
// This one holds a verifier, derives its own S from it and answers with the
// M2 that follows — so a client that gets u, PAD() or the identity wrong
// fails here rather than in production.

package axiam

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

const (
	srpTestIdentity = "alice"
	srpTestPassword = "correct horse battery staple"
	srpTestOrgID    = "44444444-4444-4444-4444-444444444444"
)

// fakeSrpServer is one enrolled account and the server half of the exchange.
type fakeSrpServer struct {
	t        *testing.T
	group    *srpGroup
	kdf      SrpKdfParams
	salt     []byte
	verifier *big.Int

	// state carried between the two calls of one exchange.
	bPriv *big.Int
	bPub  *big.Int
	aPub  *big.Int

	// knobs the tests turn.
	corruptServerProof bool
	mfaRequired        bool
	// namedGroup, when set, is answered on the first challenge so the client
	// has to restart the exchange in it.
	namedGroup string

	token string
}

func newFakeSrpServer(t *testing.T, groupName string) *fakeSrpServer {
	t.Helper()
	group, err := parseSrpGroup(groupName)
	if err != nil {
		t.Fatalf("group: %v", err)
	}
	// PBKDF2 at a low iteration count: the KDF's cost is not what these tests
	// are measuring, and Argon2id at production memory would dominate them.
	kdf := SrpKdfParams{Kdf: KdfPBKDF2SHA256, Iterations: 1000}
	salt := bytes.Repeat([]byte{0xa3}, 32)
	x, err := srpDeriveX(srpTestIdentity, srpTestPassword, salt, kdf)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	xInt := new(big.Int).Mod(new(big.Int).SetBytes(x), group.n)
	return &fakeSrpServer{
		t:        t,
		group:    group,
		kdf:      kdf,
		salt:     salt,
		verifier: new(big.Int).Exp(group.g, xInt, group.n),
		token:    makeAccessTokenWithOrgID(t, srpTestOrgID),
	}
}

func (f *fakeSrpServer) challenge(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		f.t.Fatalf("challenge body: %v", err)
	}
	if _, present := body["password"]; present {
		f.t.Fatal("the challenge request must not carry a password field")
	}
	aPubHex, _ := body["client_public"].(string)
	raw, err := hex.DecodeString(aPubHex)
	if err != nil {
		f.t.Fatalf("client_public is not hex: %q", aPubHex)
	}
	f.aPub = new(big.Int).SetBytes(raw)

	group := f.group
	if f.namedGroup != "" && f.namedGroup != group.name {
		// First round: name a different group and answer in it. The client is
		// expected to restart rather than continue with the A it already sent.
		named, err := parseSrpGroup(f.namedGroup)
		if err != nil {
			f.t.Fatalf("named group: %v", err)
		}
		f.namedGroup = ""
		f.writeChallenge(w, named, new(big.Int).SetInt64(1))
		return
	}

	f.bPriv = new(big.Int).SetBytes(bytes.Repeat([]byte{0x22}, 32))
	kv := new(big.Int).Mul(srpMultiplier(group), f.verifier)
	f.bPub = new(big.Int).Mod(new(big.Int).Add(kv, new(big.Int).Exp(group.g, f.bPriv, group.n)), group.n)
	f.writeChallenge(w, group, f.bPub)
}

func (f *fakeSrpServer) writeChallenge(w http.ResponseWriter, group *srpGroup, bPub *big.Int) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"srp_session": "opaque-session-token",
		"identity":    srpTestIdentity,
		"salt":        hex.EncodeToString(f.salt),
		"group":       group.name,
		"kdf":         f.kdf.Kdf,
		"iterations":  f.kdf.Iterations,
		"b_pub":       hex.EncodeToString(srpPad(bPub, group.byteLen)),
	})
}

// serverProof recomputes the exchange from the server's side and returns M2.
func (f *fakeSrpServer) serverProof(clientProof string) string {
	group := f.group
	u := srpHashInt(srpPad(f.aPub, group.byteLen), srpPad(f.bPub, group.byteLen))
	// S = (A * v^u)^b mod N
	s := new(big.Int).Exp(
		new(big.Int).Mod(new(big.Int).Mul(f.aPub, new(big.Int).Exp(f.verifier, u, group.n)), group.n),
		f.bPriv, group.n,
	)
	sessionKey := srpHash(srpPad(s, group.byteLen))
	m1, err := hex.DecodeString(clientProof)
	if err != nil {
		f.t.Fatalf("client_proof is not hex: %q", clientProof)
	}
	return hex.EncodeToString(srpHash(srpPad(f.aPub, group.byteLen), m1, sessionKey))
}

func (f *fakeSrpServer) verify(w http.ResponseWriter, r *http.Request) {
	var body srpVerifyRequestBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		f.t.Fatalf("verify body: %v", err)
	}
	if body.SrpSession != "opaque-session-token" {
		f.t.Fatalf("srp_session was not echoed verbatim: %q", body.SrpSession)
	}

	proof := f.serverProof(body.ClientProof)
	if f.corruptServerProof {
		proof = strings.Repeat("0", len(proof))
	}

	// Cookies are set exactly as on /auth/login (§23.5) — including on the
	// corrupt-proof path, so the test can assert the client discards them.
	http.SetCookie(w, &http.Cookie{Name: "axiam_access", Value: f.token, Path: "/"})
	http.SetCookie(w, &http.Cookie{Name: "axiam_refresh", Value: "refresh-tok", Path: "/"})
	w.Header().Set("Content-Type", "application/json")

	if f.mfaRequired {
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"challenge_token":   "mfa-challenge",
			"available_methods": []string{"totp"},
			"server_proof":      proof,
		})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"session_id":   "33333333-3333-3333-3333-333333333333",
		"expires_in":   900,
		"server_proof": proof,
	})
}

// serve mounts the fake on an httptest server, returning it plus a recorder
// of every request body seen — §23.7 rule 8 reads that back.
func (f *fakeSrpServer) serve() (*httptest.Server, *[]string) {
	var bodies []string
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r.Body)
		bodies = append(bodies, buf.String())
		r.Body = http.NoBody
		r.Body = &nopReadCloser{bytes.NewReader(buf.Bytes())}
		switch r.URL.Path {
		case srpChallengePath:
			f.challenge(w, r)
		case srpVerifyPath:
			f.verify(w, r)
		default:
			f.t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	})), &bodies
}

type nopReadCloser struct{ *bytes.Reader }

func (nopReadCloser) Close() error { return nil }

func newSrpTestClient(t *testing.T, baseURL string, opts ...Option) *Client {
	t.Helper()
	all := append([]Option{WithOrgID(uuid.MustParse(srpTestOrgID))}, opts...)
	client, err := NewClient(baseURL, "acme", all...)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// TestLoginSrp_Succeeds is the happy path against real arithmetic on both
// sides: the client's M1 satisfies a server that only ever held a verifier.
func TestLoginSrp_Succeeds(t *testing.T) {
	fake := newFakeSrpServer(t, GroupRFC5054_2048)
	server, _ := fake.serve()
	defer server.Close()

	client := newSrpTestClient(t, server.URL)
	result, err := client.LoginSrp(context.Background(), srpTestIdentity, srpTestPassword)
	if err != nil {
		t.Fatalf("LoginSrp: %v", err)
	}
	if result.MFARequired {
		t.Fatal("expected a completed login")
	}
	if result.SessionID != "33333333-3333-3333-3333-333333333333" {
		t.Fatalf("session id: %q", result.SessionID)
	}
	if result.ExpiresIn != 900 {
		t.Fatalf("expires_in: %d", result.ExpiresIn)
	}
}

// TestLoginSrp_ReturnsTheSameMfaBranchAsLogin covers §23.1's hard
// requirement that both login paths return the same result type: an
// application switching a tenant to SRP must not need a second result
// handler.
func TestLoginSrp_ReturnsTheSameMfaBranchAsLogin(t *testing.T) {
	fake := newFakeSrpServer(t, GroupRFC5054_2048)
	fake.mfaRequired = true
	server, _ := fake.serve()
	defer server.Close()

	client := newSrpTestClient(t, server.URL)
	result, err := client.LoginSrp(context.Background(), srpTestIdentity, srpTestPassword)
	if err != nil {
		t.Fatalf("LoginSrp: %v", err)
	}
	if !result.MFARequired {
		t.Fatal("a 202 must surface as MFARequired, not as an error")
	}
	if result.MFAToken != "mfa-challenge" {
		t.Fatalf("mfa token: %q", result.MFAToken)
	}
	if len(result.AvailableMethods) != 1 || result.AvailableMethods[0] != "totp" {
		t.Fatalf("available methods: %v", result.AvailableMethods)
	}
}

// TestLoginSrp_RestartsWhenTheServerNamesAnotherGroup: A is computed before
// the server has named a group, so a tenant on a narrower group must work
// rather than fail.
func TestLoginSrp_RestartsWhenTheServerNamesAnotherGroup(t *testing.T) {
	fake := newFakeSrpServer(t, GroupRFC5054_2048)
	fake.namedGroup = GroupRFC5054_2048 // differs from the opening 4096 guess
	server, _ := fake.serve()
	defer server.Close()

	client := newSrpTestClient(t, server.URL)
	if _, err := client.LoginSrp(context.Background(), srpTestIdentity, srpTestPassword); err != nil {
		t.Fatalf("LoginSrp: %v", err)
	}
}

// TestLoginSrp_RejectsAWrongServerProof covers §23.7 rule 5. The assertion is
// on the ABSENCE of a session, not merely on a thrown message: skipping M2
// keeps the half of SRP that authenticates the client and throws away the
// half that authenticates the server.
func TestLoginSrp_RejectsAWrongServerProof(t *testing.T) {
	fake := newFakeSrpServer(t, GroupRFC5054_2048)
	fake.corruptServerProof = true
	server, _ := fake.serve()
	defer server.Close()

	client := newSrpTestClient(t, server.URL)
	result, err := client.LoginSrp(context.Background(), srpTestIdentity, srpTestPassword)
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("expected ErrAuth, got %T: %v", err, err)
	}
	if result.SessionID != "" || result.MFARequired {
		t.Fatal("a rogue server must yield no session at all")
	}
	// The cookies the rogue server set must not survive: an endpoint that
	// cannot prove it holds the verifier is not the server it claims to be.
	if client.cookieValue(accessCookie) != "" {
		t.Fatal("the access cookie from an unverified server was kept")
	}
}

// TestLoginSrp_DisabledTenantIsNotACredentialFailure: 404 is a property of
// the tenant, so a caller can fall back to Login without mistaking it for a
// bad password.
func TestLoginSrp_DisabledTenantIsNotACredentialFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := newSrpTestClient(t, server.URL)
	_, err := client.LoginSrp(context.Background(), srpTestIdentity, srpTestPassword)
	if !errors.Is(err, ErrNetwork) {
		t.Fatalf("expected ErrNetwork, got %T: %v", err, err)
	}
	if errors.Is(err, ErrAuth) {
		t.Fatal("a disabled tenant must never read as a credential failure")
	}
	if !strings.Contains(err.Error(), "srp_mode") {
		t.Fatalf("the message should explain the tenant's setting: %v", err)
	}
}

// TestLoginSrp_WrongPasswordIsAnAuthError: the server rejects M1, and the
// client must not dress that up as anything else.
func TestLoginSrp_WrongPasswordIsAnAuthError(t *testing.T) {
	fake := newFakeSrpServer(t, GroupRFC5054_2048)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case srpChallengePath:
			fake.challenge(w, r)
		case srpVerifyPath:
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "authentication_failed"})
		}
	}))
	defer server.Close()

	client := newSrpTestClient(t, server.URL)
	if _, err := client.LoginSrp(context.Background(), srpTestIdentity, "wrong"); !errors.Is(err, ErrAuth) {
		t.Fatalf("expected ErrAuth, got %T: %v", err, err)
	}
}

// TestLogin_SrpRequiredIsAuthzNotAuth covers §23.7 rule 7 and §23.3 rule 10.
// A user whose password is perfectly good must never be shown "invalid
// username or password" because the tenant moved to srp_mode: required.
func TestLogin_SrpRequiredIsAuthzNotAuth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":   "srp_required",
			"message": "this tenant requires Secure Remote Password; use LoginSrp",
		})
	}))
	defer server.Close()

	client := newSrpTestClient(t, server.URL)
	_, err := client.Login(context.Background(), srpTestIdentity, srpTestPassword)
	if !errors.Is(err, ErrAuthz) {
		t.Fatalf("expected ErrAuthz, got %T: %v", err, err)
	}
	if errors.Is(err, ErrAuth) {
		t.Fatal("srp_required is a policy refusal, not a credential failure")
	}
}

// TestLoginSrp_LogsNothingSensitive covers §23.7 rule 8: A, B, M1, M2,
// srp_session, salt and the verifier must not appear in any log record at any
// level. srp_session in particular is bearer-equivalent while it lives.
func TestLoginSrp_LogsNothingSensitive(t *testing.T) {
	fake := newFakeSrpServer(t, GroupRFC5054_2048)
	server, bodies := fake.serve()
	defer server.Close()

	var sink strings.Builder
	logger := slog.New(slog.NewTextHandler(&sink, &slog.HandlerOptions{Level: slog.LevelDebug}))

	client := newSrpTestClient(t, server.URL, WithLogger(logger),
		WithTelemetryHook(func(event TelemetryEvent) {
			// Rendered with %+v so every field of every event type reaches
			// the sink — the assertion below is about absence, and a
			// selective renderer could hide the very value it should catch.
			fmt.Fprintf(&sink, "%+v", event)
		}))
	if _, err := client.LoginSrp(context.Background(), srpTestIdentity, srpTestPassword); err != nil {
		t.Fatalf("LoginSrp: %v", err)
	}

	// Pull the exact values that crossed the wire out of the recorded bodies
	// rather than guessing at them, so this cannot pass by looking for a
	// string the client never produced.
	logged := sink.String()
	for _, body := range *bodies {
		var fields map[string]any
		if err := json.Unmarshal([]byte(body), &fields); err != nil {
			continue
		}
		for _, key := range []string{"client_public", "client_proof", "srp_session"} {
			value, ok := fields[key].(string)
			if !ok || value == "" {
				continue
			}
			if strings.Contains(logged, value) {
				t.Errorf("§23.7 rule 8: %s appeared in the log sink", key)
			}
		}
	}
	if strings.Contains(logged, hex.EncodeToString(fake.salt)) {
		t.Error("§23.7 rule 8: the salt appeared in the log sink")
	}
	if strings.Contains(logged, srpTestPassword) {
		t.Error("the password appeared in the log sink")
	}
}
