// The refusals on the SRP login path (CONTRACT.md §23).
//
// srp_login_test.go drives the exchange against a server that performs real
// arithmetic; this file drives the paths where the exchange never gets that
// far. They matter more than their size suggests: §23.3 rule 4 and §23.4 both
// turn on refusing rather than guessing, and every refusal here has to reach
// the caller as a NetworkError rather than an AuthError — a client capability
// gap or a tenant setting reported as a credential failure sends a user off to
// reset a password that works perfectly.

package axiam

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// srpChallengeServer answers /srp/challenge with `body` verbatim (as JSON when
// it is a map, as raw bytes when it is a string) and fails the test if the
// client goes on to /srp/verify — every case in this file must refuse before
// a proof is ever sent.
func srpChallengeServer(t *testing.T, status int, body any) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case srpChallengePath:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			switch v := body.(type) {
			case string:
				_, _ = w.Write([]byte(v))
			case nil:
			default:
				_ = json.NewEncoder(w).Encode(v)
			}
		case srpVerifyPath:
			t.Error("a proof was sent for a challenge that should have been refused")
			w.WriteHeader(http.StatusInternalServerError)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

// wellFormedChallenge is a challenge every field of which the client accepts,
// so a test can override exactly one member and know what it is testing.
func wellFormedChallenge() map[string]any {
	return map[string]any{
		"srp_session": "opaque-session-token",
		"identity":    srpTestIdentity,
		"salt":        strings.Repeat("a3", 32),
		"group":       GroupRFC5054_4096,
		"kdf":         KdfPBKDF2SHA256,
		"iterations":  1000,
		"b_pub":       strings.Repeat("02", 512),
	}
}

func requireNetworkError(t *testing.T, err error, contains string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected a refusal, got nil")
	}
	var netErr *NetworkError
	if !errors.As(err, &netErr) {
		t.Fatalf("want NetworkError (a config/capability fault), got %T: %v", err, err)
	}
	if contains != "" && !strings.Contains(err.Error(), contains) {
		t.Fatalf("refusal must mention %q, got %q", contains, err.Error())
	}
}

func TestLoginSrp_RefusesAGroupThisSdkDoesNotImplement(t *testing.T) {
	// §23.4: computing in an unverified group could mean one whose discrete
	// log the server knows.
	challenge := wellFormedChallenge()
	challenge["group"] = "rfc5054_1024"
	server := srpChallengeServer(t, http.StatusOK, challenge)

	client := newSrpTestClient(t, server.URL)
	_, err := client.LoginSrp(context.Background(), srpTestIdentity, srpTestPassword)
	requireNetworkError(t, err, "rfc5054_1024")
}

func TestLoginSrp_RefusesAKdfThisSdkDoesNotImplement(t *testing.T) {
	// Substituting the other KDF derives a different x and surfaces as
	// "invalid password" — the single most misleading failure available here.
	challenge := wellFormedChallenge()
	challenge["kdf"] = "scrypt"
	server := srpChallengeServer(t, http.StatusOK, challenge)

	client := newSrpTestClient(t, server.URL)
	_, err := client.LoginSrp(context.Background(), srpTestIdentity, srpTestPassword)
	requireNetworkError(t, err, "scrypt")
}

func TestLoginSrp_RefusesASaltThatIsNotHex(t *testing.T) {
	challenge := wellFormedChallenge()
	challenge["salt"] = "not-hex"
	server := srpChallengeServer(t, http.StatusOK, challenge)

	client := newSrpTestClient(t, server.URL)
	_, err := client.LoginSrp(context.Background(), srpTestIdentity, srpTestPassword)
	requireNetworkError(t, err, "salt")
}

func TestLoginSrp_RefusesAServerPublicCongruentToZero(t *testing.T) {
	// §23.3 rule 5, and the classic SRP break: B ≡ 0 (mod N) makes S
	// predictable. No proof may be sent for one, which srpChallengeServer
	// asserts on its own.
	challenge := wellFormedChallenge()
	challenge["b_pub"] = strings.Repeat("00", 512)
	server := srpChallengeServer(t, http.StatusOK, challenge)

	client := newSrpTestClient(t, server.URL)
	_, err := client.LoginSrp(context.Background(), srpTestIdentity, srpTestPassword)
	// NetworkError rather than AuthError, and deliberately: the password was
	// never in question. The server is broken or hostile, and telling the user
	// their credentials were wrong would be false.
	requireNetworkError(t, err, "invalid public value")
}

func TestLoginSrp_RefusesAChallengeThatIsNotJson(t *testing.T) {
	server := srpChallengeServer(t, http.StatusOK, "not json at all")

	client := newSrpTestClient(t, server.URL)
	_, err := client.LoginSrp(context.Background(), srpTestIdentity, srpTestPassword)
	if err == nil {
		t.Fatal("an unparseable challenge must not be treated as one")
	}
}

func TestLoginSrp_ReportsAServerErrorOnTheChallengeAsItself(t *testing.T) {
	server := srpChallengeServer(t, http.StatusServiceUnavailable,
		map[string]any{"message": "the identity service is restarting"})

	client := newSrpTestClient(t, server.URL)
	_, err := client.LoginSrp(context.Background(), srpTestIdentity, srpTestPassword)
	if err == nil {
		t.Fatal("a 503 is not a login")
	}
	var authErr *AuthError
	if errors.As(err, &authErr) {
		t.Fatalf("a 503 is not a credential failure: %v", err)
	}
}

func TestLoginSrp_ReportsATransportFailureRatherThanABadPassword(t *testing.T) {
	server := srpChallengeServer(t, http.StatusOK, wellFormedChallenge())
	client := newSrpTestClient(t, server.URL)
	// Close the origin out from under the client: the challenge round trip
	// cannot complete at all.
	server.Close()

	_, err := client.LoginSrp(context.Background(), srpTestIdentity, srpTestPassword)
	if err == nil {
		t.Fatal("an unreachable server is not a successful login")
	}
	var authErr *AuthError
	if errors.As(err, &authErr) {
		t.Fatalf("an unreachable server is not a credential failure: %v", err)
	}
}

func TestLoginSrp_RefusesAfterClose(t *testing.T) {
	// §18.1 rule 4: use-after-close is an error, not a quiet reconnect.
	server := srpChallengeServer(t, http.StatusOK, wellFormedChallenge())
	client := newSrpTestClient(t, server.URL)
	if err := client.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	_, err := client.LoginSrp(context.Background(), srpTestIdentity, srpTestPassword)
	if err == nil {
		t.Fatal("a closed client must refuse rather than reconnect")
	}
}

func TestLoginSrp_RefusesARestartIntoAnUnimplementedGroup(t *testing.T) {
	// The renegotiation is the one place the group name is read twice. A name
	// this SDK cannot implement must be refused there too, rather than
	// restarting into whatever parseSrpGroup happens to return.
	challenge := wellFormedChallenge()
	challenge["group"] = "rfc5054_8192"
	server := srpChallengeServer(t, http.StatusOK, challenge)

	client := newSrpTestClient(t, server.URL)
	_, err := client.LoginSrp(context.Background(), srpTestIdentity, srpTestPassword)
	requireNetworkError(t, err, "rfc5054_8192")
}

func TestLoginSrp_RefusesWhenTheRestartedChallengeFails(t *testing.T) {
	// First challenge names a narrower group; the restart into it then fails.
	// The failure has to surface rather than the exchange continuing with the
	// A computed in the group the server did not name.
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == srpVerifyPath {
			t.Error("a proof was sent although the restart never produced a challenge")
			return
		}
		calls++
		if calls == 1 {
			challenge := wellFormedChallenge()
			challenge["group"] = GroupRFC5054_2048
			challenge["b_pub"] = strings.Repeat("02", 256)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(challenge)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	client := newSrpTestClient(t, server.URL)
	_, err := client.LoginSrp(context.Background(), srpTestIdentity, srpTestPassword)
	if err == nil {
		t.Fatal("a failed restart is not a login")
	}
	if calls != 2 {
		t.Fatalf("the exchange must be restarted exactly once, saw %d challenges", calls)
	}
}

func TestLoginSrp_RefusesAVerifyResponseThatIsNotJson(t *testing.T) {
	fake := newFakeSrpServer(t, GroupRFC5054_2048)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case srpChallengePath:
			fake.challenge(w, r)
		case srpVerifyPath:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("{not json"))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	client := newSrpTestClient(t, server.URL)
	_, err := client.LoginSrp(context.Background(), srpTestIdentity, srpTestPassword)
	if err == nil {
		t.Fatal("an unparseable verify response is not a session")
	}
}

func TestSrpEnrollment_DefaultsToArgon2idAtAxiamCosts(t *testing.T) {
	// A caller that names nothing must get AXIAM's own Argon2id costs and the
	// widest group, rather than being enrolled under something weaker by
	// omission.
	client := newSrpTestClient(t, "https://iam.example.com")
	enrolment, err := client.SrpEnrollment(SrpEnrollmentRequest{
		Identity: srpTestIdentity,
		Password: srpTestPassword,
	})
	if err != nil {
		t.Fatalf("enrolment: %v", err)
	}
	if enrolment.Kdf != KdfArgon2id {
		t.Fatalf("default KDF = %q, want %q", enrolment.Kdf, KdfArgon2id)
	}
	if enrolment.Group != GroupRFC5054_4096 {
		t.Fatalf("default group = %q, want %q", enrolment.Group, GroupRFC5054_4096)
	}
	if enrolment.Iterations != 2 || enrolment.MemoryKiB != 19456 || enrolment.Parallelism != 1 {
		t.Fatalf("default costs = t%d m%d p%d, want t2 m19456 p1",
			enrolment.Iterations, enrolment.MemoryKiB, enrolment.Parallelism)
	}
	if len(enrolment.Salt) != 64 {
		t.Fatalf("salt = %d hex chars, want 64 (§23.3 rule 11)", len(enrolment.Salt))
	}
}

func TestSrpEnrollment_FillsInThePbkdf2DefaultCost(t *testing.T) {
	// Named without a cost, PBKDF2 gets OWASP's 600k — and the Argon2id-only
	// fields stay clear, so an enrolment cannot advertise a memory cost it
	// never used.
	client := newSrpTestClient(t, "https://iam.example.com")
	enrolment, err := client.SrpEnrollment(SrpEnrollmentRequest{
		Identity:    srpTestIdentity,
		Password:    srpTestPassword,
		Group:       GroupRFC5054_2048,
		Kdf:         KdfPBKDF2SHA256,
		MemoryKiB:   4096,
		Parallelism: 4,
	})
	if err != nil {
		t.Fatalf("enrolment: %v", err)
	}
	if enrolment.Iterations != 600000 {
		t.Fatalf("PBKDF2 iterations = %d, want 600000", enrolment.Iterations)
	}
	if enrolment.MemoryKiB != 0 || enrolment.Parallelism != 0 {
		t.Fatalf("PBKDF2 must carry no Argon2id costs, got m%d p%d",
			enrolment.MemoryKiB, enrolment.Parallelism)
	}
	if len(enrolment.Verifier) != 512 {
		t.Fatalf("verifier = %d hex chars, want 512 for a 2048-bit group", len(enrolment.Verifier))
	}
}

func TestSrpEnrollment_RefusesAKdfThisSdkDoesNotImplement(t *testing.T) {
	client := newSrpTestClient(t, "https://iam.example.com")
	_, err := client.SrpEnrollment(SrpEnrollmentRequest{
		Identity: srpTestIdentity,
		Password: srpTestPassword,
		Kdf:      "scrypt",
	})
	requireNetworkError(t, err, "scrypt")
}
