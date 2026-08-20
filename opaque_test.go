// Unit tests for the OPAQUE client half (CONTRACT.md §23).
//
// These cover the layer this SDK actually owns: the two HTTP calls, the KSF
// parameters it honours, and the error taxonomy around them. The protocol
// itself is bytemare/opaque's, and that it agrees with AXIAM's server is
// asserted in opaque_interop_test.go rather than guessed at here.

package axiam

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func u32(v uint32) *uint32 { return &v }
func u8(v uint8) *uint8    { return &v }

// argon2idCheap is the cheapest Argon2id the domain model accepts. The tests
// run the real stretching function, and the production default (19 MiB, two
// passes) would dominate their runtime for no added coverage.
func argon2idCheap() OpaqueKsfParams {
	return OpaqueKsfParams{
		Ksf:         "argon2id",
		MemoryKiB:   u32(8192),
		Iterations:  u32(1),
		Parallelism: u32(1),
	}
}

// ---------------------------------------------------------------------------
// KSF parameter handling — §23.4 rules 3, 4 and 5
// ---------------------------------------------------------------------------

func TestClientOptionsUsesExactlyWhatTheServerNamed(t *testing.T) {
	opts, err := OpaqueKsfParams{
		Ksf:         "argon2id",
		MemoryKiB:   u32(65536),
		Iterations:  u32(3),
		Parallelism: u32(2),
	}.clientOptions()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// bytemare orders Argon2id as (time, memory KiB, threads).
	want := []uint64{3, 65536, 2}
	for i, v := range want {
		if opts.KSFParameters[i] != v {
			t.Fatalf("parameter %d: got %d, want %d", i, opts.KSFParameters[i], v)
		}
	}
	// These two are not in RFC 9807 and must match crates/axiam-opaque
	// exactly, or the two implementations derive different randomized
	// passwords and nothing interoperates.
	if len(opts.KSFSalt) != opaqueKSFSaltLength {
		t.Fatalf("salt length: got %d, want %d", len(opts.KSFSalt), opaqueKSFSaltLength)
	}
	for _, b := range opts.KSFSalt {
		if b != 0 {
			t.Fatal("the KSF salt must be all zero to match opaque-ke")
		}
	}
	if opts.KSFLength != opaqueKSFOutputLength {
		t.Fatalf("output length: got %d, want %d", opts.KSFLength, opaqueKSFOutputLength)
	}
}

func TestScryptParametersAreHonoured(t *testing.T) {
	opts, err := OpaqueKsfParams{Ksf: "scrypt", LogN: u8(15), R: u32(4), P: u32(2)}.clientOptions()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []uint64{15, 4, 2}
	for i, v := range want {
		if opts.KSFParameters[i] != v {
			t.Fatalf("parameter %d: got %d, want %d", i, opts.KSFParameters[i], v)
		}
	}
}

func TestAnUnknownKsfIsRefusedRatherThanSubstituted(t *testing.T) {
	// Substituting produces a well-formed randomized password that no AXIAM
	// server agrees with, reported to the user as a wrong password.
	_, err := OpaqueKsfParams{Ksf: "pbkdf2_sha256", Iterations: u32(600000)}.clientOptions()
	var netErr *NetworkError
	if !errors.As(err, &netErr) {
		t.Fatalf("want *NetworkError, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "pbkdf2_sha256") {
		t.Fatalf("the refusal must name the KSF: %v", err)
	}
}

func TestAMissingCostParameterIsRefusedNotReadAsZero(t *testing.T) {
	// Absent is not zero. Reading a missing memory_kib as 0 would stretch with
	// the wrong cost and fail against a record that is perfectly good.
	cases := map[string]OpaqueKsfParams{
		"argon2id without memory_kib":  {Ksf: "argon2id", Iterations: u32(1), Parallelism: u32(1)},
		"argon2id without iterations":  {Ksf: "argon2id", MemoryKiB: u32(8192), Parallelism: u32(1)},
		"argon2id without parallelism": {Ksf: "argon2id", MemoryKiB: u32(8192), Iterations: u32(1)},
		"scrypt without log_n":         {Ksf: "scrypt", R: u32(8), P: u32(1)},
		"scrypt without r":             {Ksf: "scrypt", LogN: u8(15), P: u32(1)},
		"scrypt without p":             {Ksf: "scrypt", LogN: u8(15), R: u32(8)},
	}
	for name, params := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := params.clientOptions(); err == nil {
				t.Fatal("want an error, got none")
			}
		})
	}
}

func TestOutOfRangeCostsAreRefusedRatherThanClamped(t *testing.T) {
	// A server is trusted to name its own policy, not to name a cost that
	// would wedge every device an account owns. Clamping would be worse than
	// failing: the client would stretch with a cost the server did not name.
	cases := map[string]OpaqueKsfParams{
		"memory too low":   {Ksf: "argon2id", MemoryKiB: u32(64), Iterations: u32(1), Parallelism: u32(1)},
		"memory too high":  {Ksf: "argon2id", MemoryKiB: u32(4_194_304), Iterations: u32(1), Parallelism: u32(1)},
		"too many passes":  {Ksf: "argon2id", MemoryKiB: u32(8192), Iterations: u32(99), Parallelism: u32(1)},
		"too parallel":     {Ksf: "argon2id", MemoryKiB: u32(8192), Iterations: u32(1), Parallelism: u32(99)},
		"scrypt n too low": {Ksf: "scrypt", LogN: u8(10), R: u32(8), P: u32(1)},
		"scrypt n too big": {Ksf: "scrypt", LogN: u8(24), R: u32(8), P: u32(1)},
	}
	for name, params := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := params.clientOptions(); err == nil {
				t.Fatal("want an error, got none")
			}
		})
	}
}

func TestAcceptedBoundsAreInclusive(t *testing.T) {
	for _, params := range []OpaqueKsfParams{
		{Ksf: "argon2id", MemoryKiB: u32(8192), Iterations: u32(1), Parallelism: u32(1)},
		{Ksf: "argon2id", MemoryKiB: u32(1_048_576), Iterations: u32(10), Parallelism: u32(16)},
		{Ksf: "scrypt", LogN: u8(14), R: u32(1), P: u32(1)},
		{Ksf: "scrypt", LogN: u8(20), R: u32(16), P: u32(16)},
	} {
		if _, err := params.clientOptions(); err != nil {
			t.Fatalf("%+v should be accepted: %v", params, err)
		}
	}
}

// ---------------------------------------------------------------------------
// The HTTP paths
// ---------------------------------------------------------------------------

func newOpaqueTestClient(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(handler)
	client, err := NewClient(server.URL, "default", WithOrgSlug("acme"))
	if err != nil {
		server.Close()
		t.Fatalf("client: %v", err)
	}
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})
	return client, server
}

func TestOpaqueDisabledTenantIsANetworkErrorNotAnAuthError(t *testing.T) {
	// Reporting this as a credential failure would send a user off to reset a
	// password that works, and would stop a caller falling back to Login.
	client, _ := newOpaqueTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	_, err := client.LoginOpaque(context.Background(), "alice", "pw")
	var netErr *NetworkError
	if !errors.As(err, &netErr) {
		t.Fatalf("want *NetworkError, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "Login") {
		t.Fatalf("the message should point at the fallback: %v", err)
	}
}

func TestTheLoginStartBodyCarriesTheWorkspaceAndNoPassword(t *testing.T) {
	var body map[string]any
	client, _ := newOpaqueTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.WriteHeader(http.StatusNotFound) // stop the exchange here
	})

	_, _ = client.LoginOpaque(context.Background(), "alice", "hunter2-not-sent")

	if body["tenant_slug"] != "default" || body["org_slug"] != "acme" {
		t.Fatalf("workspace not resolved: %+v", body)
	}
	if body["username_or_email"] != "alice" {
		t.Fatalf("username not sent: %+v", body)
	}
	if _, present := body["ke1"]; !present {
		t.Fatalf("ke1 missing: %+v", body)
	}
	// The property the whole protocol exists for.
	raw, _ := json.Marshal(body)
	if strings.Contains(string(raw), "hunter2-not-sent") {
		t.Fatalf("the request body carried the plaintext password: %s", raw)
	}
}

func TestAMalformedKE2IsANetworkErrorAndNothingIsFinished(t *testing.T) {
	var finishCalls int
	client, _ := newOpaqueTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/login/finish") {
			finishCalls++
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"opaque_session": "s",
			"ke2":            "not hex",
			"suite":          "ristretto255_sha512",
			"ksf":            "argon2id",
			"memory_kib":     8192,
			"iterations":     1,
			"parallelism":    1,
		})
	})

	_, err := client.LoginOpaque(context.Background(), "alice", "pw")
	var netErr *NetworkError
	if !errors.As(err, &netErr) {
		t.Fatalf("want *NetworkError, got %T: %v", err, err)
	}
	if finishCalls != 0 {
		t.Fatal("nothing may be sent to login/finish after KE2 fails")
	}
}

func TestAnUnknownKsfOverHttpStopsBeforeFinish(t *testing.T) {
	var finishCalls int
	client, _ := newOpaqueTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/login/finish") {
			finishCalls++
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"opaque_session": "s",
			"ke2":            hex.EncodeToString(make([]byte, 320)),
			"suite":          "ristretto255_sha512",
			"ksf":            "bcrypt",
		})
	})

	_, err := client.LoginOpaque(context.Background(), "alice", "pw")
	if err == nil || !strings.Contains(err.Error(), "bcrypt") {
		t.Fatalf("want a refusal naming the KSF, got %v", err)
	}
	if finishCalls != 0 {
		t.Fatal("nothing may be sent to login/finish after a KSF refusal")
	}
}

func TestEnrolmentRefusesADisabledTenant(t *testing.T) {
	client, _ := newOpaqueTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	_, err := client.OpaqueEnrollment(context.Background(), "pw")
	var netErr *NetworkError
	if !errors.As(err, &netErr) {
		t.Fatalf("want *NetworkError, got %T: %v", err, err)
	}
}

func TestEnrolmentSendsTheWorkspaceAndARegistrationRequest(t *testing.T) {
	var body map[string]any
	client, _ := newOpaqueTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.WriteHeader(http.StatusNotFound)
	})

	_, _ = client.OpaqueEnrollment(context.Background(), "secret-not-sent")

	if body["tenant_slug"] != "default" || body["org_slug"] != "acme" {
		t.Fatalf("workspace not resolved: %+v", body)
	}
	req, _ := body["registration_request"].(string)
	// A blinded ristretto255 element: 32 bytes, hex.
	if len(req) != 64 {
		t.Fatalf("registration_request should be 32 bytes of hex, got %d chars", len(req))
	}
	raw, _ := json.Marshal(body)
	if strings.Contains(string(raw), "secret-not-sent") {
		t.Fatalf("the request body carried the plaintext password: %s", raw)
	}
}

func TestOpaqueAvailableIsTrueForThisBuild(t *testing.T) {
	client, _ := newOpaqueTestClient(t, func(w http.ResponseWriter, r *http.Request) {})
	if !client.OpaqueAvailable() {
		t.Fatal("the Go SDK compiles the implementation in")
	}
}

func TestOpaqueCallsAreRefusedAfterClose(t *testing.T) {
	// §18 deterministic shutdown: a closed client fails rather than silently
	// working.
	client, _ := newOpaqueTestClient(t, func(w http.ResponseWriter, r *http.Request) {})
	client.Close()

	if _, err := client.LoginOpaque(context.Background(), "alice", "pw"); err == nil {
		t.Fatal("LoginOpaque should refuse a closed client")
	}
	if _, err := client.OpaqueEnrollment(context.Background(), "pw"); err == nil {
		t.Fatal("OpaqueEnrollment should refuse a closed client")
	}
}

// ---------------------------------------------------------------------------
// The remaining branches
// ---------------------------------------------------------------------------

func TestScryptBoundsAreCheckedIndividually(t *testing.T) {
	// opaqueCheckScrypt has three independent guards, and a test that only
	// tripped log_n would leave the other two unexercised — which is how a
	// copy-paste error in a bounds check survives review.
	for name, params := range map[string]OpaqueKsfParams{
		"r too small": {Ksf: "scrypt", LogN: u8(15), R: u32(0), P: u32(1)},
		"r too large": {Ksf: "scrypt", LogN: u8(15), R: u32(64), P: u32(1)},
		"p too small": {Ksf: "scrypt", LogN: u8(15), R: u32(8), P: u32(0)},
		"p too large": {Ksf: "scrypt", LogN: u8(15), R: u32(8), P: u32(64)},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := params.clientOptions(); err == nil {
				t.Fatal("want an error, got none")
			}
		})
	}
}

func TestANonNotFoundErrorFromLoginStartIsMapped(t *testing.T) {
	// 404 has its own meaning (the tenant does not offer OPAQUE); everything
	// else must go through the shared error mapper rather than being reported
	// as a disabled tenant.
	client, _ := newOpaqueTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	_, err := client.LoginOpaque(context.Background(), "alice", "pw")
	if err == nil {
		t.Fatal("a 500 must not sign in")
	}
	if strings.Contains(err.Error(), "does not offer OPAQUE") {
		t.Fatalf("a 500 is not a disabled tenant: %v", err)
	}
}

func TestAMalformedLoginStartBodyIsADeserialisationError(t *testing.T) {
	client, _ := newOpaqueTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{not json"))
	})

	if _, err := client.LoginOpaque(context.Background(), "alice", "pw"); err == nil {
		t.Fatal("a malformed body must not sign in")
	}
}

func TestANonNotFoundErrorFromRegisterStartIsMapped(t *testing.T) {
	client, _ := newOpaqueTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})

	_, err := client.OpaqueEnrollment(context.Background(), "pw")
	if err == nil {
		t.Fatal("a 403 must not produce an enrolment")
	}
	if strings.Contains(err.Error(), "does not offer OPAQUE") {
		t.Fatalf("a 403 is not a disabled tenant: %v", err)
	}
}

func TestAMalformedRegisterStartBodyIsADeserialisationError(t *testing.T) {
	client, _ := newOpaqueTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{not json"))
	})

	if _, err := client.OpaqueEnrollment(context.Background(), "pw"); err == nil {
		t.Fatal("a malformed body must not produce an enrolment")
	}
}

func TestAnUnknownKsfIsRefusedDuringEnrolment(t *testing.T) {
	// The same rule as on the login path, on the path that actually writes a
	// credential: enrolling under a substituted KSF would store a record the
	// server can never open.
	client, _ := newOpaqueTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"opaque_session":        "s",
			"registration_response": hex.EncodeToString(make([]byte, 64)),
			"suite":                 "ristretto255_sha512",
			"ksf":                   "bcrypt",
		})
	})

	_, err := client.OpaqueEnrollment(context.Background(), "pw")
	if err == nil || !strings.Contains(err.Error(), "bcrypt") {
		t.Fatalf("want a refusal naming the KSF, got %v", err)
	}
}

func TestAMalformedRegistrationResponseIsRefused(t *testing.T) {
	client, _ := newOpaqueTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"opaque_session":        "s",
			"registration_response": "not hex",
			"suite":                 "ristretto255_sha512",
			"ksf":                   "argon2id",
			"memory_kib":            8192,
			"iterations":            1,
			"parallelism":           1,
		})
	})

	var netErr *NetworkError
	_, err := client.OpaqueEnrollment(context.Background(), "pw")
	if !errors.As(err, &netErr) {
		t.Fatalf("want *NetworkError, got %T: %v", err, err)
	}
}
